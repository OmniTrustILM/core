package com.otilm.core.service.ai;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;
import com.otilm.ai.runtime.protocol.ManagementAction;
import com.otilm.ai.runtime.protocol.ManagementBinding;
import com.otilm.ai.runtime.protocol.ManagementDispatchEnvelope;
import com.otilm.ai.runtime.protocol.ProtocolCodec;
import com.otilm.ai.runtime.protocol.RunBinding;
import com.otilm.ai.runtime.protocol.RunDispatchEnvelope;
import com.otilm.core.model.ai.AiModelDispatchPayload;
import com.otilm.core.model.ai.AiModelDispatchState.ConnectionVersion;
import com.otilm.core.model.ai.AiModelDispatchState.ExactPayload;
import com.otilm.core.model.ai.AiModelDispatchState.ResolvedDispatch;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.time.Instant;
import java.util.Arrays;
import java.util.Base64;
import java.util.HexFormat;
import java.util.UUID;
import java.util.function.Consumer;
import java.util.stream.Stream;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;
import org.junit.jupiter.params.provider.ValueSource;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class AiRuntimeGatewayWireTest {
    private static final ObjectMapper JSON = new ObjectMapper();
    private static final ProtocolCodec PROTOCOL = new ProtocolCodec();
    private static final UUID INTENT = UUID.fromString("00000000-0000-0000-0000-000000000001");
    private static final UUID CORRELATION = UUID.fromString("00000000-0000-0000-0000-000000000002");
    private static final Instant EXPIRY = Instant.parse("2030-01-01T00:00:00Z");
    private static final RunBinding BINDING = new RunBinding(UUID.randomUUID(), UUID.randomUUID(), UUID.randomUUID(),
            UUID.randomUUID(), 4, EXPIRY);
    private static final String DIGEST = "a".repeat(64);
    private static final RunDispatchEnvelope ENVELOPE = new RunDispatchEnvelope(1, INTENT, DIGEST, BINDING);
    private final AiRuntimeGatewayWire wire = new AiRuntimeGatewayWire();

    @Test
    void readsActualProtocolRunEnvelopeWithoutGrantingAuthority() throws Exception {
        var parsed = wire.readRedeem(bytes(redeem()));
        assertThat(parsed).isNotNull();
        assertThat(parsed.correlation()).isEqualTo(CORRELATION);
        assertThat(parsed.envelope()).isEqualTo(ENVELOPE);
        assertThat(parsed.toString()).doesNotContain(BINDING.claimId().toString(), DIGEST);
    }

    @Test
    void unknownAndHttpObservationsPreserveExactOwnedBytes() throws Exception {
        byte[] observed = {0, 1, (byte) 255};
        byte[] input = bytes(outcome(observed));
        byte[] original = input.clone();
        var parsed = wire.readOutcome(input);
        assertThat(parsed).isNotNull();
        assertThat(parsed.protocolVersion()).isEqualTo(1);
        assertThat(parsed.kind()).isEqualTo("run-outcome");
        assertThat(parsed.intentId()).isEqualTo(INTENT);
        assertThat(parsed.gatewayCorrelation()).isEqualTo(CORRELATION);
        assertThat(parsed.binding()).isEqualTo(BINDING);
        assertThat(parsed.payloadSha256()).isEqualTo(DIGEST);
        assertThat(parsed.transportCode()).isEqualTo(AiRuntimeGatewayWire.TransportCode.HTTP_200);
        assertThat(parsed.usage()).isEqualTo(AiRuntimeGatewayWire.Usage.UNKNOWN);
        assertThat(parsed.responseBytes()).containsExactly(observed);
        assertThat(parsed.responseSha256()).isEqualTo(sha(observed));
        assertThat(parsed.responseByteCount()).isEqualTo(observed.length);
        assertThat(parsed.outcomeSha256()).isEqualTo(sha(original));
        input[0] = 0;
        parsed.requestBytes()[0] = 0;
        parsed.responseBytes()[0] = 99;
        assertThat(parsed.requestBytes()).containsExactly(original);
        assertThat(parsed.responseBytes()).containsExactly(observed);
        assertThat(parsed.toString()).doesNotContain(DIGEST, parsed.responseBase64(), INTENT.toString());
        var unknown = wire.readOutcome(bytes(outcome(null)));
        assertThat(unknown).isNotNull();
        assertThat(unknown.transportCode()).isEqualTo(AiRuntimeGatewayWire.TransportCode.UNKNOWN);
        assertThat(unknown.responseBytes()).isNull();
        assertThat(unknown.responseBase64()).isNull();
        assertThat(unknown.responseSha256()).isNull();
        assertThat(unknown.responseByteCount()).isZero();
    }

    @Test
    void replyMapsOnlyActualResolvedDispatchAndValidatedBinding() throws Exception {
        var dispatch = dispatch();
        byte[] encoded = wire.consumedReply(dispatch, BINDING);
        assertThat(encoded).isNotEmpty().hasSizeLessThanOrEqualTo(1_500_000);
        JsonNode reply = JSON.readTree(encoded);
        assertThat(reply.size()).isEqualTo(12);
        assertThat(reply.get("kind").textValue()).isEqualTo("run-consumed");
        assertThat(reply.get("protocolVersion").intValue()).isEqualTo(1);
        assertThat(reply.get("intentId").textValue()).isEqualTo(dispatch.intentId().toString());
        assertThat(reply.get("gatewayCorrelation").textValue()).isEqualTo(dispatch.gatewayCorrelation().toString());
        assertThat(reply.get("binding")).isEqualTo(redeem().get("envelope").get("binding"));
        assertThat(Base64.getDecoder().decode(reply.get("payloadBase64").textValue()))
                .containsExactly(dispatch.payload().bytes());
        assertThat(reply.get("payloadSha256").textValue()).isEqualTo(sha(dispatch.payload().bytes()));
        var connection = reply.get("connection");
        assertThat(connection.size()).isEqualTo(5);
        assertThat(connection.get("id").textValue()).isEqualTo(dispatch.connection().id().toString());
        assertThat(connection.get("configuration").longValue()).isEqualTo(2);
        assertThat(connection.get("destination").longValue()).isEqualTo(3);
        assertThat(connection.get("authentication").longValue()).isEqualTo(4);
        assertThat(connection.get("modelIdentifier").textValue()).isEqualTo("lab");
        assertThat(reply.get("origin").textValue()).isEqualTo(dispatch.origin().toString());
        assertThat(reply.get("credentialReference").textValue()).isEqualTo(dispatch.credentialReference());
        assertThat(reply.get("outputTokens").intValue()).isEqualTo(32);
        assertThat(reply.get("expiresAt").textValue()).isEqualTo(EXPIRY.toString());
    }

    @Test
    void acknowledgementContainsActualServerDigestAndVersionOnly() throws Exception {
        byte[] encoded = wire.acknowledgement(INTENT, CORRELATION, DIGEST, 17);
        assertThat(encoded).isNotEmpty().hasSizeLessThanOrEqualTo(4096);
        JsonNode ack = JSON.readTree(encoded);
        assertThat(ack.size()).isEqualTo(6);
        assertThat(ack.get("protocolVersion").intValue()).isEqualTo(1);
        assertThat(ack.get("kind").textValue()).isEqualTo("run-outcome-recorded");
        assertThat(ack.get("intentId").textValue()).isEqualTo(INTENT.toString());
        assertThat(ack.get("gatewayCorrelation").textValue()).isEqualTo(CORRELATION.toString());
        assertThat(ack.get("outcomeSha256").textValue()).isEqualTo(DIGEST);
        assertThat(ack.get("resultVersion").longValue()).isEqualTo(17);
    }

    @ParameterizedTest
    @MethodSource("invalidDocuments")
    void rejectsMalformedClosedRedeemDocuments(byte[] input) {
        assertThatThrownBy(() -> wire.readRedeem(input))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessage("Invalid gateway wire message")
                .hasNoCause();
    }

    static Stream<byte[]> invalidDocuments() throws Exception {
        String valid = new String(bytes(redeem()), StandardCharsets.UTF_8);
        var management = new ManagementDispatchEnvelope(1, INTENT, DIGEST, new ManagementBinding(UUID.randomUUID(),
                UUID.randomUUID(), UUID.randomUUID(), 1, ManagementAction.CONNECTION_CHECK, EXPIRY));
        ObjectNode crossKind = redeem();
        crossKind.set("envelope", JSON.readTree(PROTOCOL.writeDispatch(management)));
        return Stream
                .of(null, new byte[0], " ".getBytes(StandardCharsets.UTF_8), new byte[]{(byte) 0xc0, (byte) 0xaf},
                        ("\uFEFF" + valid).getBytes(StandardCharsets.UTF_8),
                        (valid + "{}").getBytes(StandardCharsets.UTF_8), "null".getBytes(StandardCharsets.UTF_8),
                        "[]".getBytes(StandardCharsets.UTF_8),
                        valid
                                .replace("\"protocolVersion\":1", "\"protocolVersion\":1,\"protocolVersion\":1")
                                .getBytes(StandardCharsets.UTF_8),
                        valid
                                .replace("\"protocolVersion\":1", "\"protocolVersion\":\"1\"")
                                .getBytes(StandardCharsets.UTF_8),
                        valid
                                .replace("\"protocolVersion\":1", "\"protocolVersion\":1.0")
                                .getBytes(StandardCharsets.UTF_8),
                        valid
                                .replace("\"protocolVersion\":1", "\"protocolVersion\":2")
                                .getBytes(StandardCharsets.UTF_8),
                        valid
                                .replace("\"gatewayCorrelation\":", "\"extra\":true,\"gatewayCorrelation\":")
                                .getBytes(StandardCharsets.UTF_8),
                        valid.replace(CORRELATION.toString(), "1-1-1-1-1").getBytes(StandardCharsets.UTF_8),
                        valid.replace("\"fence\":4", "\"fence\":\"4\"").getBytes(StandardCharsets.UTF_8),
                        valid
                                .replace("2030-01-01T00:00:00Z", "2030-01-01T00:00:00+00:00")
                                .getBytes(StandardCharsets.UTF_8),
                        valid.replace(DIGEST, "A".repeat(64)).getBytes(StandardCharsets.UTF_8),
                        ("{\"x\":" + "[".repeat(40) + "0" + "]".repeat(40) + "}").getBytes(StandardCharsets.UTF_8),
                        bytes(crossKind), (" ".repeat(8193)).getBytes(StandardCharsets.UTF_8));
    }

    @ParameterizedTest
    @MethodSource("invalidOutcomes")
    void rejectsInvalidOutcomeContract(byte[] input) {
        assertThatThrownBy(() -> wire.readOutcome(input))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessage("Invalid gateway wire message")
                .hasNoCause();
    }

    static Stream<byte[]> invalidOutcomes() throws Exception {
        var variants = new java.util.ArrayList<byte[]>();
        for (Consumer<ObjectNode> change : java.util.List
                .<Consumer<ObjectNode>>of(o -> o.put("kind", "management-outcome"), o -> o.put("protocolVersion", 2),
                        o -> o.put("protocolVersion", "1"), o -> o.put("protocolVersion", true),
                        o -> o.put("protocolVersion", 1.0), o -> o.put("intentId", 1),
                        o -> o.put("gatewayCorrelation", "invalid"), o -> o.put("payloadSha256", "A".repeat(64)),
                        o -> o.put("transportCode", "HTTP_201"), o -> o.put("responseBase64", "YQ"),
                        o -> o.put("responseBase64", "YR=="), o -> o.put("responseBase64", "YQ==\n"),
                        o -> o.put("responseBase64", "YQ-_"), o -> o.put("responseBase64", ""),
                        o -> o.put("responseSha256", DIGEST), o -> o.put("responseByteCount", 0),
                        o -> o.put("responseByteCount", -1), o -> o.put("responseByteCount", "1"),
                        o -> o.putNull("responseBase64"), o -> o.putNull("responseSha256"),
                        o -> o.put("responseByteCount", new java.math.BigInteger("999999999999999999999999")),
                        o -> o.put("responseByteCount", 1.0), o -> o.put("responseByteCount", Long.MAX_VALUE),
                        o -> o.put("extra", "SYNTHETIC_CONTENT_CANARY"), o -> o.remove("responseSha256"),
                        o -> o.putNull("binding"), o -> ((ObjectNode) o.get("usage")).put("kind", "known"),
                        o -> ((ObjectNode) o.get("usage")).put("promptTokens", 1), o -> o.putNull("usage"))) {
            ObjectNode node = outcome(new byte[]{'a'});
            change.accept(node);
            variants.add(bytes(node));
        }
        ObjectNode unknown = outcome(null);
        unknown.put("responseBase64", "YQ==");
        variants.add(bytes(unknown));
        unknown = outcome(null);
        unknown.put("responseSha256", DIGEST);
        variants.add(bytes(unknown));
        unknown = outcome(null);
        unknown.put("responseByteCount", 1);
        variants.add(bytes(unknown));
        String valid = new String(bytes(outcome(null)), StandardCharsets.UTF_8);
        variants.add((valid + "true").getBytes(StandardCharsets.UTF_8));
        variants
                .add(valid
                        .replace("\"kind\":\"unknown\"", "\"kind\":\"unknown\",\"kind\":\"unknown\"")
                        .getBytes(StandardCharsets.UTF_8));
        variants.add(valid.replace("UNKNOWN", "\\uD800").getBytes(StandardCharsets.UTF_8));
        return variants.stream();
    }

    @Test
    void acceptsExactByteLimitsAndRejectsDecodedResponseOverLimit() throws Exception {
        byte[] redeem = pad(bytes(redeem()), 8192);
        assertThat(wire.readRedeem(redeem)).isNotNull();
        byte[] maximum = new byte[1_048_576];
        Arrays.fill(maximum, (byte) 'x');
        byte[] outcome = pad(bytes(outcome(maximum)), 1_500_000);
        var parsed = wire.readOutcome(outcome);
        assertThat(parsed).isNotNull();
        assertThat(parsed.responseBytes()).containsExactly(maximum);
        assertThat(parsed.outcomeSha256()).isEqualTo(sha(outcome));
        assertThat(parsed.requestBytes()).containsExactly(outcome);
        ObjectNode oversizedResponse = outcome(new byte[1_048_577]);
        oversizedResponse.put("responseByteCount", 1_048_576);
        byte[] invalid = bytes(oversizedResponse);
        assertThatThrownBy(() -> wire.readOutcome(invalid)).isInstanceOf(IllegalArgumentException.class);
    }

    @Test
    void refusesInvalidAcknowledgementAndExpiryMismatch() {
        assertThatThrownBy(() -> wire.acknowledgement(null, CORRELATION, DIGEST, 1))
                .isInstanceOf(IllegalArgumentException.class);
        assertThatThrownBy(() -> wire.acknowledgement(INTENT, null, DIGEST, 1))
                .isInstanceOf(IllegalArgumentException.class);
        assertThatThrownBy(() -> wire.acknowledgement(INTENT, CORRELATION, DIGEST.toUpperCase(), 1))
                .isInstanceOf(IllegalArgumentException.class);
        assertThatThrownBy(() -> wire.acknowledgement(INTENT, CORRELATION, null, 1))
                .isInstanceOf(IllegalArgumentException.class);
        assertThatThrownBy(() -> wire.acknowledgement(INTENT, CORRELATION, DIGEST, 0))
                .isInstanceOf(IllegalArgumentException.class);
        var wrong = new RunBinding(BINDING.runId(), BINDING.attemptId(), BINDING.podUid(), BINDING.claimId(),
                BINDING.fence(), EXPIRY.plusSeconds(1));
        var dispatch = dispatch();
        assertThatThrownBy(() -> wire.consumedReply(dispatch, wrong)).isInstanceOf(IllegalArgumentException.class);
        assertThatThrownBy(() -> wire.consumedReply(null, BINDING)).isInstanceOf(IllegalArgumentException.class);
    }

    private static ObjectNode redeem() throws Exception {
        ObjectNode root = JSON
                .createObjectNode()
                .put("protocolVersion", 1)
                .put("gatewayCorrelation", CORRELATION.toString());
        root.set("envelope", JSON.readTree(PROTOCOL.writeDispatch(ENVELOPE)));
        return root;
    }

    private static ObjectNode outcome(byte[] response) throws Exception {
        ObjectNode root = JSON
                .createObjectNode()
                .put("protocolVersion", 1)
                .put("kind", "run-outcome")
                .put("intentId", INTENT.toString())
                .put("gatewayCorrelation", CORRELATION.toString());
        root.set("binding", redeem().get("envelope").get("binding"));
        root.put("payloadSha256", DIGEST).put("transportCode", response == null ? "UNKNOWN" : "HTTP_200");
        if (response == null) {
            root.putNull("responseBase64").putNull("responseSha256").put("responseByteCount", 0);
        } else {
            root
                    .put("responseBase64", Base64.getEncoder().encodeToString(response))
                    .put("responseSha256", sha(response))
                    .put("responseByteCount", response.length);
        }
        root.putObject("usage").put("kind", "unknown");
        return root;
    }

    private static ResolvedDispatch dispatch() {
        return new ResolvedDispatch(INTENT, new ConnectionVersion(UUID.randomUUID(), 2, 3, 4, "lab"),
                AiModelDispatchPayload.text("lab", 32, "instructions", "protected prompt", "protected context"), 32,
                URI.create("https://provider.invalid:8443"), "provider-reference", EXPIRY, CORRELATION);
    }

    private static byte[] bytes(JsonNode node) throws Exception {
        return JSON.writeValueAsBytes(node);
    }

    private static String sha(byte[] bytes) throws Exception {
        return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(bytes));
    }

    private static byte[] pad(byte[] bytes, int size) {
        byte[] padded = Arrays.copyOf(bytes, size);
        Arrays.fill(padded, bytes.length, size, (byte) ' ');
        return padded;
    }

    @Test
    void consumedReplySupportsExactMaximumCorePayloadWithoutReserialization() throws Exception {
        ObjectNode root = JSON.createObjectNode().put("model", "lab").put("max_tokens", 32).put("stream", false);
        var messages = root.putArray("messages");
        for (int i = 0; i < 16; i++) {
            messages.addObject().put("role", "user").put("content", "x".repeat(65000));
        }
        int remaining = 1_048_576 - bytes(root).length;
        for (JsonNode message : messages) {
            int extra = Math.min(536, remaining);
            ((ObjectNode) message).put("content", "x".repeat(65000 + extra));
            remaining -= extra;
        }
        assertThat(remaining).isZero();
        byte[] exact = bytes(root);
        assertThat(exact).hasSize(1_048_576);
        var original = dispatch();
        var maximum = new ResolvedDispatch(original.intentId(), original.connection(), new ExactPayload(exact),
                original.outputTokens(), original.origin(), original.credentialReference(), EXPIRY, CORRELATION);
        byte[] reply = wire.consumedReply(maximum, BINDING);
        assertThat(reply).isNotEmpty().hasSizeLessThanOrEqualTo(1_500_000);
        JsonNode parsed = JSON.readTree(reply);
        assertThat(Base64.getDecoder().decode(parsed.get("payloadBase64").textValue())).containsExactly(exact);
        assertThat(parsed.get("payloadSha256").textValue()).isEqualTo(sha(exact));
    }

    @Test
    void exactRequestDigestIncludesWhitespaceAndEscapesWithoutNormalizing() throws Exception {
        byte[] plain = bytes(outcome(null));
        byte[] escaped = (" " + new String(plain, StandardCharsets.UTF_8).replace("UNKNOWN", "\\u0055NKNOWN") + "\n")
                .getBytes(StandardCharsets.UTF_8);
        var first = wire.readOutcome(plain);
        var second = wire.readOutcome(escaped);
        assertThat(first).isNotNull();
        assertThat(second).isNotNull();
        assertThat(second.transportCode()).isEqualTo(first.transportCode());
        assertThat(second.outcomeSha256()).isEqualTo(sha(escaped)).isNotEqualTo(first.outcomeSha256());
        assertThat(second.requestBytes()).containsExactly(escaped);
    }

    @Test
    void unicodeAndMalformedFieldNamesNeverEscapeInFailures() {
        byte[] high = "{\"x\":\"\\uD800x\"}".getBytes(StandardCharsets.UTF_8);
        byte[] low = "{\"x\":\"\\uDC00\"}".getBytes(StandardCharsets.UTF_8);
        byte[] validPairButUnknown = "{\"x\":\"\\uD83D\\uDE00\"}".getBytes(StandardCharsets.UTF_8);
        byte[] badName = "{\"\\uD800\":\"SYNTHETIC_CONTENT_CANARY\"}".getBytes(StandardCharsets.UTF_8);
        for (byte[] input : new byte[][]{high, low, validPairButUnknown, badName}) {
            assertThatThrownBy(() -> wire.readOutcome(input))
                    .isInstanceOf(IllegalArgumentException.class)
                    .hasMessage("Invalid gateway wire message")
                    .hasNoCause();
        }
    }

    @ParameterizedTest
    @ValueSource(booleans = {false, true})
    void rejectsOneByteBeyondLimitEvenWhenTheWholeDocumentIsValidJson(boolean outcome) throws Exception {
        byte[] input = outcome ? pad(bytes(outcome(null)), 1_500_001) : pad(bytes(redeem()), 8193);
        // The ordinary JSON parser accepts the entire candidate; only the wire byte cap is wrong.
        assertThat(JSON.readTree(input).isObject()).isTrue();
        if (outcome) {
            assertThatThrownBy(() -> wire.readOutcome(input)).isInstanceOf(IllegalArgumentException.class);
        } else {
            assertThatThrownBy(() -> wire.readRedeem(input)).isInstanceOf(IllegalArgumentException.class);
        }
    }

    @ParameterizedTest
    @MethodSource("nestedProtocolViolations")
    void rejectsNestedProtocolCoercionAndUnknownFields(boolean outcome, byte[] input) {
        if (outcome) {
            assertThatThrownBy(() -> wire.readOutcome(input)).isInstanceOf(IllegalArgumentException.class);
        } else {
            assertThatThrownBy(() -> wire.readRedeem(input)).isInstanceOf(IllegalArgumentException.class);
        }
    }

    static Stream<Arguments> nestedProtocolViolations() throws Exception {
        var cases = new java.util.ArrayList<Arguments>();
        for (double fence : new double[]{4.0, 4.5}) {
            ObjectNode redeem = redeem();
            ((ObjectNode) redeem.get("envelope").get("binding")).put("fence", fence);
            cases.add(Arguments.of(false, bytes(redeem)));
            ObjectNode outcome = outcome(null);
            ((ObjectNode) outcome.get("binding")).put("fence", fence);
            cases.add(Arguments.of(true, bytes(outcome)));
        }
        ObjectNode redeem = redeem();
        ((ObjectNode) redeem.get("envelope")).put("protocolVersion", 1.0);
        cases.add(Arguments.of(false, bytes(redeem)));
        redeem = redeem();
        ((ObjectNode) redeem.get("envelope")).put("unexpected", "forbidden");
        cases.add(Arguments.of(false, bytes(redeem)));
        redeem = redeem();
        ((ObjectNode) redeem.get("envelope").get("binding")).put("unexpected", "forbidden");
        cases.add(Arguments.of(false, bytes(redeem)));
        ObjectNode outcome = outcome(null);
        ((ObjectNode) outcome.get("binding")).put("unexpected", "forbidden");
        cases.add(Arguments.of(true, bytes(outcome)));
        return cases.stream();
    }

}
