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
import org.junit.jupiter.params.provider.EnumSource;
import org.junit.jupiter.params.provider.MethodSource;
import org.junit.jupiter.params.provider.ValueSource;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/** Pure syntax/mapping; public actor/session/configuration data never grants management authority. */
class AiRuntimeManagementWireTest {
    private static final ObjectMapper JSON = new ObjectMapper();
    private static final ProtocolCodec PROTOCOL = new ProtocolCodec();
    private static final UUID INTENT = UUID.randomUUID();
    private static final UUID CORRELATION = UUID.randomUUID();
    private static final UUID ACTOR = UUID.randomUUID();
    private static final UUID SESSION = UUID.randomUUID();
    private static final UUID CONFIGURATION = UUID.randomUUID();
    private static final Instant EXPIRY = Instant.parse("2030-01-01T00:00:00Z");
    private static final String DIGEST = "a".repeat(64);
    private static final ManagementBinding BINDING = binding(ManagementAction.CONNECTION_CHECK);
    private final AiRuntimeManagementWire wire = new AiRuntimeManagementWire();

    @ParameterizedTest
    @EnumSource(ManagementAction.class)
    void readsExactActualManagementEnvelopeWithoutRunRecords(ManagementAction action) throws Exception {
        var envelope = new ManagementDispatchEnvelope(1, INTENT, DIGEST, binding(action));
        var parsed = wire.readRedeem(bytes(redeem(envelope)));
        assertThat(parsed).isNotNull();
        assertThat(parsed.correlation()).isEqualTo(CORRELATION);
        assertThat(parsed.envelope()).isEqualTo(envelope);
        assertThat(parsed.toString()).doesNotContain(ACTOR.toString(), SESSION.toString(), DIGEST);
    }

    @Test
    void runAndManagementAudiencesCannotBeCoercedIntoEachOther() throws Exception {
        var run = new RunDispatchEnvelope(1, INTENT, DIGEST,
                new RunBinding(UUID.randomUUID(), UUID.randomUUID(), UUID.randomUUID(), UUID.randomUUID(), 1, EXPIRY));
        var managementBytes = bytes(redeem(new ManagementDispatchEnvelope(1, INTENT, DIGEST, BINDING)));
        var runBytes = bytes(redeem(run));
        assertThatThrownBy(() -> wire.readRedeem(runBytes)).isInstanceOf(IllegalArgumentException.class);
        var runCodec = new AiRuntimeGatewayWire();
        assertThatThrownBy(() -> runCodec.readRedeem(managementBytes)).isInstanceOf(IllegalArgumentException.class);
    }

    @Test
    void ownsExactOutcomeBytesAndComputesOriginalRequestDigest() throws Exception {
        byte[] provider = {0, 1, (byte) 255};
        byte[] raw = (" \n" + new String(bytes(outcome(provider)), StandardCharsets.UTF_8) + " \t")
                .getBytes(StandardCharsets.UTF_8);
        byte[] original = raw.clone();
        var parsed = wire.readOutcome(raw);
        assertThat(parsed.protocolVersion()).isEqualTo(1);
        assertThat(parsed.kind()).isEqualTo("management-outcome");
        assertThat(parsed.intentId()).isEqualTo(INTENT);
        assertThat(parsed.gatewayCorrelation()).isEqualTo(CORRELATION);
        assertThat(parsed.binding()).isEqualTo(BINDING);
        assertThat(parsed.payloadSha256()).isEqualTo(DIGEST);
        assertThat(parsed.transportCode()).isEqualTo(AiRuntimeGatewayWire.TransportCode.HTTP_200);
        assertThat(parsed.usage()).isEqualTo(AiRuntimeGatewayWire.Usage.UNKNOWN);
        assertThat(parsed.responseByteCount()).isEqualTo(provider.length);
        assertThat(parsed.responseSha256()).isEqualTo(sha(provider));
        assertThat(parsed.outcomeSha256()).isEqualTo(sha(original));
        raw[0] = 0;
        parsed.requestBytes()[0] = 0;
        parsed.responseBytes()[0] = 4;
        assertThat(parsed.requestBytes()).containsExactly(original);
        assertThat(parsed.responseBytes()).containsExactly(provider);
        assertThat(parsed.toString())
                .doesNotContain(ACTOR.toString(), SESSION.toString(), DIGEST, parsed.responseBase64());
        var unknown = wire.readOutcome(bytes(outcome(null)));
        assertThat(unknown.transportCode()).isEqualTo(AiRuntimeGatewayWire.TransportCode.UNKNOWN);
        assertThat(unknown.responseBase64()).isNull();
        assertThat(unknown.responseSha256()).isNull();
        assertThat(unknown.responseBytes()).isNull();
        assertThat(unknown.responseByteCount()).isZero();
    }

    @Test
    void mapsActualConsumedMetadataAndExactManagementBinding() throws Exception {
        var dispatch = dispatch();
        var reply = JSON.readTree(wire.consumedReply(dispatch, BINDING));
        assertThat(reply.size()).isEqualTo(12);
        assertThat(reply.get("protocolVersion").intValue()).isEqualTo(1);
        assertThat(reply.get("kind").textValue()).isEqualTo("management-consumed");
        assertThat(reply.get("intentId").textValue()).isEqualTo(INTENT.toString());
        assertThat(reply.get("gatewayCorrelation").textValue()).isEqualTo(CORRELATION.toString());
        assertThat(reply.get("binding")).isEqualTo(outcome(null).get("binding"));
        assertThat(reply.get("connection").size()).isEqualTo(5);
        assertThat(reply.get("connection").get("id").textValue()).isEqualTo(CONFIGURATION.toString());
        assertThat(reply.get("connection").get("configuration").longValue()).isEqualTo(2);
        assertThat(reply.get("connection").get("destination").longValue()).isEqualTo(3);
        assertThat(reply.get("connection").get("authentication").longValue()).isEqualTo(4);
        assertThat(reply.get("connection").get("modelIdentifier").textValue()).isEqualTo("lab");
        assertThat(Base64.getDecoder().decode(reply.get("payloadBase64").textValue()))
                .containsExactly(dispatch.payload().bytes());
        assertThat(reply.get("payloadSha256").textValue()).isEqualTo(sha(dispatch.payload().bytes()));
        assertThat(reply.get("outputTokens").intValue()).isEqualTo(32);
        assertThat(reply.get("origin").textValue()).isEqualTo("https://provider.invalid:8443");
        assertThat(reply.get("credentialReference").textValue()).isEqualTo("ilm-management-provider");
        assertThat(reply.get("expiresAt").textValue()).isEqualTo(EXPIRY.toString());
    }

    @ParameterizedTest
    @ValueSource(strings = {"configuration", "revision", "expiry"})
    void mappingCannotConfirmConflictingConsumedConfiguration(String field) {
        var dispatch = dispatch();
        var changed = new ManagementBinding(ACTOR, SESSION,
                field.equals("configuration") ? UUID.randomUUID() : CONFIGURATION, field.equals("revision") ? 3 : 2,
                ManagementAction.CONNECTION_CHECK, field.equals("expiry") ? EXPIRY.plusNanos(1) : EXPIRY);
        assertThatThrownBy(() -> wire.consumedReply(dispatch, changed)).isInstanceOf(IllegalArgumentException.class);
    }

    @Test
    void acknowledgementUsesSeparateKindActualServerHashAndPositiveVersion() throws Exception {
        var ack = JSON.readTree(wire.acknowledgement(INTENT, CORRELATION, DIGEST, 7));
        assertThat(ack.size()).isEqualTo(6);
        assertThat(ack.get("kind").textValue()).isEqualTo("management-outcome-recorded");
        assertThat(ack.get("intentId").textValue()).isEqualTo(INTENT.toString());
        assertThat(ack.get("gatewayCorrelation").textValue()).isEqualTo(CORRELATION.toString());
        assertThat(ack.get("outcomeSha256").textValue()).isEqualTo(DIGEST);
        assertThat(ack.get("resultVersion").longValue()).isEqualTo(7);
        assertThatThrownBy(() -> wire.acknowledgement(INTENT, CORRELATION, DIGEST, 0))
                .isInstanceOf(IllegalArgumentException.class);
    }

    @ParameterizedTest
    @MethodSource("badRedeemDocuments")
    void rejectsClosedMalformedAndCoercedRequests(byte[] input) {
        assertThatThrownBy(() -> wire.readRedeem(input)).isInstanceOf(IllegalArgumentException.class).hasNoCause();
    }

    static Stream<byte[]> badRedeemDocuments() throws Exception {
        var valid = redeem(new ManagementDispatchEnvelope(1, INTENT, DIGEST, BINDING));
        String text = new String(bytes(valid), StandardCharsets.UTF_8);
        return Stream
                .of(null, new byte[0], "null".getBytes(StandardCharsets.UTF_8), "[]".getBytes(StandardCharsets.UTF_8),
                        new byte[]{(byte) 0xc0, (byte) 0xaf}, ("\uFEFF" + text).getBytes(StandardCharsets.UTF_8),
                        (text + "{}").getBytes(StandardCharsets.UTF_8),
                        ("{\"protocolVersion\":1," + text.substring(1)).getBytes(StandardCharsets.UTF_8),
                        change(valid, n -> n.put("extra", true)), change(valid, n -> n.remove("protocolVersion")),
                        change(valid, n -> n.put("protocolVersion", 1.0)),
                        change(valid, n -> n.put("protocolVersion", "1")),
                        change(valid, n -> n.put("protocolVersion", 2)),
                        change(valid, n -> n.put("gatewayCorrelation", 1)),
                        change(valid, n -> ((ObjectNode) n.get("envelope")).put("extra", 0)),
                        change(valid,
                                n -> ((ObjectNode) n.get("envelope").get("binding"))
                                        .put("runId", UUID.randomUUID().toString())),
                        change(valid,
                                n -> ((ObjectNode) n.get("envelope").get("binding")).put("configurationRevision", 0)),
                        change(valid,
                                n -> ((ObjectNode) n.get("envelope").get("binding")).put("configurationRevision", 2.0)),
                        change(valid,
                                n -> ((ObjectNode) n.get("envelope").get("binding")).put("action", "connection_check")),
                        change(valid, n -> ((ObjectNode) n.get("envelope").get("binding")).put("actorId", "foreign")),
                        change(valid, n -> ((ObjectNode) n.get("envelope").get("binding")).put("sessionId", true)));
    }

    @ParameterizedTest
    @MethodSource("badOutcomes")
    void rejectsClosedTransportUsageHashAndScalarConfusion(byte[] input) {
        assertThatThrownBy(() -> wire.readOutcome(input)).isInstanceOf(IllegalArgumentException.class).hasNoCause();
    }

    static Stream<byte[]> badOutcomes() throws Exception {
        var valid = outcome(new byte[]{1, 2});
        var unknown = outcome(null);
        String text = new String(bytes(valid), StandardCharsets.UTF_8);
        return Stream
                .of(change(valid, n -> n.put("kind", "run-outcome")), change(valid, n -> n.put("intentId", false)),
                        change(valid, n -> n.put("extra", true)), change(valid, n -> n.remove("binding")),
                        change(valid, n -> n.put("responseBase64", "AQI")),
                        change(valid, n -> n.put("responseBase64", "AQI=\n")),
                        change(valid, n -> n.put("responseByteCount", 2.0)),
                        change(valid, n -> n.put("responseByteCount", "2")),
                        change(valid, n -> n.put("responseByteCount", 3)),
                        change(valid, n -> n.put("responseSha256", "0".repeat(64))),
                        change(valid, n -> n.put("payloadSha256", "A".repeat(64))),
                        change(valid, n -> n.put("responseBase64", false)),
                        change(valid, n -> ((ObjectNode) n.get("usage")).put("kind", "known")),
                        change(valid, n -> ((ObjectNode) n.get("usage")).put("totalTokens", 1)),
                        change(unknown, n -> n.put("responseBase64", "")),
                        change(unknown, n -> n.put("responseByteCount", 1)),
                        (text + " false").getBytes(StandardCharsets.UTF_8),
                        text
                                .replace("\"kind\":\"unknown\"", "\"kind\":\"unknown\",\"kind\":\"unknown\"")
                                .getBytes(StandardCharsets.UTF_8),
                        text.replace("\"unknown\"", "\"\\ud800\"").getBytes(StandardCharsets.UTF_8));
    }

    @Test
    void validJsonWhitespaceAndProviderSizeBoundariesAreInclusive() throws Exception {
        byte[] raw = bytes(outcome(null));
        byte[] maximum = Arrays.copyOf(raw, 1_500_000);
        Arrays.fill(maximum, raw.length, maximum.length, (byte) ' ');
        assertThat(wire.readOutcome(maximum).outcomeSha256()).isEqualTo(sha(maximum));
        byte[] tooLarge = Arrays.copyOf(maximum, 1_500_001);
        tooLarge[tooLarge.length - 1] = ' ';
        assertThatThrownBy(() -> wire.readOutcome(tooLarge)).isInstanceOf(IllegalArgumentException.class);
        byte[] provider = new byte[1_048_576];
        assertThat(wire.readOutcome(bytes(outcome(provider))).responseByteCount()).isEqualTo(provider.length);
        byte[] providerTooLarge = bytes(outcome(new byte[1_048_577]));
        assertThatThrownBy(() -> wire.readOutcome(providerTooLarge)).isInstanceOf(IllegalArgumentException.class);
        byte[] redeem = bytes(redeem(new ManagementDispatchEnvelope(1, INTENT, DIGEST, BINDING)));
        byte[] exact = Arrays.copyOf(redeem, 8192);
        Arrays.fill(exact, redeem.length, exact.length, (byte) ' ');
        assertThat(wire.readRedeem(exact).envelope().binding()).isEqualTo(BINDING);
        byte[] beyond = Arrays.copyOf(exact, 8193);
        beyond[beyond.length - 1] = ' ';
        assertThatThrownBy(() -> wire.readRedeem(beyond)).isInstanceOf(IllegalArgumentException.class);
    }

    private static ManagementBinding binding(ManagementAction action) {
        return new ManagementBinding(ACTOR, SESSION, CONFIGURATION, 2, action, EXPIRY);
    }

    private static ObjectNode redeem(com.otilm.ai.runtime.protocol.DispatchEnvelope envelope) throws Exception {
        var n = JSON.createObjectNode().put("protocolVersion", 1).put("gatewayCorrelation", CORRELATION.toString());
        n.set("envelope", JSON.readTree(PROTOCOL.writeDispatch(envelope)));
        return n;
    }

    private static ObjectNode outcome(byte[] response) throws Exception {
        var n = JSON
                .createObjectNode()
                .put("protocolVersion", 1)
                .put("kind", "management-outcome")
                .put("intentId", INTENT.toString())
                .put("gatewayCorrelation", CORRELATION.toString());
        n
                .set("binding",
                        redeem(new ManagementDispatchEnvelope(1, INTENT, DIGEST, BINDING))
                                .get("envelope")
                                .get("binding"));
        n.put("payloadSha256", DIGEST).put("transportCode", response == null ? "UNKNOWN" : "HTTP_200");
        if (response == null) {
            n.putNull("responseBase64").putNull("responseSha256").put("responseByteCount", 0);
        } else {
            n
                    .put("responseBase64", Base64.getEncoder().encodeToString(response))
                    .put("responseSha256", sha(response))
                    .put("responseByteCount", response.length);
        }
        n.putObject("usage").put("kind", "unknown");
        return n;
    }

    private static ResolvedDispatch dispatch() {
        return new ResolvedDispatch(INTENT, new ConnectionVersion(CONFIGURATION, 2, 3, 4, "lab"),
                AiModelDispatchPayload.text("lab", 32, "fixed instructions", "fixed check", ""), 32,
                URI.create("https://provider.invalid:8443"), "ilm-management-provider", EXPIRY, CORRELATION);
    }

    private static byte[] bytes(JsonNode n) throws Exception {
        return JSON.writeValueAsBytes(n);
    }

    private static byte[] change(ObjectNode source, Consumer<ObjectNode> c) throws Exception {
        var n = source.deepCopy();
        c.accept(n);
        return bytes(n);
    }

    private static String sha(byte[] b) throws Exception {
        return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(b));
    }
}
