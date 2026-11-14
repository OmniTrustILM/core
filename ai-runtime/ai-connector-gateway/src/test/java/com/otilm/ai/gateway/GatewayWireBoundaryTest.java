package com.otilm.ai.gateway;

import com.fasterxml.jackson.databind.node.ObjectNode;
import com.otilm.ai.runtime.protocol.PayloadFingerprint;
import com.otilm.ai.runtime.protocol.RunBinding;
import com.otilm.ai.runtime.protocol.RunDispatchEnvelope;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.Base64;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

import static com.otilm.ai.gateway.GatewayRunWireTest.BINDING;
import static com.otilm.ai.gateway.GatewayRunWireTest.CALL;
import static com.otilm.ai.gateway.GatewayRunWireTest.CONNECTION;
import static com.otilm.ai.gateway.GatewayRunWireTest.ENVELOPE;
import static com.otilm.ai.gateway.GatewayRunWireTest.INTENT;
import static com.otilm.ai.gateway.GatewayRunWireTest.JSON;
import static com.otilm.ai.gateway.GatewayRunWireTest.PAYLOAD;
import static com.otilm.ai.gateway.GatewayRunWireTest.PROTOCOL;
import static com.otilm.ai.gateway.GatewayRunWireTest.consumed;
import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class GatewayWireBoundaryTest {
    @Test
    void aMaximumProtectedResponseStillAcceptsTheExactOutcomeDocumentAcknowledgement() throws Exception {
        byte[] outcome = GatewayRunWire.outcome(ENVELOPE, CALL, new byte[GatewayRunWire.RESPONSE_LIMIT]);
        String digest = java.util.HexFormat
                .of()
                .formatHex(java.security.MessageDigest.getInstance("SHA-256").digest(outcome));
        ObjectNode ack = JSON
                .createObjectNode()
                .put("protocolVersion", 1)
                .put("kind", "run-outcome-recorded")
                .put("intentId", INTENT.toString())
                .put("gatewayCorrelation", CALL.toString())
                .put("outcomeSha256", digest)
                .put("resultVersion", 9);
        assertTrue(outcome.length > GatewayRunWire.RESPONSE_LIMIT);
        assertEquals(9, assertDoesNotThrow(
                () -> GatewayRunWire.acknowledgement(JSON.writeValueAsBytes(ack), ENVELOPE, CALL, outcome)));
    }

    @ParameterizedTest
    @ValueSource(strings = {
            "kind",
            "version",
            "intent",
            "correlation",
            "extra",
            "zero",
            "fraction",
            "overflow",
            "text-version",
            "null-digest"})
    void onlyAnExactPositiveServerAcknowledgementCanRecordAnOutcome(String mode) throws Exception {
        byte[] outcome = GatewayRunWire.outcome(ENVELOPE, CALL, "{}".getBytes(StandardCharsets.US_ASCII));
        ObjectNode ack = JSON
                .createObjectNode()
                .put("protocolVersion", 1)
                .put("kind", "run-outcome-recorded")
                .put("intentId", INTENT.toString())
                .put("gatewayCorrelation", CALL.toString())
                .put("outcomeSha256", PayloadFingerprint.sha256(outcome))
                .put("resultVersion", 9);
        switch (mode) {
            case "kind" -> ack.put("kind", "management-outcome-recorded");
            case "version" -> ack.put("protocolVersion", 2);
            case "intent" -> ack.put("intentId", BINDING.runId().toString());
            case "correlation" -> ack.put("gatewayCorrelation", BINDING.attemptId().toString());
            case "extra" -> ack.put("authority", true);
            case "zero" -> ack.put("resultVersion", 0);
            case "fraction" -> ack.put("resultVersion", 9.5);
            case "overflow" -> ack.put("resultVersion", BigInteger.valueOf(Long.MAX_VALUE).add(BigInteger.ONE));
            case "text-version" -> ack.put("resultVersion", "9");
            case "null-digest" -> ack.putNull("outcomeSha256");
        }
        assertThrows(GatewayFailure.class,
                () -> GatewayRunWire.acknowledgement(JSON.writeValueAsBytes(ack), ENVELOPE, CALL, outcome));
    }

    @ParameterizedTest
    @ValueSource(strings = {
            "empty-payload",
            "large-payload",
            "large-output",
            "text-output",
            "null-output",
            "blank-model",
            "nul-model",
            "large-model",
            "numeric-model",
            "connection-array",
            "uuid-short",
            "http",
            "userinfo",
            "query",
            "fragment",
            "zero-port",
            "large-port"})
    void positiveConsumeCannotCoerceUnboundedOrWrongTypedPrimitives(String mode) throws Exception {
        var root = consumed();
        var connection = (ObjectNode) root.get("connection");
        switch (mode) {
            case "empty-payload" -> root.put("payloadBase64", "");
            case "large-payload" -> root.put("payloadBase64", Base64.getEncoder().encodeToString(new byte[1_048_577]));
            case "large-output" -> root.put("outputTokens", 1L + Integer.MAX_VALUE);
            case "text-output" -> root.put("outputTokens", "32");
            case "null-output" -> root.putNull("outputTokens");
            case "blank-model" -> connection.put("modelIdentifier", " ");
            case "nul-model" -> connection.put("modelIdentifier", "a\0b");
            case "large-model" -> connection.put("modelIdentifier", "a".repeat(256));
            case "numeric-model" -> connection.put("modelIdentifier", 7);
            case "connection-array" -> root.putArray("connection");
            case "uuid-short" -> root.put("intentId", "0-0-4000-8000-1");
            case "http" -> root.put("origin", "http://provider.test");
            case "userinfo" -> root.put("origin", "https://synthetic@provider.test");
            case "query" -> root.put("origin", "https://provider.test?selector=x");
            case "fragment" -> root.put("origin", "https://provider.test#x");
            case "zero-port" -> root.put("origin", "https://provider.test:0");
            case "large-port" -> root.put("origin", "https://provider.test:65536");
        }
        assertThrows(GatewayFailure.class, () -> GatewayRunWire.consumed(JSON.writeValueAsBytes(root), ENVELOPE, CALL));
    }

    @Test
    void evenAnExactlyEchoedExpiredBindingCannotAuthorizeAProviderPhase() throws Exception {
        var expired = new RunBinding(BINDING.runId(), BINDING.attemptId(), BINDING.podUid(), BINDING.claimId(),
                BINDING.fence(), Instant.EPOCH);
        var envelope = new RunDispatchEnvelope(1, INTENT, ENVELOPE.payloadSha256(), expired);
        var root = consumed();
        root.set("binding", JSON.readTree(PROTOCOL.writeDispatch(envelope)).get("binding"));
        root.put("expiresAt", Instant.EPOCH.toString());
        assertThrows(GatewayFailure.class, () -> GatewayRunWire.consumed(JSON.writeValueAsBytes(root), envelope, CALL));
    }

    @Test
    void protectedOutcomeCapAcceptsTheExactMaximumAndRejectsEmptyOrOneByteMore() throws Exception {
        byte[] bytes = new byte[GatewayRunWire.RESPONSE_LIMIT];
        java.util.Arrays.fill(bytes, (byte) 'a');
        byte[] outcome = GatewayRunWire.outcome(ENVELOPE, CALL, bytes);
        var root = JSON.readTree(outcome);
        assertTrue(outcome.length <= GatewayRunWire.DOCUMENT_LIMIT);
        assertEquals(bytes.length, root.get("responseByteCount").intValue());
        assertArrayEquals(bytes, Base64.getDecoder().decode(root.get("responseBase64").textValue()));
        assertThrows(GatewayFailure.class, () -> GatewayRunWire.outcome(ENVELOPE, CALL, new byte[0]));
        assertThrows(GatewayFailure.class,
                () -> GatewayRunWire.outcome(ENVELOPE, CALL, new byte[GatewayRunWire.RESPONSE_LIMIT + 1]));
    }

    @ParameterizedTest
    @ValueSource(strings = {
            "null",
            "empty",
            "large",
            "array",
            "scalar",
            "duplicate",
            "trailing",
            "bom",
            "utf8",
            "low-surrogate",
            "depth"})
    void reflectedResponseInspectionKeepsItsOwnClosedBoundedJsonRules(String mode) {
        byte[] bytes = switch (mode) {
            case "null" -> null;
            case "empty" -> new byte[0];
            case "large" -> new byte[GatewayRunWire.RESPONSE_LIMIT + 1];
            case "array" -> "[]".getBytes(StandardCharsets.UTF_8);
            case "scalar" -> "true".getBytes(StandardCharsets.UTF_8);
            case "duplicate" -> "{\"a\":1,\"a\":2}".getBytes(StandardCharsets.UTF_8);
            case "trailing" -> "{}{}".getBytes(StandardCharsets.UTF_8);
            case "bom" -> "\ufeff{}".getBytes(StandardCharsets.UTF_8);
            case "utf8" -> new byte[]{(byte) 0xff};
            case "low-surrogate" -> "{\"a\":\"\\udc00\"}".getBytes(StandardCharsets.UTF_8);
            default -> ("{\"a\":" + "[".repeat(257) + "0" + "]".repeat(257) + "}").getBytes(StandardCharsets.UTF_8);
        };
        assertThrows(GatewayFailure.class, () -> GatewayRunWire.safeResponse(bytes, "synthetic-bearer"));
    }

    @Test
    void validUnicodeAndIndependentCopyableLabelsRemainUnchanged() throws Exception {
        byte[] bytes = "{\"a\":\"\\ud83d\\ude00\"}".getBytes(StandardCharsets.UTF_8);
        assertArrayEquals(bytes, GatewayRunWire.safeResponse(bytes, "synthetic-bearer"));
        assertNotEquals(INTENT, BINDING.runId());
        assertNotEquals(CALL, BINDING.attemptId());
        assertNotEquals(CONNECTION, BINDING.podUid());
        assertArrayEquals(PAYLOAD,
                GatewayRunWire.consumed(JSON.writeValueAsBytes(consumed()), ENVELOPE, CALL).payload());
    }
}
