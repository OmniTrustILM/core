package com.otilm.ai.gateway;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;
import com.otilm.ai.runtime.protocol.PayloadFingerprint;
import com.otilm.ai.runtime.protocol.ProtocolCodec;
import com.otilm.ai.runtime.protocol.RunBinding;
import com.otilm.ai.runtime.protocol.RunDispatchEnvelope;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.Base64;
import java.util.UUID;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class GatewayRunWireTest {
    static final ObjectMapper JSON = new ObjectMapper();
    static final ProtocolCodec PROTOCOL = new ProtocolCodec();
    static final UUID INTENT = UUID.fromString("00000000-0000-4000-8000-000000000001");
    static final UUID CALL = UUID.fromString("00000000-0000-4000-8000-000000000002");
    static final UUID CONNECTION = UUID.fromString("00000000-0000-4000-8000-000000000003");
    static final byte[] PAYLOAD = "{\"model\":\"lab\",\"messages\":[{\"role\":\"user\",\"content\":\"public fixture\"}],\"max_tokens\":32,\"stream\":false}"
            .getBytes(StandardCharsets.UTF_8);
    static final RunBinding BINDING = new RunBinding(UUID.fromString("00000000-0000-4000-8000-000000000011"),
            UUID.fromString("00000000-0000-4000-8000-000000000012"),
            UUID.fromString("00000000-0000-4000-8000-000000000013"),
            UUID.fromString("00000000-0000-4000-8000-000000000014"), 7, Instant.parse("2030-01-01T00:00:00Z"));
    static final RunDispatchEnvelope ENVELOPE = new RunDispatchEnvelope(1, INTENT, PayloadFingerprint.sha256(PAYLOAD),
            BINDING);

    static ObjectNode consumed() throws Exception {
        ObjectNode root = JSON
                .createObjectNode()
                .put("protocolVersion", 1)
                .put("kind", "run-consumed")
                .put("intentId", INTENT.toString())
                .put("gatewayCorrelation", CALL.toString());
        root.set("binding", JSON.readTree(PROTOCOL.writeDispatch(ENVELOPE)).get("binding"));
        root
                .put("payloadSha256", ENVELOPE.payloadSha256())
                .put("payloadBase64", Base64.getEncoder().encodeToString(PAYLOAD));
        root
                .putObject("connection")
                .put("id", CONNECTION.toString())
                .put("configuration", 2)
                .put("destination", 3)
                .put("authentication", 4)
                .put("modelIdentifier", "lab");
        return root
                .put("outputTokens", 32)
                .put("origin", "https://provider.test:8443")
                .put("credentialReference", "lab-key")
                .put("expiresAt", BINDING.expiresAt().toString());
    }

    @ParameterizedTest
    @ValueSource(strings = {"number", "name", "depth"})
    void protectedProviderResponsesKeepExactBytesBeyondControlMessageScalarLimits(String kind) {
        String value = switch (kind) {
            case "number" -> "{\"logprob\":-0.000012345678901234567}";
            case "name" -> "{\"" + "a".repeat(129) + "\":true}";
            default -> "{\"metadata\":" + "[".repeat(17) + "0" + "]".repeat(17) + "}";
        };
        byte[] bytes = value.getBytes(StandardCharsets.UTF_8);
        assertArrayEquals(bytes, assertDoesNotThrow(() -> GatewayRunWire.safeResponse(bytes, "synthetic-bearer")));
    }

    @Test
    void mapsActualPrimitivesAndOwnsExactPayloadWithoutGrantingAuthority() throws Exception {
        var reply = assertDoesNotThrow(
                () -> GatewayRunWire.consumed(JSON.writeValueAsBytes(consumed()), ENVELOPE, CALL));
        assertArrayEquals(PAYLOAD, reply.payload());
        reply.payload()[0] = 0;
        assertArrayEquals(PAYLOAD, reply.payload());
        assertEquals(CONNECTION, reply.connection().id());
        assertEquals(4, reply.connection().authentication());
        assertEquals("lab-key", reply.credentialReference());
        assertFalse(reply.toString().contains("public fixture"));
        var redeem = JSON.readTree(GatewayRunWire.redeem(ENVELOPE, CALL));
        assertEquals(3, redeem.size());
        assertEquals(ENVELOPE, PROTOCOL.readDispatch(JSON.writeValueAsBytes(redeem.get("envelope"))));
    }

    @ParameterizedTest
    @ValueSource(strings = {
            "version",
            "kind",
            "intent",
            "correlation",
            "binding",
            "digest",
            "payload",
            "base64",
            "expiry",
            "extra",
            "connection",
            "output",
            "origin",
            "reference",
            "fraction"})
    void deniesInvalidOrUnboundPositiveReply(String mode) throws Exception {
        var root = consumed();
        switch (mode) {
            case "version" -> root.put("protocolVersion", 2);
            case "kind" -> root.put("kind", "management-consumed");
            case "intent" -> root.put("intentId", CALL.toString());
            case "correlation" -> root.put("gatewayCorrelation", INTENT.toString());
            case "binding" -> ((ObjectNode) root.get("binding")).put("fence", 8);
            case "digest" -> root.put("payloadSha256", "a".repeat(64));
            case "payload" -> root.put("payloadBase64", "e30=");
            case "base64" -> root.put("payloadBase64", root.get("payloadBase64").textValue() + "=");
            case "expiry" -> root.put("expiresAt", Instant.EPOCH.toString());
            case "extra" -> root.put("headers", "PRIVATE_HEADER_CANARY");
            case "connection" -> ((ObjectNode) root.get("connection")).put("authentication", 0);
            case "output" -> root.put("outputTokens", 0);
            case "origin" -> root.put("origin", "https://provider.test/arbitrary");
            case "reference" -> root.put("credentialReference", "../PRIVATE_KEY_CANARY");
            case "fraction" -> root.put("outputTokens", 3.5);
        }
        var failure = assertThrows(GatewayFailure.class,
                () -> GatewayRunWire.consumed(JSON.writeValueAsBytes(root), ENVELOPE, CALL));
        assertNull(failure.getCause());
        assertFalse(failure.getMessage().contains("PRIVATE"));
    }

    @ParameterizedTest
    @ValueSource(strings = {"duplicate", "trailing", "utf8", "bom", "oversized", "surrogate", "missing"})
    void rejectsInvalidDocumentsBeforeMapping(String mode) throws Exception {
        byte[] bytes = JSON.writeValueAsBytes(consumed());
        String value = new String(bytes, StandardCharsets.UTF_8);
        bytes = switch (mode) {
            case "duplicate" -> value
                    .replace("\"protocolVersion\":1", "\"protocolVersion\":1,\"protocolVersion\":1")
                    .getBytes(StandardCharsets.UTF_8);
            case "trailing" -> (value + "{}").getBytes(StandardCharsets.UTF_8);
            case "utf8" -> new byte[]{(byte) 0xff};
            case "bom" -> ("\ufeff" + value).getBytes(StandardCharsets.UTF_8);
            case "oversized" -> new byte[1_500_001];
            case "surrogate" -> value.replace("lab-key", "bad\\ud800").getBytes(StandardCharsets.UTF_8);
            default -> "{}".getBytes(StandardCharsets.UTF_8);
        };
        byte[] actual = bytes;
        assertThrows(GatewayFailure.class, () -> GatewayRunWire.consumed(actual, ENVELOPE, CALL));
    }

    @Test
    void outcomePreservesResponseAndRequiresExactServerAcknowledgement() throws Exception {
        byte[] response = "{\"model\":\"lab\",\"choices\":[]}".getBytes(StandardCharsets.UTF_8);
        byte[] encoded = assertDoesNotThrow(() -> GatewayRunWire.outcome(ENVELOPE, CALL, response));
        var root = JSON.readTree(encoded);
        assertEquals("HTTP_200", root.get("transportCode").textValue());
        assertArrayEquals(response, Base64.getDecoder().decode(root.get("responseBase64").textValue()));
        assertEquals(PayloadFingerprint.sha256(response), root.get("responseSha256").textValue());
        assertEquals("unknown", root.get("usage").get("kind").textValue());
        ObjectNode ack = JSON
                .createObjectNode()
                .put("protocolVersion", 1)
                .put("kind", "run-outcome-recorded")
                .put("intentId", INTENT.toString())
                .put("gatewayCorrelation", CALL.toString())
                .put("outcomeSha256", PayloadFingerprint.sha256(encoded))
                .put("resultVersion", 9);
        assertEquals(9, GatewayRunWire.acknowledgement(JSON.writeValueAsBytes(ack), ENVELOPE, CALL, encoded));
        ack.put("outcomeSha256", "b".repeat(64));
        assertThrows(GatewayFailure.class,
                () -> GatewayRunWire.acknowledgement(JSON.writeValueAsBytes(ack), ENVELOPE, CALL, encoded));
        var unknown = JSON.readTree(GatewayRunWire.outcome(ENVELOPE, CALL, null));
        assertEquals("UNKNOWN", unknown.get("transportCode").textValue());
        assertTrue(unknown.get("responseBase64").isNull());
        assertEquals(0, unknown.get("responseByteCount").intValue());
    }

    @ParameterizedTest
    @ValueSource(strings = {"raw", "escaped", "escaped-key", "invalid"})
    void knownBearerCannotBeReflectedThroughRawOrEscapedProviderJson(String mode) {
        String secret = "PRIVATE_BEARER_CANARY";
        String response = mode.equals("escaped")
                ? "{\"answer\":\"PRIVATE_\\u0042EARER_CANARY\"}"
                : mode.equals("escaped-key")
                        ? "{\"PRIVATE_\\u0042EARER_CANARY\":\"value\"}"
                        : mode.equals("raw") ? "{\"answer\":\"" + secret + "\"}" : "not json";
        assertThrows(GatewayFailure.class,
                () -> GatewayRunWire.safeResponse(response.getBytes(StandardCharsets.UTF_8), secret));
    }
}
