package com.otilm.ai.gateway;

import com.fasterxml.jackson.databind.node.ObjectNode;
import com.otilm.ai.runtime.protocol.ManagementAction;
import com.otilm.ai.runtime.protocol.ManagementBinding;
import com.otilm.ai.runtime.protocol.ManagementDispatchEnvelope;
import com.otilm.ai.runtime.protocol.PayloadFingerprint;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.Base64;
import java.util.UUID;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.EnumSource;
import org.junit.jupiter.params.provider.ValueSource;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;

/** Wire values only; neither a management session nor a Core consume grant is manufactured here. */
class GatewayManagementWireTest {
    static final com.fasterxml.jackson.databind.ObjectMapper JSON = new com.fasterxml.jackson.databind.ObjectMapper();
    static final com.otilm.ai.runtime.protocol.ProtocolCodec PROTOCOL = new com.otilm.ai.runtime.protocol.ProtocolCodec();
    static final UUID CONFIGURATION = UUID.fromString("00000000-0000-4000-8000-000000000105");
    static final UUID INTENT = UUID.fromString("00000000-0000-4000-8000-000000000101");
    static final UUID CALL = UUID.fromString("00000000-0000-4000-8000-000000000102");
    static final UUID ACTOR = UUID.fromString("00000000-0000-4000-8000-000000000103");
    static final UUID SESSION = UUID.fromString("00000000-0000-4000-8000-000000000104");
    static final byte[] PAYLOAD = "{\"model\":\"lab\",\"messages\":[{\"role\":\"user\",\"content\":\"public management probe\"}],\"max_tokens\":1,\"stream\":false}"
            .getBytes(StandardCharsets.UTF_8);

    static ManagementDispatchEnvelope envelope(ManagementAction action) {
        return new ManagementDispatchEnvelope(1, INTENT, PayloadFingerprint.sha256(PAYLOAD),
                new ManagementBinding(ACTOR, SESSION, CONFIGURATION, 2, action, Instant.parse("2030-01-01T00:00:00Z")));
    }

    static ObjectNode consumed(ManagementAction action) throws Exception {
        var envelope = envelope(action);
        var root = JSON
                .createObjectNode()
                .put("protocolVersion", 1)
                .put("kind", "management-consumed")
                .put("intentId", INTENT.toString())
                .put("gatewayCorrelation", CALL.toString());
        root.set("binding", JSON.readTree(PROTOCOL.writeDispatch(envelope)).get("binding"));
        root
                .put("payloadSha256", envelope.payloadSha256())
                .put("payloadBase64", Base64.getEncoder().encodeToString(PAYLOAD));
        root
                .putObject("connection")
                .put("id", CONFIGURATION.toString())
                .put("configuration", 2)
                .put("destination", 3)
                .put("authentication", 4)
                .put("modelIdentifier", "lab");
        return root
                .put("outputTokens", 1)
                .put("origin", "https://provider.test:8443")
                .put("credentialReference", "lab-key")
                .put("expiresAt", envelope.binding().expiresAt().toString());
    }

    @ParameterizedTest
    @EnumSource(ManagementAction.class)
    void mapsTheActualManagementBindingAndExactPayloadWithoutAnyRunClaim(ManagementAction action) throws Exception {
        var reply = assertDoesNotThrow(() -> read(JSON.writeValueAsBytes(consumed(action)), envelope(action), CALL));
        assertArrayEquals(PAYLOAD, reply.payload());
        assertEquals(CONFIGURATION, reply.connection().id());
        assertEquals(2, reply.connection().configuration());
        byte[] request = assertDoesNotThrow(() -> GatewayRunWire.redeem(envelope(action), CALL));
        var root = JSON.readTree(request);
        var binding = root.get("envelope").get("binding");
        assertEquals("management", root.get("envelope").get("kind").textValue());
        assertEquals(ACTOR.toString(), binding.get("actorId").textValue());
        assertEquals(SESSION.toString(), binding.get("sessionId").textValue());
        assertFalse(binding.has("runId"));
        assertFalse(binding.has("podUid"));
        assertFalse(binding.has("claimId"));
        assertFalse(binding.has("fence"));
    }

    @ParameterizedTest
    @ValueSource(strings = {
            "kind",
            "actor",
            "session",
            "configuration-id",
            "configuration-revision",
            "action",
            "connection-id",
            "connection-revision",
            "correlation",
            "intent",
            "digest",
            "extra",
            "expiry"})
    void rejectsAnyUnboundOrRunShapedManagementPositiveReply(String mode) throws Exception {
        var root = consumed(ManagementAction.CONNECTION_CHECK);
        var binding = (ObjectNode) root.get("binding");
        switch (mode) {
            case "kind" -> root.put("kind", "run-consumed");
            case "actor" -> binding.put("actorId", INTENT.toString());
            case "session" -> binding.put("sessionId", CALL.toString());
            case "configuration-id" -> binding.put("configurationId", ACTOR.toString());
            case "configuration-revision" -> binding.put("configurationRevision", 3);
            case "action" -> binding.put("action", "CAPABILITY_CHECK");
            case "connection-id" -> ((ObjectNode) root.get("connection")).put("id", ACTOR.toString());
            case "connection-revision" -> ((ObjectNode) root.get("connection")).put("configuration", 3);
            case "correlation" -> root.put("gatewayCorrelation", SESSION.toString());
            case "intent" -> root.put("intentId", ACTOR.toString());
            case "digest" -> root.put("payloadSha256", "a".repeat(64));
            case "extra" -> binding.put("claimId", CALL.toString());
            case "expiry" -> root.put("expiresAt", Instant.EPOCH.toString());
        }
        var failure = assertThrows(GatewayFailure.class,
                () -> read(JSON.writeValueAsBytes(root), envelope(ManagementAction.CONNECTION_CHECK), CALL));
        assertNull(failure.getCause());
    }

    @Test
    void managementProtectedOutcomeAndAckUseOnlyTheManagementBindingAndKinds() throws Exception {
        var envelope = envelope(ManagementAction.CAPABILITY_CHECK);
        byte[] response = "{\"model\":\"lab\",\"choices\":[]}".getBytes(StandardCharsets.UTF_8);
        byte[] bytes = assertDoesNotThrow(() -> GatewayRunWire.outcome(envelope, CALL, response));
        var root = JSON.readTree(bytes);
        assertEquals("management-outcome", root.get("kind").textValue());
        assertEquals(ACTOR.toString(), root.get("binding").get("actorId").textValue());
        assertFalse(root.get("binding").has("runId"));
        String sha = java.util.HexFormat
                .of()
                .formatHex(java.security.MessageDigest.getInstance("SHA-256").digest(bytes));
        var ack = JSON
                .createObjectNode()
                .put("protocolVersion", 1)
                .put("kind", "management-outcome-recorded")
                .put("intentId", INTENT.toString())
                .put("gatewayCorrelation", CALL.toString())
                .put("outcomeSha256", sha)
                .put("resultVersion", 11);
        assertEquals(11L, assertDoesNotThrow(
                () -> GatewayRunWire.acknowledgement(JSON.writeValueAsBytes(ack), envelope, CALL, bytes)));
        ack.put("kind", "run-outcome-recorded");
        assertThrows(GatewayFailure.class,
                () -> GatewayRunWire.acknowledgement(JSON.writeValueAsBytes(ack), envelope, CALL, bytes));
    }

    private static GatewayRunWire.Consumed read(byte[] bytes, ManagementDispatchEnvelope envelope, UUID correlation) {
        return GatewayRunWire.consumed(bytes, envelope, correlation);
    }
}
