package com.otilm.ai.controller;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.Set;
import java.util.UUID;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;

/** Metadata codec tests do not establish controller identity or cleanup authority. */
class ControllerControlWireTest {
    private static final ObjectMapper JSON = new ObjectMapper();
    private static final ControllerWire.Locator LOCATOR = new ControllerWire.Locator(
            UUID.fromString("a38cebd7-eafd-4cac-aed1-e1fcae264b85"),
            UUID.fromString("e7a0989e-4cd6-42d7-baf6-344caf843551"),
            UUID.fromString("d00f5707-e1ad-41e0-9f21-b66c74358c99"));
    private static final ControllerWire.Control CONTROL = new ControllerWire.Control(LOCATOR, 8, 4,
            UUID.fromString("736947e7-2778-4b40-8b0b-a514e319113c"),
            Set.of(new ControllerWire.Pod("lab", UUID.fromString("34adfc5b-55f9-4ffd-9b7a-b48eaaf0baf3"))));

    @Test
    void statusAndFenceRequestsCarryOnlyThePublicLocator() throws Exception {
        for (var operation : new ControllerWire.ControlOperation[]{
                ControllerWire.ControlOperation.STATUS,
                ControllerWire.ControlOperation.FENCE}) {
            var bytes = ControllerWire.controlRequest(operation, LOCATOR, null);
            assertEquals(5, JSON.readTree(bytes).size());
            var decoded = assertDoesNotThrow(() -> ControllerWire.readControlRequest(bytes, operation));
            assertEquals(LOCATOR, decoded.locator());
            assertNull(decoded.expected());
            assertThrows(ObservationFailure.class, () -> ControllerWire.controlRequest(operation, LOCATOR, CONTROL));
        }
    }

    @Test
    void cleanupResumptionHasOnlyALocatorAndClosedRequiredOrRecordedReplies() throws Exception {
        var request = ControllerWire.cleanupResumeRequest(LOCATOR);
        assertEquals(5, JSON.readTree(request).size());
        assertEquals(LOCATOR, ControllerWire.readCleanupResumeRequest(request));
        var extra = JSON.writeValueAsBytes(((ObjectNode) JSON.readTree(request)).put("runRevision", 8));
        assertThrows(ObservationFailure.class, () -> ControllerWire.readCleanupResumeRequest(extra));
        for (var operation : new ControllerWire.ControlOperation[]{
                ControllerWire.ControlOperation.FENCE,
                ControllerWire.ControlOperation.CLEANUP}) {
            byte[] reply = ControllerWire
                    .controlReply(operation, new ControllerWire.ControlReply(CONTROL, null, null, null));
            var decoded = ControllerWire.readCleanupResumeReply(reply, LOCATOR);
            assertEquals(CONTROL, decoded.control());
            assertEquals(operation == ControllerWire.ControlOperation.CLEANUP, decoded.done());
        }
        byte[] ordinary = ControllerWire
                .controlReply(ControllerWire.ControlOperation.STATUS,
                        new ControllerWire.ControlReply(CONTROL, "CANCELLED", "FENCED", null));
        assertThrows(ObservationFailure.class, () -> ControllerWire.readCleanupResumeReply(ordinary, LOCATOR));
        for (var incomplete : new ControllerWire.Control[]{
                new ControllerWire.Control(LOCATOR, 8, 4, null, Set.of()),
                new ControllerWire.Control(LOCATOR, 8, 4, CONTROL.jobUid(), Set.of())}) {
            byte[] reply = ControllerWire
                    .controlReply(ControllerWire.ControlOperation.FENCE,
                            new ControllerWire.ControlReply(incomplete, null, null, null));
            assertThrows(ObservationFailure.class, () -> ControllerWire.readCleanupResumeReply(reply, LOCATOR));
        }
    }

    @Test
    void terminalAndCleanupRequestsBindCurrentRunFenceAndTheExactFullUidSet() {
        for (var operation : new ControllerWire.ControlOperation[]{
                ControllerWire.ControlOperation.TERMINAL,
                ControllerWire.ControlOperation.CLEANUP}) {
            byte[] bytes = ControllerWire.controlRequest(operation, LOCATOR, CONTROL);
            assertEquals(CONTROL,
                    assertDoesNotThrow(() -> ControllerWire.readControlRequest(bytes, operation)).expected());
            assertThrows(ObservationFailure.class, () -> ControllerWire.controlRequest(operation, LOCATOR, null));
        }
    }

    @Test
    void malformedOrCrossOperationControlBindingsFailClosed() throws Exception {
        var operation = ControllerWire.ControlOperation.CLEANUP;
        byte[] valid = ControllerWire.controlRequest(operation, LOCATOR, CONTROL);
        var root = (ObjectNode) JSON.readTree(valid);
        for (String field : new String[]{"runRevision", "fence"}) {
            var invalid = root.deepCopy().put(field, 0);
            assertThrows(ObservationFailure.class,
                    () -> ControllerWire.readControlRequest(JSON.writeValueAsBytes(invalid), operation));
        }
        var duplicate = root.deepCopy();
        ((com.fasterxml.jackson.databind.node.ArrayNode) duplicate.get("workloads"))
                .add(duplicate.path("workloads").get(0).deepCopy());
        assertThrows(ObservationFailure.class,
                () -> ControllerWire.readControlRequest(JSON.writeValueAsBytes(duplicate), operation));
        assertThrows(ObservationFailure.class,
                () -> ControllerWire.readControlRequest(valid, ControllerWire.ControlOperation.STATUS));
        assertThrows(ObservationFailure.class, () -> ControllerWire
                .readControlRequest((new String(valid, StandardCharsets.UTF_8) + "{}").getBytes(StandardCharsets.UTF_8),
                        operation));
        assertThrows(ObservationFailure.class, () -> ControllerWire
                .readControlRequest(JSON.writeValueAsBytes(root.deepCopy().put("extra", "value")), operation));
    }

    @Test
    void repliesBindTheLocatorAndClosedStatusOrTerminalEvidenceWithoutInferringDone() {
        for (var operation : ControllerWire.ControlOperation.values()) {
            var reply = new ControllerWire.ControlReply(CONTROL, "CANCELLED", "FENCED",
                    Instant.parse("2026-11-06T10:00:00Z"));
            var decoded = ControllerWire
                    .readControlReply(ControllerWire.controlReply(operation, reply), operation, LOCATOR);
            assertEquals(CONTROL, decoded.control());
            if (operation == ControllerWire.ControlOperation.STATUS) {
                assertEquals("CANCELLED", decoded.runState());
                assertEquals("FENCED", decoded.attemptState());
            } else if (operation == ControllerWire.ControlOperation.TERMINAL) {
                assertEquals(reply.validUntil(), decoded.validUntil());
            }
            assertThrows(ObservationFailure.class, () -> ControllerWire
                    .readControlReply(ControllerWire.controlReply(operation, reply), operation,
                            new ControllerWire.Locator(UUID.randomUUID(), LOCATOR.runId(), LOCATOR.attemptId())));
        }
    }

    @Test
    void unobservedLaunchStatusCanHaveNoJobButCannotFabricateTerminalValidityOrUnknownStates() throws Exception {
        var unobserved = new ControllerWire.Control(LOCATOR, 7, 3, null, Set.of());
        var initial = new ControllerWire.ControlReply(unobserved, "QUEUED", "LAUNCHING", null);
        var bytes = ControllerWire.controlReply(ControllerWire.ControlOperation.STATUS, initial);
        assertEquals(initial, ControllerWire.readControlReply(bytes, ControllerWire.ControlOperation.STATUS, LOCATOR));
        assertNull(JSON.readTree(bytes).get("jobUid").textValue());
        for (String field : new String[]{"runState", "attemptState"}) {
            var invalid = ((ObjectNode) JSON.readTree(bytes)).put(field, "CALLER_READY");
            assertThrows(ObservationFailure.class,
                    () -> ControllerWire
                            .readControlReply(JSON.writeValueAsBytes(invalid), ControllerWire.ControlOperation.STATUS,
                                    LOCATOR));
        }
        assertThrows(ObservationFailure.class,
                () -> ControllerWire.controlReply(ControllerWire.ControlOperation.TERMINAL, initial));
        assertThrows(ObservationFailure.class,
                () -> ControllerWire
                        .controlReply(ControllerWire.ControlOperation.STATUS,
                                new ControllerWire.ControlReply(unobserved, null, "LAUNCHING", null)));
        assertThrows(ObservationFailure.class,
                () -> ControllerWire
                        .controlReply(ControllerWire.ControlOperation.STATUS,
                                new ControllerWire.ControlReply(unobserved, "QUEUED", null, null)));
    }

    @Test
    void terminalAndCleanupRequireAKnownJobWhileAnExactKnownEmptyFootprintRemainsRepresentable() throws Exception {
        var unobserved = new ControllerWire.Control(LOCATOR, 7, 3, null, Set.of());
        for (var operation : new ControllerWire.ControlOperation[]{
                ControllerWire.ControlOperation.TERMINAL,
                ControllerWire.ControlOperation.CLEANUP}) {
            assertThrows(ObservationFailure.class, () -> ControllerWire.controlRequest(operation, LOCATOR, unobserved));
            var root = (ObjectNode) JSON
                    .readTree(ControllerWire
                            .controlReply(ControllerWire.ControlOperation.FENCE,
                                    new ControllerWire.ControlReply(unobserved, null, null, null)));
            root
                    .put("kind",
                            operation == ControllerWire.ControlOperation.TERMINAL
                                    ? "cleanup-terminal-status"
                                    : "cleanup-reconcile");
            assertThrows(ObservationFailure.class,
                    () -> ControllerWire.readControlRequest(JSON.writeValueAsBytes(root), operation));
            var empty = new ControllerWire.Control(LOCATOR, 8, 4, CONTROL.jobUid(), Set.of());
            assertEquals(empty,
                    ControllerWire
                            .readControlRequest(ControllerWire.controlRequest(operation, LOCATOR, empty), operation)
                            .expected());
        }
    }
}
