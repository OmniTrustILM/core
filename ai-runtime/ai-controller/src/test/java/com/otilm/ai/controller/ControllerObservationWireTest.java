package com.otilm.ai.controller;

import com.fasterxml.jackson.databind.ObjectMapper;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.UUID;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

class ControllerObservationWireTest {
    private static final ObjectMapper JSON = new ObjectMapper();
    private static final ControllerWire.Locator LOCATOR = new ControllerWire.Locator(
            UUID.fromString("a38cebd7-eafd-4cac-aed1-e1fcae264b85"),
            UUID.fromString("e7a0989e-4cd6-42d7-baf6-344caf843551"),
            UUID.fromString("d00f5707-e1ad-41e0-9f21-b66c74358c99"));
    private static final UUID POD = UUID.fromString("34adfc5b-55f9-4ffd-9b7a-b48eaaf0baf3");
    private static final UUID JOB = UUID.fromString("736947e7-2778-4b40-8b0b-a514e319113c");

    @Test
    void eligibleAndRegistrationMetadataStayDistinctAndBindTheActualPodTuple() throws Exception {
        var request = new ControllerWire.ObservationRequest(LOCATOR, POD);
        for (var operation : new ControllerWire.Operation[]{
                ControllerWire.Operation.ELIGIBLE,
                ControllerWire.Operation.REGISTER}) {
            byte[] body = assertDoesNotThrow(() -> ControllerWire.observationRequest(operation, request));
            var parsed = JSON.readTree(body);
            assertEquals(6, parsed.size());
            assertEquals(operation == ControllerWire.Operation.ELIGIBLE ? "workload-eligible" : "workload-register",
                    parsed.path("kind").textValue());
            assertEquals(POD.toString(), parsed.path("podUid").textValue());
            assertEquals(request, ControllerWire.readObservationRequest(body, operation));
            var other = operation == ControllerWire.Operation.ELIGIBLE
                    ? ControllerWire.Operation.REGISTER
                    : ControllerWire.Operation.ELIGIBLE;
            assertThrows(ObservationFailure.class, () -> ControllerWire.readObservationRequest(body, other));
        }
    }

    @Test
    void acknowledgementsCarryExactActualJobPodResourceVersionAndCoreObservationBinding() {
        var request = new ControllerWire.ObservationRequest(LOCATOR, POD);
        var reply = new ControllerWire.ObservationReply(request, JOB, "pod-rv-7", 7, 3, 1,
                Instant.parse("2026-11-06T18:00:20Z"));
        for (var operation : new ControllerWire.Operation[]{
                ControllerWire.Operation.ELIGIBLE,
                ControllerWire.Operation.REGISTER}) {
            byte[] encoded = assertDoesNotThrow(() -> ControllerWire.observationReply(operation, reply));
            assertEquals(reply, ControllerWire.readObservationReply(encoded, operation, request));
            var otherPod = new ControllerWire.ObservationRequest(LOCATOR, UUID.randomUUID());
            assertThrows(ObservationFailure.class,
                    () -> ControllerWire.readObservationReply(encoded, operation, otherPod));
        }
    }

    @Test
    void unknownFieldsVersionsKindsAndNonpositiveBindingsCannotBecomeEligibility() {
        String valid = """
                {"version":1,"kind":"workload-eligible","correlationId":"a38cebd7-eafd-4cac-aed1-e1fcae264b85",
                 "runId":"e7a0989e-4cd6-42d7-baf6-344caf843551","attemptId":"d00f5707-e1ad-41e0-9f21-b66c74358c99",
                 "podUid":"34adfc5b-55f9-4ffd-9b7a-b48eaaf0baf3","jobUid":"736947e7-2778-4b40-8b0b-a514e319113c",
                 "podResourceVersion":"pod-rv-7","runRevision":7,"fence":3,"observationSequence":1,"validUntil":"2026-11-06T18:00:20Z"}
                """;
        var request = new ControllerWire.ObservationRequest(LOCATOR, POD);
        assertDoesNotThrow(() -> ControllerWire
                .readObservationReply(valid.getBytes(StandardCharsets.UTF_8), ControllerWire.Operation.ELIGIBLE,
                        request));
        for (String invalid : new String[]{
                valid.replace("\"version\":1", "\"version\":2"),
                valid.replace("\"fence\":3", "\"fence\":0"),
                valid.replace("\"observationSequence\":1", "\"observationSequence\":18446744073709551617"),
                valid.replace("\"kind\":\"workload-eligible\"", "\"kind\":\"workload-registered\""),
                valid.replace("\"version\":1", "\"version\":1,\"ready\":true"),
                valid.replace("pod-rv-7", "unsafe/path"),
                valid.replace(JOB.toString(), "00000000-0000-0000-0000-000000000000"),
                valid + "{}"}) {
            assertThrows(ObservationFailure.class,
                    () -> ControllerWire
                            .readObservationReply(invalid.getBytes(StandardCharsets.UTF_8),
                                    ControllerWire.Operation.ELIGIBLE, request));
        }
    }
}
