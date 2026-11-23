package com.otilm.ai.controller;

import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.UUID;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;

/** Closed labels and canonical Core launch data are not a standalone launch or identity grant. */
class ControllerWireTest {
    private static final UUID CORRELATION = UUID.fromString("a38cebd7-eafd-4cac-aed1-e1fcae264b85");
    private static final UUID RUN = UUID.fromString("e7a0989e-4cd6-42d7-baf6-344caf843551");
    private static final UUID ATTEMPT = UUID.fromString("d00f5707-e1ad-41e0-9f21-b66c74358c99");
    private static final String REQUEST = "{\"version\":1,\"kind\":\"launch-reconcile\",\"correlationId\":\""
            + CORRELATION + "\",\"runId\":\"" + RUN + "\",\"attemptId\":\"" + ATTEMPT + "\"}";
    static final String BINDING = """
            {"version":1,"kind":"launch-binding","correlationId":"a38cebd7-eafd-4cac-aed1-e1fcae264b85",
             "runId":"e7a0989e-4cd6-42d7-baf6-344caf843551","attemptId":"d00f5707-e1ad-41e0-9f21-b66c74358c99",
             "runRevision":7,"fence":3,"launchDeadline":"2026-11-06T18:00:30Z","maxDeadline":"2026-11-06T18:01:30Z",
             "imageDigest":"sha256:%s","profileRevision":11,"securityRevision":12,"trustRevision":13,"protocol":"v1",
             "cluster":"lab","namespaceName":"runtime","namespaceUid":"77bd9027-9e2a-43b4-890f-a36eb970ae46",
             "serviceAccountName":"runner","serviceAccountUid":"f520b467-e75e-4b51-9579-d9af91d683aa",
             "templateDigest":"sha256:%s","runtimeClass":"ilm-runsc","jobName":"ilm-ai-d00f5707e1ad41e09f21b66c74358c99"}
            """
            .formatted("a".repeat(64), "b".repeat(64));

    @Test
    void initialLocatorHasNoInventedPodAndUsesOnlyTheClosedFiveFields() {
        var locator = new ControllerWire.Locator(CORRELATION, RUN, ATTEMPT);
        byte[] encoded = assertDoesNotThrow(() -> ControllerWire.launchRequest(locator));
        assertArrayEquals(REQUEST.getBytes(StandardCharsets.UTF_8), encoded);
        assertEquals(locator, ControllerWire.readLaunchRequest(encoded));
        assertFalse(new String(encoded, StandardCharsets.UTF_8).contains("pod"));
    }

    @Test
    void canonicalLaunchReplyBindsExactLocatorAndAllExistingAttemptPrimitives() {
        var locator = new ControllerWire.Locator(CORRELATION, RUN, ATTEMPT);
        var binding = assertDoesNotThrow(() -> ControllerWire.readLaunchReply(bytes(BINDING), locator));
        assertEquals(locator, binding.locator());
        assertEquals(7, binding.runRevision());
        assertEquals(3, binding.fence());
        assertEquals(Instant.parse("2026-11-06T18:00:30Z"), binding.launchDeadline());
        assertEquals(Instant.parse("2026-11-06T18:01:30Z"), binding.maxDeadline());
        assertEquals("sha256:" + "a".repeat(64), binding.imageDigest());
        assertEquals(11, binding.profileRevision());
        assertEquals(12, binding.securityRevision());
        assertEquals(13, binding.trustRevision());
        assertEquals("v1", binding.protocol());
        assertEquals("lab", binding.cluster());
        assertEquals("runtime", binding.namespaceName());
        assertEquals(UUID.fromString("77bd9027-9e2a-43b4-890f-a36eb970ae46"), binding.namespaceUid());
        assertEquals("runner", binding.serviceAccountName());
        assertEquals(UUID.fromString("f520b467-e75e-4b51-9579-d9af91d683aa"), binding.serviceAccountUid());
        assertEquals("sha256:" + "b".repeat(64), binding.templateDigest());
        assertEquals("ilm-runsc", binding.runtimeClass());
        assertEquals("ilm-ai-d00f5707e1ad41e09f21b66c74358c99", binding.jobName());
        assertEquals(binding, ControllerWire.readLaunchReply(ControllerWire.launchReply(binding), locator));
    }

    @Test
    void copiedLocatorWrongJobNamesAndUnknownOrInvalidCanonicalPrimitivesCannotSelectLaunches() {
        var locator = new ControllerWire.Locator(CORRELATION, RUN, ATTEMPT);
        for (String invalid : new String[]{
                BINDING.replace(CORRELATION.toString(), UUID.randomUUID().toString()),
                BINDING.replace(RUN.toString(), UUID.randomUUID().toString()),
                BINDING.replace("\"launch-binding\"", "\"workload-eligible\""),
                BINDING.replace("\"version\":1", "\"version\":4294967297"),
                BINDING.replace("\"runRevision\":7", "\"runRevision\":0"),
                BINDING.replace("\"fence\":3", "\"fence\":3.0"),
                BINDING.replace("\"profileRevision\":11", "\"profileRevision\":9223372036854775808"),
                BINDING.replace("\"protocol\":\"v1\"", "\"protocol\":\"v2\""),
                BINDING.replace("ilm-ai-d00f5707e1ad41e09f21b66c74358c99", "other-job"),
                BINDING.replace("2026-11-06T18:00:30Z", "2026-11-06T18:02:30Z"),
                BINDING.replace("\"namespaceName\":\"runtime\"", "\"namespaceName\":\"../other\""),
                BINDING.replace("\"kind\":\"launch-binding\"", "\"kind\":\"launch-binding\",\"ready\":true"),
                BINDING + "{}",
                " ".repeat(4097)}) {
            var failure = assertThrows(ObservationFailure.class,
                    () -> ControllerWire.readLaunchReply(bytes(invalid), locator));
            assertEquals("OBSERVATION_UNAVAILABLE", failure.getMessage());
            assertEquals(0, failure.getStackTrace().length);
        }
    }

    @Test
    void malformedDuplicateNonUtf8AndExpandedRequestsAreClosedBeforeCoreLookup() {
        for (byte[] invalid : new byte[][]{
                bytes(REQUEST + "{}"),
                bytes(REQUEST.replace("\"version\":1", "\"version\":1,\"version\":1")),
                bytes(REQUEST.replace("\"version\":1", "\"version\":1,\"podUid\":\"" + UUID.randomUUID() + "\"")),
                REQUEST.getBytes(StandardCharsets.UTF_16),
                bytes(REQUEST.replace(RUN.toString(), "0-0-0-0-0")),
                new byte[0],
                bytes("[]")}) {
            assertThrows(ObservationFailure.class, () -> ControllerWire.readLaunchRequest(invalid));
        }
    }

    private static byte[] bytes(String value) {
        return value.getBytes(StandardCharsets.UTF_8);
    }
}
