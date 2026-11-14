package com.otilm.ai.controller;

import com.fasterxml.jackson.databind.ObjectMapper;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.attribute.PosixFilePermissions;
import java.time.Duration;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/** A deletion acknowledgement or API absence is not physical termination evidence or a Core DONE grant. */
class KubernetesDeletionTest {
    private static final ObjectMapper JSON = new ObjectMapper();
    private static final String JOB = "job-one";
    private static final String UID = "736947e7-2778-4b40-8b0b-a514e319113c";
    private static final String STATUS = """
            {"apiVersion":"v1","kind":"Status","status":"Success",
             "details":{"name":"job-one","uid":"736947e7-2778-4b40-8b0b-a514e319113c","kind":"jobs","group":"batch"}}
            """;
    private static final String DELETING = """
            {"apiVersion":"batch/v1","kind":"Job","metadata":{"namespace":"runtime","name":"job-one",
             "uid":"736947e7-2778-4b40-8b0b-a514e319113c","deletionTimestamp":"2026-11-06T00:00:00Z"}}
            """;
    private static final String ABSENT = """
            {"apiVersion":"v1","kind":"Status","reason":"NotFound","code":404,
             "details":{"name":"job-one","kind":"jobs","group":"batch"}}
            """;
    @TempDir
    Path directory;

    @Test
    void ordinaryForegroundDeleteUsesExactUidAndRvOnceAndAcceptsOnlyMatchingAcknowledgements() throws Exception {
        for (String body : new String[]{STATUS, DELETING}) {
            try (var server = fixture(body.equals(DELETING) ? 202 : 200, body)) {
                var api = client(server);
                assertDoesNotThrow(() -> api.deleteJob("runtime", JOB, UID, "job-rv-one"));
                assertEquals("DELETE", server.method.get());
                assertEquals("/apis/batch/v1/namespaces/runtime/jobs/job-one", server.path.get());
                var options = JSON.readTree(server.received.get());
                assertEquals(4, options.size());
                assertEquals("Foreground", options.path("propagationPolicy").textValue());
                assertEquals(UID, options.path("preconditions").path("uid").textValue());
                assertEquals("job-rv-one", options.path("preconditions").path("resourceVersion").textValue());
                assertFalse(options.has("gracePeriodSeconds"));
                assertFalse(api.mutationOutcomeUnknown());
                assertThrows(ObservationFailure.class, () -> api.deleteJob("runtime", JOB, UID, "job-rv-one"));
                assertEquals(1, server.requests.get());
            }
        }
    }

    @Test
    void foreignOrIncompleteDeletionAcknowledgementsRemainUnknownWithoutResend() throws Exception {
        for (String body : new String[]{
                STATUS.replace("\"v1\"", "\"v2\""),
                STATUS.replace("Success", "Failure"),
                STATUS.replace(UID, "45c37167-f4bd-4ab0-baf7-00f19eeb387b"),
                STATUS.replace("job-one", "other"),
                STATUS.replace("jobs", "pods"),
                STATUS.replace("batch", "other"),
                DELETING.replace("batch/v1", "v1"),
                DELETING.replace("\"Job\"", "\"Pod\""),
                DELETING.replace(UID, "45c37167-f4bd-4ab0-baf7-00f19eeb387b"),
                DELETING.replace("job-one", "other"),
                DELETING.replace("runtime", "other"),
                DELETING.replace(",\"deletionTimestamp\":\"2026-11-06T00:00:00Z\"", ""),
                STATUS + "{}"}) {
            try (var server = fixture(202, body)) {
                var api = client(server);
                assertThrows(ObservationFailure.class, () -> api.deleteJob("runtime", JOB, UID, "rv"));
                assertTrue(api.mutationOutcomeUnknown());
                assertThrows(ObservationFailure.class, () -> api.deleteJob("runtime", JOB, UID, "rv"));
                assertEquals(1, server.requests.get());
            }
        }
    }

    @Test
    void malformedDeletePreconditionsFailBeforeApiIo() throws Exception {
        for (String uid : new String[]{
                null,
                "copied",
                "00000000-0000-0000-0000-000000000000",
                "736947E7-2778-4B40-8B0B-A514E319113C"}) {
            try (var server = fixture(200, STATUS)) {
                var api = client(server);
                assertThrows(ObservationFailure.class, () -> api.deleteJob("runtime", JOB, uid, "rv"));
                assertEquals(0, server.requests.get());
            }
        }
        for (String rv : new String[]{null, "", "invalid/rv"}) {
            try (var server = fixture(200, STATUS)) {
                var api = client(server);
                assertThrows(ObservationFailure.class, () -> api.deleteJob("runtime", JOB, UID, rv));
                assertEquals(0, server.requests.get());
            }
        }
    }

    @Test
    void presentExactUidIsNotAbsenceAndReplacementOrForeignObjectCannotBeAccepted() throws Exception {
        try (var server = fixture(200, DELETING)) {
            assertFalse(client(server).jobAbsent("runtime", JOB, UID));
            assertEquals("GET", server.method.get());
        }
        for (String body : new String[]{
                DELETING.replace("batch/v1", "v1"),
                DELETING.replace("\"Job\"", "\"Pod\""),
                DELETING.replace(UID, "45c37167-f4bd-4ab0-baf7-00f19eeb387b"),
                DELETING.replace("job-one", "other"),
                DELETING.replace("runtime", "other")}) {
            try (var server = fixture(200, body)) {
                assertThrows(ObservationFailure.class, () -> client(server).jobAbsent("runtime", JOB, UID));
                assertEquals(1, server.requests.get());
            }
        }
    }

    @Test
    void absentResponseRequiresExactStatusResourceAndAnIntegerWithoutTruncation() throws Exception {
        try (var server = fixture(404, ABSENT)) {
            assertTrue(client(server).jobAbsent("runtime", JOB, UID));
        }
        for (String body : new String[]{
                ABSENT.replace("\"v1\"", "\"v2\""),
                ABSENT.replace("Status", "Pod"),
                ABSENT.replace("NotFound", "Forbidden"),
                ABSENT.replace("404", "4294967700"),
                ABSENT.replace("404", "\"404\""),
                ABSENT.replace("404", "403"),
                ABSENT.replace("job-one", "other"),
                ABSENT.replace("batch", "other"),
                ABSENT.replace("jobs", "pods")}) {
            try (var server = fixture(404, body)) {
                assertThrows(ObservationFailure.class, () -> client(server).jobAbsent("runtime", JOB, UID), body);
                assertEquals(1, server.requests.get());
            }
        }
    }

    private KubernetesApi client(KubernetesHttpsFixture server) throws Exception {
        Path token = Files.createTempFile(directory, "deletion-", ".token");
        Files.writeString(token, "synthetic.deletion.token");
        Files.setPosixFilePermissions(token, PosixFilePermissions.fromString("rw-------"));
        return new KubernetesApi(server.endpoint(), server.trust(), token, Duration.ofSeconds(5));
    }

    private static KubernetesHttpsFixture fixture(int code, String body) throws Exception {
        return new KubernetesHttpsFixture(code, body.getBytes(StandardCharsets.UTF_8));
    }
}
