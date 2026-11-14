package com.otilm.ai.controller;

import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.attribute.PosixFilePermissions;
import java.time.Duration;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/** Real creation wire fixtures confer no Core launch authorization or native workload authority. */
class KubernetesCreationTest {
    private static final String JOB = "ilm-ai-d00f5707e1ad41e09f21b66c74358c99";
    private static final String UID = "736947e7-2778-4b40-8b0b-a514e319113c";
    private static final byte[] CREATION = ("""
            {"apiVersion":"batch/v1","kind":"Job","metadata":{"namespace":"runtime","name":"%s"},
             "spec":{"parallelism":1,"completions":1,"backoffLimit":0,"manualSelector":true,
               "selector":{"matchLabels":{"ilm.otilm.ai/attempt":"d00f5707-e1ad-41e0-9f21-b66c74358c99"}},
               "template":{"metadata":{"labels":{"ilm.otilm.ai/attempt":"d00f5707-e1ad-41e0-9f21-b66c74358c99"}},
                 "spec":{"serviceAccountName":"runner","restartPolicy":"Never",
                   "schedulingGates":[{"name":"ilm.otilm.ai/runtime-eligible"}],
                   "containers":[{"name":"runner","image":"local.invalid/runner@sha256:%s"}]}}}}
            """).formatted(JOB, "a".repeat(64)).getBytes(StandardCharsets.UTF_8);
    private static final byte[] CREATED = ("""
            {"apiVersion":"batch/v1","kind":"Job","metadata":{"namespace":"runtime","name":"%s",
              "uid":"%s","resourceVersion":"created-rv"},"spec":{}}
            """).formatted(JOB, UID).getBytes(StandardCharsets.UTF_8);
    @TempDir
    Path directory;

    @Test
    void maintainedCreationUsesOneFixedCollectionPostAndReturnsActualApiAssignedIdentity() throws Exception {
        try (var fixture = new KubernetesHttpsFixture(201, CREATED)) {
            var api = client(fixture);
            var created = assertDoesNotThrow(() -> api.createJob("runtime", JOB, CREATION));
            assertEquals(UID, created.uid());
            assertEquals("created-rv", created.resourceVersion());
            assertEquals("POST", fixture.method.get());
            assertEquals("/apis/batch/v1/namespaces/runtime/jobs", fixture.path.get());
            assertEquals("application/json; charset=UTF-8", fixture.contentType.get());
            assertArrayEquals(CREATION, fixture.received.get());
            assertEquals("Bearer synthetic.creation.token", fixture.authorization.get());
            assertFalse(api.mutationOutcomeUnknown());
            assertFalse(api.cleanupUncertain());
            assertThrows(ObservationFailure.class, () -> api.createJob("runtime", JOB, CREATION));
            assertEquals(1, fixture.requests.get());
        }
    }

    @Test
    void conflictsChallengesAndServerErrorsNeverCauseCreationResend() throws Exception {
        for (int status : new int[]{301, 401, 407, 408, 409, 421, 503}) {
            try (var fixture = new KubernetesHttpsFixture(status, CREATED)) {
                var api = client(fixture);
                assertThrows(ObservationFailure.class, () -> api.createJob("runtime", JOB, CREATION));
                assertTrue(api.mutationOutcomeUnknown());
                assertThrows(ObservationFailure.class, () -> api.createJob("runtime", JOB, CREATION));
                assertEquals(1, fixture.requests.get(), "wire count for " + status);
            }
        }
    }

    @Test
    void mismatchedOrMalformedAcknowledgementKeepsRemoteCreationUnknown() throws Exception {
        String valid = new String(CREATED, StandardCharsets.UTF_8);
        for (String invalid : new String[]{
                valid.replace(UID, "copied"),
                valid.replace(JOB, "other-job"),
                valid.replace("runtime", "other"),
                valid.replace("created-rv", ""),
                valid.replace("\"Job\"", "\"Pod\""),
                valid.replace("\"batch/v1\"", "\"v1\""),
                valid + "{}"}) {
            try (var fixture = new KubernetesHttpsFixture(201, invalid.getBytes(StandardCharsets.UTF_8))) {
                var api = client(fixture);
                assertThrows(ObservationFailure.class, () -> api.createJob("runtime", JOB, CREATION));
                assertTrue(api.mutationOutcomeUnknown());
                assertEquals(1, fixture.requests.get());
            }
        }
    }

    @Test
    void invalidCreationMetadataAndRouteFragmentsFailBeforeApiIo() throws Exception {
        String valid = new String(CREATION, StandardCharsets.UTF_8);
        for (String invalid : new String[]{
                valid.replace(JOB, "other-job"),
                valid.replace("runtime", "other"),
                valid.replace("\"Job\"", "\"Pod\""),
                valid.replace("\"batch/v1\"", "\"v1\""),
                valid.replace("\"metadata\":{", "\"metadata\":{\"uid\":\"" + UID + "\","),
                valid.replace("\"metadata\":{", "\"metadata\":{\"generateName\":\"other-\","),
                valid.replace("\"kind\":\"Job\"", "\"kind\":\"Job\",\"kind\":\"Job\""),
                valid + "{}",
                " ".repeat(1_048_577)}) {
            try (var fixture = new KubernetesHttpsFixture(201, CREATED)) {
                var api = client(fixture);
                assertThrows(ObservationFailure.class,
                        () -> api.createJob("runtime", JOB, invalid.getBytes(StandardCharsets.UTF_8)));
                assertFalse(api.mutationOutcomeUnknown());
                assertEquals(0, fixture.requests.get());
            }
        }
        try (var fixture = new KubernetesHttpsFixture(201, CREATED)) {
            var api = client(fixture);
            assertThrows(ObservationFailure.class, () -> api.createJob("../other", JOB, CREATION));
            assertEquals(0, fixture.requests.get());
        }
    }

    @Test
    void metadataStringsCannotBeCoercedFromNumbersBeforeMutation() throws Exception {
        String valid = new String(CREATION, StandardCharsets.UTF_8);
        try (var fixture = new KubernetesHttpsFixture(201, CREATED)) {
            var api = client(fixture);
            byte[] wrong = valid
                    .replace("\"namespace\":\"runtime\"", "\"namespace\":123")
                    .getBytes(StandardCharsets.UTF_8);
            assertThrows(ObservationFailure.class, () -> api.createJob("123", JOB, wrong));
            assertEquals(0, fixture.requests.get());
        }
        try (var fixture = new KubernetesHttpsFixture(201, CREATED)) {
            var api = client(fixture);
            byte[] wrong = valid.replace("\"name\":\"" + JOB + "\"", "\"name\":123").getBytes(StandardCharsets.UTF_8);
            assertThrows(ObservationFailure.class, () -> api.createJob("runtime", "123", wrong));
            assertEquals(0, fixture.requests.get());
        }
    }

    private KubernetesApi client(KubernetesHttpsFixture fixture) throws Exception {
        Path token = Files.createTempFile(directory, "creation-", ".token");
        Files.writeString(token, "synthetic.creation.token");
        Files.setPosixFilePermissions(token, PosixFilePermissions.fromString("rw-------"));
        return new KubernetesApi(fixture.endpoint(), fixture.trust(), token, Duration.ofSeconds(5));
    }
}
