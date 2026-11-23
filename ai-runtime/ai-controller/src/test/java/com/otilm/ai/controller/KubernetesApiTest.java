package com.otilm.ai.controller;

import com.otilm.ai.proxy.CoreEndpoint;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.attribute.PosixFilePermissions;
import java.time.Duration;
import java.util.Map;
import java.util.concurrent.TimeUnit;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/** Real local TLS/API-wire controls; synthetic token material confers no Kubernetes or Core authority. */
class KubernetesApiTest {
    private static final String TOKEN = "synthetic.api.token";
    @TempDir
    Path directory;

    @Test
    void resourcePathsAndBearerAreFixedAndRequestsHaveNoBodyOrCompression() throws Exception {
        byte[] body = "{\"kind\":\"Namespace\"}".getBytes(StandardCharsets.UTF_8);
        try (var f = new KubernetesHttpsFixture(200, body)) {
            var client = new KubernetesApi(f.endpoint(), f.trust(), token(TOKEN), Duration.ofSeconds(5));
            assertArrayEquals(body, assertDoesNotThrow(() -> client.namespace("runtime"), "namespace"));
            assertEquals("/api/v1/namespaces/runtime", f.path.get());
            assertDoesNotThrow(() -> client.serviceAccount("runtime", "runner"), "serviceAccount");
            assertEquals("/api/v1/namespaces/runtime/serviceaccounts/runner", f.path.get());
            assertDoesNotThrow(() -> client.job("runtime", "job-one"), "job");
            assertEquals("/apis/batch/v1/namespaces/runtime/jobs/job-one", f.path.get());
            assertDoesNotThrow(() -> client.pod("runtime", "pod-one"), "pod");
            assertEquals("/api/v1/namespaces/runtime/pods/pod-one", f.path.get());
            assertDoesNotThrow(() -> client.pods("runtime"), "pods");
            assertEquals("/api/v1/namespaces/runtime/pods", f.path.get());
            assertDoesNotThrow(() -> client.runtimeClass("ilm-runsc"), "runtimeClass");
            assertEquals("/apis/node.k8s.io/v1/runtimeclasses/ilm-runsc", f.path.get());
            assertDoesNotThrow(() -> client.configMap("runtime", "native-client-policy"), "configMap");
            assertEquals("/api/v1/namespaces/runtime/configmaps/native-client-policy", f.path.get());
            assertEquals("Bearer " + TOKEN, f.authorization.get());
            assertEquals(0, f.received.get().length);
            assertNull(f.acceptEncoding.get());
            assertEquals(7, f.requests.get());
            assertFalse(client.cleanupUncertain());
            assertNoOwnedGuard();
        }
    }

    @Test
    void routeFragmentsAndHeaderInjectionAreDeniedBeforeAnyApiRequest() throws Exception {
        try (var f = new KubernetesHttpsFixture(200, new byte[]{'{', '}'})) {
            var client = new KubernetesApi(f.endpoint(), f.trust(), token(TOKEN), Duration.ofSeconds(5));
            for (String name : new String[]{
                    "../foreign",
                    "x?watch=true",
                    "x#fragment",
                    "x%2Fforeign",
                    "x\r\nHost:evil"}) {
                assertThrows(ObservationFailure.class, () -> client.namespace(name));
            }
            assertEquals(0, f.requests.get());
        }
        for (String bad : new String[]{"", "not-jwt", TOKEN + "\r\nX-Injected:true", "x".repeat(8193)}) {
            try (var f = new KubernetesHttpsFixture(200, new byte[]{'{', '}'})) {
                var client = new KubernetesApi(f.endpoint(), f.trust(), token(bad), Duration.ofSeconds(5));
                assertThrows(ObservationFailure.class, () -> client.namespace("runtime"));
                assertEquals(0, f.requests.get());
            }
        }
    }

    @Test
    void failuresAndChallengesAreOneAttemptAndPoisonTheSnapshotOperation() throws Exception {
        for (int status : new int[]{301, 401, 407, 408, 421, 503, 101}) {
            try (var f = new KubernetesHttpsFixture(status, new byte[]{'{', '}'})) {
                f.redirect = "https://elsewhere.invalid/";
                var client = new KubernetesApi(f.endpoint(), f.trust(), token(TOKEN), Duration.ofSeconds(5));
                assertThrows(ObservationFailure.class, () -> client.namespace("runtime"));
                assertThrows(ObservationFailure.class, () -> client.namespace("runtime"));
                assertEquals(1, f.requests.get(), "wire attempts for status " + status);
            }
        }
    }

    @Test
    void wrongServerNameAndWrongExplicitCaCannotReachTheApi() throws Exception {
        try (var f = new KubernetesHttpsFixture(200, new byte[]{'{', '}'});
                var other = new KubernetesHttpsFixture(200, new byte[]{'{', '}'})) {
            var wrongName = new CoreEndpoint(URI.create("https://wrong.invalid:" + f.endpoint().origin().getPort()),
                    f.endpoint().address());
            var named = new KubernetesApi(wrongName, f.trust(), token(TOKEN), Duration.ofSeconds(2));
            assertThrows(ObservationFailure.class, () -> named.namespace("runtime"));
            var wrongCa = new KubernetesApi(f.endpoint(), other.trust(), token(TOKEN), Duration.ofSeconds(2));
            assertThrows(ObservationFailure.class, () -> wrongCa.namespace("runtime"));
            assertEquals(0, f.requests.get());
        }
    }

    @Test
    void oversizeAndUnboundedChunkedRepliesAreClosedWithoutDraining() throws Exception {
        try (var f = new KubernetesHttpsFixture(200, new byte[1_048_577])) {
            var client = new KubernetesApi(f.endpoint(), f.trust(), token(TOKEN), Duration.ofSeconds(2));
            assertThrows(ObservationFailure.class, () -> client.namespace("runtime"));
            assertEquals(1, f.requests.get());
        }
        try (var f = new KubernetesHttpsFixture(200, new byte[]{'{', '}'})) {
            f.hostileChunked = true;
            var client = new KubernetesApi(f.endpoint(), f.trust(), token(TOKEN), Duration.ofSeconds(2));
            assertThrows(ObservationFailure.class, () -> client.namespace("runtime"));
            assertTrue(f.responseEnded.await(2, TimeUnit.SECONDS));
            assertTrue(f.responseAborted.get());
            assertTrue(f.chunksWritten.get() < 192);
        }
    }

    @Test
    void gateRemovalHasUidResourceVersionAndGateTestsAndIsNotRetried() throws Exception {
        byte[] confirmed = """
                {"apiVersion":"v1","kind":"Pod","metadata":{"namespace":"runtime","name":"pod-one",
                 "uid":"41093c61-3bc3-427d-8a53-69faea046b58","resourceVersion":"pod-rv-8"},
                 "spec":{"schedulingGates":[]}}
                """.getBytes(StandardCharsets.UTF_8);
        try (var f = new KubernetesHttpsFixture(200, confirmed)) {
            var client = new KubernetesApi(f.endpoint(), f.trust(), token(TOKEN), Duration.ofSeconds(5));
            client
                    .releaseGate("runtime", "pod-one", "41093c61-3bc3-427d-8a53-69faea046b58", "pod-rv-7",
                            "ilm.otilm.ai/runtime-eligible");
            var actual = new com.fasterxml.jackson.databind.ObjectMapper().readTree(f.received.get());
            assertEquals(4, actual.size());
            assertEquals(Map.of("op", "test", "path", "/metadata/uid", "value", "41093c61-3bc3-427d-8a53-69faea046b58"),
                    new com.fasterxml.jackson.databind.ObjectMapper().convertValue(actual.get(0), Map.class));
            assertEquals("/metadata/resourceVersion", actual.get(1).path("path").textValue());
            assertEquals("pod-rv-7", actual.get(1).path("value").textValue());
            assertEquals("/spec/schedulingGates/0/name", actual.get(2).path("path").textValue());
            assertEquals("ilm.otilm.ai/runtime-eligible", actual.get(2).path("value").textValue());
            assertEquals("remove", actual.get(3).path("op").textValue());
            assertEquals("/spec/schedulingGates/0", actual.get(3).path("path").textValue());
            assertEquals("application/json-patch+json", f.contentType.get());
            assertEquals(1, f.requests.get());
            assertFalse(client.mutationOutcomeUnknown());
        }
        try (var f = new KubernetesHttpsFixture(503, new byte[]{'{', '}'})) {
            var client = new KubernetesApi(f.endpoint(), f.trust(), token(TOKEN), Duration.ofSeconds(5));
            assertThrows(ObservationFailure.class,
                    () -> client
                            .releaseGate("runtime", "pod-one", "41093c61-3bc3-427d-8a53-69faea046b58", "pod-rv-7",
                                    "ilm.otilm.ai/runtime-eligible"));
            assertEquals(1, f.requests.get());
        }
    }

    @Test
    void bodyProgressCannotRestartTheWholeOperationBudget() throws Exception {
        try (var f = new KubernetesHttpsFixture(200, new byte[]{'{', '}'})) {
            Path credential = token(TOKEN);
            new KubernetesApi(f.endpoint(), f.trust(), credential, Duration.ofSeconds(5)).namespace("warm");
            f.slowThenStall = true;
            var client = new KubernetesApi(f.endpoint(), f.trust(), credential, Duration.ofMillis(400));
            long started = System.nanoTime();
            assertThrows(ObservationFailure.class, () -> client.namespace("runtime"));
            long elapsed = System.nanoTime() - started;
            assertTrue(elapsed < TimeUnit.MILLISECONDS.toNanos(600), "aggregate API budget exceeded: " + elapsed);
            assertEquals(2, f.requests.get());
            assertFalse(client.cleanupUncertain());
            assertNoOwnedGuard();
            assertThrows(ObservationFailure.class, () -> client.namespace("runtime"));
            assertEquals(2, f.requests.get());
        }
    }

    @Test
    void onlyPrivateStableCredentialFilesCanAuthorizeAnApiRequest() throws Exception {
        try (var f = new KubernetesHttpsFixture(200, new byte[]{'{', '}'})) {
            Path publicFile = token(TOKEN);
            Files.setPosixFilePermissions(publicFile, PosixFilePermissions.fromString("rw-r--r--"));
            assertThrows(ObservationFailure.class,
                    () -> new KubernetesApi(f.endpoint(), f.trust(), publicFile, Duration.ofSeconds(2))
                            .namespace("runtime"));
            assertThrows(ObservationFailure.class,
                    () -> new KubernetesApi(f.endpoint(), f.trust(), directory, Duration.ofSeconds(2))
                            .namespace("runtime"));
            assertThrows(ObservationFailure.class,
                    () -> new KubernetesApi(f.endpoint(), f.trust(), directory.resolve("absent"), Duration.ofSeconds(2))
                            .namespace("runtime"));
            assertEquals(0, f.requests.get());
        }
    }

    @Test
    void invalidGateMutationCannotReachTheApi() throws Exception {
        try (var f = new KubernetesHttpsFixture(200, new byte[]{'{', '}'})) {
            for (String[] values : new String[][]{
                    {"invalid", "pod-rv-7", "ilm.otilm.ai/runtime-eligible"},
                    {"41093c61-3bc3-427d-8a53-69faea046b58", "", "ilm.otilm.ai/runtime-eligible"},
                    {"41093c61-3bc3-427d-8a53-69faea046b58", "x\r\nHost:other", "ilm.otilm.ai/runtime-eligible"},
                    {"41093c61-3bc3-427d-8a53-69faea046b58", "pod-rv-7", "unqualified"},
                    {"41093c61-3bc3-427d-8a53-69faea046b58", "pod-rv-7", "x/y\""}}) {
                var client = new KubernetesApi(f.endpoint(), f.trust(), token(TOKEN), Duration.ofSeconds(2));
                assertThrows(ObservationFailure.class,
                        () -> client.releaseGate("runtime", "pod-one", values[0], values[1], values[2]));
                assertThrows(ObservationFailure.class, () -> client.namespace("runtime"));
            }
            assertEquals(0, f.requests.get());
        }
    }

    @Test
    void invalidConfigurationAndExpiredOperationHaveNoNetworkAuthority() throws Exception {
        try (var f = new KubernetesHttpsFixture(200, new byte[]{'{', '}'})) {
            Path credential = token(TOKEN);
            for (Duration duration : new Duration[]{Duration.ZERO, Duration.ofNanos(-1), Duration.ofSeconds(6)}) {
                assertThrows(ObservationFailure.class,
                        () -> new KubernetesApi(f.endpoint(), f.trust(), credential, duration));
            }
            assertThrows(ObservationFailure.class,
                    () -> new KubernetesApi(null, f.trust(), credential, Duration.ofSeconds(1)));
            assertThrows(ObservationFailure.class,
                    () -> new KubernetesApi(f.endpoint(), null, credential, Duration.ofSeconds(1)));
            assertThrows(ObservationFailure.class,
                    () -> new KubernetesApi(f.endpoint(), f.trust(), null, Duration.ofSeconds(1)));
            assertThrows(ObservationFailure.class, () -> new KubernetesApi(f.endpoint(), f.trust(), credential, null));
            assertThrows(ObservationFailure.class,
                    () -> new KubernetesApi(f.endpoint(), f.trust(), Path.of("relative"), Duration.ofSeconds(1)));
            assertThrows(ObservationFailure.class, () -> new KubernetesApi(f.endpoint(), f.trust(),
                    directory.resolve("a/../credential"), Duration.ofSeconds(1)));
            var context = new CoreEndpoint(URI.create(f.endpoint().origin() + "/api"), f.endpoint().address());
            assertThrows(ObservationFailure.class,
                    () -> new KubernetesApi(context, f.trust(), credential, Duration.ofSeconds(1)));
            var expired = new KubernetesApi(f.endpoint(), f.trust(), credential, Duration.ofNanos(1));
            assertThrows(ObservationFailure.class, () -> expired.namespace("runtime"));
            assertEquals(0, f.requests.get());
        }
    }

    @Test
    void encodingsCookiesAndNonJsonRepliesCannotBecomeAnObservation() throws Exception {
        for (String type : new String[]{
                "text/plain",
                "application/json; charset=ISO-8859-1",
                "application/json; charset=not-a-real-charset",
                "broken; charset=missing"}) {
            try (var f = new KubernetesHttpsFixture(200, new byte[]{'{', '}'})) {
                f.replyContentType = type;
                assertThrows(ObservationFailure.class,
                        () -> new KubernetesApi(f.endpoint(), f.trust(), token(TOKEN), Duration.ofSeconds(2))
                                .namespace("runtime"));
                assertEquals(1, f.requests.get());
            }
        }
        try (var f = new KubernetesHttpsFixture(200, new byte[]{'{', '}'})) {
            f.encoding = "gzip";
            assertThrows(ObservationFailure.class,
                    () -> new KubernetesApi(f.endpoint(), f.trust(), token(TOKEN), Duration.ofSeconds(2))
                            .namespace("runtime"));
            assertEquals(1, f.requests.get());
        }
        try (var f = new KubernetesHttpsFixture(200, new byte[]{'{', '}'})) {
            f.cookie = "synthetic=value";
            assertThrows(ObservationFailure.class,
                    () -> new KubernetesApi(f.endpoint(), f.trust(), token(TOKEN), Duration.ofSeconds(2))
                            .namespace("runtime"));
            assertEquals(1, f.requests.get());
        }
        try (var f = new KubernetesHttpsFixture(200, new byte[]{'{', '}'})) {
            f.extraContentType = "application/json";
            assertThrows(ObservationFailure.class,
                    () -> new KubernetesApi(f.endpoint(), f.trust(), token(TOKEN), Duration.ofSeconds(2))
                            .namespace("runtime"));
            assertEquals(1, f.requests.get());
        }
    }

    @Test
    void commaJoinedOrParameterizedMediaTypesCannotBecomeAKubernetesObservation() throws Exception {
        for (String type : new String[]{
                "application/json, text/plain",
                "application/json; charset=UTF-8, text/plain",
                "application/json; profile=foreign",
                "application/json; charset=UTF-8; charset=ISO-8859-1",
                "application/json" + " ".repeat(480) + "!",
                "application/json" + "\t".repeat(480) + "!",
                "application/json" + " \t".repeat(240) + "; charset=UTF-8!",
                "application/json;" + " \t".repeat(240) + "charset=\"utf-8"}) {
            try (var f = new KubernetesHttpsFixture(200, new byte[]{'{', '}'})) {
                f.replyContentType = type;
                var client = new KubernetesApi(f.endpoint(), f.trust(), token(TOKEN), Duration.ofSeconds(2));
                assertThrows(ObservationFailure.class, () -> client.namespace("runtime"), type);
                assertThrows(ObservationFailure.class, () -> client.namespace("runtime"));
                assertEquals(1, f.requests.get());
                assertFalse(client.cleanupUncertain());
            }
        }
    }

    @Test
    void aSingleUtf8JsonMediaTypeRemainsCompatible() throws Exception {
        for (String type : new String[]{
                "Application/JSON",
                "application/json; charset=UTF-8",
                "application/json ; charset = \"utf-8\"",
                "application/json" + " ".repeat(480) + "; charset=UTF-8",
                "application/json" + "\t".repeat(480) + "; charset=UTF-8",
                "application/json" + " \t".repeat(80) + ";" + " \t".repeat(80) + "charset" + " \t".repeat(80) + "="
                        + " \t".repeat(80) + "\"utf-8\"" + " \t".repeat(80)}) {
            try (var f = new KubernetesHttpsFixture(200, new byte[]{'{', '}'})) {
                f.replyContentType = type;
                assertArrayEquals(new byte[]{'{', '}'},
                        new KubernetesApi(f.endpoint(), f.trust(), token(TOKEN), Duration.ofSeconds(2))
                                .namespace("runtime"));
                assertEquals(1, f.requests.get());
            }
        }
    }

    @Test
    void interruptedCleanupQuarantinesItsOwnerAndDeniesAnyNewIo() throws Exception {
        try (var f = new KubernetesHttpsFixture(200, new byte[]{'{', '}'})) {
            Path credential = token(TOKEN);
            new KubernetesApi(f.endpoint(), f.trust(), credential, Duration.ofSeconds(5)).namespace("warm");
            f.slowThenStall = true;
            var client = new KubernetesApi(f.endpoint(), f.trust(), credential, Duration.ofSeconds(1));
            var outcome = new java.util.concurrent.atomic.AtomicReference<Throwable>();
            var call = new Thread(() -> {
                try {
                    client.namespace("runtime");
                } catch (Throwable failure) {
                    outcome.set(failure);
                }
            }, "synthetic-api-owner");
            call.start();
            try {
                assertTrue(f.stallEntered.await(2, TimeUnit.SECONDS));
                call.interrupt();
                call.join(2000);
                assertFalse(call.isAlive(), "Actual API caller did not terminate");
                assertTrue(outcome.get() instanceof ObservationFailure);
                assertTrue(client.cleanupUncertain());
                assertThrows(ObservationFailure.class, () -> client.namespace("runtime"));
                assertEquals(2, f.requests.get());
            } finally {
                f.releaseStall.countDown();
                call.join(2000);
                assertFalse(call.isAlive(), "Owned API caller remains alive");
            }
        }
    }

    @Test
    void acceptedGatePatchWithAStalledReplyIsUnknownAndCannotBeRepeated() throws Exception {
        try (var f = new KubernetesHttpsFixture(200, new byte[]{'{', '}'})) {
            Path credential = token(TOKEN);
            new KubernetesApi(f.endpoint(), f.trust(), credential, Duration.ofSeconds(5)).namespace("warm");
            f.slowThenStall = true;
            var client = new KubernetesApi(f.endpoint(), f.trust(), credential, Duration.ofMillis(400));
            assertThrows(ObservationFailure.class,
                    () -> client
                            .releaseGate("runtime", "pod-one", "41093c61-3bc3-427d-8a53-69faea046b58", "pod-rv-7",
                                    "ilm.otilm.ai/runtime-eligible"));
            assertEquals("application/json-patch+json", f.contentType.get());
            assertEquals(4, new com.fasterxml.jackson.databind.ObjectMapper().readTree(f.received.get()).size());
            assertTrue(client.mutationOutcomeUnknown());
            assertFalse(client.cleanupUncertain(), "Confirmed local closure does not resolve the remote mutation");
            assertThrows(ObservationFailure.class,
                    () -> client
                            .releaseGate("runtime", "pod-one", "41093c61-3bc3-427d-8a53-69faea046b58", "pod-rv-7",
                                    "ilm.otilm.ai/runtime-eligible"));
            assertEquals(2, f.requests.get());
            assertNoOwnedGuard();
        }
    }

    @Test
    void overlappingCallsCannotCreateASecondActiveHttpOwner() throws Exception {
        try (var f = new KubernetesHttpsFixture(200, new byte[]{'{', '}'})) {
            Path credential = token(TOKEN);
            new KubernetesApi(f.endpoint(), f.trust(), credential, Duration.ofSeconds(5)).namespace("warm");
            f.slowThenStall = true;
            var client = new KubernetesApi(f.endpoint(), f.trust(), credential, Duration.ofSeconds(1));
            var outcome = new java.util.concurrent.atomic.AtomicReference<ObservationFailure>();
            var first = new Thread(() -> {
                try {
                    client.namespace("first");
                } catch (ObservationFailure denied) {
                    outcome.set(denied);
                }
            }, "synthetic-first-api-call");
            first.start();
            try {
                assertTrue(f.stallEntered.await(2, TimeUnit.SECONDS));
                assertThrows(ObservationFailure.class, () -> client.namespace("second"));
                first.join(2000);
                assertFalse(first.isAlive());
                assertTrue(outcome.get() != null);
                assertEquals(2, f.requests.get(), "Only warmup and the first operation may reach the wire");
            } finally {
                f.releaseStall.countDown();
                first.join(2000);
                assertFalse(first.isAlive());
            }
        }
    }

    @Test
    void malformedOrMismatchedPatchAcknowledgementRemainsUnknown() throws Exception {
        var json = new com.fasterxml.jackson.databind.ObjectMapper();
        String confirmed = """
                {"apiVersion":"v1","kind":"Pod","metadata":{"namespace":"runtime","name":"pod-one",
                 "uid":"41093c61-3bc3-427d-8a53-69faea046b58","resourceVersion":"pod-rv-8"},"spec":{}}
                """;
        for (String[] mutation : new String[][]{
                {"/apiVersion", "other"},
                {"/kind", "other"},
                {"/metadata/namespace", "other"},
                {"/metadata/name", "other"},
                {"/metadata/uid", "other"},
                {"/metadata/resourceVersion", "pod-rv-7"},
                {"/metadata/resourceVersion", ""},
                {"/metadata/deletionTimestamp", "2026-11-06T00:00:00Z"}}) {
            var body = (com.fasterxml.jackson.databind.node.ObjectNode) json.readTree(confirmed);
            int slash = mutation[0].lastIndexOf('/');
            ((com.fasterxml.jackson.databind.node.ObjectNode) body.at(mutation[0].substring(0, slash)))
                    .put(mutation[0].substring(slash + 1), mutation[1]);
            assertUnknownPatch(json.writeValueAsBytes(body));
        }
        for (String suffix : new String[]{
                "{\"schedulingGates\":[{\"name\":\"still-gated\"}]}",
                "{\"schedulingGates\":null}",
                "null"}) {
            var body = (com.fasterxml.jackson.databind.node.ObjectNode) json.readTree(confirmed);
            body.set("spec", json.readTree(suffix));
            assertUnknownPatch(json.writeValueAsBytes(body));
        }
        assertUnknownPatch(new byte[]{'{', '}'});
    }

    @Test
    void aNewOperationReadsTheCurrentConsistentProjectedTokenRevision() throws Exception {
        try (var f = new KubernetesHttpsFixture(200, new byte[]{'{', '}'})) {
            Path mount = Files.createDirectory(directory.resolve("projected"));
            for (String revision : new String[]{"one", "two"}) {
                Path target = Files.createDirectory(mount.resolve(revision)).resolve("token");
                Files.writeString(target, "synthetic.api." + revision);
                Files.setPosixFilePermissions(target, PosixFilePermissions.fromString("rw-------"));
            }
            Files.createSymbolicLink(mount.resolve("..data"), Path.of("one"));
            Files.createSymbolicLink(mount.resolve("token"), Path.of("..data/token"));
            var client = new KubernetesApi(f.endpoint(), f.trust(), mount.resolve("token"), Duration.ofSeconds(5));
            client.namespace("runtime");
            assertEquals("Bearer synthetic.api.one", f.authorization.get());
            Files.createSymbolicLink(mount.resolve("..next"), Path.of("two"));
            Files
                    .move(mount.resolve("..next"), mount.resolve("..data"),
                            java.nio.file.StandardCopyOption.ATOMIC_MOVE,
                            java.nio.file.StandardCopyOption.REPLACE_EXISTING);
            client.namespace("runtime");
            assertEquals("Bearer synthetic.api.two", f.authorization.get());
            assertEquals(2, f.requests.get());
        }
    }

    @Test
    void oneBudgetOwnerCannotAttemptASecondGateMutationAfterItsFirstAcknowledgement() throws Exception {
        byte[] reply = """
                {"apiVersion":"v1","kind":"Pod","metadata":{"namespace":"runtime","name":"pod-one",
                 "uid":"41093c61-3bc3-427d-8a53-69faea046b58","resourceVersion":"pod-rv-8"},"spec":{}}
                """.getBytes(StandardCharsets.UTF_8);
        try (var f = new KubernetesHttpsFixture(200, reply)) {
            var client = new KubernetesApi(f.endpoint(), f.trust(), token(TOKEN), Duration.ofSeconds(2));
            client
                    .releaseGate("runtime", "pod-one", "41093c61-3bc3-427d-8a53-69faea046b58", "pod-rv-7",
                            "ilm.otilm.ai/runtime-eligible");
            assertFalse(client.mutationOutcomeUnknown());
            assertThrows(ObservationFailure.class,
                    () -> client
                            .releaseGate("runtime", "pod-one", "41093c61-3bc3-427d-8a53-69faea046b58", "pod-rv-7",
                                    "ilm.otilm.ai/runtime-eligible"));
            assertEquals(1, f.requests.get());
        }
    }

    private void assertUnknownPatch(byte[] body) throws Exception {
        try (var f = new KubernetesHttpsFixture(200, body)) {
            var client = new KubernetesApi(f.endpoint(), f.trust(), token(TOKEN), Duration.ofSeconds(2));
            assertThrows(ObservationFailure.class,
                    () -> client
                            .releaseGate("runtime", "pod-one", "41093c61-3bc3-427d-8a53-69faea046b58", "pod-rv-7",
                                    "ilm.otilm.ai/runtime-eligible"));
            assertTrue(client.mutationOutcomeUnknown());
            assertThrows(ObservationFailure.class, () -> client.namespace("runtime"));
            assertEquals(1, f.requests.get());
        }
    }

    private static void assertNoOwnedGuard() {
        assertTrue(
                Thread
                        .getAllStackTraces()
                        .keySet()
                        .stream()
                        .noneMatch(thread -> thread.isAlive() && thread.getName().equals("ai-controller-http-budget")),
                "Owned cutoff thread remains alive");
    }

    private Path token(String text) throws Exception {
        Path file = Files.createTempFile(directory, "api-", ".token");
        Files.setPosixFilePermissions(file, PosixFilePermissions.fromString("rw-------"));
        Files.writeString(file, text, StandardCharsets.US_ASCII);
        return file;
    }
}
