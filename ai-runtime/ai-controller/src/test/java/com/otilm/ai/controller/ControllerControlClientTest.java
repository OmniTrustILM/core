package com.otilm.ai.controller;

import com.fasterxml.jackson.databind.ObjectMapper;
import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.time.Duration;
import java.time.Instant;
import java.util.Set;
import java.util.UUID;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/** Real local mTLS component fixtures; Main also validates binding before any downstream effect. */
class ControllerControlClientTest {
    private static final ObjectMapper JSON = new ObjectMapper();
    private static final Duration BUDGET = Duration.ofSeconds(5);
    private static final ControllerWire.Locator LOCATOR = new ControllerWire.Locator(
            UUID.fromString("a38cebd7-eafd-4cac-aed1-e1fcae264b85"),
            UUID.fromString("e7a0989e-4cd6-42d7-baf6-344caf843551"),
            UUID.fromString("d00f5707-e1ad-41e0-9f21-b66c74358c99"));
    private static final ControllerWire.Control CONTROL = new ControllerWire.Control(LOCATOR, 8, 4,
            UUID.fromString("736947e7-2778-4b40-8b0b-a514e319113c"),
            Set.of(new ControllerWire.Pod("lab", UUID.fromString("34adfc5b-55f9-4ffd-9b7a-b48eaaf0baf3"))));
    @TempDir
    Path directory;

    @Test
    void onlyStatusCanRepeatAndEveryMutationUsesItsClosedRouteAndOneMatchingAcknowledgement() throws Exception {
        try (var server = server(false)) {
            var client = client(server);
            var request = new ControllerWire.ObservationRequest(LOCATOR,
                    CONTROL.workloads().iterator().next().podUid());
            assertThrows(ObservationFailure.class,
                    () -> client.observe(ControllerWire.Operation.REGISTER, request, BUDGET));
            assertThrows(ObservationFailure.class,
                    () -> client.control(ControllerWire.ControlOperation.STATUS, LOCATOR, null, BUDGET));
            assertEquals(0, server.requests.get());
            client.launch(LOCATOR, BUDGET);
            for (var operation : ControllerWire.Operation.values()) {
                var reply = client.observe(operation, request, BUDGET);
                assertEquals(request, reply.request());
                assertEquals(operation == ControllerWire.Operation.ELIGIBLE
                        ? "/api/internal/ai-runtime/v1/controller/launches/reconcile"
                        : "/api/internal/ai-runtime/v1/controller/workloads/register", server.path.get());
                assertThrows(ObservationFailure.class, () -> client.observe(operation, request, BUDGET));
            }
            for (int i = 0; i < 2; i++) {
                assertEquals(CONTROL,
                        client.control(ControllerWire.ControlOperation.STATUS, LOCATOR, null, BUDGET).control());
            }
            for (var operation : new ControllerWire.ControlOperation[]{
                    ControllerWire.ControlOperation.FENCE,
                    ControllerWire.ControlOperation.TERMINAL,
                    ControllerWire.ControlOperation.CLEANUP}) {
                var expected = operation == ControllerWire.ControlOperation.FENCE ? null : CONTROL;
                assertEquals(CONTROL, client.control(operation, LOCATOR, expected, BUDGET).control());
                assertThrows(ObservationFailure.class, () -> client.control(operation, LOCATOR, expected, BUDGET));
            }
            assertEquals(8, server.requests.get());
            assertFalse(client.outcomeUnknown());
            assertFalse(client.cleanupUncertain());
        }
    }

    @Test
    void eachDistinctPodHasOneObservationAttemptPerStageBeforeTheFence() throws Exception {
        try (var server = server(false)) {
            var client = client(server);
            client.launch(LOCATOR, BUDGET);
            for (var operation : ControllerWire.Operation.values()) {
                for (UUID uid : new UUID[]{
                        CONTROL.workloads().iterator().next().podUid(),
                        UUID.fromString("984a4caa-e002-4fe0-aee5-937ef7b2cfec")}) {
                    var request = new ControllerWire.ObservationRequest(LOCATOR, uid);
                    assertEquals(uid, client.observe(operation, request, BUDGET).request().podUid());
                    assertThrows(ObservationFailure.class, () -> client.observe(operation, request, BUDGET));
                }
            }
            assertEquals(5, server.requests.get());
            assertFalse(client.outcomeUnknown());
        }
    }

    @Test
    void freshCleanupResumptionAllowsOnlyTheExactTerminalAndCleanupTuple() throws Exception {
        try (var server = server(false)) {
            var client = client(server);
            var resumed = client.resumeCleanup(LOCATOR, BUDGET);
            assertEquals(CONTROL, resumed.control());
            assertFalse(resumed.done());
            assertThrows(ObservationFailure.class, () -> client.launch(LOCATOR, BUDGET));
            var request = new ControllerWire.ObservationRequest(LOCATOR,
                    CONTROL.workloads().iterator().next().podUid());
            for (var operation : ControllerWire.Operation.values()) {
                assertThrows(ObservationFailure.class, () -> client.observe(operation, request, BUDGET));
            }
            assertThrows(ObservationFailure.class,
                    () -> client.control(ControllerWire.ControlOperation.STATUS, LOCATOR, null, BUDGET));
            assertThrows(ObservationFailure.class,
                    () -> client.control(ControllerWire.ControlOperation.FENCE, LOCATOR, null, BUDGET));
            var stale = new ControllerWire.Control(LOCATOR, CONTROL.runRevision() + 1, CONTROL.fence(),
                    CONTROL.jobUid(), CONTROL.workloads());
            assertThrows(ObservationFailure.class,
                    () -> client.control(ControllerWire.ControlOperation.TERMINAL, LOCATOR, stale, BUDGET));
            assertEquals(1, server.requests.get());
            client.control(ControllerWire.ControlOperation.TERMINAL, LOCATOR, CONTROL, BUDGET);
            client.control(ControllerWire.ControlOperation.CLEANUP, LOCATOR, CONTROL, BUDGET);
            assertThrows(ObservationFailure.class, () -> client.resumeCleanup(LOCATOR, BUDGET));
            assertEquals(3, server.requests.get());
        }
    }

    @Test
    void concurrentResumptionHasOneOwnerAndCannotOpenLaunchWhileInFlight() throws Exception {
        try (var server = server(false)) {
            var entered = new java.util.concurrent.CountDownLatch(1);
            var release = new java.util.concurrent.CountDownLatch(1);
            var normal = server.responder;
            server.responder = request -> {
                entered.countDown();
                try {
                    if (!release.await(3, java.util.concurrent.TimeUnit.SECONDS)) {
                        throw new AssertionError("Synthetic owner was not released");
                    }
                } catch (InterruptedException interrupted) {
                    Thread.currentThread().interrupt();
                    throw new AssertionError(interrupted);
                }
                return normal.apply(request);
            };
            var client = client(server);
            var worker = java.util.concurrent.Executors.newSingleThreadExecutor();
            try {
                var first = worker.submit(() -> client.resumeCleanup(LOCATOR, BUDGET));
                assertTrue(entered.await(2, java.util.concurrent.TimeUnit.SECONDS));
                assertThrows(ObservationFailure.class, () -> client.resumeCleanup(LOCATOR, BUDGET));
                assertThrows(ObservationFailure.class, () -> client.launch(LOCATOR, BUDGET));
                release.countDown();
                assertEquals(CONTROL, first.get(3, java.util.concurrent.TimeUnit.SECONDS).control());
                assertEquals(1, server.requests.get());
            } finally {
                release.countDown();
                worker.shutdownNow();
                assertTrue(worker.awaitTermination(1, java.util.concurrent.TimeUnit.SECONDS));
            }
        }
    }

    @Test
    void doneResumptionCannotGrantAnyFollowupOperation() throws Exception {
        try (var server = server(false)) {
            server.responder = request -> new KubernetesHttpsFixture.Reply(200,
                    ControllerWire
                            .controlReply(ControllerWire.ControlOperation.CLEANUP,
                                    new ControllerWire.ControlReply(CONTROL, null, null, null)));
            var client = client(server);
            assertTrue(client.resumeCleanup(LOCATOR, BUDGET).done());
            for (var operation : ControllerWire.ControlOperation.values()) {
                var expected = operation == ControllerWire.ControlOperation.TERMINAL
                        || operation == ControllerWire.ControlOperation.CLEANUP ? CONTROL : null;
                assertThrows(ObservationFailure.class, () -> client.control(operation, LOCATOR, expected, BUDGET));
            }
            assertThrows(ObservationFailure.class, () -> client.launch(LOCATOR, BUDGET));
            assertEquals(1, server.requests.get());
        }
    }

    @Test
    void unknownForeignOrMalformedResumeResponsesRemainClosedWithoutFallback() throws Exception {
        for (String defect : new String[]{"http", "malformed", "foreign", "empty"}) {
            try (var server = server(false)) {
                var control = defect.equals("foreign")
                        ? new ControllerWire.Control(
                                new ControllerWire.Locator(UUID.randomUUID(), LOCATOR.runId(), LOCATOR.attemptId()),
                                CONTROL.runRevision(), CONTROL.fence(), CONTROL.jobUid(), CONTROL.workloads())
                        : defect.equals("empty")
                                ? new ControllerWire.Control(LOCATOR, CONTROL.runRevision(), CONTROL.fence(),
                                        CONTROL.jobUid(), Set.of())
                                : CONTROL;
                byte[] body = defect.equals("malformed")
                        ? new byte[]{'{'}
                        : ControllerWire
                                .controlReply(ControllerWire.ControlOperation.FENCE,
                                        new ControllerWire.ControlReply(control, null, null, null));
                server.responder = request -> new KubernetesHttpsFixture.Reply(defect.equals("http") ? 503 : 200, body);
                var client = client(server);
                assertThrows(ObservationFailure.class, () -> client.resumeCleanup(LOCATOR, BUDGET));
                assertTrue(client.outcomeUnknown());
                assertThrows(ObservationFailure.class, () -> client.launch(LOCATOR, BUDGET));
                assertThrows(ObservationFailure.class, () -> client.resumeCleanup(LOCATOR, BUDGET));
                assertThrows(ObservationFailure.class,
                        () -> client.control(ControllerWire.ControlOperation.FENCE, LOCATOR, null, BUDGET));
                assertEquals(1, server.requests.get());
            }
        }
    }

    @Test
    void resumptionCannotFollowLaunchOrEscapeUncertainHandleCleanup() throws Exception {
        try (var server = server(false)) {
            var client = client(server);
            client.launch(LOCATOR, BUDGET);
            assertThrows(ObservationFailure.class, () -> client.resumeCleanup(LOCATOR, BUDGET));
            assertEquals(1, server.requests.get());
        }
        try (var server = server(false)) {
            var material = new ControllerCoreClientTest();
            material.directory = directory;
            var client = new ControllerCoreClient(material.configuration(server), close -> {
                close.run();
                throw new IllegalStateException("synthetic cleanup fault");
            });
            assertThrows(ObservationFailure.class, () -> client.resumeCleanup(LOCATOR, BUDGET));
            assertTrue(client.cleanupUncertain());
            assertTrue(client.outcomeUnknown());
            assertThrows(ObservationFailure.class, () -> client.launch(LOCATOR, BUDGET));
            assertThrows(ObservationFailure.class,
                    () -> client.control(ControllerWire.ControlOperation.TERMINAL, LOCATOR, CONTROL, BUDGET));
            assertEquals(1, server.requests.get());
        }
    }

    @Test
    void aForeignCleanupAcknowledgementRemainsUnknownBeforeAnyFollowupMutation() throws Exception {
        try (var server = server(true)) {
            var client = client(server);
            client.launch(LOCATOR, BUDGET);
            client.control(ControllerWire.ControlOperation.FENCE, LOCATOR, null, BUDGET);
            assertThrows(ObservationFailure.class,
                    () -> client.control(ControllerWire.ControlOperation.TERMINAL, LOCATOR, CONTROL, BUDGET));
            assertTrue(client.outcomeUnknown());
            assertThrows(ObservationFailure.class,
                    () -> client.control(ControllerWire.ControlOperation.CLEANUP, LOCATOR, CONTROL, BUDGET));
            assertEquals(3, server.requests.get());
        }
    }

    @Test
    void cleanupMustFollowFenceThenTerminalAndFencingCannotReopenRegistration() throws Exception {
        try (var server = server(false)) {
            var client = client(server);
            client.launch(LOCATOR, BUDGET);
            assertThrows(ObservationFailure.class,
                    () -> client.control(ControllerWire.ControlOperation.TERMINAL, LOCATOR, CONTROL, BUDGET));
            assertThrows(ObservationFailure.class,
                    () -> client.control(ControllerWire.ControlOperation.CLEANUP, LOCATOR, CONTROL, BUDGET));
            assertEquals(1, server.requests.get());
            client.control(ControllerWire.ControlOperation.FENCE, LOCATOR, null, BUDGET);
            var request = new ControllerWire.ObservationRequest(LOCATOR,
                    CONTROL.workloads().iterator().next().podUid());
            assertThrows(ObservationFailure.class,
                    () -> client.observe(ControllerWire.Operation.REGISTER, request, BUDGET));
            client.control(ControllerWire.ControlOperation.TERMINAL, LOCATOR, CONTROL, BUDGET);
            client.control(ControllerWire.ControlOperation.CLEANUP, LOCATOR, CONTROL, BUDGET);
            assertEquals(4, server.requests.get());
        }
    }

    @Test
    void cleanupUncertaintyAfterAcceptedLaunchIndependentlyBlocksTheOtherwisePermittedFence() throws Exception {
        try (var server = server(false)) {
            var material = new ControllerCoreClientTest();
            material.directory = directory;
            var fail = new java.util.concurrent.atomic.AtomicBoolean();
            var client = new ControllerCoreClient(material.configuration(server), close -> {
                close.run();
                if (fail.get()) {
                    throw new IllegalStateException("synthetic cleanup fault");
                }
            });
            client.launch(LOCATOR, BUDGET);
            fail.set(true);
            assertThrows(ObservationFailure.class,
                    () -> client.control(ControllerWire.ControlOperation.STATUS, LOCATOR, null, BUDGET));
            assertTrue(client.cleanupUncertain());
            assertTrue(client.outcomeUnknown());
            assertThrows(ObservationFailure.class,
                    () -> client.control(ControllerWire.ControlOperation.FENCE, LOCATOR, null, BUDGET));
            assertEquals(2, server.requests.get());
        }
    }

    @Test
    void aPreFenceUnknownAllowsOneDistinctFenceAndNoNewObservation() throws Exception {
        try (var server = server(false)) {
            var client = client(server);
            client.launch(LOCATOR, BUDGET);
            var normal = server.responder;
            server.responder = request -> new KubernetesHttpsFixture.Reply(503, new byte[]{'{', '}'});
            var request = new ControllerWire.ObservationRequest(LOCATOR,
                    CONTROL.workloads().iterator().next().podUid());
            assertThrows(ObservationFailure.class,
                    () -> client.observe(ControllerWire.Operation.ELIGIBLE, request, BUDGET));
            assertTrue(client.outcomeUnknown());
            assertThrows(ObservationFailure.class,
                    () -> client.observe(ControllerWire.Operation.REGISTER, request, BUDGET));
            server.responder = normal;
            client.control(ControllerWire.ControlOperation.FENCE, LOCATOR, null, BUDGET);
            assertThrows(ObservationFailure.class,
                    () -> client.observe(ControllerWire.Operation.REGISTER, request, BUDGET));
            assertEquals(3, server.requests.get());
        }
    }

    private ControllerCoreClient client(KubernetesHttpsFixture server) throws Exception {
        var material = new ControllerCoreClientTest();
        material.directory = directory;
        return new ControllerCoreClient(material.configuration(server));
    }

    private static KubernetesHttpsFixture server(boolean foreignTerminal) throws Exception {
        var server = new KubernetesHttpsFixture(200, new byte[]{'{', '}'});
        server.requireClientAuthentication = true;
        server.responder = request -> {
            try {
                String kind = JSON.readTree(request.body()).path("kind").textValue();
                byte[] bytes;
                if (kind.equals("launch-reconcile")) {
                    bytes = ControllerWireTest.BINDING.getBytes(StandardCharsets.UTF_8);
                } else if (kind.equals("workload-eligible") || kind.equals("workload-register")) {
                    var operation = kind.equals("workload-eligible")
                            ? ControllerWire.Operation.ELIGIBLE
                            : ControllerWire.Operation.REGISTER;
                    var decoded = ControllerWire.readObservationRequest(request.body(), operation);
                    bytes = ControllerWire
                            .observationReply(operation, new ControllerWire.ObservationReply(decoded, CONTROL.jobUid(),
                                    "actual-rv", 7, 3, 1, Instant.now().plusSeconds(20)));
                } else {
                    var operation = switch (kind) {
                        case "workload-status" -> ControllerWire.ControlOperation.STATUS;
                        case "cleanup-request", "cleanup-resume" -> ControllerWire.ControlOperation.FENCE;
                        case "cleanup-terminal-status" -> ControllerWire.ControlOperation.TERMINAL;
                        case "cleanup-reconcile" -> ControllerWire.ControlOperation.CLEANUP;
                        default -> throw new AssertionError("Unexpected synthetic kind");
                    };
                    var control = foreignTerminal && operation == ControllerWire.ControlOperation.TERMINAL
                            ? new ControllerWire.Control(LOCATOR, CONTROL.runRevision(), CONTROL.fence() + 1,
                                    CONTROL.jobUid(), CONTROL.workloads())
                            : CONTROL;
                    bytes = ControllerWire
                            .controlReply(operation, new ControllerWire.ControlReply(control, "CANCELLED", "FENCED",
                                    Instant.now().plusSeconds(20)));
                }
                return new KubernetesHttpsFixture.Reply(200, bytes);
            } catch (Exception invalid) {
                return new KubernetesHttpsFixture.Reply(500, new byte[]{'{', '}'});
            }
        };
        return server;
    }
}
