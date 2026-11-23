package com.otilm.ai.gateway;

import com.otilm.ai.runtime.protocol.PayloadFingerprint;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.Executors;
import java.util.concurrent.ThreadFactory;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicReference;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class AggregateCancellationTest {
    private static final byte[] BODY = "{\"model\":\"fixture\",\"messages\":[{\"role\":\"user\",\"content\":\"synthetic\"}],\"max_tokens\":32,\"stream\":false}"
            .getBytes(StandardCharsets.UTF_8);

    private static final String DIGEST = PayloadFingerprint.sha256(BODY);
    private static final Duration ONE_SECOND = Duration.ofSeconds(1);

    @Test
    void progressingTlsRecordCannotOutliveAggregateCancellation() throws Exception {
        check(SlowProgressFixture.Phase.TLS);
    }

    @Test
    void progressingHeadersAfterCompletePostCannotOutliveAggregateCancellation() throws Exception {
        check(SlowProgressFixture.Phase.HEADERS);
    }

    @Test
    void progressingBodyAfterCompletePostStopsThePeerSocket() throws Exception {
        check(SlowProgressFixture.Phase.BODY);
    }

    @Test
    void admissionRemainsHeldUntilActualWatchdogThreadReturns() throws Exception {
        var stoppedIO = new CountDownLatch(1);
        var acknowledge = new CountDownLatch(1);
        var watchdog = new AtomicReference<Thread>();
        var selected = new ChatCompletionsTransport(Duration.ofMillis(700), ONE_SECOND,
                delayedFactory(stoppedIO, acknowledge, watchdog));
        var caller = Executors.newSingleThreadExecutor();
        var physicalCaller = new AtomicReference<Thread>();
        var interruptPreserved = new AtomicBoolean();
        try (var ca = new HttpsFixture(200, new byte[]{1});
                var hostile = new SlowProgressFixture(ca, SlowProgressFixture.Phase.HEADERS)) {
            var result = caller.submit(() -> {
                physicalCaller.set(Thread.currentThread());
                try {
                    return selected.post(hostile.endpoint(), BODY, DIGEST, "synthetic-token");
                } catch (GatewayFailure failure) {
                    interruptPreserved.set(Thread.currentThread().isInterrupted());
                    return failure;
                }
            });
            assertTrue(hostile.postObserved.await(2, TimeUnit.SECONDS));
            assertTrue(stoppedIO.await(2, TimeUnit.SECONDS));
            assertTrue(hostile.finished.await(1, TimeUnit.SECONDS));
            assertTrue(hostile.clientClosed.get());
            assertTrue(watchdog.get().isAlive());
            assertFalse(result.isDone());
            physicalCaller.get().interrupt();
            var next = selected.accepted();
            assertThrows(GatewayFailure.class, () -> selected.admit(next));
            acknowledge.countDown();
            assertTrue(result.get(2, TimeUnit.SECONDS) instanceof GatewayFailure);
            assertTrue(interruptPreserved.get());
            assertFalse(watchdog.get().isAlive());
            try (var positive = new HttpsFixture(200, new byte[]{1, 2})) {
                assertArrayEquals(new byte[]{1, 2},
                        selected.post(positive.endpoint(), BODY, DIGEST, "synthetic-token"));
                assertEquals(1, positive.requests.get());
            }
        } finally {
            acknowledge.countDown();
            caller.shutdownNow();
            assertTrue(caller.awaitTermination(3, TimeUnit.SECONDS));
            Thread observed = watchdog.get();
            if (observed != null) {
                observed.join(2000);
                assertFalse(observed.isAlive());
            }
        }
    }

    @Test
    void unacknowledgedWatchdogTerminationQuarantinesAdmission() throws Exception {
        var stoppedIO = new CountDownLatch(1);
        var acknowledge = new CountDownLatch(1);
        var watchdog = new AtomicReference<Thread>();
        var selected = new ChatCompletionsTransport(Duration.ofMillis(700), Duration.ofMillis(100),
                delayedFactory(stoppedIO, acknowledge, watchdog));
        try (var ca = new HttpsFixture(200, new byte[]{1});
                var hostile = new SlowProgressFixture(ca, SlowProgressFixture.Phase.HEADERS)) {
            var endpoint = hostile.endpoint();
            var failure = assertThrows(GatewayFailure.class,
                    () -> selected.post(endpoint, BODY, DIGEST, "synthetic-token"));
            assertEquals(GatewayFailure.Code.UPSTREAM_FAILURE, failure.code());
            assertTrue(stoppedIO.await(1, TimeUnit.SECONDS));
            assertTrue(hostile.finished.await(1, TimeUnit.SECONDS));
            assertTrue(hostile.clientClosed.get());
            assertArrayEquals(BODY, hostile.completePost.get());
            assertTrue(watchdog.get().isAlive());
            var next = selected.accepted();
            assertThrows(GatewayFailure.class, () -> selected.admit(next));
            acknowledge.countDown();
            watchdog.get().join(2000);
            assertFalse(watchdog.get().isAlive());
            var afterTermination = selected.accepted();
            assertThrows(GatewayFailure.class, () -> selected.admit(afterTermination));
        } finally {
            acknowledge.countDown();
            Thread observed = watchdog.get();
            if (observed != null) {
                observed.join(2000);
                assertFalse(observed.isAlive());
            }
        }
    }

    @Test
    void bytesCompletedBeforeDeadlineCannotEscapeAfterLateCleanup() throws Exception {
        var stoppedIO = new CountDownLatch(1);
        var acknowledge = new CountDownLatch(1);
        var watchdog = new AtomicReference<Thread>();
        var selected = new ChatCompletionsTransport(Duration.ofMillis(700), ONE_SECOND,
                delayedFactory(stoppedIO, acknowledge, watchdog));
        var caller = Executors.newSingleThreadExecutor();
        try (var positive = new HttpsFixture(200, new byte[]{1, 2})) {
            var result = caller.submit(() -> {
                try {
                    return selected.post(positive.endpoint(), BODY, DIGEST, "synthetic-token");
                } catch (GatewayFailure failure) {
                    return failure;
                }
            });
            assertTrue(stoppedIO.await(1, TimeUnit.SECONDS));
            assertFalse(new CountDownLatch(1).await(750, TimeUnit.MILLISECONDS));
            acknowledge.countDown();
            assertTrue(result.get(2, TimeUnit.SECONDS) instanceof GatewayFailure);
            assertEquals(1, positive.requests.get());
            assertFalse(watchdog.get().isAlive());
        } finally {
            acknowledge.countDown();
            caller.shutdownNow();
            assertTrue(caller.awaitTermination(3, TimeUnit.SECONDS));
        }
    }

    @Test
    void interruptedOriginalIoCallerTerminatesAndPreservesItsInterrupt() throws Exception {
        var selected = new ChatCompletionsTransport();
        var caller = Executors.newSingleThreadExecutor();
        var physicalCaller = new AtomicReference<Thread>();
        var preserved = new AtomicBoolean();
        try (var ca = new HttpsFixture(200, new byte[]{1});
                var hostile = new SlowProgressFixture(ca, SlowProgressFixture.Phase.HEADERS)) {
            var result = caller.submit(() -> {
                physicalCaller.set(Thread.currentThread());
                try {
                    selected.post(hostile.endpoint(), BODY, DIGEST, "synthetic-token");
                    return false;
                } catch (GatewayFailure failure) {
                    preserved.set(Thread.currentThread().isInterrupted());
                    return failure.mayHaveSent();
                }
            });
            assertTrue(hostile.postObserved.await(2, TimeUnit.SECONDS));
            physicalCaller.get().interrupt();
            assertTrue(result.get(7, TimeUnit.SECONDS));
            assertTrue(preserved.get());
            assertTrue(hostile.finished.await(1, TimeUnit.SECONDS));
            assertTrue(hostile.clientClosed.get());
            try (var positive = new HttpsFixture(200, new byte[]{1, 2})) {
                assertArrayEquals(new byte[]{1, 2},
                        selected.post(positive.endpoint(), BODY, DIGEST, "synthetic-token"));
            }
        } finally {
            caller.shutdownNow();
            assertTrue(caller.awaitTermination(3, TimeUnit.SECONDS));
        }
    }

    @Test
    void admissionCarriesOriginalTrustedAcceptanceAndRejectsForeignOrRepeatedUse() throws Exception {
        var selected = new ChatCompletionsTransport(Duration.ofMillis(700), ONE_SECOND, Thread.ofPlatform().factory());
        var deadline = selected.accepted();
        assertFalse(new CountDownLatch(1).await(750, TimeUnit.MILLISECONDS));
        assertThrows(GatewayFailure.class, () -> selected.admit(deadline));
        var foreign = new ChatCompletionsTransport().accepted();
        assertThrows(GatewayFailure.class, () -> selected.admit(foreign));
        assertThrows(GatewayFailure.class, () -> selected.admit(null));
        try (var positive = new HttpsFixture(200, new byte[]{1, 2});
                var operation = selected.admit(selected.accepted())) {
            var positiveEndpoint = positive.endpoint();
            var foreignCaller = Executors.newSingleThreadExecutor();
            try {
                assertTrue(foreignCaller.submit(() -> {
                    try {
                        operation.close();
                        return false;
                    } catch (GatewayFailure failure) {
                        return true;
                    }
                }).get(1, TimeUnit.SECONDS));
                var next = selected.accepted();
                assertThrows(GatewayFailure.class, () -> selected.admit(next));
                assertArrayEquals(new byte[]{1, 2},
                        operation.post(positive.endpoint(), BODY, DIGEST, "synthetic-token"));
                assertThrows(GatewayFailure.class,
                        () -> operation.post(positiveEndpoint, BODY, DIGEST, "synthetic-token"));
                assertEquals(1, positive.requests.get());
            } finally {
                foreignCaller.shutdownNow();
                assertTrue(foreignCaller.awaitTermination(1, TimeUnit.SECONDS));
            }
        }
    }

    @Test
    void invalidTrustedPoliciesAndFailedThreadCreationFailClosedWithoutLeakingAdmission() throws Exception {
        ThreadFactory normal = Thread.ofPlatform().factory();
        for (Duration invalid : new Duration[]{Duration.ZERO, Duration.ofSeconds(6)}) {
            assertThrows(IllegalArgumentException.class,
                    () -> new ChatCompletionsTransport(invalid, ONE_SECOND, normal));
        }
        for (Duration invalid : new Duration[]{Duration.ZERO, Duration.ofSeconds(2)}) {
            assertThrows(IllegalArgumentException.class,
                    () -> new ChatCompletionsTransport(ONE_SECOND, invalid, normal));
        }
        var first = new AtomicBoolean(true);
        var selected = new ChatCompletionsTransport(ONE_SECOND, ONE_SECOND,
                work -> first.getAndSet(false) ? null : normal.newThread(work));
        var deadline = selected.accepted();
        assertThrows(GatewayFailure.class, () -> selected.admit(deadline));
        try (var positive = new HttpsFixture(200, new byte[]{1, 2})) {
            assertArrayEquals(new byte[]{1, 2}, selected.post(positive.endpoint(), BODY, DIGEST, "synthetic-token"));
            assertEquals(1, positive.requests.get());
        }
    }

    @Test
    void idleAdmissionExpiresAndUnusedClosedAdmissionCannotSend() throws Exception {
        var selected = new ChatCompletionsTransport(Duration.ofMillis(700), ONE_SECOND, Thread.ofPlatform().factory());
        try (var positive = new HttpsFixture(200, new byte[]{1, 2})) {
            var positiveEndpoint = positive.endpoint();
            var unused = selected.admit(selected.accepted());
            unused.close();
            unused.close();
            assertThrows(GatewayFailure.class, () -> unused.post(positiveEndpoint, BODY, DIGEST, "synthetic-token"));
            try (var idle = selected.admit(selected.accepted())) {
                assertFalse(new CountDownLatch(1).await(750, TimeUnit.MILLISECONDS));
                assertThrows(GatewayFailure.class, () -> idle.post(positiveEndpoint, BODY, DIGEST, "synthetic-token"));
            }
            assertEquals(0, positive.requests.get());
            assertArrayEquals(new byte[]{1, 2}, selected.post(positive.endpoint(), BODY, DIGEST, "synthetic-token"));
        }
    }

    @Test
    void interruptedWatchdogAbortsTheActualSocketAndOriginalCallerReturns() throws Exception {
        var watchdog = new AtomicReference<Thread>();
        var selected = new ChatCompletionsTransport(Duration.ofSeconds(5), ONE_SECOND, work -> {
            Thread thread = new Thread(work, "f04-interrupted-watchdog");
            watchdog.set(thread);
            return thread;
        });
        var caller = Executors.newSingleThreadExecutor();
        try (var ca = new HttpsFixture(200, new byte[]{1});
                var hostile = new SlowProgressFixture(ca, SlowProgressFixture.Phase.HEADERS)) {
            var result = caller.submit(() -> {
                try {
                    selected.post(hostile.endpoint(), BODY, DIGEST, "synthetic-token");
                    return false;
                } catch (GatewayFailure failure) {
                    return failure.mayHaveSent();
                }
            });
            assertTrue(hostile.postObserved.await(2, TimeUnit.SECONDS));
            watchdog.get().interrupt();
            assertTrue(result.get(2, TimeUnit.SECONDS));
            assertTrue(hostile.finished.await(1, TimeUnit.SECONDS));
            assertTrue(hostile.clientClosed.get());
            assertFalse(watchdog.get().isAlive());
        } finally {
            caller.shutdownNow();
            assertTrue(caller.awaitTermination(3, TimeUnit.SECONDS));
        }
    }

    @Test
    void closedAcceptanceCannotBeAdmittedAgainWhileItsDeadlineIsStillValid() throws Exception {
        var selected = new ChatCompletionsTransport();
        try (var positive = new HttpsFixture(200, new byte[]{1, 2})) {
            var deadline = selected.accepted();
            try (var operation = selected.admit(deadline)) {
                assertArrayEquals(new byte[]{1, 2},
                        operation.post(positive.endpoint(), BODY, DIGEST, "synthetic-token"));
            }
            assertEquals(1, positive.requests.get());
            assertRejectedAdmission(selected, deadline);
            assertArrayEquals(new byte[]{1, 2}, selected.post(positive.endpoint(), BODY, DIGEST, "synthetic-token"));
            assertEquals(2, positive.requests.get());
        }
    }

    @Test
    void capacityDenialStillConsumesThatAcceptance() throws Exception {
        var selected = new ChatCompletionsTransport();
        var denied = selected.accepted();
        try (var held = selected.admit(selected.accepted())) {
            assertRejectedAdmission(selected, denied);
        }
        assertRejectedAdmission(selected, denied);
        try (var positive = new HttpsFixture(200, new byte[]{1, 2})) {
            assertArrayEquals(new byte[]{1, 2}, selected.post(positive.endpoint(), BODY, DIGEST, "synthetic-token"));
            assertEquals(1, positive.requests.get());
        }
    }

    @Test
    void threadCreationFailureStillConsumesThatAcceptance() throws Exception {
        var first = new AtomicBoolean(true);
        var normal = Thread.ofPlatform().factory();
        var selected = new ChatCompletionsTransport(ONE_SECOND, ONE_SECOND,
                work -> first.getAndSet(false) ? null : normal.newThread(work));
        var failed = selected.accepted();
        assertRejectedAdmission(selected, failed);
        assertRejectedAdmission(selected, failed);
        try (var positive = new HttpsFixture(200, new byte[]{1, 2})) {
            assertArrayEquals(new byte[]{1, 2}, selected.post(positive.endpoint(), BODY, DIGEST, "synthetic-token"));
            assertEquals(1, positive.requests.get());
        }
    }

    private static void assertRejectedAdmission(ChatCompletionsTransport selected,
            ChatCompletionsTransport.Deadline deadline) {
        ChatCompletionsTransport.Operation unexpected = null;
        GatewayFailure rejection = null;
        try {
            unexpected = selected.admit(deadline);
        } catch (GatewayFailure failure) {
            rejection = failure;
        } finally {
            // A failing RED still owns and joins any incorrectly admitted operation.
            if (unexpected != null) {
                unexpected.close();
            }
        }
        assertNotNull(rejection, "The same acceptance deadline was incorrectly admitted again");
        assertEquals(GatewayFailure.Code.UPSTREAM_FAILURE, rejection.code());
    }

    private static ThreadFactory delayedFactory(CountDownLatch stoppedIO, CountDownLatch acknowledge,
            AtomicReference<Thread> observed) {
        return work -> {
            Thread thread = new Thread(() -> {
                work.run();
                stoppedIO.countDown();
                try {
                    if (!acknowledge.await(3, TimeUnit.SECONDS)) {
                        throw new AssertionError("Missing owned watchdog acknowledgment");
                    }
                } catch (InterruptedException interrupted) {
                    Thread.currentThread().interrupt();
                    throw new AssertionError("Unexpected owned watchdog interruption");
                }
            }, "f04-controlled-watchdog");
            observed.set(thread);
            return thread;
        };
    }

    private void check(SlowProgressFixture.Phase phase) throws Exception {
        try (var ca = new HttpsFixture(200, new byte[]{1}); var hostile = new SlowProgressFixture(ca, phase)) {
            var selected = new ChatCompletionsTransport();
            var endpoint = hostile.endpoint();
            long started = System.nanoTime();
            var rejected = assertThrows(GatewayFailure.class,
                    () -> selected.post(endpoint, BODY, DIGEST, "synthetic-token"));
            long elapsed = System.nanoTime() - started;
            assertEquals(GatewayFailure.Code.UPSTREAM_FAILURE, rejected.code());
            assertTrue(rejected.mayHaveSent());
            assertTrue(hostile.finished.await(2, TimeUnit.SECONDS));
            assertNull(hostile.failure.get());
            if (phase == SlowProgressFixture.Phase.TLS) {
                assertTrue(hostile.clientHelloObserved.get());
            } else {
                assertArrayEquals(BODY, hostile.completePost.get());
            }
            assertTrue(hostile.progressBytes.get() > 10);
            System.out
                    .println("F04_AGGREGATE_DRIP phase=" + phase + " progressBytes=" + hostile.progressBytes.get()
                            + " elapsedMillis=" + TimeUnit.NANOSECONDS.toMillis(elapsed) + " peerClosed="
                            + hostile.clientClosed.get() + " fixtureLimit=" + hostile.fixtureLimitReached.get());
            assertFalse(hostile.fixtureLimitReached.get(), "fixture deadline, not operation cancellation, ended I/O");
            assertTrue(hostile.clientClosed.get(), "independent peer did not observe EOF/reset");
            assertTrue(elapsed < TimeUnit.SECONDS.toNanos(7),
                    "controlled scheduled lab bound, not a universal theorem");
        }
    }
}
