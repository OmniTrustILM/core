package com.otilm.ai.proxy;

import java.io.OutputStream;
import java.nio.file.Path;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;
import org.junit.jupiter.api.io.TempDir;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

@Timeout(8)
class WorkerLateCleanupTest {
    @TempDir
    Path identity;

    @Test
    void aLateAbortCannotBeginAnotherBlockingCloseAfterWatchdogTermination() throws Exception {
        var stopped = new CountDownLatch(1);
        var ownerMayFinish = new CountDownLatch(1);
        var releaseClose = new CountDownLatch(1);
        var abortFinished = new CountDownLatch(1);
        var closes = new java.util.concurrent.atomic.AtomicInteger();
        try (var fixture = new LocalTlsFixture(identity)) {
            var frame = new java.io.ByteArrayOutputStream();
            FrameCodec.writeReply(frame, new ProxyReply(ProxyReply.Outcome.UNKNOWN, WireBodies.CALL, 0, new byte[0]));
            Process owned = new WorkerProcessTest.Unreapable(frame.toByteArray()) {
                final OutputStream pipe = new java.io.ByteArrayOutputStream() {
                    @Override
                    public void close() {
                        if (closes.incrementAndGet() >= 3) {
                            try {
                                releaseClose.await();
                            } catch (InterruptedException interrupted) {
                                throw new AssertionError(interrupted);
                            }
                        }
                    }
                };

                @Override
                public OutputStream getOutputStream() {
                    return pipe;
                }

                @Override
                public boolean isAlive() {
                    return false;
                }

                @Override
                public boolean waitFor(long timeout, TimeUnit unit) {
                    return true;
                }

                @Override
                public int exitValue() {
                    return 0;
                }
            };
            var scheduler = new java.util.concurrent.ScheduledThreadPoolExecutor(2,
                    Thread.ofPlatform().daemon().factory()) {
                @Override
                public boolean awaitTermination(long timeout, TimeUnit unit) throws InterruptedException {
                    boolean terminated = super.awaitTermination(timeout, unit);
                    stopped.countDown();
                    ownerMayFinish.await();
                    return terminated;
                }
            };
            try (var worker = new WorkerProcess(fixture.configuration(), (command, environment) -> owned,
                    () -> scheduler)) {
                var result = java.util.concurrent.CompletableFuture
                        .supplyAsync(() -> worker.execute(WireBodies.bootstrap(), System.nanoTime()));
                assertTrue(stopped.await(1, TimeUnit.SECONDS));
                Thread aborter = Thread.ofPlatform().start(() -> {
                    worker.abort();
                    abortFinished.countDown();
                });
                try {
                    assertTrue(abortFinished.await(200, TimeUnit.MILLISECONDS),
                            "a stopped Process must not start another blocking pipe close");
                    assertEquals(2, closes.get());
                } finally {
                    releaseClose.countDown();
                    ownerMayFinish.countDown();
                    aborter.join(1000);
                }
                assertEquals(ProxyReply.Outcome.UNKNOWN, result.get(2, TimeUnit.SECONDS).reply().outcome());
            } finally {
                releaseClose.countDown();
                ownerMayFinish.countDown();
                scheduler.shutdownNow();
            }
        }
    }
}
