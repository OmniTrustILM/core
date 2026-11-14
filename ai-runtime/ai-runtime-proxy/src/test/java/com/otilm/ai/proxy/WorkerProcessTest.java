package com.otilm.ai.proxy;

import java.io.InputStream;
import java.io.OutputStream;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicReference;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;
import org.junit.jupiter.api.io.TempDir;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

@Timeout(12)
class WorkerProcessTest {
    @TempDir
    Path directory;

    @Test
    void acceptsOnlyACompleteCorrelatedReplyAndActualNormalWorkerExit() throws Exception {
        try (var fixture = new LocalTlsFixture(directory); var worker = new WorkerProcess(fixture.configuration())) {
            var result = worker.execute(WireBodies.bootstrap(), System.nanoTime());
            assertEquals(ProxyReply.Outcome.UPSTREAM_REPLY, result.reply().outcome());
            assertEquals(WireBodies.CALL, result.reply().correlationId());
            assertTrue(result.healthy());
            assertTrue(worker.healthy());
            assertEquals(1, fixture.requests.get());
        }
    }

    @Test
    void anExpiredAcceptanceBudgetStartsNoWorker() throws Exception {
        try (var fixture = new LocalTlsFixture(directory)) {
            AtomicReference<Process> started = new AtomicReference<>();
            try (var worker = new WorkerProcess(fixture.configuration(), (command, environment) -> {
                Process child = child(Hang.class.getName());
                started.set(child);
                return child;
            })) {
                var result = worker.execute(WireBodies.bootstrap(), System.nanoTime() - TimeUnit.SECONDS.toNanos(6));
                assertEquals(ProxyReply.Outcome.NOT_SENT, result.reply().outcome());
                assertEquals(null, started.get());
            }
        }
    }

    @Test
    void killsReapsAndClosesPipesForAHangingActualChild() throws Exception {
        try (var fixture = new LocalTlsFixture(directory)) {
            AtomicReference<Process> owned = new AtomicReference<>();
            try (var worker = new WorkerProcess(fixture.configuration(), (command, environment) -> {
                Process process = child(Hang.class.getName());
                owned.set(process);
                return process;
            })) {
                long accepted = System.nanoTime() - TimeUnit.SECONDS.toNanos(4);
                var result = worker.execute(WireBodies.bootstrap(), accepted);
                assertEquals(ProxyReply.Outcome.UNKNOWN, result.reply().outcome());
                assertTrue(result.healthy());
                assertNotNull(owned.get());
                assertFalse(owned.get().isAlive());
                assertTrue(owned.get().waitFor(1, TimeUnit.SECONDS));
            } finally {
                if (owned.get() != null) {
                    owned.get().destroyForcibly();
                    owned.get().waitFor();
                }
            }
        }
    }

    @Test
    void fixedLaunchCommandHasNoAmbientJvmOrProxyEnvironment() throws Exception {
        try (var fixture = new LocalTlsFixture(directory)) {
            AtomicReference<List<String>> captured = new AtomicReference<>();
            try (var worker = new WorkerProcess(fixture.configuration(), (command, environment) -> {
                captured.set(List.copyOf(command));
                assertEquals(Map.of(), environment);
                return child(Crash.class.getName());
            })) {
                assertEquals(ProxyReply.Outcome.UNKNOWN,
                        worker.execute(WireBodies.bootstrap(), System.nanoTime()).reply().outcome());
                var command = captured.get();
                assertNotNull(command);
                assertEquals(Path.of(System.getProperty("java.home"), "bin/java").toString(), command.getFirst());
                assertTrue(command.contains("-XX:-UsePerfData"));
                assertTrue(command.contains("-XX:+DisableAttachMechanism"));
                assertTrue(command.contains("-XX:-CreateCoredumpOnCrash"));
                assertTrue(command.contains("-XX:-HeapDumpOnOutOfMemoryError"));
                assertTrue(command.contains("-XX:-FlightRecorder"));
                assertTrue(command.contains("-XX:ErrorFile=/dev/null"));
                assertTrue(command.contains("-XX:+DisplayVMOutputToStderr"));
                int entry = command.indexOf(WorkerMain.class.getName());
                assertEquals(command.size() - 6, entry);
                assertEquals(fixture.configuration().coreOrigin().toString(), command.get(entry + 1));
            }
        }
    }

    @ParameterizedTest
    @ValueSource(strings = {"valid", "wrong-id", "extra", "malformed", "nonzero", "empty", "close-then-hang", "drip"})
    void aCompleteReplyNeverReplacesActualOwnedProcessExitAndCleanup(String mode) throws Exception {
        try (var fixture = new LocalTlsFixture(directory)) {
            AtomicReference<Process> owned = new AtomicReference<>();
            try (var worker = new WorkerProcess(fixture.configuration(), (command, environment) -> {
                Process child = child(ReplyChild.class.getName(), mode);
                owned.set(child);
                return child;
            })) {
                long accepted = System.nanoTime()
                        - (mode.equals("close-then-hang") || mode.equals("drip") ? TimeUnit.SECONDS.toNanos(4) : 0);
                var result = worker.execute(WireBodies.bootstrap(), accepted);
                assertEquals(mode.equals("valid") ? ProxyReply.Outcome.UPSTREAM_REPLY : ProxyReply.Outcome.UNKNOWN,
                        result.reply().outcome());
                assertTrue(result.healthy());
                assertNotNull(owned.get());
                assertFalse(owned.get().isAlive());
                assertTrue(owned.get().waitFor(1, TimeUnit.SECONDS));
            } finally {
                if (owned.get() != null) {
                    owned.get().destroyForcibly();
                    owned.get().waitFor();
                }
            }
        }
    }

    @Test
    void anUnreapableSourceGradeOsFailureLatchesTheOwnerUnhealthy() throws Exception {
        try (var fixture = new LocalTlsFixture(directory)) {
            var frame = new java.io.ByteArrayOutputStream();
            FrameCodec
                    .writeReply(frame, new ProxyReply(ProxyReply.Outcome.UPSTREAM_REPLY, WireBodies.CALL, 200,
                            WireBodies.PENDING));
            var failed = new Unreapable(frame.toByteArray());
            try (var worker = new WorkerProcess(fixture.configuration(), (command, environment) -> failed)) {
                var result = worker.execute(WireBodies.bootstrap(), System.nanoTime());
                assertEquals(ProxyReply.Outcome.UNKNOWN, result.reply().outcome());
                assertFalse(result.healthy());
                assertFalse(worker.healthy());
                assertTrue(failed.killed);
                assertTrue(failed.inputClosed);
                assertTrue(failed.outputClosed);
                assertTrue(failed.errorClosed);
            }
        }
    }

    @Test
    void failedWatchdogSetupDeniesAChildAndLatchesUnhealthy() throws Exception {
        try (var fixture = new LocalTlsFixture(directory)) {
            var starts = new java.util.concurrent.atomic.AtomicInteger();
            var shutdown = java.util.concurrent.Executors.newSingleThreadScheduledExecutor();
            shutdown.shutdown();
            try (var worker = new WorkerProcess(fixture.configuration(), (command, environment) -> {
                starts.incrementAndGet();
                throw new AssertionError("watchdog failure must prevent launch");
            }, () -> shutdown)) {
                var result = worker.execute(WireBodies.bootstrap(), System.nanoTime());
                assertFalse(result.healthy());
                assertFalse(worker.healthy());
                assertEquals(0, starts.get());
            }
        }
    }

    @Test
    void aFailedTerminationCannotReturnAHealthyPrelaunchReply() throws Exception {
        try (var fixture = new LocalTlsFixture(directory)) {
            var starts = new java.util.concurrent.atomic.AtomicInteger();
            var entered = new java.util.concurrent.CountDownLatch(1);
            var release = new java.util.concurrent.CountDownLatch(1);
            var scheduler = new java.util.concurrent.ScheduledThreadPoolExecutor(1,
                    Thread.ofPlatform().daemon().factory()) {
                @Override
                public java.util.concurrent.ScheduledFuture<?> schedule(Runnable action, long delay, TimeUnit unit) {
                    entered.countDown();
                    try {
                        release.await(2, TimeUnit.SECONDS);
                    } catch (InterruptedException interrupted) {
                        Thread.currentThread().interrupt();
                    }
                    return super.schedule(action, delay, unit);
                }

                @Override
                public boolean awaitTermination(long timeout, TimeUnit unit) {
                    return false;
                }
            };
            try (var worker = new WorkerProcess(fixture.configuration(), (command, environment) -> {
                starts.incrementAndGet();
                throw new AssertionError("aborted before launch");
            }, () -> scheduler)) {
                var result = java.util.concurrent.CompletableFuture
                        .supplyAsync(() -> worker.execute(WireBodies.bootstrap(), System.nanoTime()));
                assertTrue(entered.await(2, TimeUnit.SECONDS));
                worker.abort();
                release.countDown();
                assertFalse(result.get(3, TimeUnit.SECONDS).healthy());
                assertFalse(worker.healthy());
                assertEquals(0, starts.get());
            } finally {
                release.countDown();
                scheduler.shutdownNow();
            }
        }
    }

    @Test
    void blockedPipeCleanupBecomesUnhealthyWithoutPretendingTheOwnerHasFinished() throws Exception {
        try (var fixture = new LocalTlsFixture(directory)) {
            var entered = new java.util.concurrent.CountDownLatch(1);
            var release = new java.util.concurrent.CountDownLatch(1);
            Process blocked = new Process() {
                volatile boolean alive = true;
                final OutputStream output = new java.io.ByteArrayOutputStream() {
                    @Override
                    public void close() {
                        entered.countDown();
                        while (release.getCount() != 0) {
                            try {
                                release.await();
                            } catch (InterruptedException ignored) {
                            }
                        }
                    }
                };
                final InputStream input = new java.io.ByteArrayInputStream(new byte[0]);

                @Override
                public OutputStream getOutputStream() {
                    return output;
                }

                @Override
                public InputStream getInputStream() {
                    return input;
                }

                @Override
                public InputStream getErrorStream() {
                    return InputStream.nullInputStream();
                }

                @Override
                public boolean isAlive() {
                    return alive;
                }

                @Override
                public int waitFor() {
                    return 0;
                }

                @Override
                public boolean waitFor(long timeout, TimeUnit unit) {
                    return !alive;
                }

                @Override
                public int exitValue() {
                    return 0;
                }

                @Override
                public void destroy() {
                    alive = false;
                }

                @Override
                public Process destroyForcibly() {
                    alive = false;
                    return this;
                }
            };
            try (var worker = new WorkerProcess(fixture.configuration(), (command, environment) -> blocked)) {
                var result = java.util.concurrent.CompletableFuture
                        .supplyAsync(() -> worker
                                .execute(WireBodies.bootstrap(), System.nanoTime() - TimeUnit.SECONDS.toNanos(4)));
                try {
                    assertTrue(entered.await(2, TimeUnit.SECONDS));
                    long until = System.nanoTime() + TimeUnit.SECONDS.toNanos(4);
                    while (worker.healthy() && System.nanoTime() < until) {
                        java.util.concurrent.locks.LockSupport.parkNanos(TimeUnit.MILLISECONDS.toNanos(10));
                    }
                    assertFalse(worker.healthy());
                    assertFalse(result.isDone());
                } finally {
                    release.countDown();
                }
                assertFalse(result.get(2, TimeUnit.SECONDS).healthy());
            } finally {
                release.countDown();
            }
        }
    }

    @Test
    void abortBeforeLaunchAndRepeatedExecutionNeverStartAnotherChild() throws Exception {
        try (var fixture = new LocalTlsFixture(directory)) {
            var starts = new java.util.concurrent.atomic.AtomicInteger();
            try (var worker = new WorkerProcess(fixture.configuration(), (command, environment) -> {
                starts.incrementAndGet();
                return child(Crash.class.getName());
            })) {
                worker.abort();
                assertEquals(ProxyReply.Outcome.NOT_SENT,
                        worker.execute(WireBodies.bootstrap(), System.nanoTime()).reply().outcome());
                assertEquals(0, starts.get());
                assertEquals(ProxyReply.Outcome.UNKNOWN,
                        worker.execute(WireBodies.bootstrap(), System.nanoTime()).reply().outcome());
                assertFalse(worker.healthy());
                assertEquals(0, starts.get());
            }
        }
    }

    @Test
    void anUncertainLaunchFailurePoisonsSupervisionWithoutExposingItsCause() throws Exception {
        try (var fixture = new LocalTlsFixture(directory);
                var worker = new WorkerProcess(fixture.configuration(), (command, environment) -> {
                    throw new java.io.IOException("PRIVATE_LAUNCH_CANARY");
                })) {
            var result = worker.execute(WireBodies.bootstrap(), System.nanoTime());
            assertEquals(ProxyReply.Outcome.UNKNOWN, result.reply().outcome());
            assertFalse(result.healthy());
            assertFalse(worker.healthy());
            assertEquals(0, result.reply().payload().length);
        }
    }

    @Test
    void anErrorClosingOnePipeStillClosesAllOtherPipesAndAcknowledgesFailure() throws Exception {
        try (var fixture = new LocalTlsFixture(directory)) {
            var owned = new Unreapable(new byte[0]) {
                @Override
                public OutputStream getOutputStream() {
                    return new java.io.ByteArrayOutputStream() {
                        @Override
                        public void close() {
                            outputClosed = true;
                            throw new AssertionError("PRIVATE_PIPE_CANARY");
                        }
                    };
                }
            };
            try (var worker = new WorkerProcess(fixture.configuration(), (command, environment) -> owned)) {
                var result = org.junit.jupiter.api.Assertions
                        .assertDoesNotThrow(() -> worker.execute(WireBodies.bootstrap(), System.nanoTime()));
                assertFalse(result.healthy());
                assertTrue(owned.killed);
                assertTrue(owned.outputClosed);
                assertTrue(owned.inputClosed);
                assertTrue(owned.errorClosed);
            }
        }
    }

    @Test
    void concurrentAbortCannotAcknowledgeWhileAnotherCloserStillOwnsThePipe() throws Exception {
        try (var fixture = new LocalTlsFixture(directory)) {
            var atClose = new java.util.concurrent.CountDownLatch(1);
            var closing = new java.util.concurrent.CountDownLatch(1);
            var release = new java.util.concurrent.CountDownLatch(1);
            var frame = new java.io.ByteArrayOutputStream();
            FrameCodec
                    .writeReply(frame, new ProxyReply(ProxyReply.Outcome.UNKNOWN,
                            WireBodies.bootstrap().correlationId(), 0, new byte[0]));
            var gets = new java.util.concurrent.atomic.AtomicInteger();
            Process owned = new Unreapable(frame.toByteArray()) {
                final OutputStream pipe = new java.io.FilterOutputStream(new java.io.ByteArrayOutputStream()) {
                    @Override
                    public void close() throws java.io.IOException {
                        super.close();
                    }

                    @Override
                    public void flush() {
                        if (gets.get() >= 3) {
                            closing.countDown();
                            try {
                                release.await();
                            } catch (InterruptedException interrupted) {
                                throw new AssertionError(interrupted);
                            }
                        }
                    }
                };

                @Override
                public OutputStream getOutputStream() {
                    if (gets.incrementAndGet() == 2) {
                        atClose.countDown();
                        try {
                            closing.await();
                        } catch (InterruptedException interrupted) {
                            throw new AssertionError(interrupted);
                        }
                    }
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
            try (var worker = new WorkerProcess(fixture.configuration(), (command, environment) -> owned)) {
                var result = java.util.concurrent.CompletableFuture
                        .supplyAsync(() -> worker.execute(WireBodies.bootstrap(), System.nanoTime()));
                assertTrue(atClose.await(1, TimeUnit.SECONDS));
                Thread aborter = Thread.ofPlatform().start(worker::abort);
                try {
                    assertTrue(closing.await(1, TimeUnit.SECONDS));
                    Thread.sleep(100);
                    assertFalse(result.isDone(), "a second close is not the first closer's acknowledgment");
                } finally {
                    release.countDown();
                    aborter.join(1000);
                }
                assertEquals(ProxyReply.Outcome.UNKNOWN, result.get(2, TimeUnit.SECONDS).reply().outcome());
            } finally {
                release.countDown();
            }
        }
    }

    static class Unreapable extends Process {
        boolean killed;
        boolean inputClosed;
        boolean outputClosed;
        boolean errorClosed;
        private final OutputStream output = new java.io.ByteArrayOutputStream() {
            @Override
            public void close() {
                outputClosed = true;
            }
        };
        private final InputStream error = new java.io.ByteArrayInputStream(new byte[0]) {
            @Override
            public void close() {
                errorClosed = true;
            }
        };
        private final InputStream input;

        Unreapable(byte[] bytes) {
            input = new java.io.ByteArrayInputStream(bytes) {
                @Override
                public void close() {
                    inputClosed = true;
                }
            };
        }

        @Override
        public OutputStream getOutputStream() {
            return output;
        }

        @Override
        public InputStream getInputStream() {
            return input;
        }

        @Override
        public InputStream getErrorStream() {
            return error;
        }

        @Override
        public boolean isAlive() {
            return true;
        }

        @Override
        public int waitFor() {
            return 1;
        }

        @Override
        public boolean waitFor(long timeout, TimeUnit unit) {
            return false;
        }

        @Override
        public int exitValue() {
            throw new IllegalThreadStateException();
        }

        @Override
        public void destroy() {
            killed = true;
        }

        @Override
        public Process destroyForcibly() {
            killed = true;
            return this;
        }
    }

    public static final class ReplyChild {
        public static void main(String[] arguments) throws Exception {
            ProxyRequest request = FrameCodec.readRequest(System.in);
            String mode = arguments[0];
            if (mode.equals("empty")) {
                return;
            }
            if (mode.equals("malformed")) {
                System.out.write(new byte[]{1, 2, 3});
                return;
            }
            var frame = new java.io.ByteArrayOutputStream();
            FrameCodec
                    .writeReply(frame,
                            new ProxyReply(ProxyReply.Outcome.UPSTREAM_REPLY,
                                    mode.equals("wrong-id") ? java.util.UUID.randomUUID() : request.correlationId(),
                                    200, WireBodies.PENDING));
            if (mode.equals("drip")) {
                for (byte value : frame.toByteArray()) {
                    System.out.write(value);
                    System.out.flush();
                    Thread.sleep(100);
                }
                return;
            }
            System.out.write(frame.toByteArray());
            if (mode.equals("extra")) {
                System.out.write(0);
            }
            System.out.flush();
            if (mode.equals("close-then-hang")) {
                System.out.close();
                new java.util.concurrent.CountDownLatch(1).await();
            }
            if (mode.equals("nonzero")) {
                Runtime.getRuntime().halt(3);
            }
        }
    }

    private static Process child(String main, String... arguments) throws java.io.IOException {
        var command = new ArrayList<String>(List
                .of(Path.of(System.getProperty("java.home"), "bin/java").toString(), "-cp",
                        System.getProperty("java.class.path"), main));
        command.addAll(List.of(arguments));
        return new ProcessBuilder(command).redirectError(ProcessBuilder.Redirect.DISCARD).start();
    }

    public static final class Hang {
        public static void main(String[] arguments) throws Exception {
            new java.util.concurrent.CountDownLatch(1).await();
        }
    }

    public static final class Crash {
        public static void main(String[] arguments) {
            Runtime.getRuntime().halt(3);
        }
    }
}
