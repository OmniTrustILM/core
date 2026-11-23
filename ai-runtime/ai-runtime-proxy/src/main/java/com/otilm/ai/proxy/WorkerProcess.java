package com.otilm.ai.proxy;

import java.io.Closeable;
import java.io.IOException;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicLong;

/** Owns exactly one fixed worker. A result never substitutes for actual process and watchdog cleanup. */
public final class WorkerProcess implements AutoCloseable {
    static final long CLEANUP_NANOS = TimeUnit.SECONDS.toNanos(2);

    @FunctionalInterface
    interface Launcher {
        Process start(List<String> command, Map<String, String> environment) throws IOException;
    }

    public record Result(ProxyReply reply, boolean healthy) {
    }

    private final ProxyConfiguration configuration;
    private final Launcher launcher;
    private final java.util.function.Supplier<ScheduledExecutorService> supervisors;
    private final AtomicBoolean begun = new AtomicBoolean();
    private final AtomicBoolean aborted = new AtomicBoolean();
    private final AtomicBoolean healthy = new AtomicBoolean(true);
    private final AtomicLong cleanupStarted = new AtomicLong();
    private final CountDownLatch completed = new CountDownLatch(1);
    private final Object cleanupLock = new Object();
    private volatile Process process;
    private Process stoppedProcess;
    private volatile ScheduledExecutorService monitor;
    private volatile Runnable failureSignal = () -> {
    };

    public WorkerProcess(ProxyConfiguration configuration) {
        this(configuration, (command, environment) -> {
            var builder = new ProcessBuilder(command).redirectError(ProcessBuilder.Redirect.DISCARD);
            builder.environment().clear();
            builder.environment().putAll(environment);
            return builder.start();
        });
    }

    WorkerProcess(ProxyConfiguration configuration, Launcher launcher) {
        this(configuration, launcher, () -> Executors
                .newScheduledThreadPool(2, Thread.ofPlatform().daemon().name("worker-owner-cutoff").factory()));
    }

    WorkerProcess(ProxyConfiguration configuration, Launcher launcher,
            java.util.function.Supplier<ScheduledExecutorService> supervisors) {
        this.supervisors = Objects.requireNonNull(supervisors);
        this.configuration = Objects.requireNonNull(configuration);
        this.launcher = Objects.requireNonNull(launcher);
    }

    public Result execute(ProxyRequest request, long acceptedAt) {
        if (!begun.compareAndSet(false, true)) {
            fail();
            return result(request, ProxyReply.Outcome.UNKNOWN);
        }
        ScheduledExecutorService watchdog = null;
        ProxyReply reply = null;
        boolean attempted = false;
        boolean supervisionAttempted = false;
        boolean supervised = false;
        try {
            if (!aborted.get() && remaining(acceptedAt) > 0) {
                supervisionAttempted = true;
                watchdog = supervisors.get();
                monitor = watchdog;
                watchdog.schedule(this::abort, Math.max(0, remaining(acceptedAt)), TimeUnit.NANOSECONDS);
                supervised = true;
                if (!aborted.get() && remaining(acceptedAt) > 0) {
                    attempted = true;
                    process = launcher.start(command(), Map.of());
                    reply = readStartedWorkerReply(request, acceptedAt);
                }
            }
        } catch (Throwable ambiguous) {
            recordExecutionFailure(ambiguous, supervisionAttempted, supervised, attempted);
        } finally {
            finishExecution(watchdog);
        }
        if (reply != null && healthy.get() && !aborted.get() && remaining(acceptedAt) > 0) {
            return new Result(reply, true);
        }
        return result(request, attempted ? ProxyReply.Outcome.UNKNOWN : ProxyReply.Outcome.NOT_SENT);
    }

    private void recordExecutionFailure(Throwable ambiguous, boolean supervisionAttempted, boolean supervised,
            boolean attempted) {
        if (ambiguous instanceof InterruptedException) {
            Thread.currentThread().interrupt();
        }
        if (ambiguous instanceof Error || (supervisionAttempted && !supervised) || (attempted && process == null)) {
            fail();
        }
        // A started or uncertain start is never evidence of NOT_SENT and is never retried.
    }

    private ProxyReply readStartedWorkerReply(ProxyRequest request, long acceptedAt)
            throws IOException, InterruptedException {
        if (aborted.get() || remaining(acceptedAt) <= 0) {
            abort();
            return null;
        }
        FrameCodec.writeRequest(process.getOutputStream(), request);
        process.getOutputStream().close();
        ProxyReply candidate = FrameCodec.readReply(process.getInputStream());
        long available = remaining(acceptedAt);
        if (available > 0 && process.waitFor(available, TimeUnit.NANOSECONDS) && process.exitValue() == 0
                && request.correlationId().equals(candidate.correlationId()) && !aborted.get()
                && remaining(acceptedAt) > 0) {
            return candidate;
        }
        return null;
    }

    private void finishExecution(ScheduledExecutorService watchdog) {
        synchronized (cleanupLock) {
            beginCleanup();
            stopProcess();
        }
        awaitOwnedExit();
        stopSupervisor(watchdog);
        synchronized (cleanupLock) {
            if (cleanupRemaining() < 0) {
                fail();
            }
            completed.countDown();
        }
    }

    private void awaitOwnedExit() {
        Process owned = process;
        if (owned != null) {
            try {
                if (!owned.waitFor(Math.max(0, cleanupRemaining()), TimeUnit.NANOSECONDS)) {
                    fail();
                }
            } catch (Throwable uncertainReap) {
                fail();
                if (uncertainReap instanceof InterruptedException) {
                    Thread.currentThread().interrupt();
                }
            }
        }
    }

    private void stopSupervisor(ScheduledExecutorService watchdog) {
        if (watchdog != null) {
            try {
                watchdog.shutdownNow();
                if (!watchdog.awaitTermination(Math.max(0, cleanupRemaining()), TimeUnit.NANOSECONDS)) {
                    fail();
                }
            } catch (Throwable interrupted) {
                fail();
                if (interrupted instanceof InterruptedException) {
                    Thread.currentThread().interrupt();
                }
            }
        }
    }

    public void abort() {
        synchronized (cleanupLock) {
            if (completed.getCount() == 0) {
                return;
            }
            aborted.set(true);
            beginCleanup();
            stopProcess();
        }
    }

    private void stopProcess() {
        Process owned = process;
        if (owned == null || owned == stoppedProcess) {
            return;
        }
        try {
            if (owned.isAlive()) {
                owned.destroyForcibly();
            }
        } catch (Throwable uncertainKill) {
            fail();
        }
        closePipe(owned::getOutputStream);
        closePipe(owned::getInputStream);
        closePipe(owned::getErrorStream);
        stoppedProcess = owned;
    }

    private void closePipe(java.util.function.Supplier<? extends Closeable> pipe) {
        try {
            pipe.get().close();
        } catch (Throwable uncertainClosure) {
            fail();
        }
    }

    private List<String> command() {
        Path javaExecutable = Path.of(System.getProperty("java.home"), "bin/java");
        String classpath = System.getProperty("java.class.path");
        if (!javaExecutable.isAbsolute() || classpath == null || classpath.isEmpty()) {
            throw new IllegalStateException("WORKER_PROFILE");
        }
        classpath = java.util.Arrays
                .stream(classpath.split(java.io.File.pathSeparator, -1))
                .map(entry -> Path.of(entry.isEmpty() ? "." : entry).toAbsolutePath().normalize().toString())
                .collect(java.util.stream.Collectors.joining(java.io.File.pathSeparator));
        var command = new ArrayList<String>(List
                .of(javaExecutable.toString(), "-XX:-UsePerfData", "-XX:+DisableAttachMechanism",
                        "-XX:-CreateCoredumpOnCrash", "-XX:-HeapDumpOnOutOfMemoryError", "-XX:ErrorFile=/dev/null",
                        "-XX:-FlightRecorder", "-XX:+DisplayVMOutputToStderr", "-Xms16m", "-Xmx64m",
                        "-XX:MaxMetaspaceSize=64m", "-Xss512k", "-XX:MaxDirectMemorySize=8m",
                        "-XX:ReservedCodeCacheSize=32m", "-cp", classpath, WorkerMain.class.getName(),
                        configuration.coreOrigin().toString(), configuration.coreAddress().getHostAddress(),
                        configuration.certificateFile().toString(), configuration.privateKeyFile().toString(),
                        configuration.serverCaFile().toString()));
        return List.copyOf(command);
    }

    private void beginCleanup() {
        if (cleanupStarted.compareAndSet(0, System.nanoTime())) {
            ScheduledExecutorService current = monitor;
            try {
                if (current != null && !current.isShutdown()) {
                    current.schedule(this::fail, CLEANUP_NANOS, TimeUnit.NANOSECONDS);
                }
            } catch (Throwable unavailableAudit) {
                fail();
            }
        }
    }

    void onUnhealthy(Runnable signal) {
        failureSignal = Objects.requireNonNull(signal);
        if (!healthy.get()) {
            fail();
        }
    }

    private void fail() {
        healthy.set(false);
        try {
            failureSignal.run();
        } catch (Throwable unavailableSignal) {
            // Ownership remains unhealthy even when the metadata signal itself is unavailable.
        }
    }

    private long cleanupRemaining() {
        return CLEANUP_NANOS - (System.nanoTime() - cleanupStarted.get());
    }

    private static long remaining(long acceptedAt) {
        return CoreRpcClient.BUDGET_NANOS - (System.nanoTime() - acceptedAt);
    }

    private Result result(ProxyRequest request, ProxyReply.Outcome outcome) {
        return new Result(new ProxyReply(outcome, request.correlationId(), 0, new byte[0]), healthy.get());
    }

    public boolean healthy() {
        return healthy.get();
    }

    @Override
    public void close() {
        abort();
        if (begun.get()) {
            try {
                if (!completed.await(CLEANUP_NANOS, TimeUnit.NANOSECONDS)) {
                    fail();
                }
            } catch (InterruptedException interrupted) {
                fail();
                Thread.currentThread().interrupt();
            }
        }
    }
}
