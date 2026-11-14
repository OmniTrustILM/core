package com.otilm.ai.proxy;

import java.io.IOException;
import java.net.StandardProtocolFamily;
import java.net.UnixDomainSocketAddress;
import java.nio.channels.Channels;
import java.nio.channels.ServerSocketChannel;
import java.nio.channels.SocketChannel;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.Path;
import java.nio.file.attribute.BasicFileAttributes;
import java.nio.file.attribute.PosixFileAttributeView;
import java.nio.file.attribute.PosixFilePermissions;
import java.util.Objects;
import java.util.UUID;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicLong;
import java.util.concurrent.atomic.AtomicReference;

/** One bounded pathname-socket operation at a time; native peer, mount and PID1 proofs remain required. */
public final class ProxyServer implements AutoCloseable {
    private static final System.Logger LOG = System.getLogger(ProxyServer.class.getName());
    private static final long INPUT_NANOS = TimeUnit.SECONDS.toNanos(1);

    @FunctionalInterface
    interface Workers {
        WorkerProcess create();
    }

    private final Path socket;
    private final Object socketKey;
    private final PeerPolicy policy;
    private final Workers workers;
    private final java.util.function.Supplier<ScheduledExecutorService> timers;
    private final java.util.function.Consumer<Thread> starter;
    private final ServerSocketChannel listener;
    private final AtomicBoolean closed = new AtomicBoolean();
    private final java.util.concurrent.CountDownLatch closeFinished = new java.util.concurrent.CountDownLatch(1);
    private final AtomicLong closeStarted = new AtomicLong();
    private final AtomicBoolean healthy = new AtomicBoolean(true);
    private final AtomicReference<Operation> active = new AtomicReference<>();
    private final Object admission = new Object();

    public ProxyServer(Path socket, ProxyConfiguration configuration) throws IOException {
        this(socket, configuration, PeerPolicy.fixedRunner(), () -> new WorkerProcess(configuration));
    }

    ProxyServer(Path socket, ProxyConfiguration configuration, PeerPolicy policy, Workers workers) throws IOException {
        this(socket, configuration, policy, workers,
                () -> Executors.newScheduledThreadPool(2, Thread.ofPlatform().daemon().name("proxy-cutoff").factory()));
    }

    ProxyServer(Path socket, ProxyConfiguration configuration, PeerPolicy policy, Workers workers,
            java.util.function.Supplier<ScheduledExecutorService> timers) throws IOException {
        this(socket, configuration, policy, workers, timers, Thread::start);
    }

    ProxyServer(Path socket, ProxyConfiguration configuration, PeerPolicy policy, Workers workers,
            java.util.function.Supplier<ScheduledExecutorService> timers, java.util.function.Consumer<Thread> starter)
            throws IOException {
        this.starter = Objects.requireNonNull(starter);
        this.timers = Objects.requireNonNull(timers);
        Objects.requireNonNull(configuration);
        this.socket = Objects.requireNonNull(socket).normalize();
        this.policy = Objects.requireNonNull(policy);
        this.workers = Objects.requireNonNull(workers);
        Path directory = this.socket.getParent();
        try {
            if (!this.socket.isAbsolute() || directory == null || !directory.toRealPath().equals(directory)
                    || !Files.isDirectory(directory, LinkOption.NOFOLLOW_LINKS)
                    || Files.exists(this.socket, LinkOption.NOFOLLOW_LINKS)) {
                throw new IOException("SOCKET_PROFILE");
            }
            var owner = directory
                    .getFileSystem()
                    .getUserPrincipalLookupService()
                    .lookupPrincipalByName(System.getProperty("user.name"));
            try (var entries = Files.list(directory)) {
                if (!Files.getOwner(directory, LinkOption.NOFOLLOW_LINKS).equals(owner)
                        || entries.findAny().isPresent()) {
                    throw new IOException("SOCKET_PROFILE");
                }
            }
            var attributes = Files
                    .getFileAttributeView(directory, PosixFileAttributeView.class, LinkOption.NOFOLLOW_LINKS);
            attributes.setGroup(policy.socketGroup());
            attributes.setPermissions(PosixFilePermissions.fromString("rwx--x---"));
        } catch (IOException | RuntimeException unavailable) {
            throw new IOException("SOCKET_PROFILE");
        }
        listener = ServerSocketChannel.open(StandardProtocolFamily.UNIX);
        Object boundKey = null;
        try {
            listener.bind(UnixDomainSocketAddress.of(this.socket), 8);
            boundKey = Files
                    .readAttributes(this.socket, BasicFileAttributes.class, LinkOption.NOFOLLOW_LINKS)
                    .fileKey();
            if (boundKey == null) {
                throw new IOException("SOCKET_PROFILE");
            }
            var attributes = Files
                    .getFileAttributeView(this.socket, PosixFileAttributeView.class, LinkOption.NOFOLLOW_LINKS);
            attributes.setGroup(policy.socketGroup());
            // NOFOLLOW chmod is unsupported for sockets on some POSIX JDKs. The qualified directory is immutable
            // to the runner; bind owns this inode, and a changed inode fails setup rather than being accepted.
            Files.setPosixFilePermissions(this.socket, PosixFilePermissions.fromString("rw-rw----"));
            if (!boundKey
                    .equals(Files
                            .readAttributes(this.socket, BasicFileAttributes.class, LinkOption.NOFOLLOW_LINKS)
                            .fileKey())) {
                throw new IOException("SOCKET_PROFILE");
            }
            socketKey = boundKey;
        } catch (IOException | RuntimeException unavailable) {
            try {
                listener.close();
            } catch (Throwable uncertainClosure) {
            }
            try {
                if (boundKey != null && boundKey
                        .equals(Files
                                .readAttributes(this.socket, BasicFileAttributes.class, LinkOption.NOFOLLOW_LINKS)
                                .fileKey())) {
                    Files.delete(this.socket);
                }
            } catch (Throwable uncertainUnlink) {
            }
            throw new IOException("SOCKET_PROFILE");
        }
    }

    public void serve() throws IOException {
        while (!closed.get()) {
            synchronized (admission) {
                SocketChannel channel;
                try {
                    channel = listener.accept();
                } catch (IOException unavailable) {
                    if (closed.get()) {
                        return;
                    }
                    healthy.set(false);
                    throw new IOException("LISTENER_UNAVAILABLE");
                }
                long acceptedAt = System.nanoTime();
                try {
                    admitAcceptedChannel(channel, acceptedAt);
                } catch (Throwable unavailable) {
                    healthy.set(false);
                    try {
                        channel.close();
                    } catch (Throwable uncertainClosure) {
                    }
                    event("admission", null, "UNHEALTHY", null);
                    throw new IOException("LISTENER_UNAVAILABLE");
                }
            }
        }
    }

    private void admitAcceptedChannel(SocketChannel channel, long acceptedAt) throws IOException {
        if (closed.get() || !healthy.get()) {
            channel.close();
            event("admission", null, "DENIED", null);
            return;
        }
        Operation operation = new Operation(channel, acceptedAt);
        if (!active.compareAndSet(null, operation)) {
            channel.close();
            event("admission", null, "CAPACITY", null);
            return;
        }
        starter.accept(operation.thread);
    }

    public boolean healthy() {
        return healthy.get() && (!closed.get() || closeFinished.getCount() == 0);
    }

    private static void event(String phase, LocalOperation operation, String code, UUID correlation) {
        LOG
                .log("UNHEALTHY".equals(code) ? System.Logger.Level.ERROR : System.Logger.Level.DEBUG,
                        "phase={0} op={1} code={2} correlation={3}", phase, operation == null ? "-" : operation.name(),
                        code, correlation == null ? "-" : correlation);
    }

    private final class Operation implements Runnable {
        private final SocketChannel channel;
        private final long acceptedAt;
        private final AtomicBoolean aborted = new AtomicBoolean();
        private final AtomicLong cleanupAt = new AtomicLong();
        private final Thread thread;
        private volatile WorkerProcess worker;
        private volatile ScheduledExecutorService monitor;
        private volatile LocalOperation operation;
        private volatile UUID correlation;

        Operation(SocketChannel channel, long acceptedAt) {
            this.channel = channel;
            this.acceptedAt = acceptedAt;
            thread = Thread.ofPlatform().daemon().name("proxy-operation").unstarted(this);
        }

        private long remaining() {
            return CoreRpcClient.BUDGET_NANOS - (System.nanoTime() - acceptedAt);
        }

        private long cleanupRemaining() {
            return WorkerProcess.CLEANUP_NANOS - (System.nanoTime() - cleanupAt.get());
        }

        private void cleanupStart() {
            if (cleanupAt.compareAndSet(0, System.nanoTime())) {
                ScheduledExecutorService current = monitor;
                if (current != null && !current.isShutdown()) {
                    try {
                        current.schedule(this::poison, WorkerProcess.CLEANUP_NANOS, TimeUnit.NANOSECONDS);
                    } catch (Throwable unavailableAudit) {
                        poison();
                    }
                }
            }
        }

        private void poison() {
            if (healthy.compareAndSet(true, false)) {
                event("cleanup", operation, "UNHEALTHY", correlation);
            }
        }

        void abort() {
            aborted.set(true);
            cleanupStart();
            try {
                channel.close();
            } catch (Throwable uncertainClosure) {
                healthy.set(false);
            }
            WorkerProcess owned = worker;
            if (owned != null) {
                try {
                    owned.abort();
                } catch (Throwable uncertainAbort) {
                    poison();
                }
            }
        }

        @Override
        public void run() {
            ScheduledExecutorService watchdog = null;
            ProxyRequest request = null;
            boolean supervised = false;
            try {
                watchdog = timers.get();
                monitor = watchdog;
                var inputCutoff = watchdog
                        .schedule(this::abort, Math.max(0, Math.min(INPUT_NANOS, remaining())), TimeUnit.NANOSECONDS);
                watchdog.schedule(this::abort, Math.max(0, remaining()), TimeUnit.NANOSECONDS);
                supervised = true;
                if (!policy.allowed(channel) || aborted.get() || closed.get()) {
                    event("admission", null, "DENIED", null);
                    return;
                }
                request = FrameCodec.readRequest(Channels.newInputStream(channel));
                if (!inputCutoff.cancel(false) || aborted.get() || System.nanoTime() - acceptedAt >= INPUT_NANOS
                        || remaining() <= 0) {
                    return;
                }
                executeSupervisedRequest(request);
            } catch (Throwable unavailable) {
                if (!supervised || unavailable instanceof Error) {
                    poison();
                }
                event("operation", request == null ? null : request.operation(), "UNKNOWN",
                        request == null ? null : request.correlationId());
            } finally {
                finishOperation(watchdog, request);
            }
        }

        private void executeSupervisedRequest(ProxyRequest request) throws IOException {
            operation = request.operation();
            correlation = request.correlationId();
            event("input", operation, "VALID", correlation);
            worker = workers.create();
            worker.onUnhealthy(this::poison);
            if (aborted.get() || remaining() <= 0) {
                worker.abort();
                return;
            }
            WorkerProcess.Result result = worker.execute(request, acceptedAt);
            if (!result.healthy() || !worker.healthy()) {
                healthy.set(false);
            }
            if (!aborted.get() && remaining() > 0) {
                FrameCodec.writeReply(Channels.newOutputStream(channel), result.reply());
                event("reply", request.operation(), result.reply().outcome().name(), request.correlationId());
            }
        }

        private void finishOperation(ScheduledExecutorService watchdog, ProxyRequest request) {
            cleanupStart();
            closeOwnedWorker();
            closeChannel();
            stopWatchdog(watchdog);
            if (cleanupRemaining() < 0) {
                healthy.set(false);
            }
            if (healthy.get()) {
                active.compareAndSet(this, null);
            } else {
                event("cleanup", request == null ? null : request.operation(), "UNHEALTHY",
                        request == null ? null : request.correlationId());
            }
        }

        private void closeOwnedWorker() {
            WorkerProcess owned = worker;
            if (owned != null) {
                try {
                    owned.close();
                    if (!owned.healthy()) {
                        healthy.set(false);
                    }
                } catch (Throwable uncertainClosure) {
                    poison();
                }
            }
        }

        private void closeChannel() {
            try {
                channel.close();
            } catch (Throwable uncertainClosure) {
                healthy.set(false);
            }
        }

        private void stopWatchdog(ScheduledExecutorService watchdog) {
            if (watchdog != null) {
                try {
                    watchdog.shutdownNow();
                    if (!watchdog.awaitTermination(Math.max(0, cleanupRemaining()), TimeUnit.NANOSECONDS)) {
                        healthy.set(false);
                    }
                } catch (Throwable interrupted) {
                    healthy.set(false);
                    if (interrupted instanceof InterruptedException) {
                        Thread.currentThread().interrupt();
                    }
                }
            }
        }
    }

    @Override
    public void close() {
        if (!closed.compareAndSet(false, true)) {
            awaitClose();
            return;
        }
        closeStarted.set(System.nanoTime());
        try {
            try {
                listener.close();
            } catch (Throwable uncertainClosure) {
                healthy.set(false);
            }
            Operation operation;
            synchronized (admission) {
                operation = active.get();
            }
            if (operation != null) {
                try {
                    operation.abort();
                } catch (Throwable uncertainAbort) {
                    healthy.set(false);
                }
                try {
                    operation.thread.join(Math.max(1, TimeUnit.NANOSECONDS.toMillis(closeRemaining())));
                    if (operation.thread.isAlive()) {
                        healthy.set(false);
                    }
                } catch (InterruptedException interrupted) {
                    healthy.set(false);
                    Thread.currentThread().interrupt();
                }
            }
            try {
                Object current = Files
                        .readAttributes(socket, BasicFileAttributes.class, LinkOption.NOFOLLOW_LINKS)
                        .fileKey();
                if (socketKey.equals(current)) {
                    Files.delete(socket);
                } else {
                    healthy.set(false);
                }
            } catch (Throwable uncertainUnlink) {
                healthy.set(false);
            }
        } finally {
            if (closeRemaining() < 0) {
                healthy.set(false);
            }
            closeFinished.countDown();
        }
    }

    private long closeRemaining() {
        return WorkerProcess.CLEANUP_NANOS - (System.nanoTime() - closeStarted.get());
    }

    private void awaitClose() {
        try {
            long available = closeStarted.get() == 0 ? WorkerProcess.CLEANUP_NANOS : Math.max(0, closeRemaining());
            if (!closeFinished.await(available, TimeUnit.NANOSECONDS)) {
                healthy.set(false);
            }
        } catch (InterruptedException interrupted) {
            healthy.set(false);
            Thread.currentThread().interrupt();
        }
    }
}
