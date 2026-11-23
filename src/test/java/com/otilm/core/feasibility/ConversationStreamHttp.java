package com.otilm.core.feasibility;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.otilm.api.model.core.logging.enums.AuthMethod;
import com.otilm.core.security.authn.PlatformUserDetails;
import jakarta.servlet.AsyncContext;
import jakarta.servlet.AsyncEvent;
import jakarta.servlet.AsyncListener;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.net.SocketTimeoutException;
import java.nio.charset.StandardCharsets;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.UUID;
import java.util.concurrent.Callable;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.Semaphore;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicLong;
import java.util.concurrent.atomic.AtomicReference;
import org.slf4j.MDC;
import org.springframework.http.CacheControl;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.authentication.AnonymousAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.transaction.support.TransactionSynchronizationManager;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.context.request.RequestContextHolder;

/** Explicit test handler; actor identity comes only from the ordinary Core security chain. */
public final class ConversationStreamHttp {
    private static final long WINDOW_NANOS = TimeUnit.SECONDS.toNanos(8);
    private static final long HEARTBEAT_NANOS = TimeUnit.MILLISECONDS.toNanos(100);
    private final ConversationTimeline timeline;
    private final ConversationStreamFixture fixture;
    private final ConversationStreamAuthorization authorization;
    private final ConversationStreamFrames frames;
    private final Semaphore capacity = new Semaphore(4);
    private final AtomicInteger held = new AtomicInteger();
    private final AtomicInteger workers = new AtomicInteger();
    private final AtomicInteger rejected = new AtomicInteger();
    private final ConcurrentHashMap<Integer, Probe> probes = new ConcurrentHashMap<>();
    private final AtomicReference<Probe> completed = new AtomicReference<>();
    private final AtomicReference<UUID> lastActor = new AtomicReference<>();
    private final AtomicReference<AuthMethod> lastMethod = new AtomicReference<>();
    private volatile Runnable beforeRead = () -> {
    };
    private volatile Runnable beforeLeaseRelease = () -> {
    };
    private volatile Runnable beforeEmit = () -> {
    };

    public enum End {
        NONE,
        COMPLETE,
        WINDOW,
        UNVERIFIED_ACCESS,
        WRITE_TIMEOUT,
        PEER_IO,
        FRAME_LIMIT,
        INTERNAL,
        INTERRUPTED
    }

    public static final class Probe {
        public volatile int remotePort;
        public volatile Thread writer;
        public volatile boolean writeActive;
        public volatile long writeStarted;
        public volatile long finished;
        public volatile boolean contextClean;
        public volatile boolean contextCleanBeforeFinalClear = true;
        public volatile boolean authorityContextClean = true;
        public volatile boolean authorityThreadMatches = true;
        public final AtomicInteger authorityChecks = new AtomicInteger();
        public volatile boolean transactionAtWrite;
        public volatile End end = End.NONE;
        public final AtomicLong offered = new AtomicLong();
        public final AtomicLong written = new AtomicLong();
        public final AtomicInteger maximumFrame = new AtomicInteger();
    }

    public ConversationStreamHttp(ConversationTimeline timeline, ConversationStreamFixture fixture,
            ConversationStreamAuthorization authorization, ObjectMapper mapper) {
        this.timeline = timeline;
        this.fixture = fixture;
        this.authorization = authorization;
        frames = new ConversationStreamFrames(mapper);
    }

    public ResponseEntity<?> timeline(@PathVariable UUID conversation, HttpServletRequest request) {
        try {
            UUID actor = actor();
            var cursor = cursor(actor, conversation, request);
            var batch = fixture.read(actor, conversation, cursor, 8);
            Map<String, Object> body = new LinkedHashMap<>();
            body
                    .put("entries",
                            batch
                                    .events()
                                    .stream()
                                    .map(event -> Map
                                            .of("cursor", event.cursor().toString(), "runId", event.runId().toString(),
                                                    "value", event.value()))
                                    .toList());
            body.put("title", batch.title());
            body.put("count", batch.count());
            batch.run().ifPresent(run -> body.put("run", runBody(run)));
            if (!batch.events().isEmpty()) {
                body.put("cursor", batch.events().getLast().cursor().toString());
            } else {
                cursor.ifPresent(value -> body.put("cursor", value.toString()));
            }
            return ResponseEntity.ok().cacheControl(CacheControl.noStore()).body(body);
        } catch (ConversationTimeline.CursorExpired failure) {
            return error(410);
        } catch (AccessDeniedException failure) {
            return error(403);
        } catch (RuntimeException failure) {
            return error(500);
        }
    }

    public ResponseEntity<?> start(@PathVariable UUID conversation, HttpServletRequest request) {
        return command(conversation, null, ConversationTimeline.CommandKind.START, request);
    }

    public ResponseEntity<?> follow(@PathVariable UUID conversation, HttpServletRequest request) {
        return command(conversation, null, ConversationTimeline.CommandKind.FOLLOW_UP, request);
    }

    public ResponseEntity<?> cancel(@PathVariable UUID conversation, @PathVariable UUID run,
            HttpServletRequest request) {
        return command(conversation, run, ConversationTimeline.CommandKind.CANCEL, request);
    }

    private ResponseEntity<?> command(UUID conversation, UUID run, ConversationTimeline.CommandKind kind,
            HttpServletRequest request) {
        try {
            UUID actor = actor();
            byte[] body = commandBody(request);
            String key = request.getHeader("Idempotency-Key");
            var result = kind == ConversationTimeline.CommandKind.CANCEL
                    ? fixture.cancel(actor, conversation, run, key, body)
                    : fixture.command(actor, conversation, kind, key, body);
            return ResponseEntity.status(202).cacheControl(CacheControl.noStore()).body(runBody(result));
        } catch (BodyLimit failure) {
            return error(413);
        } catch (ConversationTimeline.CommandConflict failure) {
            return error(409);
        } catch (AccessDeniedException failure) {
            return error(403);
        } catch (IllegalArgumentException | IOException failure) {
            return error(400);
        } catch (RuntimeException failure) {
            return error(500);
        }
    }

    public void events(@PathVariable UUID conversation, HttpServletRequest request, HttpServletResponse response) {
        UUID actor;
        try {
            actor = actor();
        } catch (RuntimeException failure) {
            streamError(response, 403);
            return;
        }
        if (!capacity.tryAcquire()) {
            rejected.incrementAndGet();
            streamError(response, 503);
            return;
        }
        held.incrementAndGet();
        Lease lease = new Lease(request.getRemotePort());
        Window window = new Window();
        try {
            var cursor = cursor(actor, conversation, request);
            var initial = read(actor, conversation, cursor, window);
            if (!initial.events().isEmpty()) {
                frames.entry(initial.events().getFirst());
            }
            response.setStatus(200);
            response.setContentType("text/event-stream");
            response.setCharacterEncoding(StandardCharsets.UTF_8.name());
            response.setHeader("Cache-Control", "no-store");
            AsyncContext async = request.startAsync();
            async.setTimeout(20000);
            async.addListener(new AsyncListener() {
                @Override
                public void onComplete(AsyncEvent event) {
                    lease.releaseUnused();
                }

                @Override
                public void onError(AsyncEvent event) {
                    lease.releaseUnused();
                }

                @Override
                public void onTimeout(AsyncEvent event) {
                    lease.releaseUnused();
                }

                @Override
                public void onStartAsync(AsyncEvent event) {
                    // This fixture completes its initial async cycle and never starts another dispatch cycle.
                }
            });
            try {
                async.start(() -> stream(actor, conversation, cursor, initial, window, lease, async));
            } catch (RuntimeException failure) {
                lease.releaseUnused();
                async.complete();
                throw failure;
            }
        } catch (ConversationTimeline.CursorExpired failure) {
            lease.releaseUnused();
            streamError(response, 410);
        } catch (AccessDeniedException failure) {
            lease.releaseUnused();
            streamError(response, 403);
        } catch (RuntimeException failure) {
            lease.releaseUnused();
            streamError(response, 500);
        }
    }

    public Callable<ResponseEntity<?>> ordinary() {
        actor();
        return () -> ResponseEntity.ok(Map.of("status", "ordinary"));
    }

    public void ordinaryServlet(HttpServletRequest request, HttpServletResponse response) {
        actor();
        response.setStatus(200);
        response.setContentType("application/json");
        AsyncContext async = request.startAsync();
        async.setTimeout(20000);
        async.start(() -> {
            clearThread();
            try {
                response.getOutputStream().write("{\"status\":\"ordinary\"}".getBytes(StandardCharsets.UTF_8));
            } catch (IOException failure) {
                response.setStatus(500);
            } finally {
                clearThread();
                async.complete();
            }
        });
    }

    private void stream(UUID actor, UUID conversation, Optional<UUID> cursor, ConversationTimeline.Batch initial,
            Window window, Lease lease, AsyncContext async) {
        if (!lease.begin()) {
            return;
        }
        Probe probe = lease.probe;
        clearThread();
        try {
            OutputStream output = async.getResponse().getOutputStream();
            write(output, frames.connected(), probe);
            pump(actor, conversation, cursor, initial, window, output, probe);
        } catch (WindowClosed failure) {
            probe.end = End.WINDOW;
        } catch (AccessDeniedException failure) {
            probe.end = End.UNVERIFIED_ACCESS;
            if (!window.expired()) {
                try {
                    write(async.getResponse().getOutputStream(), frames.forbidden(), probe);
                } catch (IOException io) {
                    probe.end = writeTimeout(io) ? End.WRITE_TIMEOUT : End.PEER_IO;
                }
            }
        } catch (ConversationStreamFrames.FrameUnavailable failure) {
            probe.end = End.FRAME_LIMIT;
        } catch (IOException failure) {
            probe.end = writeTimeout(failure) ? End.WRITE_TIMEOUT : End.PEER_IO;
        } catch (InterruptedException failure) {
            Thread.currentThread().interrupt();
            probe.end = End.INTERRUPTED;
        } catch (RuntimeException failure) {
            probe.end = End.INTERNAL;
        } finally {
            probe.contextCleanBeforeFinalClear = cleanThread();
            clearThread();
            probe.contextClean = cleanThread();
            SecurityContextHolder.clearContext();
            try {
                async.complete();
            } finally {
                lease.finish();
            }
        }
    }

    private void pump(UUID actor, UUID conversation, Optional<UUID> cursor, ConversationTimeline.Batch initial,
            Window window, OutputStream output, Probe probe) throws IOException, InterruptedException {
        ConversationTimeline.Batch pending = initial;
        long heartbeat = System.nanoTime();
        while (!window.expired()) {
            var batch = admit(actor, conversation, cursor, pending, window, probe);
            if (!batch.events().isEmpty()) {
                var event = batch.events().getFirst();
                byte[] frame = frames.entry(event);
                window.check();
                write(output, frame, probe);
                cursor = Optional.of(event.cursor());
                heartbeat = System.nanoTime();
            } else if (batch.run().isPresent() && terminal(batch.run().orElseThrow().state())) {
                window.check();
                write(output, frames.complete(), probe);
                probe.end = End.COMPLETE;
                return;
            } else {
                if (System.nanoTime() - heartbeat >= HEARTBEAT_NANOS) {
                    window.check();
                    write(output, frames.heartbeat(), probe);
                    heartbeat = System.nanoTime();
                }
                java.util.concurrent.locks.LockSupport.parkNanos(TimeUnit.MILLISECONDS.toNanos(25));
                if (Thread.currentThread().isInterrupted()) {
                    throw new InterruptedException("Stream interrupted");
                }
            }
            pending = read(actor, conversation, cursor, window, probe);
        }
        probe.end = End.WINDOW;
    }

    private ConversationTimeline.Batch read(UUID actor, UUID conversation, Optional<UUID> cursor, Window window) {
        return read(actor, conversation, cursor, window, null);
    }

    private ConversationTimeline.Batch read(UUID actor, UUID conversation, Optional<UUID> cursor, Window window,
            Probe probe) {
        for (int attempt = 0; attempt < 3; attempt++) {
            window.check();
            var scope = timeline.scope(actor, conversation);
            window.check();
            observeAuthorityContext(probe);
            authorization.require(actor, scope);
            window.check();
            beforeRead.run();
            window.check();
            var result = timeline.read(conversation, scope.revision(), cursor, 1);
            window.check();
            if (result.isPresent() && result.orElseThrow().scope().equals(scope)) {
                return result.orElseThrow();
            }
        }
        throw new AccessDeniedException("Conversation unavailable");
    }

    private ConversationTimeline.Batch admit(UUID actor, UUID conversation, Optional<UUID> cursor,
            ConversationTimeline.Batch pending, Window window, Probe probe) {
        for (int attempt = 0; attempt < 3; attempt++) {
            window.check();
            beforeEmit.run();
            window.check();
            observeAuthorityContext(probe);
            authorization.require(actor, pending.scope());
            window.check();
            var current = timeline.read(conversation, pending.scope().revision(), cursor, 1);
            window.check();
            if (current.isPresent() && current.orElseThrow().scope().equals(pending.scope())) {
                return current.orElseThrow();
            }
            pending = read(actor, conversation, cursor, window, probe);
        }
        throw new AccessDeniedException("Conversation unavailable");
    }

    private Optional<UUID> cursor(UUID actor, UUID conversation, HttpServletRequest request) {
        var headers = request.getHeaders("Last-Event-ID");
        if (!headers.hasMoreElements()) {
            return Optional.empty();
        }
        authorization.require(actor, timeline.scope(actor, conversation));
        String raw = headers.nextElement();
        if (headers.hasMoreElements() || raw.length() > 512
                || !raw.matches("[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}")) {
            throw new ConversationTimeline.CursorExpired();
        }
        return Optional.of(UUID.fromString(raw));
    }

    private static byte[] commandBody(HttpServletRequest request) throws IOException {
        long start = System.nanoTime();
        ByteArrayOutputStream body = new ByteArrayOutputStream();
        byte[] buffer = new byte[512];
        while (true) {
            if (System.nanoTime() - start > TimeUnit.SECONDS.toNanos(5)) {
                throw new IOException("Input unavailable");
            }
            int count = request.getInputStream().read(buffer);
            if (count < 0) {
                return body.toByteArray();
            }
            if (count > 4096 - body.size()) {
                throw new BodyLimit();
            }
            if (count == 0) {
                throw new IOException("Input unavailable");
            }
            body.write(buffer, 0, count);
        }
    }

    private UUID actor() {
        var authentication = SecurityContextHolder.getContext().getAuthentication();
        if (authentication == null || !authentication.isAuthenticated()
                || authentication instanceof AnonymousAuthenticationToken
                || !(authentication.getPrincipal() instanceof PlatformUserDetails details)) {
            throw new AccessDeniedException("Conversation unavailable");
        }
        UUID actor = UUID.fromString(details.getUserUuid());
        lastActor.set(actor);
        lastMethod.set(details.getAuthMethod());
        return actor;
    }

    private static Map<String, Object> runBody(ConversationTimeline.RunResult run) {
        return Map.of("runId", run.runId().toString(), "state", run.state().name(), "replay", run.replay());
    }

    private static boolean terminal(ConversationTimeline.RunState state) {
        return state == ConversationTimeline.RunState.COMPLETE || state == ConversationTimeline.RunState.CANCELLED;
    }

    private static ResponseEntity<?> error(int status) {
        if (status == 410) {
            return ResponseEntity.status(status).cacheControl(CacheControl.noStore()).build();
        }
        return ResponseEntity.status(status).cacheControl(CacheControl.noStore()).body(Map.of("status", "unavailable"));
    }

    private static void streamError(HttpServletResponse response, int status) {
        response.setStatus(status);
        response.setHeader("Cache-Control", "no-store");
    }

    private static boolean cleanThread() {
        return SecurityContextHolder.getContext().getAuthentication() == null
                && RequestContextHolder.getRequestAttributes() == null && MDC.getCopyOfContextMap() == null;
    }

    private static void observeAuthorityContext(Probe probe) {
        if (probe != null) {
            probe.authorityContextClean &= cleanThread();
            probe.authorityThreadMatches &= Thread.currentThread() == probe.writer;
            probe.authorityChecks.incrementAndGet();
        }
    }

    private static void clearThread() {
        SecurityContextHolder.clearContext();
        RequestContextHolder.resetRequestAttributes();
        MDC.clear();
    }

    private static void write(OutputStream output, byte[] frame, Probe probe) throws IOException {
        probe.transactionAtWrite |= TransactionSynchronizationManager.isActualTransactionActive();
        if (probe.transactionAtWrite) {
            throw new IllegalStateException("Transaction during write unavailable");
        }
        probe.maximumFrame.accumulateAndGet(frame.length, Math::max);
        probe.offered.addAndGet(frame.length);
        probe.writeStarted = System.nanoTime();
        probe.writeActive = true;
        try {
            output.write(frame);
            output.flush();
            probe.written.addAndGet(frame.length);
        } finally {
            probe.writeActive = false;
        }
    }

    private static boolean writeTimeout(IOException failure) {
        Throwable current = failure;
        for (int depth = 0; current != null && depth < 8; depth++, current = current.getCause()) {
            if (current instanceof SocketTimeoutException && List
                    .of(current.getStackTrace())
                    .stream()
                    .anyMatch(frame -> frame.getClassName().contains("NioSocketWrapper")
                            && frame.getMethodName().equals("doWrite"))) {
                return true;
            }
        }
        return false;
    }

    private final class Lease {
        private final AtomicInteger state = new AtomicInteger();
        private final Probe probe = new Probe();
        private final int remotePort;

        Lease(int remotePort) {
            this.remotePort = remotePort;
        }

        boolean begin() {
            if (!state.compareAndSet(0, 1)) {
                return false;
            }
            probe.writer = Thread.currentThread();
            probe.remotePort = remotePort;
            probes.put(remotePort, probe);
            workers.incrementAndGet();
            return true;
        }

        void releaseUnused() {
            if (state.compareAndSet(0, 2)) {
                held.decrementAndGet();
                capacity.release();
            }
        }

        void finish() {
            if (state.compareAndSet(1, 2)) {
                try {
                    beforeLeaseRelease.run();
                } finally {
                    probe.writer = null;
                    probes.remove(remotePort, probe);
                    completed.set(probe);
                    workers.decrementAndGet();
                    held.decrementAndGet();
                    capacity.release();
                    probe.finished = System.nanoTime();
                }
            }
        }
    }

    private static final class Window {
        private final long start = System.nanoTime();

        boolean expired() {
            return System.nanoTime() - start >= WINDOW_NANOS;
        }

        void check() {
            if (expired() || Thread.currentThread().isInterrupted()) {
                throw new WindowClosed();
            }
        }
    }

    private static final class WindowClosed extends RuntimeException {
        WindowClosed() {
            super("Stream closed", null, false, false);
        }
    }

    private static final class BodyLimit extends RuntimeException {
        BodyLimit() {
            super("Input unavailable", null, false, false);
        }
    }

    public void beforeRead(Runnable hook) {
        beforeRead = java.util.Objects.requireNonNull(hook);
    }

    public void beforeEmit(Runnable hook) {
        beforeEmit = java.util.Objects.requireNonNull(hook);
    }

    public int activeReaders() {
        return held.get();
    }

    public int activeWorkers() {
        return workers.get();
    }

    public int rejectedReaders() {
        return rejected.get();
    }

    public Probe activeProbe(int remotePort) {
        return probes.get(remotePort);
    }

    public Probe activeProbe() {
        return probes.values().stream().findFirst().orElse(null);
    }

    public Probe completedProbe() {
        return completed.get();
    }

    public UUID lastActor() {
        return lastActor.get();
    }

    public AuthMethod lastAuthenticationMethod() {
        return lastMethod.get();
    }

    public void beforeLeaseRelease(Runnable hook) {
        beforeLeaseRelease = java.util.Objects.requireNonNull(hook);
    }

    public void resetObservations() {
        if (held.get() != 0 || workers.get() != 0) {
            throw new IllegalStateException("Active proof observation unavailable");
        }
        lastActor.set(null);
        lastMethod.set(null);
        completed.set(null);
    }
}
