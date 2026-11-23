package com.otilm.ai.controller;

import com.otilm.ai.proxy.FixedCoreHttp;
import com.otilm.ai.proxy.IdentityFiles;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.net.URI;
import java.time.Duration;
import java.util.HashSet;
import java.util.Objects;
import java.util.Set;
import java.util.UUID;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.function.Consumer;
import org.apache.hc.client5.http.classic.methods.HttpPost;
import org.apache.hc.client5.http.impl.classic.CloseableHttpClient;
import org.apache.hc.client5.http.impl.classic.CloseableHttpResponse;
import org.apache.hc.core5.http.ContentType;
import org.apache.hc.core5.http.HttpVersion;
import org.apache.hc.core5.http.io.entity.InputStreamEntity;
import org.apache.hc.core5.io.CloseMode;

/** Fixed controller Core routes only; current Core verification remains the sole operation authority. */
final class ControllerCoreClient {
    private static final String RECONCILE = "/internal/ai-runtime/v1/controller/launches/reconcile";
    private final ControllerConfiguration configuration;
    private final Consumer<Runnable> closeClient;
    private final AtomicBoolean resumeAttempted = new AtomicBoolean();
    private ControllerWire.Control resumed;
    private final AtomicBoolean launchAttempted = new AtomicBoolean();
    private final Set<UUID> eligibleAttempted = new HashSet<>();
    private final Set<UUID> registerAttempted = new HashSet<>();
    private final AtomicBoolean fenceAttempted = new AtomicBoolean();
    private final AtomicBoolean terminalAttempted = new AtomicBoolean();
    private final AtomicBoolean cleanupAttempted = new AtomicBoolean();
    private final AtomicBoolean inFlight = new AtomicBoolean();
    private ControllerWire.Locator accepted;
    private boolean fenceAccepted;
    private boolean terminalAccepted;
    private volatile boolean unknown;
    private volatile boolean cleanupUncertain;
    private volatile Owner quarantined;

    ControllerCoreClient(ControllerConfiguration configuration) {
        this(configuration, Runnable::run);
    }

    ControllerCoreClient(ControllerConfiguration configuration, Consumer<Runnable> closeClient) {
        this.configuration = Objects.requireNonNull(configuration);
        this.closeClient = Objects.requireNonNull(closeClient);
    }

    ControllerWire.Launch launch(ControllerWire.Locator locator, Duration budget) {
        long started = System.nanoTime();
        if (resumeAttempted.get() || !launchAttempted.compareAndSet(false, true)) {
            throw new ObservationFailure();
        }
        try {
            var reply = ControllerWire
                    .readLaunchReply(post(RECONCILE, ControllerWire.launchRequest(locator), budget, started), locator);
            remaining(budget, started);
            accepted = locator;
            unknown = false;
            return reply;
        } catch (Throwable unavailable) {
            throw new ObservationFailure();
        }
    }

    ControllerWire.CleanupResumeReply resumeCleanup(ControllerWire.Locator locator, Duration budget) {
        long started = System.nanoTime();
        if (locator == null || launchAttempted.get() || !resumeAttempted.compareAndSet(false, true)) {
            throw new ObservationFailure();
        }
        var reply = ControllerWire
                .readCleanupResumeReply(post("/internal/ai-runtime/v1/controller/workloads/status",
                        ControllerWire.cleanupResumeRequest(locator), budget, started), locator);
        remaining(budget, started);
        accepted = locator;
        resumed = reply.control();
        fenceAccepted = !reply.done();
        unknown = false;
        return reply;
    }

    ControllerWire.ObservationReply observe(ControllerWire.Operation operation,
            ControllerWire.ObservationRequest request, Duration budget) {
        long started = System.nanoTime();
        var attempted = operation == ControllerWire.Operation.ELIGIBLE ? eligibleAttempted : registerAttempted;
        if (operation == null || request == null || !request.locator().equals(accepted) || unknown
                || resumeAttempted.get() || fenceAttempted.get() || !firstAttempt(attempted, request.podUid())) {
            throw new ObservationFailure();
        }
        try {
            String path = switch (operation) {
                case ELIGIBLE -> RECONCILE;
                case REGISTER -> "/internal/ai-runtime/v1/controller/workloads/register";
            };
            var reply = ControllerWire
                    .readObservationReply(
                            post(path, ControllerWire.observationRequest(operation, request), budget, started),
                            operation, request);
            remaining(budget, started);
            unknown = false;
            return reply;
        } catch (Throwable unavailable) {
            throw new ObservationFailure();
        }
    }

    private static boolean firstAttempt(Set<UUID> attempted, UUID pod) {
        synchronized (attempted) {
            return attempted.size() < 16 && attempted.add(pod);
        }
    }

    ControllerWire.ControlReply control(ControllerWire.ControlOperation operation, ControllerWire.Locator locator,
            ControllerWire.Control expected, Duration budget) {
        long started = System.nanoTime();
        if (operation == null || locator == null || !locator.equals(accepted)
                || resumeAttempted.get() && (operation != ControllerWire.ControlOperation.TERMINAL
                        && operation != ControllerWire.ControlOperation.CLEANUP || !Objects.equals(resumed, expected))
                || unknown && operation != ControllerWire.ControlOperation.FENCE
                || operation == ControllerWire.ControlOperation.TERMINAL && !fenceAccepted
                || operation == ControllerWire.ControlOperation.CLEANUP && !terminalAccepted) {
            throw new ObservationFailure();
        }
        AtomicBoolean attempted = switch (operation) {
            case STATUS -> null;
            case FENCE -> fenceAttempted;
            case TERMINAL -> terminalAttempted;
            case CLEANUP -> cleanupAttempted;
        };
        if (attempted != null && !attempted.compareAndSet(false, true)) {
            throw new ObservationFailure();
        }
        try {
            String path = switch (operation) {
                case STATUS, TERMINAL -> "/internal/ai-runtime/v1/controller/workloads/status";
                case FENCE, CLEANUP -> "/internal/ai-runtime/v1/controller/cleanup/reconcile";
            };
            var reply = ControllerWire
                    .readControlReply(
                            post(path, ControllerWire.controlRequest(operation, locator, expected), budget, started),
                            operation, locator);
            if (expected != null && !expected.equals(reply.control())) {
                throw new ObservationFailure();
            }
            remaining(budget, started);
            if (operation == ControllerWire.ControlOperation.FENCE) {
                fenceAccepted = true;
            } else if (operation == ControllerWire.ControlOperation.TERMINAL) {
                terminalAccepted = true;
            }
            unknown = false;
            return reply;
        } catch (Throwable unavailable) {
            throw new ObservationFailure();
        }
    }

    private byte[] post(String path, byte[] bytes, Duration budget, long started) {
        if (cleanupUncertain() || !inFlight.compareAndSet(false, true)) {
            throw new ObservationFailure();
        }
        try {
            remaining(budget, started);
            var request = new HttpPost(URI.create(configuration.core().origin().toASCIIString() + path));
            request.setVersion(HttpVersion.HTTP_1_1);
            request.setHeader("Connection", "close");
            request.setHeader("Accept", "application/json");
            request.setHeader("Cache-Control", "no-store");
            request
                    .setEntity(new InputStreamEntity(new ByteArrayInputStream(bytes), bytes.length,
                            ContentType.APPLICATION_JSON));
            byte[] reply;
            var owner = new Owner(request, budget.toNanos(), started);
            try (owner) {
                owner.remaining();
                var identity = IdentityFiles
                        .load(configuration.certificateFile(), configuration.privateKeyFile(),
                                configuration.serverCaFile());
                owner.client = FixedCoreHttp.open(configuration.core(), identity, owner.remaining());
                owner.remaining();
                unknown = true;
                var response = CloseableHttpResponse.adapt(owner.client.executeOpen(null, request, null));
                try {
                    if (response.getCode() != 200 || !HttpVersion.HTTP_1_1.equals(response.getVersion())
                            || response.containsHeader("Content-Encoding") || response.containsHeader("Set-Cookie")
                            || response.containsHeader("Set-Cookie2") || response.getHeaders("Content-Type").length != 1
                            || response.getEntity() == null || response.getEntity().getContentLength() > 4096) {
                        throw new ObservationFailure();
                    }
                    String type = response.getFirstHeader("Content-Type").getValue();
                    if (type == null || !type
                            .matches(
                                    "(?i)application/json[ \\t]*+(?:;[ \\t]*+charset[ \\t]*+=[ \\t]*+(?:utf-8|\"utf-8\"))?[ \\t]*+")) {
                        throw new ObservationFailure();
                    }
                    var body = new ByteArrayOutputStream();
                    var input = response.getEntity().getContent();
                    byte[] buffer = new byte[1024];
                    while (true) {
                        owner.remaining();
                        int count = input.read(buffer, 0, Math.min(buffer.length, 4097 - body.size()));
                        owner.remaining();
                        if (count < 0) {
                            break;
                        }
                        body.write(buffer, 0, count);
                        if (body.size() > 4096) {
                            throw new ObservationFailure();
                        }
                    }
                    reply = body.toByteArray();
                    owner.remaining();
                } finally {
                    request.cancel();
                    response.close(CloseMode.IMMEDIATE);
                }
            }
            owner.remaining();
            return reply;
        } catch (Throwable unavailable) {
            throw new ObservationFailure();
        } finally {
            if (!cleanupUncertain()) {
                inFlight.set(false);
            }
        }
    }

    private static void remaining(Duration budget, long started) {
        if (budget == null || budget.isZero() || budget.isNegative() || budget.compareTo(Duration.ofSeconds(5)) > 0
                || System.nanoTime() - started >= budget.toNanos() || Thread.currentThread().isInterrupted()) {
            throw new ObservationFailure();
        }
    }

    boolean outcomeUnknown() {
        return unknown;
    }

    boolean cleanupUncertain() {
        return cleanupUncertain || quarantined != null;
    }

    private final class Owner implements AutoCloseable {
        private final HttpPost request;
        private final long duration;
        private final long started;
        private volatile CloseableHttpClient client;
        private volatile boolean failed;
        private final ScheduledExecutorService guard = Executors
                .newSingleThreadScheduledExecutor(
                        Thread.ofPlatform().daemon().name("ai-controller-core-budget").factory());

        private Owner(HttpPost request, long duration, long started) {
            this.request = request;
            this.duration = duration;
            this.started = started;
            try {
                guard.schedule(() -> {
                    failed = true;
                    stopHandles();
                }, remaining(), TimeUnit.NANOSECONDS);
            } catch (Throwable unavailable) {
                failed = true;
                close();
                throw new ObservationFailure();
            }
        }

        private long remaining() {
            long left = duration - (System.nanoTime() - started);
            if (failed || left <= 0 || Thread.currentThread().isInterrupted()) {
                throw new ObservationFailure();
            }
            return Math.min(left, duration);
        }

        private void stopHandles() {
            try {
                request.cancel();
            } catch (Throwable failure) {
                uncertain();
            }
            var active = client;
            if (active != null) {
                try {
                    closeClient.accept(() -> active.close(CloseMode.IMMEDIATE));
                } catch (Throwable failure) {
                    uncertain();
                }
            }
        }

        private void uncertain() {
            cleanupUncertain = true;
            quarantined = this;
            failed = true;
        }

        @Override
        public void close() {
            try {
                guard.shutdownNow();
            } catch (Throwable failure) {
                uncertain();
            }
            stopHandles();
            try {
                if (!guard.awaitTermination(1, TimeUnit.SECONDS)) {
                    uncertain();
                }
            } catch (InterruptedException interrupted) {
                Thread.currentThread().interrupt();
                uncertain();
            }
            if (failed || cleanupUncertain()) {
                throw new ObservationFailure();
            }
        }
    }
}
