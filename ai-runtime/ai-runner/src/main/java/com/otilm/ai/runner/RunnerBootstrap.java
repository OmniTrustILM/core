package com.otilm.ai.runner;

import com.otilm.ai.proxy.LocalOperation;
import com.otilm.ai.proxy.ProxyReply;
import com.otilm.ai.proxy.ProxyRequest;
import com.otilm.ai.runtime.protocol.BootstrapClaimedReply;
import com.otilm.ai.runtime.protocol.BootstrapPendingReply;
import com.otilm.ai.runtime.protocol.BootstrapRequest;
import com.otilm.ai.runtime.protocol.ClaimBinding;
import com.otilm.ai.runtime.protocol.ClaimHeartbeatRequest;
import com.otilm.ai.runtime.protocol.ProtocolCodec;
import java.time.Instant;
import java.util.Objects;
import java.util.UUID;
import java.util.concurrent.TimeUnit;

/** Finite bootstrap/heartbeat probe; current Core authority is never inferred from local identifiers. */
public final class RunnerBootstrap {
    private static final long BUDGET_NANOS = TimeUnit.SECONDS.toNanos(110);
    private final LocalRpcClient client;
    private final ProtocolCodec codec = new ProtocolCodec();

    public RunnerBootstrap(LocalRpcClient client) {
        this.client = Objects.requireNonNull(client);
    }

    public boolean run(UUID run, UUID attempt, UUID pod, long started) {
        try {
            for (int number = 0; number < 11; number++) {
                if (remaining(started) <= 0) {
                    return false;
                }
                var request = new ProxyRequest(LocalOperation.BOOTSTRAP, UUID.randomUUID(),
                        codec.writeBootstrapRequest(new BootstrapRequest(1, run, attempt, pod)));
                ProxyReply reply = client.exchange(request, remaining(started));
                if (!accepted(reply, started)) {
                    return false;
                }
                switch (codec.readBootstrapReply(reply.payload())) {
                    case BootstrapPendingReply pending -> {
                        event("bootstrap", "PENDING", reply.correlationId());
                        if (!awaitPending(pending, number, started)) {
                            return false;
                        }
                    }
                    case BootstrapClaimedReply claimed -> {
                        return acceptClaimed(claimed, reply, run, attempt, pod, started);
                    }
                }
            }
        } catch (Exception unavailable) {
            if (unavailable instanceof InterruptedException) {
                Thread.currentThread().interrupt();
            }
        }
        return false;
    }

    private static boolean awaitPending(BootstrapPendingReply pending, int number, long started)
            throws InterruptedException {
        if (number == 10 || remaining(started) <= TimeUnit.MILLISECONDS.toNanos(pending.retryAfterMillis())) {
            return false;
        }
        Thread.sleep(pending.retryAfterMillis());
        return true;
    }

    private boolean acceptClaimed(BootstrapClaimedReply claimed, ProxyReply reply, UUID run, UUID attempt, UUID pod,
            long started) throws java.io.IOException {
        ClaimBinding binding = claimed.binding();
        if (!run.equals(binding.runId()) || !attempt.equals(binding.attemptId()) || !pod.equals(binding.podUid())
                || !claimed.leaseExpiresAt().isAfter(Instant.now())) {
            return false;
        }
        event("bootstrap", "CLAIMED", reply.correlationId());
        return heartbeat(binding, started);
    }

    private boolean heartbeat(ClaimBinding binding, long started) throws java.io.IOException {
        var request = new ProxyRequest(LocalOperation.HEARTBEAT, UUID.randomUUID(),
                codec.writeClaimHeartbeatRequest(new ClaimHeartbeatRequest(1, binding, 1)));
        ProxyReply reply = client.exchange(request, remaining(started));
        if (!accepted(reply, started)) {
            return false;
        }
        var heartbeat = codec.readClaimHeartbeatReply(reply.payload());
        if (!binding.equals(heartbeat.binding()) || heartbeat.sequence() != 1
                || !heartbeat.leaseExpiresAt().isAfter(Instant.now()) || remaining(started) <= 0) {
            return false;
        }
        event("heartbeat", "ACK", reply.correlationId());
        return true;
    }

    private static boolean accepted(ProxyReply reply, long started) {
        return reply.outcome() == ProxyReply.Outcome.UPSTREAM_REPLY && reply.httpStatus() == 200
                && remaining(started) > 0;
    }

    private static long remaining(long started) {
        long elapsed = System.nanoTime() - started;
        return elapsed < 0 ? 0 : BUDGET_NANOS - elapsed;
    }

    private static void event(String operation, String code, UUID correlation) {
        System.out.println("phase=runner op=" + operation + " code=" + code + " correlation=" + correlation);
    }
}
