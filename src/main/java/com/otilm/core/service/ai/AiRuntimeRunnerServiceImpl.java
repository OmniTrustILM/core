package com.otilm.core.service.ai;

import com.otilm.ai.runtime.protocol.BootstrapClaimedReply;
import com.otilm.ai.runtime.protocol.BootstrapPendingReply;
import com.otilm.ai.runtime.protocol.BootstrapRequest;
import com.otilm.ai.runtime.protocol.ClaimHeartbeatReply;
import com.otilm.ai.runtime.protocol.ClaimHeartbeatRequest;
import com.otilm.ai.runtime.protocol.ProtocolCodec;
import com.otilm.ai.runtime.protocol.ProtocolException;
import com.otilm.ai.runtime.protocol.RuntimeErrorCode;
import com.otilm.ai.runtime.protocol.RuntimeErrorReply;
import com.otilm.api.exception.PlatformException;
import com.otilm.core.aop.TraceMetadataOnly;
import com.otilm.core.model.ai.AiRuntimeState.Claim;
import com.otilm.core.model.ai.AiRuntimeState.ClaimBinding;
import com.otilm.core.model.ai.AiRuntimeState.Expected;
import com.otilm.core.model.ai.AiRuntimeState.RunSnapshot;
import com.otilm.core.model.ai.AiRuntimeState.Status;
import com.otilm.core.model.ai.AiRuntimeState.Transition;
import com.otilm.core.model.ai.AiRuntimeState.WorkloadRef;
import com.otilm.core.model.ai.AiRuntimeState.WorkloadState;
import com.otilm.core.security.ai.RuntimeProxyCertificateClaims;
import com.otilm.core.security.ai.RuntimeProxyTransport;
import com.otilm.core.security.authn.client.AuthenticationInfo;
import com.otilm.core.security.authn.client.PlatformAuthenticationClient;
import com.otilm.core.security.authz.ProtocolEndpoint;
import com.otilm.core.service.AiRuntimeRunnerExternalService;
import java.io.IOException;
import java.io.InputStream;
import java.time.Duration;
import java.util.Arrays;
import java.util.Objects;
import java.util.UUID;
import java.util.function.LongSupplier;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.CacheControl;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Propagation;
import org.springframework.transaction.annotation.Transactional;

/** Current actor is evaluated outside locks; the kernel rechecks current control at the final transition. */
@Service
@TraceMetadataOnly
public class AiRuntimeRunnerServiceImpl implements AiRuntimeRunnerExternalService {
    private static final Logger LOG = LoggerFactory.getLogger(AiRuntimeRunnerServiceImpl.class);
    private static final int MAX_BODY = 4096;
    private final AiFeatureGate feature;
    private final AiRuntimeKernel kernel;
    private final PlatformAuthenticationClient auth;
    private final LongSupplier nanos;
    private final ProtocolCodec codec = new ProtocolCodec();

    @Autowired
    public AiRuntimeRunnerServiceImpl(AiRuntimeKernel kernel, PlatformAuthenticationClient auth,
            AiFeatureGate feature) {
        this(kernel, auth, System::nanoTime, feature);
    }

    AiRuntimeRunnerServiceImpl(AiRuntimeKernel kernel, PlatformAuthenticationClient auth, LongSupplier nanos,
            AiFeatureGate feature) {
        this.feature = Objects.requireNonNull(feature);
        this.kernel = Objects.requireNonNull(kernel);
        this.auth = Objects.requireNonNull(auth);
        this.nanos = Objects.requireNonNull(nanos);
    }

    @Override
    @ProtocolEndpoint
    @Transactional(propagation = Propagation.NOT_SUPPORTED)
    public ResponseEntity<byte[]> bootstrap(InputStream body) {
        return execute(body, false);
    }

    @Override
    @ProtocolEndpoint
    @Transactional(propagation = Propagation.NOT_SUPPORTED)
    public ResponseEntity<byte[]> heartbeat(InputStream body) {
        return execute(body, true);
    }

    private ResponseEntity<byte[]> execute(InputStream body, boolean heartbeat) {
        if (!feature.enabled()) {
            return error(heartbeat ? "heartbeat" : "bootstrap", RuntimeErrorCode.DENIED);
        }
        Budget budget = new Budget();
        String operation = heartbeat ? "heartbeat" : "bootstrap";
        try {
            var peer = RuntimeProxyTransport.currentPeer().orElseThrow(() -> failure(RuntimeErrorCode.UNAUTHENTICATED));
            byte[] bytes = readBody(body, budget);
            return heartbeat
                    ? heartbeat(codec.readClaimHeartbeatRequest(bytes), peer, budget)
                    : bootstrap(codec.readBootstrapRequest(bytes), peer, budget);
        } catch (ProtocolException failure) {
            if (budget.transitionStarted) {
                return error(operation, RuntimeErrorCode.UNKNOWN_OUTCOME);
            }
            return error(operation, switch (failure.reason()) {
                case UNSUPPORTED_VERSION -> RuntimeErrorCode.UNSUPPORTED_VERSION;
                case INPUT_TOO_LARGE, LIMIT_EXCEEDED -> RuntimeErrorCode.LIMIT_EXCEEDED;
                default -> RuntimeErrorCode.INVALID_REQUEST;
            });
        } catch (Rejected failure) {
            return error(operation, failure.code);
        } catch (AiRuntimeOperationBudget.Unavailable unavailable) {
            return error(operation,
                    unavailable.interrupted() ? RuntimeErrorCode.INTERRUPTED : RuntimeErrorCode.UNAVAILABLE);
        } catch (IOException | RuntimeException failure) {
            return error(operation,
                    budget.transitionStarted ? RuntimeErrorCode.UNKNOWN_OUTCOME : RuntimeErrorCode.UNAVAILABLE);
        }
    }

    private ResponseEntity<byte[]> bootstrap(BootstrapRequest request, RuntimeProxyCertificateClaims peer,
            Budget budget) {
        RunSnapshot run = pinned(request.runId(), request.attemptId(), request.podUid(), peer, budget);
        currentActor(run, budget);
        budget.beforeTransition();
        Transition<Claim> result = kernel
                .bootstrap(
                        new Expected(run.spec().runId(), run.attempt().spec().attemptId(), run.revision(), run.fence()),
                        new WorkloadRef(peer.cluster(), peer.podUid().toString()), budget.operation);
        if (result.status() == Status.PENDING) {
            budget.check();
            byte[] bytes = codec.writeBootstrapReply(new BootstrapPendingReply(1, 500));
            budget.check();
            return response(200, bytes);
        }
        Claim claim = accepted(result);
        budget.check();
        byte[] bytes = codec
                .writeBootstrapReply(new BootstrapClaimedReply(1, wire(claim.binding()), claim.leaseUntil()));
        budget.check();
        return response(200, bytes);
    }

    private ResponseEntity<byte[]> heartbeat(ClaimHeartbeatRequest request, RuntimeProxyCertificateClaims peer,
            Budget budget) {
        var binding = request.binding();
        RunSnapshot run = pinned(binding.runId(), binding.attemptId(), binding.podUid(), peer, budget);
        ClaimBinding stored = run
                .attempt()
                .claim()
                .orElseThrow(() -> failure(RuntimeErrorCode.STALE_BINDING))
                .binding();
        if (!wire(stored).equals(binding) || !stored.workload().cluster().equals(peer.cluster())) {
            throw failure(RuntimeErrorCode.STALE_BINDING);
        }
        currentActor(run, budget);
        budget.beforeTransition();
        Claim claim = accepted(kernel.heartbeat(stored, request.sequence(), budget.operation));
        budget.check();
        byte[] bytes = codec
                .writeClaimHeartbeatReply(new ClaimHeartbeatReply(1, wire(claim.binding()), claim.heartbeatSequence(),
                        claim.leaseUntil()));
        budget.check();
        return response(200, bytes);
    }

    private RunSnapshot pinned(UUID runId, UUID attemptId, UUID podUid, RuntimeProxyCertificateClaims peer,
            Budget budget) {
        if (!peer.podUid().equals(podUid)) {
            throw failure(RuntimeErrorCode.DENIED);
        }
        budget.check();
        RunSnapshot run = kernel
                .snapshot(runId, budget.operation)
                .orElseThrow(() -> failure(RuntimeErrorCode.UNAVAILABLE));
        budget.check();
        if (!run.spec().runId().equals(runId) || !run.attempt().spec().attemptId().equals(attemptId)) {
            throw failure(RuntimeErrorCode.UNAVAILABLE);
        }
        var launch = run.attempt().spec().launch();
        if (!launch.equals(run.launch().spec()) || !launch.cluster().equals(peer.cluster())
                || !launch.namespaceName().equals(peer.namespace())
                || !launch.serviceAccountName().equals(peer.serviceAccount())) {
            throw failure(RuntimeErrorCode.UNAVAILABLE);
        }
        var ref = new WorkloadRef(peer.cluster(), peer.podUid().toString());
        var workload = run
                .workloads()
                .stream()
                .filter(row -> row.ref().equals(ref))
                .findFirst()
                .orElseThrow(() -> failure(RuntimeErrorCode.UNAVAILABLE));
        if (!workload.podName().equals(peer.podName())
                || run.launch().jobUid().filter(workload.jobUid()::equals).isEmpty()
                || (workload.state() != WorkloadState.ELIGIBLE && workload.state() != WorkloadState.REGISTERED)) {
            throw failure(RuntimeErrorCode.UNAVAILABLE);
        }
        return run;
    }

    private void currentActor(RunSnapshot run, Budget budget) {
        AuthenticationInfo info;
        try {
            info = auth.authenticateByUserUuidAuthoritatively(run.spec().actorId(), budget.remaining());
        } catch (RuntimeException failure) {
            budget.check();
            throw failure(RuntimeErrorCode.UNAVAILABLE);
        }
        budget.check();
        if (info == null || info.isAnonymous() || !run.spec().actorId().toString().equals(info.getUserUuid())
                || info.getRawData() == null) {
            throw failure(RuntimeErrorCode.UNAVAILABLE);
        }
    }

    private static Claim accepted(Transition<Claim> result) {
        if (result.status() == Status.APPLIED || result.status() == Status.REPLAY) {
            return result.value().orElseThrow(() -> failure(RuntimeErrorCode.UNKNOWN_OUTCOME));
        }
        throw failure(switch (result.status()) {
            case STALE -> RuntimeErrorCode.STALE_BINDING;
            case EXPIRED -> RuntimeErrorCode.EXPIRED;
            case CANCELLED -> RuntimeErrorCode.CANCELLED;
            case CONFLICT -> RuntimeErrorCode.CONFLICT;
            case LIMIT_REACHED -> RuntimeErrorCode.LIMIT_EXCEEDED;
            case DENIED, LOSER -> RuntimeErrorCode.DENIED;
            default -> RuntimeErrorCode.UNKNOWN_OUTCOME;
        });
    }

    private byte[] readBody(InputStream body, Budget budget) throws IOException {
        if (body == null) {
            throw failure(RuntimeErrorCode.INVALID_REQUEST);
        }
        byte[] bytes = new byte[MAX_BODY + 1];
        int size = 0;
        while (size < bytes.length) {
            budget.check();
            int read = body.read(bytes, size, bytes.length - size);
            budget.check();
            if (read < 0) {
                return Arrays.copyOf(bytes, size);
            }
            if (read == 0) {
                budget.check();
                int value = body.read();
                budget.check();
                if (value < 0) {
                    return Arrays.copyOf(bytes, size);
                }
                bytes[size++] = (byte) value;
            } else {
                size += read;
            }
        }
        throw failure(RuntimeErrorCode.LIMIT_EXCEEDED);
    }

    private static com.otilm.ai.runtime.protocol.ClaimBinding wire(ClaimBinding binding) {
        return new com.otilm.ai.runtime.protocol.ClaimBinding(binding.runId(), binding.attemptId(),
                UUID.fromString(binding.workload().podUid()), binding.claimId(), binding.fence());
    }

    private ResponseEntity<byte[]> error(String operation, RuntimeErrorCode code) {
        int status = switch (code) {
            case UNAUTHENTICATED -> 401;
            case DENIED -> 403;
            case LIMIT_EXCEEDED -> 413;
            case INVALID_REQUEST, UNSUPPORTED_VERSION -> 400;
            case UNAVAILABLE, UNKNOWN_OUTCOME, INTERRUPTED -> 503;
            default -> 409;
        };
        UUID correlation = UUID.randomUUID();
        byte[] bytes = codec.writeRuntimeError(new RuntimeErrorReply(1, code, correlation));
        if (code == RuntimeErrorCode.UNAVAILABLE || code == RuntimeErrorCode.UNKNOWN_OUTCOME) {
            LOG.warn("AI runner operation={} code={} correlation={}", operation, code.name(), correlation);
        } else {
            LOG.debug("AI runner operation={} code={} correlation={}", operation, code.name(), correlation);
        }
        return response(status, bytes);
    }

    private static ResponseEntity<byte[]> response(int status, byte[] bytes) {
        return ResponseEntity
                .status(status)
                .contentType(MediaType.APPLICATION_JSON)
                .cacheControl(CacheControl.noStore())
                .body(bytes);
    }

    private static Rejected failure(RuntimeErrorCode code) {
        return new Rejected(code);
    }

    private static final class Rejected extends RuntimeException implements PlatformException {
        private static final long serialVersionUID = 1L;
        private final RuntimeErrorCode code;

        private Rejected(RuntimeErrorCode code) {
            super(code.name(), null, false, false);
            this.code = code;
        }
    }

    private final class Budget {
        private final AiRuntimeOperationBudget operation = AiRuntimeOperationBudget.start(nanos);
        private boolean transitionStarted;

        private Duration remaining() {
            try {
                return operation.remaining();
            } catch (AiRuntimeOperationBudget.Unavailable unavailable) {
                if (transitionStarted) {
                    throw failure(RuntimeErrorCode.UNKNOWN_OUTCOME);
                }
                throw failure(unavailable.interrupted() ? RuntimeErrorCode.INTERRUPTED : RuntimeErrorCode.UNAVAILABLE);
            }
        }

        private void beforeTransition() {
            check();
            transitionStarted = true;
        }

        private void check() {
            remaining();
        }
    }
}
