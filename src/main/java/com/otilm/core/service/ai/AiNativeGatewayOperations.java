package com.otilm.core.service.ai;

import com.otilm.ai.runtime.protocol.ManagementDispatchEnvelope;
import com.otilm.ai.runtime.protocol.ProtocolCodec;
import com.otilm.ai.runtime.protocol.RunDispatchEnvelope;
import com.otilm.ai.runtime.protocol.RuntimeErrorCode;
import com.otilm.ai.runtime.protocol.RuntimeErrorReply;
import com.otilm.core.aop.TraceMetadataOnly;
import com.otilm.core.model.ai.AiModelDispatchState.ResolvedDispatch;
import com.otilm.core.model.ai.AiRuntimeState.Status;
import com.otilm.core.security.ai.AiRuntimeGatewayAuthority;
import com.otilm.core.security.ai.AiRuntimeManagementGatewayAuthority;
import com.otilm.core.security.ai.RuntimePeer;
import com.otilm.core.security.ai.RuntimePeerRole;
import com.otilm.core.security.ai.RuntimeProxyTransport;
import com.otilm.core.service.writer.ai.AiModelManagementGatewayWriter;
import com.otilm.core.service.writer.ai.AiModelManagementOutcomeWriter;
import com.otilm.core.service.writer.ai.AiModelRunOutcomeWriter;
import java.io.IOException;
import java.io.InputStream;
import java.time.Instant;
import java.util.Objects;
import java.util.Optional;
import java.util.UUID;
import java.util.function.LongSupplier;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.CacheControl;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.AccessDeniedException;

/** Closed native HTTP phase handling. Fixed typed factories only; no caller-supplied role, policy or effect hook. */
@TraceMetadataOnly
final class AiNativeGatewayOperations {
    private final AiFeatureGate feature;
    private final Ports ports;
    private final LongSupplier nanos;
    private final Logger log;
    private final AiRuntimeGatewayWire runWire = new AiRuntimeGatewayWire();
    private final AiRuntimeManagementWire managementWire = new AiRuntimeManagementWire();
    private final ProtocolCodec codec = new ProtocolCodec();

    private AiNativeGatewayOperations(Ports ports, LongSupplier nanos, Class<?> owner, AiFeatureGate feature) {
        this.feature = Objects.requireNonNull(feature);
        this.ports = ports;
        this.nanos = Objects.requireNonNull(nanos);
        this.log = LoggerFactory.getLogger(owner);
    }

    static AiNativeGatewayOperations run(AiRuntimeGatewayAuthority authority, AiModelRunDispatchService dispatch,
            AiModelRunOutcomeWriter outcomes, LongSupplier nanos, AiFeatureGate feature) {
        return new AiNativeGatewayOperations(new Run(Objects.requireNonNull(authority),
                Objects.requireNonNull(dispatch), Objects.requireNonNull(outcomes)), nanos,
                AiRuntimeGatewayServiceImpl.class, feature);
    }

    static AiNativeGatewayOperations management(AiRuntimeManagementGatewayAuthority authority,
            AiModelManagementDispatchService dispatch, AiModelManagementGatewayWriter assignments,
            AiModelManagementOutcomeWriter outcomes, LongSupplier nanos, AiFeatureGate feature) {
        return new AiNativeGatewayOperations(
                new Management(Objects.requireNonNull(authority), Objects.requireNonNull(dispatch),
                        Objects.requireNonNull(assignments), Objects.requireNonNull(outcomes)),
                nanos, AiRuntimeManagementGatewayServiceImpl.class, feature);
    }

    ResponseEntity<byte[]> registration() {
        var budget = AiRuntimeOperationBudget.start(nanos);
        try {
            var peer = RuntimeProxyTransport.currentWorkloadPeer().orElse(null);
            if (peer == null) {
                return error("registration", RuntimeErrorCode.UNAUTHENTICATED);
            }
            boolean management = ports instanceof Management;
            if (peer.role() != (management ? RuntimePeerRole.GATEWAY_MANAGEMENT : RuntimePeerRole.GATEWAY_RUN)) {
                return error("registration", RuntimeErrorCode.DENIED);
            }
            boolean ready = feature.enabled() && (management
                    ? ((Management) ports).authority.current(peer, budget).isPresent()
                    : ((Run) ports).authority.current(peer, budget).isPresent());
            budget.remaining();
            return response(200, AiRuntimeRegistrationWire.reply(management, ready));
        } catch (AccessDeniedException denied) {
            return error("registration", RuntimeErrorCode.DENIED);
        } catch (AiRuntimeOperationBudget.Unavailable unavailable) {
            return error("registration",
                    unavailable.interrupted() ? RuntimeErrorCode.INTERRUPTED : RuntimeErrorCode.UNAVAILABLE);
        } catch (RuntimeException unavailable) {
            return error("registration", RuntimeErrorCode.UNAVAILABLE);
        }
    }

    ResponseEntity<byte[]> redeem(InputStream body) {
        if (!feature.enabled()) {
            return error("redeem", RuntimeErrorCode.DENIED);
        }
        return execute(body, false);
    }

    ResponseEntity<byte[]> outcome(InputStream body) {
        return execute(body, true);
    }

    private ResponseEntity<byte[]> execute(InputStream body, boolean outcome) {
        var step = new Step(AiRuntimeOperationBudget.start(nanos));
        String operation = outcome ? "outcome" : "redeem";
        try {
            return authorizedRequest(body, outcome, step, operation);
        } catch (AiModelRunDispatchService.Failure failure) {
            return error(operation, failure.code());
        } catch (AiModelManagementDispatchService.Failure failure) {
            return error(operation, failure.code());
        } catch (AiRuntimeRequestBody.LimitExceeded failure) {
            return error(operation, RuntimeErrorCode.LIMIT_EXCEEDED);
        } catch (IllegalArgumentException failure) {
            return error(operation, step, RuntimeErrorCode.INVALID_REQUEST);
        } catch (AccessDeniedException failure) {
            return error(operation, step, RuntimeErrorCode.DENIED);
        } catch (AiRuntimeOperationBudget.Unavailable failure) {
            return error(operation, step,
                    failure.interrupted() ? RuntimeErrorCode.INTERRUPTED : RuntimeErrorCode.UNAVAILABLE);
        } catch (IOException | RuntimeException failure) {
            return error(operation, step, RuntimeErrorCode.UNAVAILABLE);
        }
    }

    private ResponseEntity<byte[]> authorizedRequest(InputStream body, boolean outcome, Step step, String operation)
            throws IOException {
        step.budget.remaining();
        var peer = RuntimeProxyTransport.currentWorkloadPeer().orElse(null);
        if (peer == null) {
            return error(operation, RuntimeErrorCode.UNAUTHENTICATED);
        }
        if (ports instanceof Run run) {
            if (peer.role() != RuntimePeerRole.GATEWAY_RUN) {
                return error(operation, RuntimeErrorCode.DENIED);
            }
            run.authority.requireCurrent(peer, step.budget);
        } else {
            var management = (Management) ports;
            if (peer.role() != RuntimePeerRole.GATEWAY_MANAGEMENT) {
                return error(operation, RuntimeErrorCode.DENIED);
            }
            management.authority.requireCurrent(peer, step.budget);
        }
        byte[] bytes = AiRuntimeRequestBody.read(body, outcome ? 1500000 : 8192, step.budget);
        return outcome ? append(bytes, peer, step) : consume(bytes, peer, step);
    }

    private ResponseEntity<byte[]> consume(byte[] bytes, RuntimePeer peer, Step step) {
        var request = AiRuntimeGatewayWire.parseRedeem(bytes);
        var envelope = request.envelope();
        Optional<ResolvedDispatch> resolved;
        Instant expiry;
        if (ports instanceof Run run && envelope instanceof RunDispatchEnvelope typed) {
            expiry = typed.binding().expiresAt();
            run.outcomes.requireAssigned(typed.intentId(), peer, step.budget);
            step.budget.remaining();
            step.writerStarted = true;
            resolved = run.dispatch.consume(typed, request.correlation(), peer, step.budget);
        } else if (ports instanceof Management management && envelope instanceof ManagementDispatchEnvelope typed) {
            expiry = typed.binding().expiresAt();
            management.assignments.requireAssigned(typed.intentId(), peer, step.budget);
            step.budget.remaining();
            step.writerStarted = true;
            resolved = management.dispatch.consume(typed, request.correlation(), peer, step.budget);
        } else {
            throw AiRuntimeGatewayWire.invalid();
        }
        step.budget.remaining();
        if (resolved.isEmpty()) {
            return error("redeem", RuntimeErrorCode.DENIED);
        }
        var value = resolved.orElseThrow();
        if (!value.intentId().equals(envelope.intentId()) || !value.gatewayCorrelation().equals(request.correlation())
                || !value.payload().sha256().equals(envelope.payloadSha256()) || !value.expiresAt().equals(expiry)) {
            return error("redeem", RuntimeErrorCode.UNKNOWN_OUTCOME);
        }
        byte[] reply = envelope instanceof RunDispatchEnvelope typed
                ? runWire.consumedReply(value, typed.binding())
                : managementWire.consumedReply(value, ((ManagementDispatchEnvelope) envelope).binding());
        step.budget.remaining();
        return response(200, reply);
    }

    private ResponseEntity<byte[]> append(byte[] bytes, RuntimePeer peer, Step step) {
        Recorded recorded;
        if (ports instanceof Run run) {
            var request = runWire.readOutcome(bytes);
            step.budget.remaining();
            step.writerStarted = true;
            var result = run.outcomes.append(request, peer, step.budget);
            step.budget.remaining();
            recorded = new Recorded(result.status(), result
                    .value()
                    .map(r -> new Receipt(r.intentId(), r.gatewayCorrelation(), r.outcomeSha256(), r.resultVersion())),
                    request.intentId(), request.gatewayCorrelation(), request.outcomeSha256());
        } else {
            var management = (Management) ports;
            var request = managementWire.readOutcome(bytes);
            step.budget.remaining();
            step.writerStarted = true;
            var result = management.outcomes.append(request, peer, step.budget);
            step.budget.remaining();
            recorded = new Recorded(result.status(), result
                    .value()
                    .map(r -> new Receipt(r.intentId(), r.gatewayCorrelation(), r.outcomeSha256(), r.resultVersion())),
                    request.intentId(), request.gatewayCorrelation(), request.outcomeSha256());
        }
        if (recorded.receipt.isEmpty()) {
            return error("outcome", switch (recorded.status) {
                case CONFLICT -> RuntimeErrorCode.CONFLICT;
                case DENIED -> RuntimeErrorCode.DENIED;
                default -> RuntimeErrorCode.UNKNOWN_OUTCOME;
            });
        }
        if (recorded.status != Status.APPLIED && recorded.status != Status.REPLAY) {
            return error("outcome", RuntimeErrorCode.UNKNOWN_OUTCOME);
        }
        var receipt = recorded.receipt.orElseThrow();
        if (!receipt.intent.equals(recorded.intent) || !receipt.correlation.equals(recorded.correlation)
                || !receipt.sha.equals(recorded.sha)) {
            return error("outcome", RuntimeErrorCode.UNKNOWN_OUTCOME);
        }
        byte[] reply = ports instanceof Run
                ? runWire.acknowledgement(receipt.intent, receipt.correlation, receipt.sha, receipt.version)
                : managementWire.acknowledgement(receipt.intent, receipt.correlation, receipt.sha, receipt.version);
        step.budget.remaining();
        return response(200, reply);
    }

    private ResponseEntity<byte[]> error(String operation, Step step, RuntimeErrorCode code) {
        return error(operation, step.writerStarted ? RuntimeErrorCode.UNKNOWN_OUTCOME : code);
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
        if (code == RuntimeErrorCode.UNAVAILABLE || code == RuntimeErrorCode.UNKNOWN_OUTCOME) {
            log.warn("AI gateway operation={} code={} correlation={}", operation, code.name(), correlation);
        } else {
            log.debug("AI gateway operation={} code={} correlation={}", operation, code.name(), correlation);
        }
        return response(status, codec.writeRuntimeError(new RuntimeErrorReply(1, code, correlation)));
    }

    private static ResponseEntity<byte[]> response(int status, byte[] bytes) {
        return ResponseEntity
                .status(status)
                .contentType(MediaType.APPLICATION_JSON)
                .cacheControl(CacheControl.noStore())
                .body(bytes);
    }

    private sealed interface Ports permits Run, Management {
    }

    private record Run(AiRuntimeGatewayAuthority authority, AiModelRunDispatchService dispatch,
            AiModelRunOutcomeWriter outcomes) implements Ports {
    }

    private record Management(AiRuntimeManagementGatewayAuthority authority, AiModelManagementDispatchService dispatch,
            AiModelManagementGatewayWriter assignments, AiModelManagementOutcomeWriter outcomes) implements Ports {
    }

    private record Receipt(UUID intent, UUID correlation, String sha, long version) {
    }

    private record Recorded(Status status, Optional<Receipt> receipt, UUID intent, UUID correlation, String sha) {
    }

    private static final class Step {
        private final AiRuntimeOperationBudget budget;
        private boolean writerStarted;

        private Step(AiRuntimeOperationBudget budget) {
            this.budget = budget;
        }
    }
}
