package com.otilm.core.service.ai;

import com.otilm.ai.runtime.protocol.RunBinding;
import com.otilm.ai.runtime.protocol.RunDispatchEnvelope;
import com.otilm.ai.runtime.protocol.RuntimeErrorCode;
import com.otilm.api.exception.PlatformException;
import com.otilm.core.aop.TraceMetadataOnly;
import com.otilm.core.model.ai.AiModelDispatchPayload;
import com.otilm.core.model.ai.AiModelDispatchState;
import com.otilm.core.model.ai.AiModelRunInput;
import com.otilm.core.model.ai.AiRuntimeState;
import com.otilm.core.security.ai.AiModelCertificateContext;
import com.otilm.core.security.ai.AiModelUseAuthorization;
import com.otilm.core.security.ai.CertificateReadScope;
import com.otilm.core.security.ai.RuntimePeer;
import com.otilm.core.security.ai.RuntimePeerRole;
import com.otilm.core.serialization.ObjectMapperFactory;
import com.otilm.core.service.handler.StoredCertificateHealth;
import com.otilm.core.service.writer.ai.AiModelDispatchWriter;
import com.otilm.core.service.writer.ai.AiModelRunInputWriter;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import java.util.UUID;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Propagation;
import org.springframework.transaction.annotation.Transactional;
import tools.jackson.databind.json.JsonMapper;

/** Composes stored run input and fresh business authorization before durable single-use dispatch. */
@Service
@TraceMetadataOnly
public class AiModelRunDispatchService {
    private static final String PREPARE_OPERATION = "prepare";
    private static final String CONSUME_OPERATION = "consume";
    private static final Logger LOG = LoggerFactory.getLogger(AiModelRunDispatchService.class);
    private static final JsonMapper JSON = ObjectMapperFactory.aiRunContext();
    private final AiFeatureGate feature;
    private final AiRuntimeKernel kernel;
    private final AiModelRunInputWriter inputs;
    private final AiModelDispatchWriter writer;
    private final AiModelUseAuthorization models;
    private final AiModelCertificateContext contexts;

    public AiModelRunDispatchService(AiRuntimeKernel kernel, AiModelRunInputWriter inputs, AiModelDispatchWriter writer,
            AiModelUseAuthorization models, AiModelCertificateContext contexts, AiFeatureGate feature) {
        this.feature = Objects.requireNonNull(feature);
        this.kernel = Objects.requireNonNull(kernel);
        this.inputs = Objects.requireNonNull(inputs);
        this.writer = Objects.requireNonNull(writer);
        this.models = Objects.requireNonNull(models);
        this.contexts = Objects.requireNonNull(contexts);
    }

    @Transactional(propagation = Propagation.NOT_SUPPORTED)
    public AiRuntimeState.Transition<RunDispatchEnvelope> prepare(AiRuntimeState.ClaimBinding claim, UUID requestKey,
            AiRuntimeOperationBudget budget) {
        var step = new Step();
        try {
            feature.requireEnabled();
            budget.remaining();
            Objects.requireNonNull(requestKey);
            Facts facts = facts(claim, budget);
            var previous = writer.preparedRunByKey(claim.runId(), requestKey, budget);
            budget.remaining();
            AiModelDispatchState.RunIntent intent;
            if (previous.isPresent()) {
                intent = previous.orElseThrow();
                requireIntent(intent, facts, claim);
            } else {
                var payload = AiModelDispatchPayload
                        .text(facts.connection.modelIdentifier(), facts.input.outputTokens(),
                                facts.input.instructions(), facts.input.prompt(), observations(facts.observations));
                Instant expiry = facts.run.spec().runDeadline().isBefore(facts.run.attempt().spec().maxDeadline())
                        ? facts.run.spec().runDeadline()
                        : facts.run.attempt().spec().maxDeadline();
                intent = new AiModelDispatchState.RunIntent(UUID.randomUUID(), facts.run.spec().actorId(), claim,
                        facts.connection, payload, facts.input.outputTokens(), expiry.truncatedTo(ChronoUnit.MICROS));
            }
            var request = new AiModelDispatchState.RunPreparation(intent.intentId(), requestKey, expected(facts.run),
                    claim, facts.connection, intent.payload(), intent.outputTokens(), intent.expiresAt());
            var prepared = envelope(intent.intentId(), claim, intent.payload().sha256(), intent.expiresAt());
            budget.remaining();
            step.writerStarted = true;
            var result = writer.prepareRun(request, facts.run.spec().actorId(), budget);
            budget.remaining();
            if (result.value().isEmpty()) {
                log(PREPARE_OPERATION, result.status().name());
                return AiRuntimeState.Transition.empty(result.status());
            }
            var reply = new RunDispatchEnvelope(1, result.value().orElseThrow(), prepared.payloadSha256(),
                    prepared.binding());
            log(PREPARE_OPERATION, result.status().name());
            return AiRuntimeState.Transition.value(result.status(), reply);
        } catch (RuntimeException failure) {
            throw unavailable(PREPARE_OPERATION, step, failure);
        }
    }

    @Transactional(propagation = Propagation.NOT_SUPPORTED)
    public Optional<AiModelDispatchState.ResolvedDispatch> consume(RunDispatchEnvelope envelope,
            UUID gatewayCorrelation, AiRuntimeOperationBudget budget) {
        return consumeInternal(envelope, gatewayCorrelation, null, budget);
    }

    @Transactional(propagation = Propagation.NOT_SUPPORTED)
    public Optional<AiModelDispatchState.ResolvedDispatch> consume(RunDispatchEnvelope envelope,
            UUID gatewayCorrelation, RuntimePeer gateway, AiRuntimeOperationBudget budget) {
        if (gateway == null || gateway.role() != RuntimePeerRole.GATEWAY_RUN) {
            log(CONSUME_OPERATION, RuntimeErrorCode.DENIED.name());
            throw new Failure(RuntimeErrorCode.DENIED);
        }
        return consumeInternal(envelope, gatewayCorrelation, gateway, budget);
    }

    private Optional<AiModelDispatchState.ResolvedDispatch> consumeInternal(RunDispatchEnvelope envelope,
            UUID gatewayCorrelation, RuntimePeer gateway, AiRuntimeOperationBudget budget) {
        var step = new Step();
        try {
            feature.requireEnabled();
            budget.remaining();
            Objects.requireNonNull(gatewayCorrelation);
            var wire = Objects.requireNonNull(envelope).binding();
            var run = kernel.snapshot(wire.runId(), budget).orElseThrow(AiModelRunDispatchService::denied);
            budget.remaining();
            var claim = run.attempt().claim().orElseThrow(AiModelRunDispatchService::denied).binding();
            if (!envelope(envelope.intentId(), claim, envelope.payloadSha256(), wire.expiresAt()).equals(envelope)) {
                throw denied();
            }
            Facts facts = facts(run, claim, budget);
            var intent = writer
                    .preparedRunById(claim.runId(), envelope.intentId(), budget)
                    .orElseThrow(AiModelRunDispatchService::denied);
            budget.remaining();
            requireIntent(intent, facts, claim);
            if (!intent.payload().sha256().equals(envelope.payloadSha256())
                    || !intent.expiresAt().equals(wire.expiresAt())) {
                throw denied();
            }
            var request = new AiModelDispatchState.RunRedemption(intent.intentId(), expected(facts.run), claim,
                    facts.connection, envelope.payloadSha256(), intent.expiresAt(), gatewayCorrelation);
            budget.remaining();
            step.writerStarted = true;
            var result = gateway == null
                    ? writer.consumeRun(request, run.spec().actorId(), budget)
                    : writer.consumeRun(request, run.spec().actorId(), gateway, budget);
            budget.remaining();
            log(CONSUME_OPERATION, result.isPresent() ? "CONSUMED" : "DENIED");
            return result;
        } catch (RuntimeException failure) {
            throw unavailable(CONSUME_OPERATION, step, failure);
        }
    }

    private Facts facts(AiRuntimeState.ClaimBinding claim, AiRuntimeOperationBudget budget) {
        var run = kernel.snapshot(claim.runId(), budget).orElseThrow(AiModelRunDispatchService::denied);
        budget.remaining();
        return facts(run, claim, budget);
    }

    private Facts facts(AiRuntimeState.RunSnapshot run, AiRuntimeState.ClaimBinding claim,
            AiRuntimeOperationBudget budget) {
        requireClaim(run, claim);
        budget.remaining();
        var model = inputs.connection(claim.runId(), budget).orElseThrow(AiModelRunDispatchService::denied);
        budget.remaining();
        models.requireUse(run.spec().actorId(), model.id(), budget);
        budget.remaining();
        var input = inputs.read(claim.runId(), model, budget).orElseThrow(AiModelRunDispatchService::denied);
        budget.remaining();
        if (!input.runId().equals(claim.runId())) {
            throw denied();
        }
        var scope = new CertificateReadScope(input.raProfileUuid(), input.certificateUuids());
        var observations = contexts.read(run.spec().actorId(), model.id(), scope, budget);
        budget.remaining();
        var current = kernel.snapshot(claim.runId(), budget).orElseThrow(AiModelRunDispatchService::denied);
        budget.remaining();
        requireClaim(current, claim);
        if (!current.spec().equals(run.spec()) || !current.attempt().spec().equals(run.attempt().spec())
                || current.controlGeneration() != run.controlGeneration()) {
            throw denied();
        }
        return new Facts(current, model, input, List.copyOf(observations));
    }

    private static void requireClaim(AiRuntimeState.RunSnapshot run, AiRuntimeState.ClaimBinding claim) {
        if (run.state() != AiRuntimeState.RunState.RUNNING
                || run.attempt().state() != AiRuntimeState.AttemptState.CLAIMED
                || !run.spec().runId().equals(claim.runId())
                || !run.attempt().spec().attemptId().equals(claim.attemptId()) || run.fence() != claim.fence()
                || run.attempt().claim().filter(value -> value.binding().equals(claim)).isEmpty()) {
            throw denied();
        }
    }

    private static void requireIntent(AiModelDispatchState.RunIntent intent, Facts facts,
            AiRuntimeState.ClaimBinding claim) {
        if (!intent.actorId().equals(facts.run.spec().actorId()) || !intent.claim().equals(claim)
                || !intent.connection().equals(facts.connection)
                || intent.outputTokens() != facts.input.outputTokens()) {
            throw denied();
        }
    }

    private static AiRuntimeState.Expected expected(AiRuntimeState.RunSnapshot run) {
        return new AiRuntimeState.Expected(run.spec().runId(), run.attempt().spec().attemptId(), run.revision(),
                run.fence());
    }

    private static RunDispatchEnvelope envelope(UUID intent, AiRuntimeState.ClaimBinding claim, String digest,
            Instant expiry) {
        try {
            return new RunDispatchEnvelope(1, intent, digest, new RunBinding(claim.runId(), claim.attemptId(),
                    UUID.fromString(claim.workload().podUid()), claim.claimId(), claim.fence(), expiry));
        } catch (IllegalArgumentException invalid) {
            throw denied();
        }
    }

    private static String observations(List<StoredCertificateHealth> observations) {
        var root = JSON.createObjectNode().put("evidence", "OBSERVATIONS");
        var rows = root.putArray("certificates");
        for (var observation : observations) {
            var row = rows.addObject();
            row.put("certificateUuid", observation.certificateUuid().toString());
            row.put("raProfileUuid", observation.raProfileUuid().toString());
            row.put("commonName", observation.commonName());
            row.put("serialNumber", observation.serialNumber());
            row.put("issuerCommonName", observation.issuerCommonName());
            row.put("fingerprint", observation.fingerprint());
            row.put("notBefore", text(observation.notBefore()));
            row.put("notAfter", text(observation.notAfter()));
            row.put("state", text(observation.state()));
            row.put("validationStatus", text(observation.validationStatus()));
            row.put("validationTimestamp", text(observation.validationTimestamp()));
            row.put("evidence", text(observation.evidence()));
            var checks = row.putObject("checks");
            observation
                    .checks()
                    .entrySet()
                    .stream()
                    .sorted(java.util.Map.Entry.comparingByKey())
                    .forEach(check -> checks.put(check.getKey().getCode(), check.getValue().getCode()));
        }
        return JSON.writeValueAsString(root);
    }

    private static String text(Object value) {
        return value == null ? null : value.toString();
    }

    private static AccessDeniedException denied() {
        return new AccessDeniedException("Model run operation unavailable");
    }

    private static Failure unavailable(String operation, Step step, RuntimeException failure) {
        RuntimeErrorCode code;
        if (step.writerStarted) {
            code = RuntimeErrorCode.UNKNOWN_OUTCOME;
        } else if (Thread.currentThread().isInterrupted()) {
            code = RuntimeErrorCode.INTERRUPTED;
        } else if (failure instanceof AccessDeniedException) {
            code = RuntimeErrorCode.DENIED;
        } else if (failure instanceof AiRuntimeOperationBudget.Unavailable exhausted && exhausted.interrupted()) {
            code = RuntimeErrorCode.INTERRUPTED;
        } else {
            code = RuntimeErrorCode.UNAVAILABLE;
        }
        log(operation, code.name());
        return new Failure(code);
    }

    private static void log(String operation, String code) {
        LOG.debug("AI model run operation={} code={} correlation={}", operation, code, UUID.randomUUID());
    }

    private record Facts(AiRuntimeState.RunSnapshot run, AiModelDispatchState.ConnectionVersion connection,
            AiModelRunInput input, List<StoredCertificateHealth> observations) {
    }

    private static final class Step {
        private boolean writerStarted;
    }

    public static final class Failure extends RuntimeException implements PlatformException {
        private static final long serialVersionUID = 1L;
        private final RuntimeErrorCode code;

        private Failure(RuntimeErrorCode code) {
            super("Model run operation unavailable", null, false, false);
            this.code = code;
        }

        public RuntimeErrorCode code() {
            return code;
        }
    }
}
