package com.otilm.core.service.ai;

import com.otilm.core.aop.TraceMetadataOnly;
import com.otilm.core.dao.repository.ai.AiRuntimeRepository;
import com.otilm.core.model.ai.AiRuntimeState.AttemptSpec;
import com.otilm.core.model.ai.AiRuntimeState.Claim;
import com.otilm.core.model.ai.AiRuntimeState.ClaimBinding;
import com.otilm.core.model.ai.AiRuntimeState.ControlPins;
import com.otilm.core.model.ai.AiRuntimeState.ControlSnapshot;
import com.otilm.core.model.ai.AiRuntimeState.ControlVersion;
import com.otilm.core.model.ai.AiRuntimeState.Expected;
import com.otilm.core.model.ai.AiRuntimeState.ReadinessObservation;
import com.otilm.core.model.ai.AiRuntimeState.RunSnapshot;
import com.otilm.core.model.ai.AiRuntimeState.RunSpec;
import com.otilm.core.model.ai.AiRuntimeState.Status;
import com.otilm.core.model.ai.AiRuntimeState.Transition;
import com.otilm.core.model.ai.AiRuntimeState.WorkloadObservation;
import com.otilm.core.model.ai.AiRuntimeState.WorkloadRef;
import com.otilm.core.service.writer.ai.AiRuntimeWriter;
import java.util.Objects;
import java.util.Optional;
import java.util.UUID;
import java.util.function.Supplier;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.dao.DataAccessException;
import org.springframework.stereotype.Service;
import org.springframework.transaction.TransactionException;
import org.springframework.transaction.annotation.Propagation;
import org.springframework.transaction.annotation.Transactional;

@Service
@TraceMetadataOnly
public class AiRuntimeKernel {
    private static final Logger LOGGER = LoggerFactory.getLogger(AiRuntimeKernel.class);
    private final AiFeatureGate feature;
    private final AiRuntimeRepository repository;
    private final AiRuntimeWriter writer;

    public AiRuntimeKernel(AiRuntimeRepository repository, AiRuntimeWriter writer, AiFeatureGate feature) {
        this.feature = Objects.requireNonNull(feature);
        this.repository = repository;
        this.writer = writer;
    }

    @Transactional(propagation = Propagation.NOT_SUPPORTED)
    public Optional<ControlSnapshot> control() {
        Optional<ControlSnapshot> result = access("CONTROL_SNAPSHOT", null, repository::control);
        decision("CONTROL_SNAPSHOT", null, result.isPresent() ? "PRESENT" : "ABSENT");
        return result;
    }

    @Transactional(propagation = Propagation.NOT_SUPPORTED)
    public Optional<ControlSnapshot> control(AiRuntimeOperationBudget budget) {
        java.util.Objects.requireNonNull(budget).remaining();
        Optional<ControlSnapshot> result = access("CONTROL_SNAPSHOT", null, () -> writer.control(budget));
        decision("CONTROL_SNAPSHOT", null, result.isPresent() ? "PRESENT" : "ABSENT");
        return result;
    }

    @Transactional(propagation = Propagation.NOT_SUPPORTED)
    public Optional<RunSnapshot> snapshot(UUID runId, AiRuntimeOperationBudget budget) {
        java.util.Objects.requireNonNull(budget).remaining();
        Optional<RunSnapshot> result = access("SNAPSHOT", runId, () -> writer.snapshot(runId, budget));
        decision("SNAPSHOT", runId, result.isPresent() ? "PRESENT" : "ABSENT");
        return result;
    }

    @Transactional(propagation = Propagation.NOT_SUPPORTED)
    public Transition<Void> observe(WorkloadObservation observation, AiRuntimeOperationBudget budget) {
        if (!feature.enabled()) {
            return disabled("OBSERVE");
        }
        java.util.Objects.requireNonNull(budget).remaining();
        return boundedTransition("OBSERVE", observation.expected().runId(), () -> writer.observe(observation, budget));
    }

    @Transactional(propagation = Propagation.NOT_SUPPORTED)
    public Transition<Void> invalidate(Expected expected, AiRuntimeOperationBudget budget) {
        java.util.Objects.requireNonNull(budget).remaining();
        return boundedTransition("INVALIDATE", expected.runId(), () -> writer.invalidate(expected, budget));
    }

    /** Local transitions only; no production readiness producer or administrator entrypoint is installed. */
    @Transactional(propagation = Propagation.NOT_SUPPORTED)
    public Transition<ControlSnapshot> changeControl(ControlVersion expected, ControlPins pins) {
        return transition("CONTROL_CHANGE", null, () -> writer.changeControl(expected, pins));
    }

    @Transactional(propagation = Propagation.NOT_SUPPORTED)
    public Transition<Void> observeControl(ReadinessObservation observation) {
        return transition("CONTROL_OBSERVE", null, () -> writer.observeControl(observation));
    }

    @Transactional(propagation = Propagation.NOT_SUPPORTED)
    public Transition<Void> enableControl(ControlVersion expected) {
        if (!feature.enabled()) {
            return disabled("CONTROL_ENABLE");
        }
        return transition("CONTROL_ENABLE", null, () -> writer.enableControl(expected));
    }

    @Transactional(propagation = Propagation.NOT_SUPPORTED)
    public Transition<Void> disableControl(ControlVersion expected) {
        return transition("CONTROL_DISABLE", null, () -> writer.disableControl(expected));
    }

    @Transactional(propagation = Propagation.NOT_SUPPORTED)
    public RunSnapshot create(ControlVersion expectedControl, RunSpec run, AttemptSpec attempt) {
        feature.requireEnabled();
        RunSnapshot result = access("CREATE", run.runId(), () -> writer.create(expectedControl, run, attempt));
        decision("CREATE", run.runId(), "APPLIED");
        return result;
    }

    @Transactional(propagation = Propagation.NOT_SUPPORTED)
    public Optional<RunSnapshot> snapshot(UUID runId) {
        Optional<RunSnapshot> result = access("SNAPSHOT", runId, () -> repository.snapshot(runId));
        decision("SNAPSHOT", runId, result.isPresent() ? "PRESENT" : "ABSENT");
        return result;
    }

    @Transactional(propagation = Propagation.NOT_SUPPORTED)
    public Transition<Void> observe(WorkloadObservation observation) {
        if (!feature.enabled()) {
            return disabled("OBSERVE");
        }
        return transition("OBSERVE", observation.expected().runId(), () -> writer.observe(observation));
    }

    @Transactional(propagation = Propagation.NOT_SUPPORTED)
    public Transition<Claim> bootstrap(Expected expected, WorkloadRef workload) {
        if (!feature.enabled()) {
            return disabled("BOOTSTRAP");
        }
        return transition("BOOTSTRAP", expected.runId(), () -> writer.bootstrap(expected, workload));
    }

    @Transactional(propagation = Propagation.NOT_SUPPORTED)
    public Transition<Claim> heartbeat(ClaimBinding claim, long sequence) {
        if (!feature.enabled()) {
            return disabled("HEARTBEAT");
        }
        return transition("HEARTBEAT", claim == null ? null : claim.runId(), () -> writer.heartbeat(claim, sequence));
    }

    @Transactional(propagation = Propagation.NOT_SUPPORTED)
    public Transition<Claim> bootstrap(Expected expected, WorkloadRef workload, AiRuntimeOperationBudget budget) {
        if (!feature.enabled()) {
            return disabled("BOOTSTRAP");
        }
        java.util.Objects.requireNonNull(budget).remaining();
        return boundedTransition("BOOTSTRAP", expected.runId(), () -> writer.bootstrap(expected, workload, budget));
    }

    @Transactional(propagation = Propagation.NOT_SUPPORTED)
    public Transition<Claim> heartbeat(ClaimBinding claim, long sequence, AiRuntimeOperationBudget budget) {
        if (!feature.enabled()) {
            return disabled("HEARTBEAT");
        }
        java.util.Objects.requireNonNull(budget).remaining();
        return boundedTransition("HEARTBEAT", claim == null ? null : claim.runId(),
                () -> writer.heartbeat(claim, sequence, budget));
    }

    @Transactional(propagation = Propagation.NOT_SUPPORTED)
    public Transition<Void> cancel(UUID runId) {
        return transition("CANCEL", runId, () -> writer.cancel(runId));
    }

    @Transactional(propagation = Propagation.NOT_SUPPORTED)
    public Transition<Void> invalidate(Expected expected) {
        return transition("INVALIDATE", expected.runId(), () -> writer.invalidate(expected));
    }

    @Transactional(propagation = Propagation.NOT_SUPPORTED)
    public Transition<Void> expire(Expected expected) {
        return transition("EXPIRE", expected.runId(), () -> writer.expire(expected));
    }

    @Transactional(propagation = Propagation.NOT_SUPPORTED)
    public Transition<RunSnapshot> replace(Expected expected, AttemptSpec next) {
        if (!feature.enabled()) {
            return disabled("REPLACE");
        }
        return transition("REPLACE", expected.runId(), () -> writer.replace(expected, next));
    }

    private static <T> Transition<T> disabled(String operation) {
        decision(operation, null, Status.DENIED.name());
        return Transition.empty(Status.DENIED);
    }

    private static <T> Transition<T> transition(String operation, UUID runId, Supplier<Transition<T>> action) {
        Transition<T> result;
        try {
            result = access(operation, runId, action);
        } catch (AiRuntimeWriter.Rejected | DataAccessException | TransactionException exception) {
            result = Transition.empty(Status.CONFLICT);
        }
        decision(operation, runId, result.status().name());
        return result;
    }

    private static <T> Transition<T> boundedTransition(String operation, UUID runId, Supplier<Transition<T>> action) {
        Transition<T> result;
        try {
            result = access(operation, runId, action);
        } catch (AiRuntimeWriter.Rejected definiteRollback) {
            result = Transition.empty(Status.CONFLICT);
        }
        decision(operation, runId, result.status().name());
        return result;
    }

    private static <T> T access(String operation, UUID runId, Supplier<T> action) {
        try {
            return action.get();
        } catch (DataAccessException | TransactionException failure) {
            LOGGER.warn("AI runtime persistence failure operation={} status=UNAVAILABLE run={}", operation, runId);
            throw failure;
        }
    }

    private static void decision(String operation, UUID runId, String status) {
        LOGGER.debug("AI runtime operation={} status={} run={}", operation, status, runId);
    }
}
