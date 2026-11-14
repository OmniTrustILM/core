package com.otilm.core.service.writer.ai;

import com.otilm.api.exception.PlatformException;
import com.otilm.core.aop.TraceMetadataOnly;
import com.otilm.core.dao.repository.ai.AiModelDispatchRepository;
import com.otilm.core.dao.repository.ai.AiModelDispatchRepository.DispatchRow;
import com.otilm.core.dao.repository.ai.AiModelDispatchRepository.ReplayRow;
import com.otilm.core.dao.repository.ai.AiRuntimeRepository;
import com.otilm.core.model.ai.AiModelDispatchPayload;
import com.otilm.core.model.ai.AiModelDispatchState.ManagementIntent;
import com.otilm.core.model.ai.AiModelDispatchState.ManagementPreparation;
import com.otilm.core.model.ai.AiModelDispatchState.ManagementRedemption;
import com.otilm.core.model.ai.AiModelDispatchState.ResolvedDispatch;
import com.otilm.core.model.ai.AiModelDispatchState.RunIntent;
import com.otilm.core.model.ai.AiModelDispatchState.RunPreparation;
import com.otilm.core.model.ai.AiModelDispatchState.RunRedemption;
import com.otilm.core.model.ai.AiRuntimeState.Expected;
import com.otilm.core.model.ai.AiRuntimeState.Status;
import com.otilm.core.model.ai.AiRuntimeState.Transition;
import com.otilm.core.security.ai.RuntimePeer;
import com.otilm.core.service.ai.AiRuntimeOperationBudget;
import java.time.Instant;
import java.util.Objects;
import java.util.Optional;
import java.util.UUID;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

/** Internal durable component. Fresh actor/modelUSE and native audience gates must precede invocation. */
@Service
@TraceMetadataOnly
public class AiModelDispatchWriter {
    private final AiRuntimeRepository runtime;
    private final AiRuntimeDatabaseCalls database;
    private final AiModelDispatchRepository model;

    public AiModelDispatchWriter(AiRuntimeRepository runtime, AiModelDispatchRepository model) {
        this.runtime = Objects.requireNonNull(runtime);
        this.database = new AiRuntimeDatabaseCalls(this.runtime);
        this.model = Objects.requireNonNull(model);
    }

    @Transactional(readOnly = true, timeout = 5)
    public Optional<RunIntent> preparedRunByKey(UUID runId, UUID requestKey, AiRuntimeOperationBudget budget) {
        return database.query(budget, () -> model.preparedRunByKey(runId, requestKey));
    }

    @Transactional(readOnly = true, timeout = 5)
    public Optional<RunIntent> preparedRunById(UUID runId, UUID intentId, AiRuntimeOperationBudget budget) {
        return database.query(budget, () -> model.preparedRunById(runId, intentId));
    }

    @Transactional(readOnly = true, timeout = 5)
    public Optional<ManagementIntent> preparedManagementByKey(UUID sessionId, UUID requestKey,
            AiRuntimeOperationBudget budget) {
        return database.query(budget, () -> model.preparedManagementByKey(sessionId, requestKey));
    }

    @Transactional(readOnly = true, timeout = 5)
    public Optional<ManagementIntent> preparedManagementById(UUID sessionId, UUID intentId,
            AiRuntimeOperationBudget budget) {
        return database.query(budget, () -> model.preparedManagementById(sessionId, intentId));
    }

    @Transactional(timeout = 5)
    public Transition<UUID> prepareRun(RunPreparation request, AiRuntimeOperationBudget budget) {
        return prepareRunInternal(request, null, budget);
    }

    @Transactional(timeout = 5)
    public Transition<UUID> prepareRun(RunPreparation request, UUID authorizedActor, AiRuntimeOperationBudget budget) {
        return prepareRunInternal(request, Objects.requireNonNull(authorizedActor), budget);
    }

    private Transition<UUID> prepareRunInternal(RunPreparation request, UUID authorizedActor,
            AiRuntimeOperationBudget budget) {
        Objects.requireNonNull(request);
        Objects.requireNonNull(budget).remaining();
        if (!AiModelDispatchPayload
                .hasModelAndOutputLimit(request.payload(), request.outputTokens(),
                        request.connection().modelIdentifier())) {
            return Transition.empty(Status.DENIED);
        }
        if (!lockRun(request.expected(), request.connection().id(), authorizedActor, budget)) {
            return Transition.empty(Status.DENIED);
        }
        Instant cutoff = budget.databaseCutoff(database.query(budget, runtime::decisionTime));
        Optional<ReplayRow> replay = database.query(budget, () -> model.runReplay(request, request.expected()));
        if (!Boolean.TRUE
                .equals(database
                        .query(budget, () -> model.runPreparationCurrent(request, request.expected(), cutoff)))) {
            return Transition.empty(Status.DENIED);
        }
        if (replay.isPresent()) {
            return replay(replay.orElseThrow());
        }
        if (database.query(budget, () -> model.reserveRun(request, request.expected(), cutoff)) != 1) {
            return Transition.empty(Status.DENIED);
        }
        applied(database.query(budget, () -> model.insertRunIntent(request, request.expected(), cutoff)));
        return Transition.value(Status.APPLIED, request.intentId());
    }

    @Transactional(timeout = 5)
    public Optional<ResolvedDispatch> consumeRun(RunRedemption request, AiRuntimeOperationBudget budget) {
        return consumeRunInternal(request, null, null, budget);
    }

    @Transactional(timeout = 5)
    public Optional<ResolvedDispatch> consumeRun(RunRedemption request, UUID authorizedActor,
            AiRuntimeOperationBudget budget) {
        return consumeRunInternal(request, Objects.requireNonNull(authorizedActor), null, budget);
    }

    @Transactional(timeout = 5)
    public Optional<ResolvedDispatch> consumeRun(RunRedemption request, UUID authorizedActor, RuntimePeer gateway,
            AiRuntimeOperationBudget budget) {
        return consumeRunInternal(request, Objects.requireNonNull(authorizedActor), Objects.requireNonNull(gateway),
                budget);
    }

    private Optional<ResolvedDispatch> consumeRunInternal(RunRedemption request, UUID authorizedActor,
            RuntimePeer gateway, AiRuntimeOperationBudget budget) {
        Objects.requireNonNull(request);
        Objects.requireNonNull(budget).remaining();
        if (!lockRun(request.expected(), request.connection().id(), authorizedActor, budget)) {
            return Optional.empty();
        }
        Instant cutoff = budget.databaseCutoff(database.query(budget, runtime::decisionTime));
        int consumed = gateway == null
                ? database.query(budget, () -> model.consumeRunIntent(request, request.expected(), cutoff))
                : database
                        .query(budget,
                                () -> model
                                        .consumeAssignedRunIntent(request, request.expected(), request.intentId(),
                                                gateway.role().name(), gateway.subject(), cutoff));
        if (consumed != 1) {
            return Optional.empty();
        }
        return Optional
                .of(database
                        .query(budget, () -> model.runDispatch(request.intentId(), request.gatewayCorrelation()))
                        .map(DispatchRow::dispatch)
                        .orElseThrow(Rejected::new));
    }

    @Transactional(timeout = 5)
    public Transition<UUID> prepareManagement(ManagementPreparation request, AiRuntimeOperationBudget budget) {
        Objects.requireNonNull(request);
        Objects.requireNonNull(budget).remaining();
        if (!AiModelDispatchPayload
                .hasModelAndOutputLimit(request.payload(), request.outputTokens(),
                        request.connection().modelIdentifier())) {
            return Transition.empty(Status.DENIED);
        }
        if (!lockManagement(request.connection().id(), request.sessionId(), budget)) {
            return Transition.empty(Status.DENIED);
        }
        Instant cutoff = budget.databaseCutoff(database.query(budget, runtime::decisionTime));
        Optional<ReplayRow> replay = database.query(budget, () -> model.managementReplay(request));
        if (!Boolean.TRUE.equals(database.query(budget, () -> model.managementPreparationCurrent(request, cutoff)))) {
            return Transition.empty(Status.DENIED);
        }
        if (replay.isPresent()) {
            return replay(replay.orElseThrow());
        }
        if (database.query(budget, () -> model.reserveManagement(request, cutoff)) != 1) {
            return Transition.empty(Status.DENIED);
        }
        applied(database.query(budget, () -> model.insertManagementIntent(request, cutoff)));
        return Transition.value(Status.APPLIED, request.intentId());
    }

    @Transactional(timeout = 5)
    public Optional<ResolvedDispatch> consumeManagement(ManagementRedemption request, AiRuntimeOperationBudget budget) {
        Objects.requireNonNull(request);
        Objects.requireNonNull(budget).remaining();
        if (!lockManagement(request.connection().id(), request.sessionId(), budget)) {
            return Optional.empty();
        }
        Instant cutoff = budget.databaseCutoff(database.query(budget, runtime::decisionTime));
        if (database.query(budget, () -> model.consumeManagementIntent(request, cutoff)) != 1) {
            return Optional.empty();
        }
        return Optional
                .of(database
                        .query(budget, () -> model.managementDispatch(request.intentId(), request.gatewayCorrelation()))
                        .map(DispatchRow::dispatch)
                        .orElseThrow(Rejected::new));
    }

    @Transactional(timeout = 5)
    public Transition<UUID> prepareManagement(ManagementPreparation request, UUID authorizedActor,
            AiRuntimeOperationBudget budget) {
        if (authorizedActor == null || !Objects.requireNonNull(request).actorId().equals(authorizedActor)) {
            return Transition.empty(Status.DENIED);
        }
        return prepareManagement(request, budget);
    }

    @Transactional(timeout = 5)
    public Optional<ResolvedDispatch> consumeManagement(ManagementRedemption request, UUID authorizedActor,
            RuntimePeer gateway, AiRuntimeOperationBudget budget) {
        Objects.requireNonNull(request);
        Objects.requireNonNull(budget).remaining();
        if (authorizedActor == null || !authorizedActor.equals(request.actorId()) || gateway == null
                || gateway.role() != com.otilm.core.security.ai.RuntimePeerRole.GATEWAY_MANAGEMENT
                || database.query(budget, model::lockManagementDeployment).isEmpty()
                || !lockManagement(request.connection().id(), request.sessionId(), budget)
                || database
                        .query(budget, () -> model.lockManagementIntent(request.intentId()))
                        .filter(request.sessionId()::equals)
                        .isEmpty()) {
            return Optional.empty();
        }
        Instant cutoff = budget.databaseCutoff(database.query(budget, runtime::decisionTime));
        if (database
                .query(budget,
                        () -> model
                                .consumeAssignedManagementIntent(request, request.intentId(), gateway.role().name(),
                                        gateway.subject(), cutoff)) != 1) {
            return Optional.empty();
        }
        return Optional
                .of(database
                        .query(budget, () -> model.managementDispatch(request.intentId(), request.gatewayCorrelation()))
                        .map(DispatchRow::dispatch)
                        .orElseThrow(Rejected::new));
    }

    private boolean lockRun(Expected expected, UUID connection, UUID authorizedActor, AiRuntimeOperationBudget budget) {
        if (database.query(budget, runtime::lockControl).isEmpty()
                || database.query(budget, () -> runtime.lockRun(expected.runId())).isEmpty()) {
            return false;
        }
        var snapshot = database.query(budget, () -> runtime.snapshot(expected.runId()));
        if (snapshot.isEmpty() || !snapshot.orElseThrow().attempt().spec().attemptId().equals(expected.attemptId())
                || authorizedActor != null && !authorizedActor.equals(snapshot.orElseThrow().spec().actorId())) {
            return false;
        }
        database.query(budget, () -> runtime.lockAttempt(expected.attemptId()));
        database.query(budget, () -> runtime.lockLaunch(expected.attemptId()));
        database.query(budget, () -> runtime.lockWorkloads(expected.attemptId()));
        return database.query(budget, () -> model.lockConnection(connection)).isPresent()
                && database.query(budget, () -> model.lockRunBudget(expected.runId())).isPresent();
    }

    private boolean lockManagement(UUID connection, UUID session, AiRuntimeOperationBudget budget) {
        return database.query(budget, () -> model.lockConnection(connection)).isPresent()
                && database.query(budget, () -> model.lockManagementSession(session)).isPresent();
    }

    private static Transition<UUID> replay(ReplayRow row) {
        return row.getExact() ? Transition.value(Status.REPLAY, row.getIntentId()) : Transition.empty(Status.CONFLICT);
    }

    private static void applied(int rows) {
        if (rows != 1) {
            // Escapes the transactional proxy, rolling back an earlier conservative reservation.
            throw new Rejected();
        }
    }

    public static final class Rejected extends RuntimeException implements PlatformException {
        private static final long serialVersionUID = 1L;

        public Rejected() {
            super("Model dispatch conflict", null, false, false);
        }
    }
}
