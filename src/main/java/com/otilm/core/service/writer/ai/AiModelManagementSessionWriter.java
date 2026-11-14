package com.otilm.core.service.writer.ai;

import com.otilm.api.exception.PlatformException;
import com.otilm.core.aop.TraceMetadataOnly;
import com.otilm.core.dao.repository.ai.AiModelDispatchRepository;
import com.otilm.core.dao.repository.ai.AiModelManagementSessionRepository;
import com.otilm.core.dao.repository.ai.AiRuntimeRepository;
import com.otilm.core.model.ai.AiModelDispatchState.ConnectionVersion;
import com.otilm.core.model.ai.AiModelManagementSession.Facts;
import com.otilm.core.model.ai.AiModelManagementSession.Spec;
import com.otilm.core.model.ai.AiRuntimeState.Status;
import com.otilm.core.model.ai.AiRuntimeState.Transition;
import com.otilm.core.service.ai.AiRuntimeOperationBudget;
import java.util.Objects;
import java.util.Optional;
import java.util.UUID;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

/** Short model-before-session transactions only. Callers perform fresh CONNECT outside these transactions. */
@Service
@TraceMetadataOnly
public class AiModelManagementSessionWriter {
    private final AiRuntimeRepository runtime;
    private final AiRuntimeDatabaseCalls database;
    private final AiModelDispatchRepository models;
    private final AiModelManagementSessionRepository sessions;

    public AiModelManagementSessionWriter(AiRuntimeRepository runtime, AiModelDispatchRepository models,
            AiModelManagementSessionRepository sessions) {
        this.runtime = Objects.requireNonNull(runtime);
        this.database = new AiRuntimeDatabaseCalls(this.runtime);
        this.models = Objects.requireNonNull(models);
        this.sessions = Objects.requireNonNull(sessions);
    }

    @Transactional(readOnly = true, timeout = 5)
    public Optional<ConnectionVersion> connection(UUID id, AiRuntimeOperationBudget budget) {
        Objects.requireNonNull(id);
        var cutoff = budget.databaseCutoff(database.query(budget, runtime::decisionTime));
        return database
                .query(budget, () -> sessions.connection(id, cutoff))
                .map(AiModelManagementSessionRepository.ConnectionRow::connection);
    }

    @Transactional(timeout = 5)
    public Transition<Facts> create(Spec spec, AiRuntimeOperationBudget budget) {
        Objects.requireNonNull(spec);
        if (database.query(budget, () -> models.lockConnection(spec.connection().id())).isEmpty()) {
            return Transition.empty(Status.DENIED);
        }
        database.query(budget, () -> models.lockManagementSession(spec.sessionId()));
        var cutoff = budget.databaseCutoff(database.query(budget, runtime::decisionTime));
        if (!Boolean.TRUE.equals(database.query(budget, () -> sessions.modelCurrent(spec, cutoff)))) {
            return Transition.empty(Status.DENIED);
        }
        var stored = database.query(budget, () -> sessions.stored(spec.sessionId()));
        if (stored.isPresent()) {
            var row = stored.orElseThrow();
            if (!row.getEnabled()) {
                return Transition.empty(Status.DENIED);
            }
            if (!row.spec().equals(spec)) {
                return Transition.empty(Status.CONFLICT);
            }
            return database
                    .query(budget, () -> sessions.metadata(spec.sessionId(), cutoff))
                    .map(value -> Transition.value(Status.REPLAY, value.facts()))
                    .orElseGet(() -> Transition.empty(Status.DENIED));
        }
        if (database.query(budget, () -> sessions.insert(spec, cutoff)) != 1) {
            return Transition.empty(Status.CONFLICT);
        }
        var facts = database
                .query(budget, () -> sessions.metadata(spec.sessionId(), cutoff))
                .orElseThrow(Rejected::new)
                .facts();
        return Transition.value(Status.APPLIED, facts);
    }

    @Transactional(readOnly = true, timeout = 5)
    public Optional<Facts> metadata(UUID id, AiRuntimeOperationBudget budget) {
        Objects.requireNonNull(id);
        var cutoff = budget.databaseCutoff(database.query(budget, runtime::decisionTime));
        return database
                .query(budget, () -> sessions.metadata(id, cutoff))
                .map(AiModelManagementSessionRepository.SessionRow::facts);
    }

    @Transactional(timeout = 5)
    public Transition<Void> close(UUID id, AiRuntimeOperationBudget budget) {
        Objects.requireNonNull(id);
        var before = database.query(budget, () -> sessions.stored(id));
        if (before.isEmpty()
                || database.query(budget, () -> models.lockConnection(before.orElseThrow().getConnectionId())).isEmpty()
                || database.query(budget, () -> models.lockManagementSession(id)).isEmpty()) {
            return Transition.empty(Status.DENIED);
        }
        var row = database.query(budget, () -> sessions.stored(id)).orElseThrow(Rejected::new);
        if (!row.getEnabled()) {
            return Transition.empty(Status.REPLAY);
        }
        var cutoff = budget.databaseCutoff(database.query(budget, runtime::decisionTime));
        return Transition
                .empty(database.query(budget, () -> sessions.close(id, cutoff)) == 1 ? Status.APPLIED : Status.DENIED);
    }

    private static final class Rejected extends RuntimeException implements PlatformException {
        private static final long serialVersionUID = 1L;

        private Rejected() {
            super("Management session conflict", null, false, false);
        }
    }
}
