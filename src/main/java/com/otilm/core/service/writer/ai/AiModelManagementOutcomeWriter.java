package com.otilm.core.service.writer.ai;

import com.otilm.core.aop.TraceMetadataOnly;
import com.otilm.core.dao.repository.ai.AiModelManagementGatewayRepository;
import com.otilm.core.dao.repository.ai.AiModelManagementOutcomeRepository;
import com.otilm.core.dao.repository.ai.AiRuntimeManagementGatewayRepository;
import com.otilm.core.dao.repository.ai.AiRuntimeRepository;
import com.otilm.core.model.ai.AiModelManagementOutcome.Receipt;
import com.otilm.core.model.ai.AiModelManagementOutcome.Result;
import com.otilm.core.model.ai.AiModelRunOutcome.DerivedResult;
import com.otilm.core.model.ai.AiModelRunResult;
import com.otilm.core.model.ai.AiRuntimeState.Status;
import com.otilm.core.model.ai.AiRuntimeState.Transition;
import com.otilm.core.security.ai.RuntimePeer;
import com.otilm.core.security.ai.RuntimePeerRole;
import com.otilm.core.service.ai.AiRuntimeManagementWire;
import com.otilm.core.service.ai.AiRuntimeManagementWire.OutcomeRequest;
import com.otilm.core.service.ai.AiRuntimeOperationBudget;
import java.time.Instant;
import java.util.Objects;
import java.util.Optional;
import java.util.UUID;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

/** Appends evidence only. It cannot approve, refund, re-enable or reopen any session or model. */
@Service
@TraceMetadataOnly
public class AiModelManagementOutcomeWriter {
    private final AiRuntimeRepository runtime;
    private final AiRuntimeDatabaseCalls database;
    private final AiRuntimeManagementGatewayRepository registry;
    private final AiModelManagementGatewayRepository assignments;
    private final AiModelManagementOutcomeRepository outcomes;
    private final AiRuntimeManagementWire wire = new AiRuntimeManagementWire();

    public AiModelManagementOutcomeWriter(AiRuntimeRepository runtime, AiRuntimeManagementGatewayRepository registry,
            AiModelManagementGatewayRepository assignments, AiModelManagementOutcomeRepository outcomes) {
        this.runtime = Objects.requireNonNull(runtime);
        this.database = new AiRuntimeDatabaseCalls(this.runtime);
        this.registry = Objects.requireNonNull(registry);
        this.assignments = Objects.requireNonNull(assignments);
        this.outcomes = Objects.requireNonNull(outcomes);
    }

    @Transactional(timeout = 5)
    public Transition<Receipt> append(OutcomeRequest supplied, RuntimePeer peer, AiRuntimeOperationBudget budget) {
        budget.remaining();
        if (peer == null || peer.role() != RuntimePeerRole.GATEWAY_MANAGEMENT || supplied == null) {
            return Transition.empty(Status.DENIED);
        }
        var request = wire.readOutcome(supplied.requestBytes());
        budget.remaining();
        Instant cutoff = cutoff(budget);
        var before = database
                .query(budget, () -> outcomes.metadata(request, peer.role().name(), peer.subject(), cutoff));
        if (before.isEmpty()) {
            return Transition.empty(Status.DENIED);
        }
        var stored = before.orElseThrow();
        // Validation is bounded and server-derived, before acquiring the management deployment lock.
        var derived = DerivedResult
                .from(AiModelRunResult
                        .validate(request.responseBytes(), stored.getModelIdentifier(), stored.getOutputTokens()));
        budget.remaining();
        if (database.query(budget, registry::lockDeployment).isEmpty()
                || database.query(budget, () -> assignments.lockIntent(request.intentId())).isEmpty()) {
            return Transition.empty(Status.DENIED);
        }
        Instant finalCutoff = cutoff(budget);
        var confirmed = database
                .query(budget, () -> outcomes.metadata(request, peer.role().name(), peer.subject(), finalCutoff));
        if (confirmed.isEmpty()) {
            return Transition.empty(Status.DENIED);
        }
        var current = confirmed.orElseThrow();
        if (!stored.getModelIdentifier().equals(current.getModelIdentifier())
                || stored.getOutputTokens() != current.getOutputTokens()
                || !stored.getExpiresAt().equals(current.getExpiresAt())) {
            return Transition.empty(Status.DENIED);
        }
        int inserted = database
                .query(budget,
                        () -> outcomes.append(request, derived, peer.role().name(), peer.subject(), finalCutoff));
        var receipt = database
                .query(budget, () -> outcomes.receipt(request, peer.role().name(), peer.subject(), finalCutoff));
        if (receipt.isEmpty() || !receipt.orElseThrow().getExact()) {
            if (inserted == 1) {
                throw rejected();
            }
            return Transition.empty(receipt.isEmpty() ? Status.DENIED : Status.CONFLICT);
        }
        return Transition.value(inserted == 1 ? Status.APPLIED : Status.REPLAY, receipt.orElseThrow().receipt());
    }

    @Transactional(readOnly = true, timeout = 5)
    public Optional<Result> read(UUID session, UUID intent, UUID authorizedActor, AiRuntimeOperationBudget budget) {
        if (session == null || intent == null || authorizedActor == null) {
            return Optional.empty();
        }
        Instant cutoff = cutoff(budget);
        return database
                .query(budget, () -> outcomes.read(session, intent, authorizedActor, cutoff))
                .map(AiModelManagementOutcomeRepository.ResultRow::result);
    }

    private Instant cutoff(AiRuntimeOperationBudget budget) {
        return budget.databaseCutoff(database.query(budget, runtime::decisionTime));
    }

    private static IllegalStateException rejected() {
        return new IllegalStateException("Management evidence conflict");
    }
}
