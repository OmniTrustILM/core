package com.otilm.core.service.writer.ai;

import com.otilm.core.aop.TraceMetadataOnly;
import com.otilm.core.dao.repository.ai.AiModelRunOutcomeRepository;
import com.otilm.core.dao.repository.ai.AiRuntimeRepository;
import com.otilm.core.model.ai.AiModelRunOutcome.DerivedResult;
import com.otilm.core.model.ai.AiModelRunOutcome.Receipt;
import com.otilm.core.model.ai.AiModelRunResult;
import com.otilm.core.model.ai.AiRuntimeState.Status;
import com.otilm.core.model.ai.AiRuntimeState.Transition;
import com.otilm.core.security.ai.RuntimePeer;
import com.otilm.core.security.ai.RuntimePeerRole;
import com.otilm.core.service.ai.AiRuntimeGatewayWire;
import com.otilm.core.service.ai.AiRuntimeGatewayWire.OutcomeRequest;
import com.otilm.core.service.ai.AiRuntimeOperationBudget;
import java.time.Instant;
import java.util.Objects;
import java.util.UUID;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

/** Core-only delegation/evidence storage. Native verification and remote authority precede these short transactions. */
@Service
@TraceMetadataOnly
public class AiModelRunOutcomeWriter {
    private final AiRuntimeRepository runtime;
    private final AiRuntimeDatabaseCalls database;
    private final AiModelRunOutcomeRepository outcomes;
    private final AiRuntimeGatewayWire wire = new AiRuntimeGatewayWire();

    public AiModelRunOutcomeWriter(AiRuntimeRepository runtime, AiModelRunOutcomeRepository outcomes) {
        this.runtime = Objects.requireNonNull(runtime);
        this.database = new AiRuntimeDatabaseCalls(this.runtime);
        this.outcomes = Objects.requireNonNull(outcomes);
    }

    @Transactional(timeout = 5)
    public Transition<Void> assign(UUID intentId, RuntimePeer peer, AiRuntimeOperationBudget budget) {
        Objects.requireNonNull(budget).remaining();
        if (!runGateway(peer) || !lock(intentId, budget)) {
            return Transition.empty(Status.DENIED);
        }
        Instant cutoff = cutoff(budget);
        if (database.query(budget, () -> outcomes.assign(intentId, peer.role().name(), peer.subject(), cutoff)) == 1) {
            return Transition.empty(Status.APPLIED);
        }
        var previous = database
                .query(budget, () -> outcomes.assignmentReplay(intentId, peer.role().name(), peer.subject(), cutoff));
        return Transition
                .empty(previous.map(row -> row.getExact() ? Status.REPLAY : Status.CONFLICT).orElse(Status.DENIED));
    }

    @Transactional(readOnly = true, timeout = 5)
    public void requireAssigned(UUID intentId, RuntimePeer peer, AiRuntimeOperationBudget budget) {
        Objects.requireNonNull(budget).remaining();
        if (!runGateway(peer) || intentId == null) {
            throw denied();
        }
        Instant cutoff = cutoff(budget);
        if (!Boolean.TRUE
                .equals(database
                        .query(budget,
                                () -> outcomes.assigned(intentId, peer.role().name(), peer.subject(), cutoff)))) {
            throw denied();
        }
    }

    @Transactional(timeout = 5)
    public Transition<Receipt> append(OutcomeRequest supplied, RuntimePeer peer, AiRuntimeOperationBudget budget) {
        Objects.requireNonNull(budget).remaining();
        if (!runGateway(peer) || supplied == null) {
            return Transition.empty(Status.DENIED);
        }
        // Reparse owned original bytes; manually constructed DTO fields or a caller hash are never a result grant.
        OutcomeRequest request = wire.readOutcome(supplied.requestBytes());
        budget.remaining();
        Instant cutoff = cutoff(budget);
        var metadata = database
                .query(budget, () -> outcomes.metadata(request, peer.role().name(), peer.subject(), cutoff));
        if (metadata.isEmpty() || !metadata.orElseThrow().getExpiresAt().equals(request.binding().expiresAt())) {
            return Transition.empty(Status.DENIED);
        }
        var stored = metadata.orElseThrow();
        var validation = AiModelRunResult
                .validate(request.responseBytes(), stored.getModelIdentifier(), stored.getOutputTokens());
        budget.remaining();
        var derived = DerivedResult.from(validation);
        if (!lock(request.intentId(), budget)) {
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
        var row = database
                .query(budget, () -> outcomes.receipt(request, peer.role().name(), peer.subject(), finalCutoff));
        if (row.isEmpty()) {
            if (inserted == 1) {
                throw rejected();
            }
            return Transition.empty(Status.DENIED);
        }
        if (!row.orElseThrow().getExact()) {
            if (inserted == 1) {
                throw rejected();
            }
            return Transition.empty(Status.CONFLICT);
        }
        return Transition.value(inserted == 1 ? Status.APPLIED : Status.REPLAY, row.orElseThrow().receipt());
    }

    private boolean lock(UUID intentId, AiRuntimeOperationBudget budget) {
        if (intentId == null || database.query(budget, runtime::lockControl).isEmpty()) {
            return false;
        }
        var run = database.query(budget, () -> outcomes.intentRun(intentId));
        return run.isPresent() && database.query(budget, () -> runtime.lockRun(run.orElseThrow())).isPresent()
                && database
                        .query(budget, () -> outcomes.lockIntent(intentId))
                        .filter(run.orElseThrow()::equals)
                        .isPresent();
    }

    private Instant cutoff(AiRuntimeOperationBudget budget) {
        return budget.databaseCutoff(database.query(budget, runtime::decisionTime));
    }

    private static boolean runGateway(RuntimePeer peer) {
        return peer != null && peer.role() == RuntimePeerRole.GATEWAY_RUN;
    }

    private static AccessDeniedException denied() {
        return new AccessDeniedException("Gateway assignment required");
    }

    private static IllegalStateException rejected() {
        return new IllegalStateException("Model outcome transition unavailable");
    }
}
