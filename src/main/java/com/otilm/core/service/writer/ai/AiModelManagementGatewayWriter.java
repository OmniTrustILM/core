package com.otilm.core.service.writer.ai;

import com.otilm.core.aop.TraceMetadataOnly;
import com.otilm.core.dao.repository.ai.AiModelManagementGatewayRepository;
import com.otilm.core.dao.repository.ai.AiRuntimeManagementGatewayRepository;
import com.otilm.core.dao.repository.ai.AiRuntimeRepository;
import com.otilm.core.model.ai.AiRuntimeState.Status;
import com.otilm.core.model.ai.AiRuntimeState.Transition;
import com.otilm.core.security.ai.RuntimePeer;
import com.otilm.core.security.ai.RuntimePeerRole;
import com.otilm.core.service.ai.AiRuntimeOperationBudget;
import java.time.Instant;
import java.util.Objects;
import java.util.UUID;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

/** Trusted Core controller delegation after observed workload verification; never a public registration grant. */
@Service
@TraceMetadataOnly
public class AiModelManagementGatewayWriter {
    private final AiRuntimeRepository runtime;
    private final AiRuntimeDatabaseCalls database;
    private final AiRuntimeManagementGatewayRepository registry;
    private final AiModelManagementGatewayRepository assignments;

    public AiModelManagementGatewayWriter(AiRuntimeRepository runtime, AiRuntimeManagementGatewayRepository registry,
            AiModelManagementGatewayRepository assignments) {
        this.runtime = Objects.requireNonNull(runtime);
        this.database = new AiRuntimeDatabaseCalls(this.runtime);
        this.registry = Objects.requireNonNull(registry);
        this.assignments = Objects.requireNonNull(assignments);
    }

    @Transactional(timeout = 5)
    public Transition<Void> assign(UUID intent, RuntimePeer peer, AiRuntimeOperationBudget budget) {
        if (!management(peer) || intent == null || database.query(budget, registry::lockDeployment).isEmpty()
                || database.query(budget, () -> assignments.lockIntent(intent)).isEmpty()) {
            return Transition.empty(Status.DENIED);
        }
        Instant cutoff = cutoff(budget);
        if (database.query(budget, () -> assignments.assign(intent, peer.role().name(), peer.subject(), cutoff)) == 1) {
            return Transition.empty(Status.APPLIED);
        }
        return Transition
                .empty(database
                        .query(budget, () -> assignments.replay(intent, peer.role().name(), peer.subject(), cutoff))
                        .map(row -> row.getExact() ? Status.REPLAY : Status.CONFLICT)
                        .orElse(Status.DENIED));
    }

    @Transactional(readOnly = true, timeout = 5)
    public void requireAssigned(UUID intent, RuntimePeer peer, AiRuntimeOperationBudget budget) {
        if (!management(peer) || intent == null) {
            throw denied();
        }
        Instant cutoff = cutoff(budget);
        if (!database.query(budget, () -> assignments.assigned(intent, peer.role().name(), peer.subject(), cutoff))) {
            throw denied();
        }
    }

    private static boolean management(RuntimePeer peer) {
        return peer != null && peer.role() == RuntimePeerRole.GATEWAY_MANAGEMENT;
    }

    private Instant cutoff(AiRuntimeOperationBudget budget) {
        return budget.databaseCutoff(database.query(budget, runtime::decisionTime));
    }

    private static AccessDeniedException denied() {
        return new AccessDeniedException("Management assignment required");
    }
}
