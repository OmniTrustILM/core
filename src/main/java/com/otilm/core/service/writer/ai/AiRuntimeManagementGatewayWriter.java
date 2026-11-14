package com.otilm.core.service.writer.ai;

import com.otilm.core.aop.TraceMetadataOnly;
import com.otilm.core.dao.repository.ai.AiRuntimeManagementGatewayRepository;
import com.otilm.core.dao.repository.ai.AiRuntimeRepository;
import com.otilm.core.model.ai.AiRuntimeManagementGatewayState.Deployment;
import com.otilm.core.model.ai.AiRuntimeManagementGatewayState.Observation;
import com.otilm.core.model.ai.AiRuntimeManagementGatewayState.Pins;
import com.otilm.core.model.ai.AiRuntimeManagementGatewayState.Registration;
import com.otilm.core.model.ai.AiRuntimeState.LaunchSpec;
import com.otilm.core.model.ai.AiRuntimeState.Status;
import com.otilm.core.model.ai.AiRuntimeState.Transition;
import com.otilm.core.security.ai.RuntimePeer;
import com.otilm.core.security.ai.RuntimePeerRole;
import com.otilm.core.service.ai.AiRuntimeOperationBudget;
import java.time.Instant;
import java.util.Objects;
import java.util.Optional;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

/** Short independent management-deployment transactions; trusted verification finishes before entry. */
@Service
@TraceMetadataOnly
public class AiRuntimeManagementGatewayWriter {
    private final AiRuntimeRepository runtime;
    private final AiRuntimeDatabaseCalls database;
    private final AiRuntimeManagementGatewayRepository gateways;

    public AiRuntimeManagementGatewayWriter(AiRuntimeRepository runtime,
            AiRuntimeManagementGatewayRepository gateways) {
        this.runtime = Objects.requireNonNull(runtime);
        this.database = new AiRuntimeDatabaseCalls(this.runtime);
        this.gateways = Objects.requireNonNull(gateways);
    }

    @Transactional(timeout = 5)
    public Transition<Deployment> configure(long expected, Pins pins, AiRuntimeOperationBudget budget) {
        Objects.requireNonNull(pins);
        if (!lock(expected, budget)) {
            return Transition.empty(Status.CONFLICT);
        }
        Instant cutoff = cutoff(budget);
        if (database.query(budget, () -> gateways.configure(expected, pins, cutoff)) != 1) {
            return Transition.empty(Status.DENIED);
        }
        database.query(budget, gateways::clearObservations);
        return Transition.value(Status.APPLIED, new Deployment(expected + 1, pins));
    }

    @Transactional(timeout = 5)
    public Transition<Long> disable(long expected, AiRuntimeOperationBudget budget) {
        if (!lock(expected, budget)) {
            return Transition.empty(Status.CONFLICT);
        }
        Instant cutoff = cutoff(budget);
        if (database.query(budget, () -> gateways.disable(expected, cutoff)) != 1) {
            return Transition.empty(Status.DENIED);
        }
        database.query(budget, gateways::clearObservations);
        return Transition.value(Status.APPLIED, expected + 1);
    }

    @Transactional(timeout = 5)
    public Transition<Void> observe(Observation observation, AiRuntimeOperationBudget budget) {
        Objects.requireNonNull(observation);
        if (!lock(observation.deployment().revision(), budget)) {
            return Transition.empty(Status.DENIED);
        }
        Instant cutoff = cutoff(budget);
        if (database.query(budget, () -> gateways.replay(observation, cutoff))) {
            return Transition.empty(Status.REPLAY);
        }
        return Transition
                .empty(database.query(budget, () -> gateways.observe(observation, cutoff)) == 1
                        ? Status.APPLIED
                        : Status.DENIED);
    }

    @Transactional(timeout = 5)
    public Transition<Void> revoke(RuntimePeer peer, AiRuntimeOperationBudget budget) {
        if (!management(peer) || database.query(budget, gateways::lockDeployment).isEmpty()) {
            return Transition.empty(Status.DENIED);
        }
        var revoked = database.query(budget, () -> gateways.revoked(peer.subject()));
        if (revoked.isEmpty()) {
            return Transition.empty(Status.DENIED);
        }
        if (revoked.orElseThrow()) {
            return Transition.empty(Status.REPLAY);
        }
        Instant cutoff = cutoff(budget);
        return Transition
                .empty(database.query(budget, () -> gateways.revoke(peer.subject(), cutoff)) == 1
                        ? Status.APPLIED
                        : Status.DENIED);
    }

    @Transactional(readOnly = true, timeout = 5)
    public Optional<Deployment> deployment(AiRuntimeOperationBudget budget) {
        return database.query(budget, gateways::deployment).map(row -> {
            var launch = new LaunchSpec(row.getCluster(), row.getNamespaceName(), row.getNamespaceUid(),
                    row.getServiceAccountName(), row.getServiceAccountUid(), row.getTemplateDigest(),
                    row.getRuntimeClass());
            return new Deployment(row.getVersion(), new Pins(row.getImageDigest(), launch));
        });
    }

    @Transactional(readOnly = true, timeout = 5)
    public long nextObservationSequence(long version, AiRuntimeOperationBudget budget) {
        long current = database.query(budget, () -> gateways.observationSequence(version));
        return Math.addExact(current, 1);
    }

    @Transactional(readOnly = true, timeout = 5)
    public Optional<Registration> current(RuntimePeer peer, AiRuntimeOperationBudget budget) {
        if (!management(peer)) {
            return Optional.empty();
        }
        Instant cutoff = cutoff(budget);
        return database
                .query(budget, () -> gateways.current(peer.subject(), cutoff))
                .map(row -> new Registration(peer.subject(), row.getDeploymentRevision(), row.getObservationSequence(),
                        row.getEvidenceId(), row.getValidUntil()));
    }

    @Transactional(readOnly = true, timeout = 5)
    public long revision(AiRuntimeOperationBudget budget) {
        return database.query(budget, gateways::revision).orElse(0L);
    }

    private boolean lock(long expected, AiRuntimeOperationBudget budget) {
        return expected >= 0 && expected < Long.MAX_VALUE
                && database
                        .query(budget, gateways::lockDeployment)
                        .filter(revision -> revision == expected)
                        .isPresent();
    }

    private static boolean management(RuntimePeer peer) {
        return peer != null && peer.role() == RuntimePeerRole.GATEWAY_MANAGEMENT;
    }

    private Instant cutoff(AiRuntimeOperationBudget budget) {
        return budget.databaseCutoff(database.query(budget, runtime::decisionTime));
    }

}
