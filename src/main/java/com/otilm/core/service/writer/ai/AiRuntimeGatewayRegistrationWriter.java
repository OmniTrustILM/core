package com.otilm.core.service.writer.ai;

import com.otilm.core.aop.TraceMetadataOnly;
import com.otilm.core.dao.repository.ai.AiRuntimeGatewayRepository;
import com.otilm.core.dao.repository.ai.AiRuntimeRepository;
import com.otilm.core.model.ai.AiRuntimeGatewayState.Deployment;
import com.otilm.core.model.ai.AiRuntimeGatewayState.Observation;
import com.otilm.core.model.ai.AiRuntimeGatewayState.Registration;
import com.otilm.core.model.ai.AiRuntimeState.LaunchSpec;
import com.otilm.core.security.ai.RuntimePeer;
import com.otilm.core.security.ai.RuntimePeerRole;
import com.otilm.core.service.ai.AiRuntimeOperationBudget;
import java.util.Objects;
import java.util.Optional;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

/** Publishes trusted observations; Kubernetes verification must finish before entering this transaction. */
@Service
@TraceMetadataOnly
public class AiRuntimeGatewayRegistrationWriter {
    private final AiRuntimeRepository runtime;
    private final AiRuntimeDatabaseCalls database;
    private final AiRuntimeGatewayRepository gateways;

    public AiRuntimeGatewayRegistrationWriter(AiRuntimeRepository runtime, AiRuntimeGatewayRepository gateways) {
        this.runtime = Objects.requireNonNull(runtime);
        this.database = new AiRuntimeDatabaseCalls(this.runtime);
        this.gateways = Objects.requireNonNull(gateways);
    }

    @Transactional(timeout = 5)
    public boolean configure(Deployment deployment, AiRuntimeOperationBudget budget) {
        if (database
                .query(budget, runtime::lockControl)
                .filter(value -> value == deployment.controlGeneration())
                .isEmpty()) {
            return false;
        }
        return database.query(budget, () -> gateways.configure(deployment.role().name(), deployment)) == 1;
    }

    @Transactional(timeout = 5)
    public boolean observe(Observation observation, AiRuntimeOperationBudget budget) {
        if (database
                .query(budget, runtime::lockControl)
                .filter(value -> value == observation.deployment().controlGeneration())
                .isEmpty()) {
            return false;
        }
        return database.query(budget, () -> gateways.observe(observation.deployment().role().name(), observation)) == 1;
    }

    @Transactional(readOnly = true, timeout = 5)
    public Optional<Deployment> deployment(AiRuntimeOperationBudget budget) {
        return database.query(budget, gateways::deployment).map(row -> {
            var launch = new LaunchSpec(row.getCluster(), row.getNamespaceName(), row.getNamespaceUid(),
                    row.getServiceAccountName(), row.getServiceAccountUid(), row.getTemplateDigest(),
                    row.getRuntimeClass());
            return new Deployment(RuntimePeerRole.GATEWAY_RUN, row.getVersion(), row.getImageDigest(), launch);
        });
    }

    @Transactional(readOnly = true, timeout = 5)
    public long nextObservationSequence(long version, AiRuntimeOperationBudget budget) {
        long current = database.query(budget, () -> gateways.observationSequence(version));
        return Math.addExact(current, 1);
    }

    @Transactional(readOnly = true, timeout = 5)
    public Optional<Registration> current(RuntimePeer peer, AiRuntimeOperationBudget budget) {
        return database
                .query(budget, () -> gateways.current(peer.role().name(), peer.subject()))
                .map(row -> new Registration(peer.role(), peer.subject(), row.getControlGeneration(),
                        row.getObservationSequence(), row.getEvidenceId(), row.getValidUntil()));
    }

    @Transactional(timeout = 5)
    public boolean revoke(RuntimePeer peer, AiRuntimeOperationBudget budget) {
        var generation = database.query(budget, runtime::lockControl);
        return generation.isPresent() && database
                .query(budget,
                        () -> gateways.revoke(peer.role().name(), peer.subject(), generation.orElseThrow())) == 1;
    }

}
