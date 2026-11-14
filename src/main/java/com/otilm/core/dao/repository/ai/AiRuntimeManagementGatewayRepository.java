package com.otilm.core.dao.repository.ai;

import com.otilm.core.dao.entity.ai.AiRuntimeRun;
import com.otilm.core.model.ai.AiRuntimeManagementGatewayState.Observation;
import com.otilm.core.model.ai.AiRuntimeManagementGatewayState.Pins;
import com.otilm.core.security.ai.RuntimeProxyCertificateClaims;
import java.time.Instant;
import java.util.Optional;
import java.util.UUID;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.Repository;
import org.springframework.data.repository.query.Param;

/** Native-query marker only; these methods neither create nor need an AiRuntimeRun. */
public interface AiRuntimeManagementGatewayRepository extends Repository<AiRuntimeRun, UUID> {
    String OPERATION_DEADLINE = "operationDeadline";

    @Query(value = "SELECT revision FROM {h-schema}ai_management_gateway_deployment WHERE id=1 FOR UPDATE",
            nativeQuery = true)
    Optional<Long> lockDeployment();

    @Query(value = "SELECT revision FROM {h-schema}ai_management_gateway_deployment WHERE id=1", nativeQuery = true)
    Optional<Long> revision();

    @Query(value = "SELECT configured FROM {h-schema}ai_management_gateway_deployment WHERE id=1", nativeQuery = true)
    Optional<Boolean> configured();

    @Modifying
    @Query(value = AiRuntimeManagementGatewaySql.STARTUP_DENY, nativeQuery = true)
    int startupDeny(@Param("expected") long expected, @Param(OPERATION_DEADLINE) Instant cutoff);

    @Modifying
    @Query(value = AiRuntimeManagementGatewaySql.CONFIGURE, nativeQuery = true)
    int configure(@Param("expected") long expected, @Param("p") Pins pins, @Param(OPERATION_DEADLINE) Instant cutoff);

    @Modifying
    @Query(value = AiRuntimeManagementGatewaySql.DISABLE, nativeQuery = true)
    int disable(@Param("expected") long expected, @Param(OPERATION_DEADLINE) Instant cutoff);

    @Modifying
    @Query(value = "DELETE FROM {h-schema}ai_management_gateway_registration", nativeQuery = true)
    int clearObservations();

    @Modifying
    @Query(value = AiRuntimeManagementGatewaySql.OBSERVE, nativeQuery = true)
    int observe(@Param("o") Observation observation, @Param(OPERATION_DEADLINE) Instant cutoff);

    @Query(value = AiRuntimeManagementGatewaySql.REPLAY, nativeQuery = true)
    boolean replay(@Param("o") Observation observation, @Param(OPERATION_DEADLINE) Instant cutoff);

    @Query(value = AiRuntimeManagementGatewaySql.CURRENT, nativeQuery = true)
    Optional<CurrentRow> current(@Param("peer") RuntimeProxyCertificateClaims peer,
            @Param(OPERATION_DEADLINE) Instant cutoff);

    @Modifying
    @Query(value = AiRuntimeManagementGatewaySql.REVOKE, nativeQuery = true)
    int revoke(@Param("peer") RuntimeProxyCertificateClaims peer, @Param(OPERATION_DEADLINE) Instant cutoff);

    @Query(value = """
            SELECT w.revoked FROM {h-schema}ai_management_gateway_registration w
            JOIN {h-schema}ai_management_gateway_deployment d ON d.revision=w.deployment_revision
            WHERE d.id=1 AND d.cluster=:#{#peer.cluster()} AND d.namespace_name=:#{#peer.namespace()}
                AND d.service_account_name=:#{#peer.serviceAccount()} AND w.pod_name=:#{#peer.podName()} AND w.pod_uid=:#{#peer.podUid()}
            """,
            nativeQuery = true)
    Optional<Boolean> revoked(@Param("peer") RuntimeProxyCertificateClaims peer);

    @Query(value = """
            SELECT revision AS "version", image_digest AS "imageDigest", cluster,
                namespace_name AS "namespaceName", namespace_uid AS "namespaceUid",
                service_account_name AS "serviceAccountName", service_account_uid AS "serviceAccountUid",
                template_digest AS "templateDigest", runtime_class AS "runtimeClass"
            FROM {h-schema}ai_management_gateway_deployment WHERE id=1 AND configured
            """, nativeQuery = true)
    Optional<AiRuntimeDeploymentRow> deployment();

    @Query(value = "SELECT COALESCE(MAX(observation_sequence),0) FROM {h-schema}ai_management_gateway_registration WHERE deployment_revision=:version",
            nativeQuery = true)
    long observationSequence(@Param("version") long version);

    interface CurrentRow {
        long getDeploymentRevision();

        long getObservationSequence();

        UUID getEvidenceId();

        Instant getValidUntil();
    }
}
