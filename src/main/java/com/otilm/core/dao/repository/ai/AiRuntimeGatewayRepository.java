package com.otilm.core.dao.repository.ai;

import com.otilm.core.dao.entity.ai.AiRuntimeRun;
import com.otilm.core.model.ai.AiRuntimeGatewayState.Deployment;
import com.otilm.core.model.ai.AiRuntimeGatewayState.Observation;
import com.otilm.core.security.ai.RuntimeProxyCertificateClaims;
import java.time.Instant;
import java.util.Optional;
import java.util.UUID;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.Repository;
import org.springframework.data.repository.query.Param;

/** Core-owned deployment and trusted controller observations; not a public registration API. */
public interface AiRuntimeGatewayRepository extends Repository<AiRuntimeRun, UUID> {
    @Modifying
    @Query(value = AiRuntimeGatewaySql.CONFIGURE, nativeQuery = true)
    int configure(@Param("role") String role, @Param("d") Deployment deployment);

    @Modifying
    @Query(value = AiRuntimeGatewaySql.OBSERVE, nativeQuery = true)
    int observe(@Param("role") String role, @Param("o") Observation observation);

    @Query(value = AiRuntimeGatewaySql.CURRENT, nativeQuery = true)
    Optional<CurrentRow> current(@Param("role") String role, @Param("peer") RuntimeProxyCertificateClaims peer);

    @Modifying
    @Query(value = AiRuntimeGatewaySql.REVOKE, nativeQuery = true)
    int revoke(@Param("role") String role, @Param("peer") RuntimeProxyCertificateClaims peer,
            @Param("generation") long generation);

    @Query(value = """
            SELECT control_generation AS "version", image_digest AS "imageDigest", cluster,
                namespace_name AS "namespaceName", namespace_uid AS "namespaceUid",
                service_account_name AS "serviceAccountName", service_account_uid AS "serviceAccountUid",
                template_digest AS "templateDigest", runtime_class AS "runtimeClass"
            FROM {h-schema}ai_runtime_gateway_deployment WHERE role='GATEWAY_RUN'
            """, nativeQuery = true)
    Optional<AiRuntimeDeploymentRow> deployment();

    @Query(value = "SELECT COALESCE(MAX(observation_sequence),0) FROM {h-schema}ai_runtime_gateway_registration WHERE role='GATEWAY_RUN' AND control_generation=:version",
            nativeQuery = true)
    long observationSequence(@Param("version") long version);

    interface CurrentRow {
        long getControlGeneration();

        long getObservationSequence();

        UUID getEvidenceId();

        Instant getValidUntil();
    }
}
