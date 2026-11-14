package com.otilm.core.dao.repository.ai;

import com.otilm.core.dao.entity.ai.AiRuntimeRun;
import com.otilm.core.security.ai.RuntimeProxyCertificateClaims;
import java.time.Instant;
import java.util.Optional;
import java.util.UUID;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.Repository;
import org.springframework.data.repository.query.Param;

/** Core-only immutable management delegation. No prompt, credential or public registration lookup. */
public interface AiModelManagementGatewayRepository extends Repository<AiRuntimeRun, UUID> {
    String OPERATION_DEADLINE = "operationDeadline";
    String INTENT_ID = "intentId";

    @Query(value = "SELECT session_uuid FROM {h-schema}ai_model_management_intent WHERE uuid=:id FOR UPDATE",
            nativeQuery = true)
    Optional<UUID> lockIntent(@Param("id") UUID intent);

    @Modifying
    @Query(value = AiModelManagementGatewaySql.ASSIGN, nativeQuery = true)
    int assign(@Param(INTENT_ID) UUID id, @Param("role") String role, @Param("peer") RuntimeProxyCertificateClaims peer,
            @Param(OPERATION_DEADLINE) Instant cutoff);

    @Query(value = AiModelManagementGatewaySql.ASSIGNED, nativeQuery = true)
    boolean assigned(@Param(INTENT_ID) UUID id, @Param("role") String role,
            @Param("peer") RuntimeProxyCertificateClaims peer, @Param(OPERATION_DEADLINE) Instant cutoff);

    @Query(value = AiModelManagementGatewaySql.REPLAY, nativeQuery = true)
    Optional<Replay> replay(@Param(INTENT_ID) UUID id, @Param("role") String role,
            @Param("peer") RuntimeProxyCertificateClaims peer, @Param(OPERATION_DEADLINE) Instant cutoff);

    interface Replay {
        boolean getExact();
    }
}
