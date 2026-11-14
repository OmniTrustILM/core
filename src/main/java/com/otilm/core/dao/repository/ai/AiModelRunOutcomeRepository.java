package com.otilm.core.dao.repository.ai;

import com.otilm.core.dao.entity.ai.AiRuntimeRun;
import com.otilm.core.model.ai.AiModelRunOutcome.DerivedResult;
import com.otilm.core.model.ai.AiModelRunOutcome.Receipt;
import com.otilm.core.security.ai.RuntimeProxyCertificateClaims;
import com.otilm.core.service.ai.AiRuntimeGatewayWire.OutcomeRequest;
import java.time.Instant;
import java.util.Optional;
import java.util.UUID;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.Repository;
import org.springframework.data.repository.query.Param;

/** Internal persistence only; metadata assignment or a receipt cannot authorize business or reader actions. */
public interface AiModelRunOutcomeRepository extends Repository<AiRuntimeRun, UUID> {
    @Query(value = "SELECT run_uuid FROM {h-schema}ai_model_run_intent WHERE uuid = :intentId", nativeQuery = true)
    Optional<UUID> intentRun(@Param("intentId") UUID intentId);

    @Query(value = "SELECT run_uuid FROM {h-schema}ai_model_run_intent WHERE uuid = :intentId FOR UPDATE",
            nativeQuery = true)
    Optional<UUID> lockIntent(@Param("intentId") UUID intentId);

    @Modifying
    @Query(value = AiModelRunOutcomeSql.ASSIGN, nativeQuery = true)
    int assign(@Param("intentId") UUID intentId, @Param("role") String role,
            @Param("peer") RuntimeProxyCertificateClaims peer, @Param("operationDeadline") Instant deadline);

    @Query(value = AiModelRunOutcomeSql.ASSIGNMENT_REPLAY, nativeQuery = true)
    Optional<ExactRow> assignmentReplay(@Param("intentId") UUID intentId, @Param("role") String role,
            @Param("peer") RuntimeProxyCertificateClaims peer, @Param("operationDeadline") Instant deadline);

    @Query(value = AiModelRunOutcomeSql.ASSIGNED, nativeQuery = true)
    boolean assigned(@Param("intentId") UUID intentId, @Param("role") String role,
            @Param("peer") RuntimeProxyCertificateClaims peer, @Param("operationDeadline") Instant deadline);

    @Query(value = AiModelRunOutcomeSql.METADATA, nativeQuery = true)
    Optional<MetadataRow> metadata(@Param("q") OutcomeRequest request, @Param("role") String role,
            @Param("peer") RuntimeProxyCertificateClaims peer, @Param("operationDeadline") Instant deadline);

    @Modifying
    @Query(value = AiModelRunOutcomeSql.APPEND, nativeQuery = true)
    int append(@Param("q") OutcomeRequest request, @Param("v") DerivedResult result, @Param("role") String role,
            @Param("peer") RuntimeProxyCertificateClaims peer, @Param("operationDeadline") Instant deadline);

    @Query(value = AiModelRunOutcomeSql.RECEIPT, nativeQuery = true)
    Optional<ReceiptRow> receipt(@Param("q") OutcomeRequest request, @Param("role") String role,
            @Param("peer") RuntimeProxyCertificateClaims peer, @Param("operationDeadline") Instant deadline);

    interface ExactRow {
        boolean getExact();
    }

    interface MetadataRow {
        String getModelIdentifier();

        int getOutputTokens();

        Instant getExpiresAt();
    }

    interface ReceiptRow extends ExactRow {
        UUID getIntentId();

        UUID getGatewayCorrelation();

        String getOutcomeSha256();

        long getResultVersion();

        default Receipt receipt() {
            return new Receipt(getIntentId(), getGatewayCorrelation(), getOutcomeSha256(), getResultVersion());
        }
    }
}
