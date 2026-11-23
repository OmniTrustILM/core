package com.otilm.core.dao.repository.ai;

import com.otilm.core.dao.entity.ai.AiRuntimeRun;
import com.otilm.core.model.ai.AiModelManagementOutcome.Receipt;
import com.otilm.core.model.ai.AiModelManagementOutcome.Result;
import com.otilm.core.model.ai.AiModelRunOutcome.DerivedResult;
import com.otilm.core.security.ai.RuntimeProxyCertificateClaims;
import com.otilm.core.service.ai.AiRuntimeManagementWire.OutcomeRequest;
import java.time.Instant;
import java.util.Optional;
import java.util.UUID;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.Repository;
import org.springframework.data.repository.query.Param;

/** Private protected evidence storage. Reader business authority is required separately before invocation. */
public interface AiModelManagementOutcomeRepository extends Repository<AiRuntimeRun, UUID> {
    String OPERATION_DEADLINE = "operationDeadline";
    String INTENT_ID = "intentId";

    @Query(value = AiModelManagementOutcomeSql.METADATA, nativeQuery = true)
    Optional<Metadata> metadata(@Param("q") OutcomeRequest request, @Param("role") String role,
            @Param("peer") RuntimeProxyCertificateClaims peer, @Param(OPERATION_DEADLINE) Instant cutoff);

    @Modifying
    @Query(value = AiModelManagementOutcomeSql.APPEND, nativeQuery = true)
    int append(@Param("q") OutcomeRequest request, @Param("v") DerivedResult derived, @Param("role") String role,
            @Param("peer") RuntimeProxyCertificateClaims peer, @Param(OPERATION_DEADLINE) Instant cutoff);

    @Query(value = AiModelManagementOutcomeSql.RECEIPT, nativeQuery = true)
    Optional<ReceiptRow> receipt(@Param("q") OutcomeRequest request, @Param("role") String role,
            @Param("peer") RuntimeProxyCertificateClaims peer, @Param(OPERATION_DEADLINE) Instant cutoff);

    @Query(value = AiModelManagementOutcomeSql.READ, nativeQuery = true)
    Optional<ResultRow> read(@Param("sessionId") UUID session, @Param(INTENT_ID) UUID intent,
            @Param("authorizedActor") UUID actor, @Param(OPERATION_DEADLINE) Instant cutoff);

    interface Metadata {
        String getModelIdentifier();

        int getOutputTokens();

        Instant getExpiresAt();
    }

    interface ReceiptRow {
        UUID getIntentId();

        UUID getGatewayCorrelation();

        String getOutcomeSha256();

        long getResultVersion();

        boolean getExact();

        default Receipt receipt() {
            return new Receipt(getIntentId(), getGatewayCorrelation(), getOutcomeSha256(), getResultVersion());
        }
    }

    interface ResultRow extends ReceiptRow {
        String getCode();

        String getText();

        String getFinish();

        Long getPromptTokens();

        Long getCompletionTokens();

        Long getTotalTokens();

        default Result result() {
            return new Result(receipt(), getCode(), getText(), getFinish(), getPromptTokens(), getCompletionTokens(),
                    getTotalTokens());
        }
    }
}
