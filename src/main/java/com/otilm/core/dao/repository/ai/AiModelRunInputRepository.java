package com.otilm.core.dao.repository.ai;

import com.otilm.core.dao.entity.ai.AiRuntimeRun;
import com.otilm.core.model.ai.AiModelDispatchState.ConnectionVersion;
import com.otilm.core.model.ai.AiModelRunInput;
import java.util.Optional;
import java.util.UUID;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.Repository;
import org.springframework.data.repository.query.Param;

/** Internal persistence only; the caller must establish fresh authority before protected input reads. */
public interface AiModelRunInputRepository extends Repository<AiRuntimeRun, UUID> {
    @Query(value = AiModelRunInputSql.CONNECTION, nativeQuery = true)
    Optional<ConnectionRow> connection(@Param("runId") UUID runId);

    @Query(value = AiModelRunInputSql.READ, nativeQuery = true)
    Optional<InputRow> read(@Param("runId") UUID runId, @Param("model") ConnectionVersion model);

    @Modifying
    @Query(value = AiModelRunInputSql.INSERT, nativeQuery = true)
    int insert(@Param("input") AiModelRunInput input, @Param("certificates") UUID[] certificates);

    @Query(value = AiModelRunInputSql.EXACT, nativeQuery = true)
    boolean exact(@Param("input") AiModelRunInput input, @Param("certificates") UUID[] certificates);

    interface ConnectionRow {
        UUID getId();

        long getConfiguration();

        long getDestination();

        long getAuthentication();

        String getModelIdentifier();

        default ConnectionVersion version() {
            return new ConnectionVersion(getId(), getConfiguration(), getDestination(), getAuthentication(),
                    getModelIdentifier());
        }
    }

    interface InputRow {
        UUID getRunId();

        UUID getRaProfileUuid();

        UUID[] getCertificateUuids();

        String getInstructions();

        String getPrompt();

        int getOutputTokens();
    }
}
