package com.otilm.core.dao.repository.ai;

import com.otilm.ai.runtime.protocol.ManagementAction;
import com.otilm.core.dao.entity.ai.AiRuntimeRun;
import com.otilm.core.model.ai.AiModelDispatchState.ConnectionVersion;
import com.otilm.core.model.ai.AiModelManagementSession.Facts;
import com.otilm.core.model.ai.AiModelManagementSession.Spec;
import java.time.Instant;
import java.util.Optional;
import java.util.UUID;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.Repository;
import org.springframework.data.repository.query.Param;

/** Internal bounded persistence only; metadata supplies no CONNECT or native management authority. */
public interface AiModelManagementSessionRepository extends Repository<AiRuntimeRun, UUID> {
    String ID = "id";
    String OPERATION_DEADLINE = "operationDeadline";

    @Query(value = """
            SELECT m.uuid AS "connectionId", m.revision AS configuration, m.destination_revision AS destination,
                m.authentication_revision AS authentication, m.model_identifier AS "modelIdentifier"
            FROM {h-schema}ai_model_connection m WHERE m.uuid=:id AND clock_timestamp() < :operationDeadline AND
            """ + AiModelManagementSessionSql.APPROVED, nativeQuery = true)
    Optional<ConnectionRow> connection(@Param(ID) UUID id, @Param(OPERATION_DEADLINE) Instant operationDeadline);

    @Query(value = AiModelManagementSessionSql.COLUMNS, nativeQuery = true)
    Optional<SessionRow> stored(@Param(ID) UUID id);

    @Query(value = AiModelManagementSessionSql.METADATA, nativeQuery = true)
    Optional<SessionRow> metadata(@Param(ID) UUID id, @Param(OPERATION_DEADLINE) Instant operationDeadline);

    @Query(value = AiModelManagementSessionSql.MODEL_CURRENT, nativeQuery = true)
    boolean modelCurrent(@Param("q") Spec spec, @Param(OPERATION_DEADLINE) Instant operationDeadline);

    @Modifying
    @Query(value = AiModelManagementSessionSql.INSERT, nativeQuery = true)
    int insert(@Param("q") Spec spec, @Param(OPERATION_DEADLINE) Instant operationDeadline);

    @Modifying
    @Query(value = AiModelManagementSessionSql.CLOSE, nativeQuery = true)
    int close(@Param(ID) UUID id, @Param(OPERATION_DEADLINE) Instant operationDeadline);

    interface ConnectionRow {
        UUID getConnectionId();

        long getConfiguration();

        long getDestination();

        long getAuthentication();

        String getModelIdentifier();

        default ConnectionVersion connection() {
            return new ConnectionVersion(getConnectionId(), getConfiguration(), getDestination(), getAuthentication(),
                    getModelIdentifier());
        }
    }

    interface SessionRow extends ConnectionRow {
        UUID getSessionId();

        UUID getActorId();

        String getAction();

        boolean getEnabled();

        Instant getExpiresAt();

        long getMaxCalls();

        long getMaxTokens();

        long getReservedCalls();

        long getReservedTokens();

        default Spec spec() {
            return new Spec(getSessionId(), getActorId(), connection(), ManagementAction.valueOf(getAction()),
                    getExpiresAt(), getMaxCalls(), getMaxTokens());
        }

        default Facts facts() {
            return new Facts(getSessionId(), getActorId(), connection(), ManagementAction.valueOf(getAction()),
                    getExpiresAt(), getMaxCalls(), getMaxTokens(), getReservedCalls(), getReservedTokens());
        }
    }
}
