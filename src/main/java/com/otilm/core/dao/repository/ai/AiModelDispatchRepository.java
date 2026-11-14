package com.otilm.core.dao.repository.ai;

import com.otilm.core.dao.entity.ai.AiRuntimeRun;
import com.otilm.core.model.ai.AiModelDispatchState.ConnectionVersion;
import com.otilm.core.model.ai.AiModelDispatchState.ExactPayload;
import com.otilm.core.model.ai.AiModelDispatchState.ManagementPreparation;
import com.otilm.core.model.ai.AiModelDispatchState.ManagementRedemption;
import com.otilm.core.model.ai.AiModelDispatchState.ResolvedDispatch;
import com.otilm.core.model.ai.AiModelDispatchState.RunIntent;
import com.otilm.core.model.ai.AiModelDispatchState.RunPreparation;
import com.otilm.core.model.ai.AiModelDispatchState.RunRedemption;
import com.otilm.core.model.ai.AiRuntimeState.ClaimBinding;
import com.otilm.core.model.ai.AiRuntimeState.Expected;
import com.otilm.core.model.ai.AiRuntimeState.WorkloadRef;
import com.otilm.core.security.ai.RuntimeProxyCertificateClaims;
import java.net.URI;
import java.time.Instant;
import java.util.Optional;
import java.util.UUID;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.Repository;
import org.springframework.data.repository.query.Param;

/** Internal persistence only. No endpoint, fresh actor evaluation, modelUSE or native gateway authentication here. */
public interface AiModelDispatchRepository extends Repository<AiRuntimeRun, UUID> {
    String PREPARED_RUN_COLUMNS = """
            SELECT i.uuid AS "intentId", i.actor_uuid AS "actorId", i.run_uuid AS "runId",
                i.attempt_uuid AS "attemptId", i.claim_uuid AS "claimId", i.cluster AS cluster,
                i.pod_uid AS "podUid", i.fence AS fence, i.connection_uuid AS "connectionId",
                i.model_identifier AS "modelIdentifier", i.configuration_revision AS configuration,
                i.destination_revision AS destination, i.authentication_revision AS authentication,
                i.payload AS payload, i.output_tokens AS "outputTokens", i.expires_at AS "expiresAt"
            FROM {h-schema}ai_model_run_intent i WHERE i.run_uuid = :runId
            """;

    @Query(value = PREPARED_RUN_COLUMNS + " AND i.request_key = :requestKey", nativeQuery = true)
    Optional<RunIntentRow> runIntentByKey(@Param("runId") UUID runId, @Param("requestKey") UUID requestKey);

    @Query(value = PREPARED_RUN_COLUMNS + " AND i.uuid = :intentId", nativeQuery = true)
    Optional<RunIntentRow> runIntentById(@Param("runId") UUID runId, @Param("intentId") UUID intentId);

    default Optional<RunIntent> preparedRunByKey(UUID runId, UUID requestKey) {
        return runIntentByKey(runId, requestKey).map(RunIntentRow::intent);
    }

    default Optional<RunIntent> preparedRunById(UUID runId, UUID intentId) {
        return runIntentById(runId, intentId).map(RunIntentRow::intent);
    }

    String MANAGEMENT_INTENT_COLUMNS = """
            SELECT i.uuid AS "intentId",i.actor_uuid AS "actorId",i.session_uuid AS "sessionId",i.action AS action,
                i.connection_uuid AS "connectionId",i.model_identifier AS "modelIdentifier",i.configuration_revision AS configuration,
                i.destination_revision AS destination,i.authentication_revision AS authentication,i.payload AS payload,
                i.output_tokens AS "outputTokens",i.expires_at AS "expiresAt"
            FROM {h-schema}ai_model_management_intent i WHERE i.session_uuid=:sessionId
            """;

    @Query(value = MANAGEMENT_INTENT_COLUMNS + " AND i.request_key=:requestKey", nativeQuery = true)
    Optional<ManagementIntentRow> managementIntentByKey(@Param("sessionId") UUID session,
            @Param("requestKey") UUID key);

    @Query(value = MANAGEMENT_INTENT_COLUMNS + " AND i.uuid=:intentId", nativeQuery = true)
    Optional<ManagementIntentRow> managementIntentById(@Param("sessionId") UUID session,
            @Param("intentId") UUID intent);

    default Optional<com.otilm.core.model.ai.AiModelDispatchState.ManagementIntent> preparedManagementByKey(
            UUID session, UUID key) {
        return managementIntentByKey(session, key).map(ManagementIntentRow::intent);
    }

    default Optional<com.otilm.core.model.ai.AiModelDispatchState.ManagementIntent> preparedManagementById(UUID session,
            UUID intent) {
        return managementIntentById(session, intent).map(ManagementIntentRow::intent);
    }

    @Query(value = "SELECT revision FROM {h-schema}ai_management_gateway_deployment WHERE id=1 FOR UPDATE",
            nativeQuery = true)
    Optional<Long> lockManagementDeployment();

    @Query(value = "SELECT session_uuid FROM {h-schema}ai_model_management_intent WHERE uuid=:id FOR UPDATE",
            nativeQuery = true)
    Optional<UUID> lockManagementIntent(@Param("id") UUID intent);

    @Modifying
    @Query(value = AiModelDispatchSql.CONSUME_MANAGEMENT_ASSIGNED, nativeQuery = true)
    int consumeAssignedManagementIntent(@Param("q") ManagementRedemption request, @Param("intentId") UUID intent,
            @Param("role") String role, @Param("peer") RuntimeProxyCertificateClaims peer,
            @Param("operationDeadline") Instant cutoff);

    interface ManagementIntentRow {
        UUID getIntentId();

        UUID getActorId();

        UUID getSessionId();

        String getAction();

        UUID getConnectionId();

        String getModelIdentifier();

        long getConfiguration();

        long getDestination();

        long getAuthentication();

        byte[] getPayload();

        int getOutputTokens();

        Instant getExpiresAt();

        default com.otilm.core.model.ai.AiModelDispatchState.ManagementIntent intent() {
            return new com.otilm.core.model.ai.AiModelDispatchState.ManagementIntent(getIntentId(), getActorId(),
                    getSessionId(), com.otilm.ai.runtime.protocol.ManagementAction.valueOf(getAction()),
                    new ConnectionVersion(getConnectionId(), getConfiguration(), getDestination(), getAuthentication(),
                            getModelIdentifier()),
                    new ExactPayload(getPayload()), getOutputTokens(), getExpiresAt());
        }
    }

    @Query(value = "SELECT uuid FROM {h-schema}ai_model_connection WHERE uuid = :id FOR UPDATE", nativeQuery = true)
    Optional<UUID> lockConnection(@Param("id") UUID id);

    @Query(value = "SELECT run_uuid FROM {h-schema}ai_model_run_budget WHERE run_uuid = :id FOR UPDATE",
            nativeQuery = true)
    Optional<UUID> lockRunBudget(@Param("id") UUID id);

    @Query(value = "SELECT session_uuid FROM {h-schema}ai_model_management_session WHERE session_uuid = :id FOR UPDATE",
            nativeQuery = true)
    Optional<UUID> lockManagementSession(@Param("id") UUID id);

    @Query(value = AiModelDispatchSql.RUN_CURRENT, nativeQuery = true)
    boolean runPreparationCurrent(@Param("q") RunPreparation request, @Param("e") Expected expected,
            @Param("operationDeadline") Instant operationDeadline);

    @Query(value = AiModelDispatchSql.MANAGEMENT_CURRENT, nativeQuery = true)
    boolean managementPreparationCurrent(@Param("q") ManagementPreparation request,
            @Param("operationDeadline") Instant operationDeadline);

    @Query(value = AiModelDispatchSql.RUN_REPLAY, nativeQuery = true)
    Optional<ReplayRow> runReplay(@Param("q") RunPreparation request, @Param("e") Expected expected);

    @Query(value = AiModelDispatchSql.MANAGEMENT_REPLAY, nativeQuery = true)
    Optional<ReplayRow> managementReplay(@Param("q") ManagementPreparation request);

    @Modifying
    @Query(value = AiModelDispatchSql.RESERVE_RUN, nativeQuery = true)
    int reserveRun(@Param("q") RunPreparation request, @Param("e") Expected expected,
            @Param("operationDeadline") Instant operationDeadline);

    @Modifying
    @Query(value = AiModelDispatchSql.RESERVE_MANAGEMENT, nativeQuery = true)
    int reserveManagement(@Param("q") ManagementPreparation request,
            @Param("operationDeadline") Instant operationDeadline);

    @Modifying
    @Query(value = AiModelDispatchSql.INSERT_RUN, nativeQuery = true)
    int insertRunIntent(@Param("q") RunPreparation request, @Param("e") Expected expected,
            @Param("operationDeadline") Instant operationDeadline);

    @Modifying
    @Query(value = AiModelDispatchSql.INSERT_MANAGEMENT, nativeQuery = true)
    int insertManagementIntent(@Param("q") ManagementPreparation request,
            @Param("operationDeadline") Instant operationDeadline);

    @Modifying
    @Query(value = AiModelDispatchSql.CONSUME_RUN, nativeQuery = true)
    int consumeRunIntent(@Param("q") RunRedemption request, @Param("e") Expected expected,
            @Param("operationDeadline") Instant operationDeadline);

    @Modifying
    @Query(value = AiModelDispatchSql.CONSUME_RUN_ASSIGNED, nativeQuery = true)
    int consumeAssignedRunIntent(@Param("q") RunRedemption request, @Param("e") Expected expected,
            @Param("intentId") UUID intentId, @Param("role") String role,
            @Param("peer") RuntimeProxyCertificateClaims peer, @Param("operationDeadline") Instant operationDeadline);

    @Modifying
    @Query(value = AiModelDispatchSql.CONSUME_MANAGEMENT, nativeQuery = true)
    int consumeManagementIntent(@Param("q") ManagementRedemption request,
            @Param("operationDeadline") Instant operationDeadline);

    @Query(value = AiModelDispatchSql.RUN_DISPATCH, nativeQuery = true)
    Optional<DispatchRow> runDispatch(@Param("intentId") UUID intentId, @Param("correlation") UUID correlation);

    @Query(value = AiModelDispatchSql.MANAGEMENT_DISPATCH, nativeQuery = true)
    Optional<DispatchRow> managementDispatch(@Param("intentId") UUID intentId, @Param("correlation") UUID correlation);

    interface ReplayRow {
        UUID getIntentId();

        boolean getExact();
    }

    interface RunIntentRow {
        UUID getIntentId();

        UUID getActorId();

        UUID getRunId();

        UUID getAttemptId();

        UUID getClaimId();

        String getCluster();

        String getPodUid();

        long getFence();

        UUID getConnectionId();

        String getModelIdentifier();

        long getConfiguration();

        long getDestination();

        long getAuthentication();

        byte[] getPayload();

        int getOutputTokens();

        Instant getExpiresAt();

        default RunIntent intent() {
            return new RunIntent(getIntentId(), getActorId(),
                    new ClaimBinding(getRunId(), getAttemptId(), new WorkloadRef(getCluster(), getPodUid()),
                            getClaimId(), getFence()),
                    new ConnectionVersion(getConnectionId(), getConfiguration(), getDestination(), getAuthentication(),
                            getModelIdentifier()),
                    new ExactPayload(getPayload()), getOutputTokens(), getExpiresAt());
        }
    }

    interface DispatchRow {
        UUID getIntentId();

        UUID getConnectionId();

        String getModelIdentifier();

        long getConfiguration();

        long getDestination();

        long getAuthentication();

        byte[] getPayload();

        int getOutputTokens();

        String getOrigin();

        String getCredentialReference();

        Instant getExpiresAt();

        UUID getGatewayCorrelation();

        default ResolvedDispatch dispatch() {
            return new ResolvedDispatch(getIntentId(),
                    new ConnectionVersion(getConnectionId(), getConfiguration(), getDestination(), getAuthentication(),
                            getModelIdentifier()),
                    new ExactPayload(getPayload()), getOutputTokens(), URI.create(getOrigin()),
                    getCredentialReference(), getExpiresAt(), getGatewayCorrelation());
        }
    }
}
