package com.otilm.core.dao.repository.ai;

import com.otilm.core.dao.entity.ai.AiRuntimeRun;
import com.otilm.core.model.ai.AiRuntimeState.AttemptSnapshot;
import com.otilm.core.model.ai.AiRuntimeState.AttemptSpec;
import com.otilm.core.model.ai.AiRuntimeState.AttemptState;
import com.otilm.core.model.ai.AiRuntimeState.Claim;
import com.otilm.core.model.ai.AiRuntimeState.ClaimBinding;
import com.otilm.core.model.ai.AiRuntimeState.CleanupState;
import com.otilm.core.model.ai.AiRuntimeState.ControlPins;
import com.otilm.core.model.ai.AiRuntimeState.ControlSnapshot;
import com.otilm.core.model.ai.AiRuntimeState.ControlVersion;
import com.otilm.core.model.ai.AiRuntimeState.Expected;
import com.otilm.core.model.ai.AiRuntimeState.FailureReason;
import com.otilm.core.model.ai.AiRuntimeState.LaunchSnapshot;
import com.otilm.core.model.ai.AiRuntimeState.LaunchSpec;
import com.otilm.core.model.ai.AiRuntimeState.ReadinessObservation;
import com.otilm.core.model.ai.AiRuntimeState.RunSnapshot;
import com.otilm.core.model.ai.AiRuntimeState.RunSpec;
import com.otilm.core.model.ai.AiRuntimeState.RunState;
import com.otilm.core.model.ai.AiRuntimeState.WorkloadObservation;
import com.otilm.core.model.ai.AiRuntimeState.WorkloadRef;
import com.otilm.core.model.ai.AiRuntimeState.WorkloadSnapshot;
import com.otilm.core.model.ai.AiRuntimeState.WorkloadState;
import java.time.Instant;
import java.util.List;
import java.util.Optional;
import java.util.UUID;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.Repository;
import org.springframework.data.repository.query.Param;

public interface AiRuntimeRepository extends Repository<AiRuntimeRun, UUID> {
    @Query(value = """
            SELECT set_config('lock_timeout', '1000ms', true) || set_config('statement_timeout', '4000ms', true)
            """, nativeQuery = true)
    String configureTransaction();

    @Query(value = """
            SELECT set_config('lock_timeout', CAST(GREATEST(1, LEAST(1000, :remainingMillis)) AS text) || 'ms', true)
                || set_config('statement_timeout', CAST(GREATEST(1, LEAST(4000, :remainingMillis)) AS text) || 'ms', true)
            """,
            nativeQuery = true)
    String configureTransaction(@Param("remainingMillis") long remainingMillis);

    @Query(value = "SELECT generation FROM {h-schema}ai_runtime_control WHERE id = 1 FOR UPDATE", nativeQuery = true)
    Optional<Long> lockControl();

    @Query(value = """
            SELECT generation, enabled, image_digest AS "imageDigest", profile_revision AS "profileRevision",
                security_revision AS "securityRevision", trust_revision AS "trustRevision", protocol, cluster,
                namespace_name AS "namespaceName", namespace_uid AS "namespaceUid",
                service_account_name AS "serviceAccountName", service_account_uid AS "serviceAccountUid",
                template_digest AS "templateDigest", runtime_class AS "runtimeClass",
                observation_sequence AS "observationSequence", evidence_id AS "evidenceId",
                observed_at AS "observedAt", valid_until AS "validUntil", created_at AS "createdAt", updated_at AS "updatedAt"
            FROM {h-schema}ai_runtime_control WHERE id = 1
            """,
            nativeQuery = true)
    Optional<AiRuntimeControlRow> controlRow();

    default Optional<ControlSnapshot> control() {
        return controlRow().map(AiRuntimeControlRow::snapshot);
    }

    @Modifying
    @Query(value = AiRuntimeControlSql.CHANGE, nativeQuery = true)
    int changeControl(@Param("expected") ControlVersion expected, @Param("pins") ControlPins pins,
            @Param("at") Instant at);

    @Modifying
    @Query(value = AiRuntimeControlSql.DISABLE, nativeQuery = true)
    int disableControl(@Param("expected") ControlVersion expected, @Param("at") Instant at);

    @Modifying
    @Query(value = AiRuntimeControlSql.ENABLE, nativeQuery = true)
    int enableControl(@Param("expected") ControlVersion expected, @Param("at") Instant at);

    @Modifying
    @Query(value = AiRuntimeControlSql.OBSERVE, nativeQuery = true)
    int observeControl(@Param("o") ReadinessObservation observation, @Param("at") Instant at);

    @Query(value = """
            SELECT EXISTS (SELECT 1 FROM {h-schema}ai_runtime_control c
                WHERE c.id = 1 AND c.generation = :generation AND c.enabled AND
            """ + AiRuntimeControlSql.FRESH + ")", nativeQuery = true)
    boolean controlUsable(@Param("generation") long generation);

    @Query(value = """
            SELECT EXISTS (SELECT 1 FROM {h-schema}ai_runtime_control c
                WHERE c.id = 1 AND c.generation = :generation AND c.observation_sequence = :sequence AND
            """ + AiRuntimeControlSql.FRESH + ")", nativeQuery = true)
    boolean controlEvidenceCurrent(@Param("generation") long generation, @Param("sequence") long sequence);

    @Query(value = AiRuntimeTransitionSql.ADMISSION_CURRENT, nativeQuery = true)
    boolean admissionCurrent(@Param("e") Expected expected);

    @Query(value = AiRuntimeTransitionSql.ADMISSION_CURRENT + AiRuntimeTransitionSql.OPERATION_CUTOFF,
            nativeQuery = true)
    boolean admissionCurrentBefore(@Param("e") Expected expected,
            @Param("operationDeadline") Instant operationDeadline);

    @Query(value = "SELECT uuid FROM {h-schema}ai_runtime_run WHERE uuid = :runId FOR UPDATE", nativeQuery = true)
    Optional<UUID> lockRun(@Param("runId") UUID runId);

    @Query(value = "SELECT uuid FROM {h-schema}ai_runtime_attempt WHERE uuid = :attemptId FOR UPDATE",
            nativeQuery = true)
    UUID lockAttempt(@Param("attemptId") UUID attemptId);

    @Query(value = "SELECT attempt_uuid FROM {h-schema}ai_runtime_launch WHERE attempt_uuid = :attemptId FOR UPDATE",
            nativeQuery = true)
    UUID lockLaunch(@Param("attemptId") UUID attemptId);

    @Query(value = """
            SELECT pod_uid FROM {h-schema}ai_runtime_workload WHERE attempt_uuid = :attemptId
            ORDER BY cluster, pod_uid FOR UPDATE
            """, nativeQuery = true)
    List<String> lockWorkloads(@Param("attemptId") UUID attemptId);

    @Query(value = "SELECT clock_timestamp()", nativeQuery = true)
    Instant decisionTime();

    @Query(value = """
            SELECT attempt_uuid FROM {h-schema}ai_runtime_workload
            WHERE cluster = :cluster AND pod_uid = :podUid
            """, nativeQuery = true)
    Optional<UUID> workloadAttempt(@Param("cluster") String cluster, @Param("podUid") String podUid);

    @Query(value = """
            SELECT count(*) FROM {h-schema}ai_runtime_workload w
            JOIN {h-schema}ai_runtime_attempt a ON a.uuid = w.attempt_uuid
            JOIN {h-schema}ai_runtime_launch l ON l.attempt_uuid = a.uuid
            WHERE a.run_uuid = :runId AND l.cleanup_state <> 'DONE'
            """, nativeQuery = true)
    long outstandingWorkloads(@Param("runId") UUID runId);

    @Modifying
    @Query(value = AiRuntimeTransitionSql.OBSERVE, nativeQuery = true)
    int observe(@Param("o") WorkloadObservation observation, @Param("at") Instant at);

    @Modifying
    @Query(value = AiRuntimeTransitionSql.CLAIM, nativeQuery = true)
    int claim(@Param("e") Expected expected, @Param("w") WorkloadRef workload, @Param("claimId") UUID claimId,
            @Param("leaseUntil") Instant leaseUntil, @Param("at") Instant at);

    @Modifying
    @Query(value = AiRuntimeTransitionSql.PENDING, nativeQuery = true)
    int pending(@Param("e") Expected expected, @Param("w") WorkloadRef workload,
            @Param("pendingDeadline") Instant pendingDeadline, @Param("at") Instant at);

    @Modifying
    @Query(value = AiRuntimeTransitionSql.HEARTBEAT, nativeQuery = true)
    int heartbeat(@Param("e") Expected expected, @Param("b") ClaimBinding binding, @Param("sequence") long sequence,
            @Param("leaseUntil") Instant leaseUntil, @Param("at") Instant at);

    @Modifying
    @Query(value = AiRuntimeTransitionSql.CLAIM + AiRuntimeTransitionSql.OPERATION_CUTOFF, nativeQuery = true)
    int claimBefore(@Param("e") Expected expected, @Param("w") WorkloadRef workload, @Param("claimId") UUID claimId,
            @Param("leaseUntil") Instant leaseUntil, @Param("at") Instant at,
            @Param("operationDeadline") Instant operationDeadline);

    @Modifying
    @Query(value = AiRuntimeTransitionSql.PENDING + AiRuntimeTransitionSql.OPERATION_CUTOFF, nativeQuery = true)
    int pendingBefore(@Param("e") Expected expected, @Param("w") WorkloadRef workload,
            @Param("pendingDeadline") Instant pendingDeadline, @Param("at") Instant at,
            @Param("operationDeadline") Instant operationDeadline);

    @Modifying
    @Query(value = AiRuntimeTransitionSql.HEARTBEAT + AiRuntimeTransitionSql.OPERATION_CUTOFF, nativeQuery = true)
    int heartbeatBefore(@Param("e") Expected expected, @Param("b") ClaimBinding binding,
            @Param("sequence") long sequence, @Param("leaseUntil") Instant leaseUntil, @Param("at") Instant at,
            @Param("operationDeadline") Instant operationDeadline);

    @Modifying
    @Query(value = AiRuntimeTransitionSql.FENCE, nativeQuery = true)
    int fence(@Param("e") Expected expected, @Param("reason") FailureReason reason, @Param("state") RunState state,
            @Param("at") Instant at);

    @Modifying
    @Query(value = AiRuntimeTransitionSql.TERMINATE_FENCED, nativeQuery = true)
    int terminateFenced(@Param("e") Expected expected, @Param("state") RunState state, @Param("at") Instant at);

    @Modifying
    @Query(value = AiRuntimeTransitionSql.REPLACE, nativeQuery = true)
    int replace(@Param("e") Expected expected, @Param("next") AttemptSpec next, @Param("at") Instant at);

    @Modifying
    @Query(value = AiRuntimeTransitionSql.CREATE, nativeQuery = true)
    int create(@Param("expected") ControlVersion expected, @Param("run") RunSpec run,
            @Param("attempt") AttemptSpec attempt);

    @Query(value = """
            SELECT r.uuid AS "runId", r.conversation_ref AS "conversationRef", r.actor_uuid AS "actorId",
                r.scope_marker AS "scopeMarker", r.state AS "runState", r.revision AS "revision", r.fence AS "runFence",
                r.attempts_used AS "attemptsUsed", r.attempt_limit AS "attemptLimit", r.run_deadline AS "runDeadline",
                r.lease_seconds AS "leaseSeconds", r.pod_limit AS "podLimit",
                r.created_at AS "runCreatedAt", r.updated_at AS "runUpdatedAt", r.control_generation AS "runControlGeneration",
                a.uuid AS "attemptId", a.attempt_no AS "attemptNo", a.state AS "attemptState",
                a.failure_reason AS "failureReason", a.fence AS "attemptFence", a.image_digest AS "imageDigest",
                a.profile_revision AS "profileRevision", a.security_revision AS "securityRevision",
                a.trust_revision AS "trustRevision", a.protocol AS "protocol", a.launch_deadline AS "launchDeadline",
                a.max_deadline AS "maxDeadline", a.winner_cluster AS "winnerCluster", a.winner_pod_uid AS "winnerPodUid",
                a.claim_uuid AS "claimId", a.lease_until AS "leaseUntil",
                a.last_heartbeat_sequence AS "heartbeatSequence", a.created_at AS "attemptCreatedAt",
                a.updated_at AS "attemptUpdatedAt", a.control_generation AS "attemptControlGeneration",
                l.cluster AS "cluster", l.namespace_name AS "namespaceName",
                l.namespace_uid AS "namespaceUid", l.service_account_name AS "serviceAccountName",
                l.service_account_uid AS "serviceAccountUid", l.job_name AS "jobName", l.job_uid AS "jobUid",
                l.template_digest AS "templateDigest", l.runtime_class AS "runtimeClass",
                l.observation_sequence AS "launchObservationSequence", l.cleanup_state AS "cleanupState",
                l.created_at AS "launchCreatedAt", l.updated_at AS "launchUpdatedAt",
                w.cluster AS "workloadCluster", w.pod_uid AS "podUid", w.pod_name AS "podName",
                w.job_uid AS "workloadJobUid", w.state AS "workloadState",
                w.observation_sequence AS "workloadObservationSequence", w.observation_valid_until AS "observationValidUntil",
                w.first_pending_at AS "firstPendingAt", w.pending_deadline AS "pendingDeadline",
                w.pending_returns AS "pendingReturns", w.bootstrap_consumed_at AS "bootstrapConsumedAt",
                w.created_at AS "workloadCreatedAt", w.updated_at AS "workloadUpdatedAt"
            FROM {h-schema}ai_runtime_run r
            JOIN {h-schema}ai_runtime_attempt a ON a.run_uuid = r.uuid AND a.uuid = r.current_attempt_uuid
            JOIN {h-schema}ai_runtime_launch l ON l.attempt_uuid = a.uuid
            LEFT JOIN {h-schema}ai_runtime_workload w ON w.attempt_uuid = a.uuid
            WHERE r.uuid = :runId
            ORDER BY w.cluster, w.pod_uid
            LIMIT 17
            """,
            nativeQuery = true)
    List<SnapshotRow> snapshotRows(@Param("runId") UUID runId);

    default Optional<RunSnapshot> snapshot(UUID runId) {
        List<SnapshotRow> rows = snapshotRows(runId);
        if (rows.isEmpty()) {
            return Optional.empty();
        }
        if (rows.size() > 16) {
            throw new IllegalStateException("Runtime workload cardinality exceeds its bound");
        }
        List<WorkloadSnapshot> workloads = rows.stream().flatMap(row -> row.workload().stream()).toList();
        return Optional.of(rows.getFirst().snapshot(workloads));
    }

    interface SnapshotRow {
        UUID getRunId();

        UUID getConversationRef();

        UUID getActorId();

        String getScopeMarker();

        String getRunState();

        long getRevision();

        long getRunFence();

        int getAttemptsUsed();

        int getAttemptLimit();

        Instant getRunDeadline();

        int getLeaseSeconds();

        int getPodLimit();

        Instant getRunCreatedAt();

        Instant getRunUpdatedAt();

        long getRunControlGeneration();

        UUID getAttemptId();

        int getAttemptNo();

        String getAttemptState();

        String getFailureReason();

        long getAttemptFence();

        String getImageDigest();

        long getProfileRevision();

        long getSecurityRevision();

        long getTrustRevision();

        String getProtocol();

        Instant getLaunchDeadline();

        Instant getMaxDeadline();

        String getWinnerCluster();

        String getWinnerPodUid();

        UUID getClaimId();

        Instant getLeaseUntil();

        Long getHeartbeatSequence();

        Instant getAttemptCreatedAt();

        Instant getAttemptUpdatedAt();

        long getAttemptControlGeneration();

        String getCluster();

        String getNamespaceName();

        String getNamespaceUid();

        String getServiceAccountName();

        String getServiceAccountUid();

        String getJobName();

        String getJobUid();

        String getTemplateDigest();

        String getRuntimeClass();

        long getLaunchObservationSequence();

        String getCleanupState();

        Instant getLaunchCreatedAt();

        Instant getLaunchUpdatedAt();

        String getWorkloadCluster();

        String getPodUid();

        String getPodName();

        String getWorkloadJobUid();

        String getWorkloadState();

        Long getWorkloadObservationSequence();

        Instant getObservationValidUntil();

        Instant getFirstPendingAt();

        Instant getPendingDeadline();

        Integer getPendingReturns();

        Instant getBootstrapConsumedAt();

        Instant getWorkloadCreatedAt();

        Instant getWorkloadUpdatedAt();

        default RunSnapshot snapshot(List<WorkloadSnapshot> workloads) {
            LaunchSpec launch = new LaunchSpec(getCluster(), getNamespaceName(), getNamespaceUid(),
                    getServiceAccountName(), getServiceAccountUid(), getTemplateDigest(), getRuntimeClass());
            AttemptSpec attempt = new AttemptSpec(getAttemptId(), getLaunchDeadline(), getMaxDeadline(),
                    getImageDigest(), getProfileRevision(), getSecurityRevision(), getTrustRevision(), getProtocol(),
                    launch);
            RunSpec run = new RunSpec(getRunId(), Optional.ofNullable(getConversationRef()), getActorId(),
                    getScopeMarker(), getAttemptLimit(), getPodLimit(), getLeaseSeconds(), getRunDeadline());
            return new RunSnapshot(run, RunState.valueOf(getRunState()), getRevision(), getRunFence(),
                    getAttemptsUsed(),
                    new AttemptSnapshot(attempt, getAttemptNo(), AttemptState.valueOf(getAttemptState()),
                            getAttemptFence(), Optional.ofNullable(getFailureReason()).map(FailureReason::valueOf),
                            claim(), getAttemptControlGeneration(), getAttemptCreatedAt(), getAttemptUpdatedAt()),
                    new LaunchSnapshot(launch, getJobName(), Optional.ofNullable(getJobUid()),
                            getLaunchObservationSequence(), CleanupState.valueOf(getCleanupState()),
                            getLaunchCreatedAt(), getLaunchUpdatedAt()),
                    workloads, getRunControlGeneration(), getRunCreatedAt(), getRunUpdatedAt());
        }

        default Optional<Claim> claim() {
            return Optional
                    .ofNullable(getClaimId())
                    .map(id -> new Claim(
                            new ClaimBinding(getRunId(), getAttemptId(),
                                    new WorkloadRef(getWinnerCluster(), getWinnerPodUid()), id, getAttemptFence()),
                            getLeaseUntil(), getHeartbeatSequence()));
        }

        default Optional<WorkloadSnapshot> workload() {
            if (getPodUid() == null) {
                return Optional.empty();
            }
            return Optional
                    .of(new WorkloadSnapshot(new WorkloadRef(getWorkloadCluster(), getPodUid()), getPodName(),
                            getWorkloadJobUid(), WorkloadState.valueOf(getWorkloadState()),
                            getWorkloadObservationSequence(), getObservationValidUntil(),
                            Optional.ofNullable(getFirstPendingAt()), Optional.ofNullable(getPendingDeadline()),
                            getPendingReturns(), Optional.ofNullable(getBootstrapConsumedAt()), getWorkloadCreatedAt(),
                            getWorkloadUpdatedAt()));
        }

    }
}
