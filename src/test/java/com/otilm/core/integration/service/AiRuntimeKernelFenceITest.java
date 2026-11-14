package com.otilm.core.integration.service;

import com.otilm.core.model.ai.AiRuntimeState.AttemptSpec;
import com.otilm.core.model.ai.AiRuntimeState.AttemptState;
import com.otilm.core.model.ai.AiRuntimeState.Claim;
import com.otilm.core.model.ai.AiRuntimeState.CleanupState;
import com.otilm.core.model.ai.AiRuntimeState.Expected;
import com.otilm.core.model.ai.AiRuntimeState.FailureReason;
import com.otilm.core.model.ai.AiRuntimeState.RunSnapshot;
import com.otilm.core.model.ai.AiRuntimeState.RunState;
import com.otilm.core.model.ai.AiRuntimeState.Status;
import com.otilm.core.model.ai.AiRuntimeState.Transition;
import com.otilm.core.model.ai.AiRuntimeState.WorkloadObservation;
import com.otilm.core.model.ai.AiRuntimeState.WorkloadRef;
import com.otilm.core.model.ai.AiRuntimeState.WorkloadSnapshot;
import com.otilm.core.model.ai.AiRuntimeState.WorkloadState;
import com.otilm.core.service.ai.AiRuntimeKernel;
import com.otilm.core.util.AiRuntimeFixture;
import com.otilm.core.util.ai.BaseAiSpringBootTest;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.time.Instant;
import java.util.List;
import java.util.UUID;
import javax.sql.DataSource;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;

import static com.otilm.core.util.AiRuntimeFixture.expected;
import static com.otilm.core.util.AiRuntimeFixture.observation;
import static org.assertj.core.api.Assertions.assertThat;

class AiRuntimeKernelFenceITest extends BaseAiSpringBootTest {
    private static final WorkloadRef FIRST = new WorkloadRef("cluster-one", "pod-one");
    private static final WorkloadRef SECOND = new WorkloadRef("cluster-one", "pod-two");
    @Autowired
    private DataSource dataSource;
    @Autowired
    private AiRuntimeKernel kernel;
    private RunSnapshot created;

    @BeforeEach
    void createRun() throws Exception {
        AiRuntimeFixture.install(dataSource);
        Instant now = AiRuntimeFixture.now(dataSource);
        var control = AiRuntimeFixture.enableTestControl(kernel, now);
        created = kernel.create(control, AiRuntimeFixture.run(now), AiRuntimeFixture.attempt(now));
    }

    @Test
    void cancellationPreservesClaimAndPendingHistoryAndReplaysWithoutMutation() {
        assertEmpty(kernel.observe(observation(current(), FIRST, 1, false)), Status.APPLIED);
        assertEmpty(kernel.bootstrap(expected(current()), FIRST), Status.PENDING);
        Claim initial = claim(SECOND);
        Claim renewed = kernel.heartbeat(initial.binding(), 2).value().orElseThrow();
        RunSnapshot before = current();

        assertEmpty(kernel.cancel(created.spec().runId()), Status.APPLIED);

        RunSnapshot cancelled = current();
        assertFence(before, cancelled, RunState.CANCELLED, FailureReason.CANCELLED);
        assertThat(cancelled.attempt().claim()).contains(renewed);
        assertEmpty(kernel.cancel(created.spec().runId()), Status.REPLAY);
        assertEmpty(kernel.bootstrap(expected(cancelled), SECOND), Status.CANCELLED);
        assertEmpty(kernel.heartbeat(renewed.binding(), 2), Status.CANCELLED);
        assertEmpty(kernel.heartbeat(renewed.binding(), 3), Status.CANCELLED);
        assertEmpty(kernel.replace(expected(cancelled), nextAttempt()), Status.CANCELLED);
        assertThat(current()).isEqualTo(cancelled);
    }

    @Test
    void cancellationOfRecoverableRunPreservesPreviouslyClosedAttemptHistory() throws Exception {
        claim(FIRST);
        expireLease();
        assertEmpty(kernel.expire(expected(current())), Status.APPLIED);
        RunSnapshot expired = current();
        assertThat(expired.state()).isEqualTo(RunState.QUEUED);
        assertThat(expired.attempt().failure()).contains(FailureReason.LEASE_EXPIRED);

        assertEmpty(kernel.cancel(expired.spec().runId()), Status.APPLIED);

        RunSnapshot cancelled = current();
        assertThat(cancelled.state()).isEqualTo(RunState.CANCELLED);
        assertThat(cancelled.revision()).isEqualTo(expired.revision() + 1);
        assertThat(cancelled.fence()).isEqualTo(expired.fence() + 1);
        assertThat(cancelled.attempt()).isEqualTo(expired.attempt());
        assertThat(cancelled.launch()).isEqualTo(expired.launch());
        assertThat(cancelled.workloads()).isEqualTo(expired.workloads());
        assertThat(cancelled.attemptsUsed()).isEqualTo(expired.attemptsUsed());
        assertEmpty(kernel.cancel(cancelled.spec().runId()), Status.REPLAY);
        assertThat(current()).isEqualTo(cancelled);
        assertOldAttemptHistory(expired);
    }

    @Test
    void expiredLeaseCannotReplayBootstrapOrHeartbeatBeforeExplicitFencing() throws Exception {
        Claim initial = claim(FIRST);
        Transition<Claim> renewal = kernel.heartbeat(initial.binding(), 1);
        assertThat(renewal.status()).isEqualTo(Status.APPLIED);
        Claim currentClaim = renewal.value().orElseThrow();
        expireLease();
        RunSnapshot expired = current();

        assertEmpty(kernel.bootstrap(expected(expired), FIRST), Status.EXPIRED);
        assertEmpty(kernel.heartbeat(currentClaim.binding(), 1), Status.EXPIRED);
        assertEmpty(kernel.heartbeat(currentClaim.binding(), 2), Status.EXPIRED);
        assertThat(current()).isEqualTo(expired);
        assertEmpty(kernel.expire(expected(expired)), Status.APPLIED);

        RunSnapshot fenced = current();
        assertFence(expired, fenced, RunState.QUEUED, FailureReason.LEASE_EXPIRED);
        assertThat(fenced.attempt().claim().orElseThrow().heartbeatSequence()).isEqualTo(1);
        assertOldAttemptHistory(fenced);
    }

    @Test
    void onlyWinningObservationExpiryCanFenceClaimedAttempt() throws Exception {
        assertEmpty(kernel.observe(observation(current(), SECOND, 1, true)), Status.APPLIED);
        Claim winner = claim(FIRST);
        expireObservation(SECOND);
        RunSnapshot losingObservationExpired = current();

        assertEmpty(kernel.expire(expected(losingObservationExpired)), Status.DENIED);
        assertThat(current()).isEqualTo(losingObservationExpired);
        Transition<Claim> renewed = kernel.heartbeat(winner.binding(), 1);
        assertThat(renewed.status()).isEqualTo(Status.APPLIED);
        assertThat(renewed.value().orElseThrow().heartbeatSequence()).isEqualTo(1);
        expireObservation(FIRST);
        RunSnapshot winningObservationExpired = current();

        assertEmpty(kernel.bootstrap(expected(winningObservationExpired), FIRST), Status.EXPIRED);
        assertEmpty(kernel.heartbeat(winner.binding(), 1), Status.EXPIRED);
        assertThat(current()).isEqualTo(winningObservationExpired);
        assertEmpty(kernel.expire(expected(winningObservationExpired)), Status.APPLIED);
        assertFence(winningObservationExpired, current(), RunState.QUEUED, FailureReason.OBSERVATION_EXPIRED);
    }

    @Test
    void replacementConsumesBudgetOnceAndOldBindingsStayFenced() throws Exception {
        Claim oldClaim = claim(FIRST);
        WorkloadObservation delayed = observation(current(), SECOND, 2, true);
        expireLease();
        assertEmpty(kernel.expire(expected(current())), Status.APPLIED);
        RunSnapshot fenced = current();
        Expected replaceOnce = expected(fenced);
        AttemptSpec next = nextAttempt();

        Transition<RunSnapshot> replacement = kernel.replace(replaceOnce, next);

        assertThat(replacement.status()).isEqualTo(Status.APPLIED);
        RunSnapshot replaced = replacement.value().orElseThrow();
        assertThat(current()).isEqualTo(replaced);
        assertReplacement(fenced, replaced, next);
        assertEmpty(kernel.replace(replaceOnce, next), Status.STALE);
        assertEmpty(kernel.bootstrap(expected(fenced), FIRST), Status.STALE);
        assertEmpty(kernel.heartbeat(oldClaim.binding(), 1), Status.STALE);
        assertEmpty(kernel.observe(delayed), Status.STALE);
        assertThat(current()).isEqualTo(replaced);
        assertOldAttemptHistory(fenced);
        assertRows(2, 2, 1);

        Claim newClaim = claim(SECOND);
        assertThat(newClaim.binding().attemptId()).isEqualTo(next.attemptId());
        assertThat(newClaim.binding().fence()).isEqualTo(replaced.fence());
        assertThat(newClaim.binding().claimId()).isNotEqualTo(oldClaim.binding().claimId());
        assertOldAttemptHistory(fenced);
        assertRows(2, 2, 2);
    }

    @Test
    void changedImageOrConfigurationPinsCannotReplaceRecoverableAttempt() throws Exception {
        claim(FIRST);
        expireLease();
        assertEmpty(kernel.expire(expected(current())), Status.APPLIED);
        RunSnapshot fenced = current();
        AttemptSpec next = nextAttempt();
        List<AttemptSpec> mismatches = List
                .of(withPins(next, "sha256:" + "c".repeat(64), 1, 1, 1), withPins(next, next.imageDigest(), 2, 1, 1),
                        withPins(next, next.imageDigest(), 1, 2, 1), withPins(next, next.imageDigest(), 1, 1, 2));

        for (AttemptSpec mismatch : mismatches) {
            assertEmpty(kernel.replace(expected(fenced), mismatch), Status.CONFLICT);
            assertThat(current()).isEqualTo(fenced);
            assertOldAttemptHistory(fenced);
            assertRows(1, 1, 1);
        }

        Transition<RunSnapshot> valid = kernel.replace(expected(fenced), next);
        assertThat(valid.status()).isEqualTo(Status.APPLIED);
        assertReplacement(fenced, valid.value().orElseThrow(), next);
        assertRows(2, 2, 1);
    }

    @Test
    void exhaustedAttemptBudgetNeverReopensTerminalRun() throws Exception {
        claim(FIRST);
        expireLease();
        assertEmpty(kernel.expire(expected(current())), Status.APPLIED);
        RunSnapshot firstClosed = current();
        AttemptSpec second = nextAttempt();
        assertThat(kernel.replace(expected(firstClosed), second).status()).isEqualTo(Status.APPLIED);
        RunSnapshot secondLaunching = current();
        assertThat(secondLaunching.attemptsUsed()).isEqualTo(2);
        expireLaunch();
        RunSnapshot due = current();

        assertEmpty(kernel.expire(expected(due)), Status.APPLIED);

        RunSnapshot limited = current();
        assertFence(due, limited, RunState.LIMIT_REACHED, FailureReason.LAUNCH_EXPIRED);
        assertThat(limited.attemptsUsed()).isEqualTo(limited.spec().attemptLimit());
        assertEmpty(kernel.replace(expected(limited), nextAttempt()), Status.LIMIT_REACHED);
        assertEmpty(kernel.bootstrap(expected(limited), SECOND), Status.LIMIT_REACHED);
        assertEmpty(kernel.expire(expected(limited)), Status.DENIED);
        assertThat(current()).isEqualTo(limited);
        assertOldAttemptHistory(firstClosed);
        assertRows(2, 2, 1);
    }

    @Test
    void launchExpiryRequiresPersistedDeadlineAndPreservesReplacementPins() throws Exception {
        assertEmpty(kernel.expire(expected(created)), Status.DENIED);
        assertThat(current()).isEqualTo(created);
        expireLaunch();
        RunSnapshot due = current();

        assertEmpty(kernel.expire(expected(due)), Status.APPLIED);

        RunSnapshot fenced = current();
        assertFence(due, fenced, RunState.QUEUED, FailureReason.LAUNCH_EXPIRED);
        assertThat(fenced.attempt().claim()).isEmpty();
        AttemptSpec next = nextAttempt();
        Transition<RunSnapshot> replacement = kernel.replace(expected(fenced), next);
        assertThat(replacement.status()).isEqualTo(Status.APPLIED);
        assertReplacement(fenced, replacement.value().orElseThrow(), next);
        assertRows(2, 2, 0);
    }

    @Test
    void delayedObservationAfterCancellationWritesNoNewBindings() throws Exception {
        assertEmpty(kernel.observe(observation(current(), FIRST, 1, true)), Status.APPLIED);
        WorkloadObservation delayed = observation(current(), SECOND, 2, true);
        RunSnapshot before = current();
        assertEmpty(kernel.cancel(before.spec().runId()), Status.APPLIED);
        RunSnapshot cancelled = current();

        assertEmpty(kernel.observe(delayed), Status.STALE);
        assertEmpty(kernel.observe(observation(cancelled, SECOND, 3, true)), Status.CANCELLED);

        assertThat(current()).isEqualTo(cancelled);
        assertThat(cancelled.launch().jobUid()).isEqualTo(before.launch().jobUid());
        assertThat(cancelled.launch().observationSequence()).isEqualTo(before.launch().observationSequence());
        assertRows(1, 1, 1);
    }

    @Test
    void invalidationRequiresCurrentExpectedAndTerminalStateNeverReopens() throws Exception {
        Expected stale = expected(created);
        Claim claim = claim(FIRST);
        RunSnapshot running = current();

        assertEmpty(kernel.invalidate(stale), Status.STALE);
        assertThat(current()).isEqualTo(running);
        assertEmpty(kernel.invalidate(expected(running)), Status.APPLIED);

        RunSnapshot invalidated = current();
        assertFence(running, invalidated, RunState.FAILED, FailureReason.INVALIDATED);
        assertEmpty(kernel.invalidate(expected(invalidated)), Status.DENIED);
        assertEmpty(kernel.expire(expected(invalidated)), Status.DENIED);
        assertEmpty(kernel.replace(expected(invalidated), nextAttempt()), Status.DENIED);
        assertEmpty(kernel.bootstrap(expected(invalidated), FIRST), Status.DENIED);
        assertEmpty(kernel.heartbeat(claim.binding(), 1), Status.DENIED);
        assertEmpty(kernel.observe(observation(invalidated, SECOND, 2, true)), Status.DENIED);
        assertThat(current()).isEqualTo(invalidated);
        assertOldAttemptHistory(invalidated);
        assertRows(1, 1, 1);
    }

    @Test
    void invalidationStopsRecoveryWithoutRewritingFencedAttempt() throws Exception {
        claim(FIRST);
        expireLease();
        assertEmpty(kernel.expire(expected(current())), Status.APPLIED);
        RunSnapshot recovering = current();

        assertEmpty(kernel.invalidate(expected(recovering)), Status.APPLIED);

        RunSnapshot invalidated = current();
        assertThat(invalidated.state()).isEqualTo(RunState.FAILED);
        assertThat(invalidated.revision()).isEqualTo(recovering.revision() + 1);
        assertThat(invalidated.fence()).isEqualTo(recovering.fence() + 1);
        assertThat(invalidated.attempt()).isEqualTo(recovering.attempt());
        assertThat(invalidated.launch()).isEqualTo(recovering.launch());
        assertThat(invalidated.workloads()).isEqualTo(recovering.workloads());
        assertEmpty(kernel.replace(expected(invalidated), nextAttempt()), Status.DENIED);
        assertEmpty(kernel.invalidate(expected(invalidated)), Status.DENIED);
        assertThat(current()).isEqualTo(invalidated);
    }

    @Test
    void expiredRecoveryTerminatesWithoutReplacementSpec() throws Exception {
        expireLaunch();
        assertEmpty(kernel.expire(expected(current())), Status.APPLIED);
        try (Connection connection = dataSource.getConnection();
                PreparedStatement statement = connection.prepareStatement("""
                        WITH cutoff AS MATERIALIZED (SELECT clock_timestamp() - interval '1 second' AS at),
                        expired_run AS (
                            UPDATE ai_runtime_run r SET run_deadline = cutoff.at
                            FROM cutoff WHERE r.uuid = ? RETURNING r.current_attempt_uuid
                        )
                        UPDATE ai_runtime_attempt a SET max_deadline = cutoff.at,
                            launch_deadline = LEAST(a.launch_deadline, cutoff.at)
                        FROM cutoff, expired_run WHERE a.uuid = expired_run.current_attempt_uuid
                        """)) {
            statement.setObject(1, created.spec().runId());
            assertThat(statement.executeUpdate()).isEqualTo(1);
        }
        RunSnapshot due = current();

        assertEmpty(kernel.expire(expected(due)), Status.APPLIED);

        RunSnapshot limited = current();
        assertThat(limited.state()).isEqualTo(RunState.LIMIT_REACHED);
        assertThat(limited.revision()).isEqualTo(due.revision() + 1);
        assertThat(limited.fence()).isEqualTo(due.fence() + 1);
        assertThat(limited.attempt()).isEqualTo(due.attempt());
        assertThat(limited.launch()).isEqualTo(due.launch());
        assertThat(limited.workloads()).isEqualTo(due.workloads());
        assertEmpty(kernel.expire(expected(limited)), Status.DENIED);
        assertThat(current()).isEqualTo(limited);
    }

    @Test
    void registrationAfterPendingDeadlineCannotClaimOrReturnGenericConflict() throws Exception {
        assertEmpty(kernel.observe(observation(current(), FIRST, 1, false)), Status.APPLIED);
        assertEmpty(kernel.bootstrap(expected(current()), FIRST), Status.PENDING);
        try (Connection connection = dataSource.getConnection();
                PreparedStatement statement = connection.prepareStatement("""
                        WITH cutoff AS (SELECT clock_timestamp() - interval '1 second' AS at)
                        UPDATE ai_runtime_workload w SET first_pending_at = cutoff.at - interval '1 second',
                            pending_deadline = cutoff.at FROM cutoff
                        WHERE w.attempt_uuid = ? AND w.cluster = ? AND w.pod_uid = ?
                        """)) {
            statement.setObject(1, created.attempt().spec().attemptId());
            statement.setString(2, FIRST.cluster());
            statement.setString(3, FIRST.podUid());
            assertThat(statement.executeUpdate()).isEqualTo(1);
        }
        assertEmpty(kernel.observe(observation(current(), FIRST, 2, true)), Status.APPLIED);
        RunSnapshot registered = current();

        assertEmpty(kernel.bootstrap(expected(registered), FIRST), Status.EXPIRED);

        assertFence(registered, current(), RunState.QUEUED, FailureReason.PENDING_EXHAUSTED);
        assertThat(current().attempt().claim()).isEmpty();
    }

    private Claim claim(WorkloadRef workload) {
        assertEmpty(kernel.observe(observation(current(), workload, 1, true)), Status.APPLIED);
        Transition<Claim> result = kernel.bootstrap(expected(current()), workload);
        assertThat(result.status()).isEqualTo(Status.APPLIED);
        return result.value().orElseThrow();
    }

    private RunSnapshot current() {
        return kernel.snapshot(created.spec().runId()).orElseThrow();
    }

    private AttemptSpec nextAttempt() {
        AttemptSpec original = created.attempt().spec();
        return new AttemptSpec(UUID.randomUUID(), original.launchDeadline(), original.maxDeadline(),
                original.imageDigest(), original.profileRevision(), original.securityRevision(),
                original.trustRevision(), original.protocol(), original.launch());
    }

    private static AttemptSpec withPins(AttemptSpec source, String image, long profile, long security, long trust) {
        return new AttemptSpec(source.attemptId(), source.launchDeadline(), source.maxDeadline(), image, profile,
                security, trust, source.protocol(), source.launch());
    }

    private static void assertEmpty(Transition<?> transition, Status status) {
        assertThat(transition.status()).isEqualTo(status);
        assertThat(transition.value()).isEmpty();
    }

    private static void assertFence(RunSnapshot before, RunSnapshot after, RunState state, FailureReason reason) {
        assertThat(after.spec()).isEqualTo(before.spec());
        assertThat(after.state()).isEqualTo(state);
        assertThat(after.revision()).isEqualTo(before.revision() + 1);
        assertThat(after.fence()).isEqualTo(before.fence() + 1);
        assertThat(after.attemptsUsed()).isEqualTo(before.attemptsUsed());
        assertThat(after.attempt().spec()).isEqualTo(before.attempt().spec());
        assertThat(after.attempt().attemptNo()).isEqualTo(before.attempt().attemptNo());
        assertThat(after.attempt().state()).isEqualTo(AttemptState.FENCED);
        assertThat(after.attempt().failure()).contains(reason);
        assertThat(after.attempt().fence()).isEqualTo(before.attempt().fence());
        assertThat(after.attempt().claim()).isEqualTo(before.attempt().claim());
        assertThat(after.attempt().createdAt()).isEqualTo(before.attempt().createdAt());
        assertThat(after.launch().cleanup()).isEqualTo(CleanupState.DUE);
        assertThat(after.launch().spec()).isEqualTo(before.launch().spec());
        assertThat(after.launch().jobName()).isEqualTo(before.launch().jobName());
        assertThat(after.launch().jobUid()).isEqualTo(before.launch().jobUid());
        assertThat(after.launch().observationSequence()).isEqualTo(before.launch().observationSequence());
        assertThat(after.workloads()).hasSameSizeAs(before.workloads());
        for (WorkloadSnapshot old : before.workloads()) {
            WorkloadSnapshot closed = after
                    .workloads()
                    .stream()
                    .filter(row -> row.ref().equals(old.ref()))
                    .findFirst()
                    .orElseThrow();
            assertThat(closed.state()).isEqualTo(WorkloadState.CLOSED);
            assertThat(closed.pendingReturns()).isEqualTo(old.pendingReturns());
            assertThat(closed.firstPendingAt()).isEqualTo(old.firstPendingAt());
            assertThat(closed.pendingDeadline()).isEqualTo(old.pendingDeadline());
            assertThat(closed.bootstrapConsumedAt()).isEqualTo(old.bootstrapConsumedAt());
            assertThat(closed.observationSequence()).isEqualTo(old.observationSequence());
            assertThat(closed.observationValidUntil()).isEqualTo(old.observationValidUntil());
            assertThat(closed.jobUid()).isEqualTo(old.jobUid());
            assertThat(closed.podName()).isEqualTo(old.podName());
            assertThat(closed.createdAt()).isEqualTo(old.createdAt());
        }
    }

    private static void assertReplacement(RunSnapshot fenced, RunSnapshot replacement, AttemptSpec next) {
        assertThat(replacement.spec()).isEqualTo(fenced.spec());
        assertThat(replacement.state()).isEqualTo(RunState.QUEUED);
        assertThat(replacement.revision()).isEqualTo(fenced.revision() + 1);
        assertThat(replacement.fence()).isEqualTo(fenced.fence() + 1);
        assertThat(replacement.attemptsUsed()).isEqualTo(fenced.attemptsUsed() + 1);
        assertThat(replacement.attempt().attemptNo()).isEqualTo(fenced.attempt().attemptNo() + 1);
        assertThat(replacement.attempt().spec()).isEqualTo(next);
        assertThat(replacement.attempt().state()).isEqualTo(AttemptState.LAUNCHING);
        assertThat(replacement.attempt().fence()).isEqualTo(replacement.fence());
        assertThat(replacement.attempt().failure()).isEmpty();
        assertThat(replacement.attempt().claim()).isEmpty();
        assertThat(replacement.launch().spec()).isEqualTo(next.launch());
        assertThat(replacement.launch().jobName()).isEqualTo("ilm-ai-" + next.attemptId().toString().replace("-", ""));
        assertThat(replacement.launch().jobUid()).isEmpty();
        assertThat(replacement.launch().observationSequence()).isZero();
        assertThat(replacement.launch().cleanup()).isEqualTo(CleanupState.NONE);
        assertThat(replacement.workloads()).isEmpty();
    }

    private void expireLease() throws Exception {
        updateCurrentAttempt("""
                WITH cutoff AS (SELECT clock_timestamp() - interval '1 second' AS value)
                UPDATE ai_runtime_attempt a
                SET lease_until = cutoff.value, last_heartbeat_lease = cutoff.value
                FROM cutoff WHERE a.uuid = ? AND a.run_uuid = ?
                """);
    }

    private void expireLaunch() throws Exception {
        updateCurrentAttempt("""
                UPDATE ai_runtime_attempt SET launch_deadline = clock_timestamp() - interval '1 second'
                WHERE uuid = ? AND run_uuid = ?
                """);
    }

    private void updateCurrentAttempt(String sql) throws Exception {
        UUID attemptId = current().attempt().spec().attemptId();
        try (Connection connection = dataSource.getConnection();
                PreparedStatement statement = connection.prepareStatement(sql)) {
            statement.setObject(1, attemptId);
            statement.setObject(2, created.spec().runId());
            assertThat(statement.executeUpdate()).isEqualTo(1);
        }
    }

    private void expireObservation(WorkloadRef workload) throws Exception {
        try (Connection connection = dataSource.getConnection();
                PreparedStatement statement = connection.prepareStatement("""
                        UPDATE ai_runtime_workload SET observation_valid_until = clock_timestamp() - interval '1 second'
                        WHERE attempt_uuid = ? AND cluster = ? AND pod_uid = ?
                        """)) {
            statement.setObject(1, current().attempt().spec().attemptId());
            statement.setString(2, workload.cluster());
            statement.setString(3, workload.podUid());
            assertThat(statement.executeUpdate()).isEqualTo(1);
        }
    }

    private void assertOldAttemptHistory(RunSnapshot closed) throws Exception {
        try (Connection connection = dataSource.getConnection();
                PreparedStatement statement = connection.prepareStatement("""
                        SELECT a.state, a.failure_reason, a.fence, a.winner_cluster, a.winner_pod_uid,
                            a.claim_uuid, a.lease_until, a.last_heartbeat_sequence, a.last_heartbeat_lease,
                            a.updated_at, l.cleanup_state,
                            (SELECT count(*) FROM ai_runtime_workload w
                             WHERE w.attempt_uuid = a.uuid AND w.state <> 'CLOSED') AS live_workloads
                        FROM ai_runtime_attempt a JOIN ai_runtime_launch l ON l.attempt_uuid = a.uuid
                        WHERE a.uuid = ? AND a.run_uuid = ?
                        """)) {
            statement.setObject(1, closed.attempt().spec().attemptId());
            statement.setObject(2, closed.spec().runId());
            try (ResultSet result = statement.executeQuery()) {
                assertThat(result.next()).isTrue();
                Claim recorded = closed.attempt().claim().orElseThrow();
                assertThat(result.getString("state")).isEqualTo(AttemptState.FENCED.name());
                assertThat(result.getString("failure_reason"))
                        .isEqualTo(closed.attempt().failure().orElseThrow().name());
                assertThat(result.getLong("fence")).isEqualTo(closed.attempt().fence());
                assertThat(result.getString("winner_cluster")).isEqualTo(recorded.binding().workload().cluster());
                assertThat(result.getString("winner_pod_uid")).isEqualTo(recorded.binding().workload().podUid());
                assertThat(result.getObject("claim_uuid", UUID.class)).isEqualTo(recorded.binding().claimId());
                assertThat(result.getTimestamp("lease_until").toInstant()).isEqualTo(recorded.leaseUntil());
                assertThat(result.getTimestamp("last_heartbeat_lease").toInstant()).isEqualTo(recorded.leaseUntil());
                assertThat(result.getLong("last_heartbeat_sequence")).isEqualTo(recorded.heartbeatSequence());
                assertThat(result.getTimestamp("updated_at").toInstant()).isEqualTo(closed.attempt().updatedAt());
                assertThat(result.getString("cleanup_state")).isEqualTo(CleanupState.DUE.name());
                assertThat(result.getLong("live_workloads")).isZero();
                assertThat(result.next()).isFalse();
            }
        }
    }

    private void assertRows(int attempts, int launches, int workloads) throws Exception {
        try (Connection connection = dataSource.getConnection();
                PreparedStatement statement = connection
                        .prepareStatement(
                                """
                                        SELECT (SELECT count(*) FROM ai_runtime_attempt WHERE run_uuid = ?) AS attempts,
                                            (SELECT count(*) FROM ai_runtime_launch l JOIN ai_runtime_attempt a ON a.uuid = l.attempt_uuid
                                             WHERE a.run_uuid = ?) AS launches,
                                            (SELECT count(*) FROM ai_runtime_workload w JOIN ai_runtime_attempt a ON a.uuid = w.attempt_uuid
                                             WHERE a.run_uuid = ?) AS workloads
                                        """)) {
            for (int parameter = 1; parameter <= 3; parameter++) {
                statement.setObject(parameter, created.spec().runId());
            }
            try (ResultSet result = statement.executeQuery()) {
                assertThat(result.next()).isTrue();
                assertThat(result.getInt("attempts")).isEqualTo(attempts);
                assertThat(result.getInt("launches")).isEqualTo(launches);
                assertThat(result.getInt("workloads")).isEqualTo(workloads);
                assertThat(result.next()).isFalse();
            }
        }
    }
}
