package com.otilm.core.integration.service;

import com.otilm.core.model.ai.AiRuntimeState.AttemptSpec;
import com.otilm.core.model.ai.AiRuntimeState.AttemptState;
import com.otilm.core.model.ai.AiRuntimeState.Claim;
import com.otilm.core.model.ai.AiRuntimeState.CleanupState;
import com.otilm.core.model.ai.AiRuntimeState.ControlVersion;
import com.otilm.core.model.ai.AiRuntimeState.FailureReason;
import com.otilm.core.model.ai.AiRuntimeState.RunSnapshot;
import com.otilm.core.model.ai.AiRuntimeState.RunSpec;
import com.otilm.core.model.ai.AiRuntimeState.Status;
import com.otilm.core.model.ai.AiRuntimeState.Transition;
import com.otilm.core.model.ai.AiRuntimeState.WorkloadObservation;
import com.otilm.core.model.ai.AiRuntimeState.WorkloadRef;
import com.otilm.core.model.ai.AiRuntimeState.WorkloadState;
import com.otilm.core.service.ai.AiRuntimeKernel;
import com.otilm.core.util.AiRuntimeFixture;
import com.otilm.core.util.ai.BaseAiSpringBootTest;
import java.time.Instant;
import java.util.UUID;
import javax.sql.DataSource;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;

import static com.otilm.core.util.AiRuntimeFixture.expected;
import static com.otilm.core.util.AiRuntimeFixture.observation;
import static org.assertj.core.api.Assertions.assertThat;

class AiRuntimeKernelClaimITest extends BaseAiSpringBootTest {
    private static final WorkloadRef FIRST = new WorkloadRef("cluster-one", "pod-one");
    private static final WorkloadRef SECOND = new WorkloadRef("cluster-one", "pod-two");
    @Autowired
    private DataSource dataSource;
    @Autowired
    private AiRuntimeKernel kernel;
    private RunSnapshot created;
    private ControlVersion control;

    @BeforeEach
    void createRun() throws Exception {
        AiRuntimeFixture.install(dataSource);
        Instant now = AiRuntimeFixture.now(dataSource);
        control = AiRuntimeFixture.enableTestControl(kernel, now);
        created = kernel.create(control, AiRuntimeFixture.run(now), AiRuntimeFixture.attempt(now));
    }

    @Test
    void pendingNeedsStoredEligibleObservation() {
        Transition<Claim> absent = kernel.bootstrap(expected(current()), FIRST);
        assertThat(absent.status()).isEqualTo(Status.DENIED);
        assertThat(absent.value()).isEmpty();
        assertThat(current().revision()).isEqualTo(created.revision());

        assertThat(kernel.observe(observation(current(), FIRST, 1, false)).status()).isEqualTo(Status.APPLIED);
        Transition<Claim> pending = kernel.bootstrap(expected(current()), FIRST);
        assertThat(pending.status()).isEqualTo(Status.PENDING);
        assertThat(pending.value()).isEmpty();
        assertThat(current().workloads()).singleElement().satisfies(row -> {
            assertThat(row.pendingReturns()).isEqualTo(1);
            assertThat(row.firstPendingAt()).isPresent();
            assertThat(row.pendingDeadline()).contains(created.attempt().spec().launchDeadline());
        });
    }

    @Test
    void pendingHasElevenResponsesThenDurableExhaustion() {
        assertThat(kernel.observe(observation(current(), FIRST, 1, false)).status()).isEqualTo(Status.APPLIED);
        for (int response = 1; response <= 11; response++) {
            Transition<Claim> pending = kernel.bootstrap(expected(current()), FIRST);
            assertThat(pending.status()).isEqualTo(Status.PENDING);
            assertThat(pending.value()).isEmpty();
            assertThat(current().workloads().getFirst().pendingReturns()).isEqualTo(response);
        }
        Transition<Claim> exhausted = kernel.bootstrap(expected(current()), FIRST);
        assertThat(exhausted.status()).isEqualTo(Status.EXPIRED);
        assertThat(exhausted.value()).isEmpty();
        RunSnapshot stopped = current();
        assertThat(stopped.attempt().state()).isEqualTo(AttemptState.FENCED);
        assertThat(stopped.attempt().failure()).contains(FailureReason.PENDING_EXHAUSTED);
        assertThat(stopped.launch().cleanup()).isEqualTo(CleanupState.DUE);
        assertThat(stopped.workloads()).allSatisfy(row -> assertThat(row.state()).isEqualTo(WorkloadState.CLOSED));
        assertThat(kernel.bootstrap(expected(stopped), FIRST).value()).isEmpty();
        assertThat(current().revision()).isEqualTo(stopped.revision());
    }

    @Test
    void registrationDoesNotResetPendingCounters() {
        kernel.observe(observation(current(), FIRST, 1, false));
        kernel.bootstrap(expected(current()), FIRST);
        Instant firstPending = current().workloads().getFirst().firstPendingAt().orElseThrow();

        assertThat(kernel.observe(observation(current(), FIRST, 2, true)).status()).isEqualTo(Status.APPLIED);

        assertThat(current().workloads()).singleElement().satisfies(row -> {
            assertThat(row.pendingReturns()).isEqualTo(1);
            assertThat(row.firstPendingAt()).contains(firstPending);
            assertThat(row.state()).isEqualTo(WorkloadState.REGISTERED);
        });
        assertThat(kernel.bootstrap(expected(current()), FIRST).status()).isEqualTo(Status.APPLIED);
    }

    @Test
    void sameWinnerRetryDoesNotRenewAndAnotherPodGetsNoClaim() {
        kernel.observe(observation(current(), FIRST, 1, true));
        kernel.observe(observation(current(), SECOND, 1, true));
        Transition<Claim> first = kernel.bootstrap(expected(current()), FIRST);
        assertThat(first.status()).isEqualTo(Status.APPLIED);
        Claim winner = first.value().orElseThrow();
        RunSnapshot claimed = current();

        Transition<Claim> retry = kernel.bootstrap(expected(claimed), FIRST);
        assertThat(retry.status()).isEqualTo(Status.REPLAY);
        assertThat(retry.value()).contains(winner);
        assertThat(current().revision()).isEqualTo(claimed.revision());
        Transition<Claim> loser = kernel.bootstrap(expected(current()), SECOND);
        assertThat(loser.status()).isEqualTo(Status.LOSER);
        assertThat(loser.value()).isEmpty();
        assertThat(current().attempt().claim()).contains(winner);
    }

    @Test
    void heartbeatReplayDoesNotExtendAndLowerSequenceFails() {
        kernel.observe(observation(current(), FIRST, 1, true));
        Claim initial = kernel.bootstrap(expected(current()), FIRST).value().orElseThrow();
        Transition<Claim> renewed = kernel.heartbeat(initial.binding(), 2);
        assertThat(renewed.status()).isEqualTo(Status.APPLIED);
        Claim latest = renewed.value().orElseThrow();
        RunSnapshot after = current();
        assertThat(latest.heartbeatSequence()).isEqualTo(2);
        assertThat(latest.leaseUntil()).isBeforeOrEqualTo(after.attempt().spec().maxDeadline());
        assertThat(latest.leaseUntil()).isBeforeOrEqualTo(after.spec().runDeadline());
        assertThat(kernel.heartbeat(initial.binding(), 2).value()).contains(latest);
        assertThat(kernel.heartbeat(initial.binding(), 1).status()).isEqualTo(Status.STALE);
        assertThat(kernel.heartbeat(initial.binding(), 0).status()).isEqualTo(Status.DENIED);
        assertThat(current().revision()).isEqualTo(after.revision());
    }

    @Test
    void claimAndHeartbeatLeaseAreCappedByStoredAttemptAndRunDeadlines() throws Exception {
        Instant now = AiRuntimeFixture.now(dataSource);
        Instant deadline = now.plusSeconds(20);
        RunSpec base = created.spec();
        RunSpec bounded = new RunSpec(UUID.randomUUID(), base.conversationRef(), base.actorId(), base.scopeMarker(),
                base.attemptLimit(), base.podLimit(), 60, deadline);
        AttemptSpec first = created.attempt().spec();
        AttemptSpec attempt = new AttemptSpec(UUID.randomUUID(), now.plusSeconds(10), deadline, first.imageDigest(),
                first.profileRevision(), first.securityRevision(), first.trustRevision(), first.protocol(),
                first.launch());
        created = kernel.create(control, bounded, attempt);
        assertThat(kernel.observe(observation(created, FIRST, 1, true)).status()).isEqualTo(Status.APPLIED);

        Claim initial = kernel.bootstrap(expected(current()), FIRST).value().orElseThrow();
        assertThat(initial.leaseUntil()).isEqualTo(deadline);
        Claim renewed = kernel.heartbeat(initial.binding(), 1).value().orElseThrow();
        assertThat(renewed.leaseUntil()).isEqualTo(deadline);
        assertThat(renewed.heartbeatSequence()).isEqualTo(1);
        RunSnapshot after = current();
        assertThat(kernel.heartbeat(initial.binding(), 1).value()).contains(renewed);
        assertThat(current()).isEqualTo(after);
    }

    @Test
    void observationReplayCannotRefreshDeadlineAndPodCardinalityIsBounded() throws Exception {
        Instant until = AiRuntimeFixture.now(dataSource).plusSeconds(20);
        kernel.observe(observation(current(), FIRST, 1, until, true));
        RunSnapshot observed = current();
        assertThat(kernel.observe(observation(observed, FIRST, 1, until, true)).status()).isEqualTo(Status.REPLAY);
        assertThat(current().revision()).isEqualTo(observed.revision());
        assertThat(kernel.observe(observation(current(), FIRST, 1, until.plusSeconds(1), true)).status())
                .isEqualTo(Status.CONFLICT);
        assertThat(current().workloads().getFirst().observationValidUntil()).isEqualTo(until);
        assertThat(kernel.observe(observation(current(), SECOND, 1, true)).status()).isEqualTo(Status.APPLIED);
        assertThat(
                kernel.observe(observation(current(), new WorkloadRef("cluster-one", "pod-three"), 1, true)).status())
                .isEqualTo(Status.LIMIT_REACHED);
        assertThat(current().workloads()).hasSize(2);
    }

    @Test
    void recreatedNamespaceIsRejectedBeforeAnyBindingChange() {
        WorkloadObservation ordinary = observation(current(), FIRST, 1, true);
        WorkloadObservation foreign = new WorkloadObservation(ordinary.expected(), ordinary.cluster(),
                ordinary.namespaceName(), "different-namespace-uid", ordinary.serviceAccountName(),
                ordinary.serviceAccountUid(), ordinary.jobName(), ordinary.jobUid(), ordinary.podName(),
                ordinary.podUid(), ordinary.imageDigest(), ordinary.templateDigest(), ordinary.runtimeClass(),
                ordinary.profileRevision(), ordinary.securityRevision(), ordinary.trustRevision(), ordinary.protocol(),
                ordinary.sequence(), ordinary.validUntil(), ordinary.registered());

        assertThat(kernel.observe(foreign).status()).isEqualTo(Status.DENIED);
        assertThat(current()).isEqualTo(created);
        assertThat(kernel.observe(ordinary).status()).isEqualTo(Status.APPLIED);
    }

    private RunSnapshot current() {
        return kernel.snapshot(created.spec().runId()).orElseThrow();
    }
}
