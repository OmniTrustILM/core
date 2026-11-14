package com.otilm.core.integration.service;

import com.otilm.core.dao.repository.ai.AiRuntimeRepository;
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
import com.otilm.core.model.ai.AiRuntimeState.WorkloadRef;
import com.otilm.core.model.ai.AiRuntimeState.WorkloadSnapshot;
import com.otilm.core.service.ai.AiFeatureGate;
import com.otilm.core.service.ai.AiRuntimeKernel;
import com.otilm.core.service.writer.ai.AiRuntimeWriter;
import com.otilm.core.util.AiRuntimeFixture;
import com.otilm.core.util.ai.BaseAiSpringBootTest;
import jakarta.persistence.EntityManager;
import jakarta.persistence.PersistenceContext;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.time.Instant;
import java.util.List;
import java.util.Set;
import java.util.UUID;
import java.util.concurrent.ConcurrentSkipListSet;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicReference;
import java.util.function.Function;
import javax.sql.DataSource;
import org.aopalliance.intercept.MethodInterceptor;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.springframework.aop.framework.ProxyFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.transaction.PlatformTransactionManager;
import org.springframework.transaction.annotation.AnnotationTransactionAttributeSource;
import org.springframework.transaction.interceptor.TransactionInterceptor;
import org.springframework.transaction.support.TransactionSynchronization;
import org.springframework.transaction.support.TransactionSynchronizationManager;

import static com.otilm.core.util.AiRuntimeFixture.expected;
import static com.otilm.core.util.AiRuntimeFixture.observation;
import static org.assertj.core.api.Assertions.assertThat;

class AiRuntimeKernelRaceITest extends BaseAiSpringBootTest {
    private static final WorkloadRef FIRST = new WorkloadRef("cluster-one", "pod-one");
    private static final WorkloadRef SECOND = new WorkloadRef("cluster-one", "pod-two");
    @Autowired
    private DataSource dataSource;
    @Autowired
    private AiRuntimeRepository repository;
    @Autowired
    private PlatformTransactionManager transactionManager;
    @PersistenceContext
    private EntityManager entityManager;
    private AiRuntimeKernel kernel;
    private RunSnapshot created;

    @BeforeEach
    void createRun() throws Exception {
        AiRuntimeFixture.install(dataSource);
        kernel = replica(null);
        Instant now = AiRuntimeFixture.now(dataSource);
        var control = AiRuntimeFixture.enableTestControl(kernel, now);
        created = kernel.create(control, AiRuntimeFixture.run(now), AiRuntimeFixture.attempt(now));
    }

    @Test
    void twoReplicasChooseOneRegisteredWinner() throws Exception {
        observe(FIRST, true);
        observe(SECOND, true);
        RunSnapshot before = current();
        Expected shared = expected(before);

        RaceResult<Claim, Claim> result = race("bootstrap", false, replica -> replica.bootstrap(shared, FIRST),
                replica -> replica.bootstrap(shared, SECOND));

        assertThat(List.of(result.first().status(), result.second().status()))
                .containsExactlyInAnyOrder(Status.APPLIED, Status.STALE);
        Transition<Claim> applied = result.first().status() == Status.APPLIED ? result.first() : result.second();
        Transition<Claim> stale = result.first().status() == Status.STALE ? result.first() : result.second();
        Claim winner = applied.value().orElseThrow();
        assertThat(stale.value()).isEmpty();
        RunSnapshot claimed = current();
        assertThat(claimed.state()).isEqualTo(RunState.RUNNING);
        assertThat(claimed.attempt().state()).isEqualTo(AttemptState.CLAIMED);
        assertThat(claimed.attempt().claim()).contains(winner);
        assertThat(claimed.revision()).isEqualTo(before.revision() + 1);
        assertThat(claimed.fence()).isEqualTo(before.fence());
        assertThat(claimed.workloads().stream().filter(row -> row.bootstrapConsumedAt().isPresent())).hasSize(1);
        assertThat(row(claimed, winner.binding().workload()).bootstrapConsumedAt()).isPresent();
        assertClaimRows(1, 1);

        WorkloadRef loser = winner.binding().workload().equals(FIRST) ? SECOND : FIRST;
        AiRuntimeKernel recreated = replica(null);
        Transition<Claim> losingRetry = recreated.bootstrap(expected(claimed), loser);
        assertThat(losingRetry.status()).isEqualTo(Status.LOSER);
        assertThat(losingRetry.value()).isEmpty();
        Transition<Claim> winningRetry = recreated.bootstrap(expected(current()), winner.binding().workload());
        assertThat(winningRetry.status()).isEqualTo(Status.REPLAY);
        assertThat(winningRetry.value()).contains(winner);
        assertThat(current()).isEqualTo(claimed);
        assertClaimRows(1, 1);
    }

    @Test
    void aSecondRegistrationAfterAClaimCannotReplaceTheWinner() throws Exception {
        observe(FIRST, true);
        Claim winner = kernel.bootstrap(expected(current()), FIRST).value().orElseThrow();
        RunSnapshot claimed = current();

        observe(SECOND, true);

        RunSnapshot registered = current();
        assertThat(registered.attempt().state()).isEqualTo(AttemptState.CLAIMED);
        assertThat(registered.attempt().claim()).contains(winner);
        assertThat(registered.fence()).isEqualTo(claimed.fence());
        assertThat(registered.revision()).isEqualTo(claimed.revision() + 1);
        assertThat(replica(null).bootstrap(expected(registered), SECOND).status()).isEqualTo(Status.LOSER);
        assertThat(current()).isEqualTo(registered);
        assertClaimRows(1, 1);
    }

    @Test
    void pendingLoserCannotFenceConcurrentWinner() throws Exception {
        RunSnapshot before = pendingAtExhaustionBoundary();
        Expected shared = expected(before);

        RaceResult<Claim, Claim> result = race("bootstrap", true, replica -> replica.bootstrap(shared, SECOND),
                replica -> replica.bootstrap(shared, FIRST));

        assertThat(result.first().status()).isEqualTo(Status.APPLIED);
        Claim winner = result.first().value().orElseThrow();
        assertThat(result.second().status()).isEqualTo(Status.STALE);
        assertThat(result.second().value()).isEmpty();
        RunSnapshot claimed = current();
        assertThat(claimed.attempt().claim()).contains(winner);
        assertThat(claimed.fence()).isEqualTo(before.fence());
        assertThat(claimed.revision()).isEqualTo(before.revision() + 1);
        assertThat(claimed.launch().cleanup()).isEqualTo(CleanupState.NONE);
        assertThat(row(claimed, FIRST).pendingReturns()).isEqualTo(11);
        assertThat(row(claimed, FIRST).firstPendingAt()).isEqualTo(row(before, FIRST).firstPendingAt());
        assertThat(row(claimed, FIRST).pendingDeadline()).isEqualTo(row(before, FIRST).pendingDeadline());
        assertThat(row(claimed, FIRST).bootstrapConsumedAt()).isEmpty();

        Transition<Claim> freshLoser = replica(null).bootstrap(expected(claimed), FIRST);
        assertThat(freshLoser.status()).isEqualTo(Status.LOSER);
        assertThat(freshLoser.value()).isEmpty();
        assertThat(current()).isEqualTo(claimed);
        assertClaimRows(1, 1);
    }

    @Test
    void pendingExhaustionBeforeClaimPreventsWinner() throws Exception {
        RunSnapshot before = pendingAtExhaustionBoundary();
        Expected shared = expected(before);

        RaceResult<Claim, Claim> result = race("bootstrap", true, replica -> replica.bootstrap(shared, FIRST),
                replica -> replica.bootstrap(shared, SECOND));

        assertThat(result.first().status()).isEqualTo(Status.EXPIRED);
        assertThat(result.first().value()).isEmpty();
        assertThat(result.second().status()).isEqualTo(Status.STALE);
        assertThat(result.second().value()).isEmpty();
        RunSnapshot exhausted = replica(null).snapshot(created.spec().runId()).orElseThrow();
        assertThat(exhausted.state()).isEqualTo(RunState.QUEUED);
        assertThat(exhausted.attempt().state()).isEqualTo(AttemptState.FENCED);
        assertThat(exhausted.attempt().failure()).contains(FailureReason.PENDING_EXHAUSTED);
        assertThat(exhausted.attempt().claim()).isEmpty();
        assertThat(exhausted.launch().cleanup()).isEqualTo(CleanupState.DUE);
        assertThat(exhausted.fence()).isEqualTo(before.fence() + 1);
        assertThat(exhausted.revision()).isEqualTo(before.revision() + 1);
        assertThat(exhausted.workloads()).allSatisfy(row -> assertThat(row.bootstrapConsumedAt()).isEmpty());
        assertThat(replica(null).bootstrap(expected(exhausted), SECOND).value()).isEmpty();
        assertThat(current()).isEqualTo(exhausted);
        assertClaimRows(0, 0);
    }

    @Test
    void heartbeatReplayPersistsAcrossBeanRecreation() throws Exception {
        observe(FIRST, true);
        Transition<Claim> initial = kernel.bootstrap(expected(current()), FIRST);
        assertThat(initial.status()).isEqualTo(Status.APPLIED);
        Claim claim = initial.value().orElseThrow();
        RunSnapshot before = current();

        RaceResult<Claim, Claim> result = race("heartbeat", false, replica -> replica.heartbeat(claim.binding(), 2),
                replica -> replica.heartbeat(claim.binding(), 2));

        assertThat(List.of(result.first().status(), result.second().status()))
                .containsExactlyInAnyOrder(Status.APPLIED, Status.REPLAY);
        Claim renewed = result.first().value().orElseThrow();
        assertThat(result.second().value()).contains(renewed);
        assertThat(renewed.heartbeatSequence()).isEqualTo(2);
        RunSnapshot stored = current();
        assertThat(stored.revision()).isEqualTo(before.revision() + 1);
        assertThat(stored.fence()).isEqualTo(before.fence());
        assertThat(stored.attempt().claim()).contains(renewed);

        AiRuntimeKernel recreated = replica(null);
        assertThat(recreated.snapshot(created.spec().runId())).contains(stored);
        Transition<Claim> replay = recreated.heartbeat(claim.binding(), 2);
        assertThat(replay.status()).isEqualTo(Status.REPLAY);
        assertThat(replay.value()).contains(renewed);
        Transition<Claim> lower = recreated.heartbeat(claim.binding(), 1);
        assertThat(lower.status()).isEqualTo(Status.STALE);
        assertThat(lower.value()).isEmpty();
        assertThat(current()).isEqualTo(stored);
        assertClaimRows(1, 1);
    }

    @ParameterizedTest
    @ValueSource(booleans = {true, false})
    void cancellationRacesClaimInBothOrders(boolean cancelFirst) throws Exception {
        observe(FIRST, true);
        RunSnapshot before = current();
        Expected shared = expected(before);
        if (cancelFirst) {
            RaceResult<Void, Claim> result = race(Set.of("cancel", "bootstrap"), true,
                    replica -> replica.cancel(before.spec().runId()), replica -> replica.bootstrap(shared, FIRST));
            assertThat(result.first().status()).isEqualTo(Status.APPLIED);
            assertThat(result.second().status()).isEqualTo(Status.STALE);
            assertThat(result.second().value()).isEmpty();
            assertClaimRows(0, 0);
        } else {
            RaceResult<Claim, Void> result = race(Set.of("cancel", "bootstrap"), true,
                    replica -> replica.bootstrap(shared, FIRST), replica -> replica.cancel(before.spec().runId()));
            assertThat(result.first().status()).isEqualTo(Status.APPLIED);
            assertThat(result.second().status()).isEqualTo(Status.APPLIED);
            assertThat(current().attempt().claim()).isEqualTo(result.first().value());
            assertClaimRows(1, 1);
        }
        RunSnapshot cancelled = current();
        assertThat(cancelled.state()).isEqualTo(RunState.CANCELLED);
        assertThat(cancelled.revision()).isEqualTo(before.revision() + (cancelFirst ? 1 : 2));
        assertThat(cancelled.fence()).isEqualTo(before.fence() + 1);
        assertThat(cancelled.attempt().failure()).contains(FailureReason.CANCELLED);
        assertThat(replica(null).bootstrap(expected(cancelled), FIRST).status()).isEqualTo(Status.CANCELLED);
        assertThat(current()).isEqualTo(cancelled);
    }

    @ParameterizedTest
    @ValueSource(booleans = {true, false})
    void cancellationRacesHeartbeatInBothOrders(boolean cancelFirst) throws Exception {
        observe(FIRST, true);
        Claim claim = kernel.bootstrap(expected(current()), FIRST).value().orElseThrow();
        RunSnapshot before = current();
        if (cancelFirst) {
            RaceResult<Void, Claim> result = race(Set.of("cancel", "heartbeat"), true,
                    replica -> replica.cancel(before.spec().runId()), replica -> replica.heartbeat(claim.binding(), 1));
            assertThat(result.first().status()).isEqualTo(Status.APPLIED);
            assertThat(result.second().status()).isEqualTo(Status.CANCELLED);
            assertThat(result.second().value()).isEmpty();
            assertThat(current().attempt().claim()).contains(claim);
        } else {
            RaceResult<Claim, Void> result = race(Set.of("cancel", "heartbeat"), true,
                    replica -> replica.heartbeat(claim.binding(), 1), replica -> replica.cancel(before.spec().runId()));
            assertThat(result.first().status()).isEqualTo(Status.APPLIED);
            assertThat(result.second().status()).isEqualTo(Status.APPLIED);
            assertThat(current().attempt().claim()).isEqualTo(result.first().value());
        }
        RunSnapshot cancelled = current();
        assertThat(cancelled.state()).isEqualTo(RunState.CANCELLED);
        assertThat(cancelled.revision()).isEqualTo(before.revision() + (cancelFirst ? 1 : 2));
        assertThat(cancelled.fence()).isEqualTo(before.fence() + 1);
        assertThat(replica(null).heartbeat(claim.binding(), 2).status()).isEqualTo(Status.CANCELLED);
        assertThat(current()).isEqualTo(cancelled);
        assertClaimRows(1, 1);
    }

    @Test
    void twoReplicasSpendReplacementBudgetOnce() throws Exception {
        try (Connection connection = dataSource.getConnection();
                PreparedStatement statement = connection.prepareStatement("""
                        UPDATE ai_runtime_attempt SET launch_deadline = clock_timestamp() - interval '1 second'
                        WHERE uuid = ?
                        """)) {
            statement.setObject(1, created.attempt().spec().attemptId());
            assertThat(statement.executeUpdate()).isEqualTo(1);
        }
        assertThat(kernel.expire(expected(current())).status()).isEqualTo(Status.APPLIED);
        RunSnapshot fenced = current();
        AttemptSpec first = replacement();
        AttemptSpec second = replacement();

        RaceResult<RunSnapshot, RunSnapshot> result = race(Set.of("replace"), false,
                replica -> replica.replace(expected(fenced), first),
                replica -> replica.replace(expected(fenced), second));

        assertThat(List.of(result.first().status(), result.second().status()))
                .containsExactlyInAnyOrder(Status.APPLIED, Status.STALE);
        RunSnapshot replaced = current();
        assertThat(replaced.attemptsUsed()).isEqualTo(2);
        assertThat(replaced.revision()).isEqualTo(fenced.revision() + 1);
        assertThat(replaced.fence()).isEqualTo(fenced.fence() + 1);
        assertThat(replaced.attempt().spec()).isIn(first, second);
        assertThat(replica(null).snapshot(created.spec().runId())).contains(replaced);
        try (Connection connection = dataSource.getConnection();
                PreparedStatement statement = connection
                        .prepareStatement("SELECT count(*) FROM ai_runtime_attempt WHERE run_uuid = ?")) {
            statement.setObject(1, created.spec().runId());
            try (ResultSet resultSet = statement.executeQuery()) {
                assertThat(resultSet.next()).isTrue();
                assertThat(resultSet.getInt(1)).isEqualTo(2);
            }
        }
    }

    private AttemptSpec replacement() {
        AttemptSpec source = created.attempt().spec();
        return new AttemptSpec(UUID.randomUUID(), source.launchDeadline(), source.maxDeadline(), source.imageDigest(),
                source.profileRevision(), source.securityRevision(), source.trustRevision(), source.protocol(),
                source.launch());
    }

    @Test
    void waiterCannotUseTransactionStartTimeToClaimExpiredLaunch() throws Exception {
        observe(FIRST, true);
        RunSnapshot before = current();
        CountDownLatch started = new CountDownLatch(1);
        CountDownLatch mayLock = new CountDownLatch(1);
        AtomicReference<Instant> transactionStart = new AtomicReference<>();
        AiRuntimeKernel waiting = replica(invocation -> {
            if (invocation.getMethod().getName().equals("bootstrap")) {
                transactionStart
                        .set((Instant) entityManager
                                .createNativeQuery("SELECT transaction_timestamp()")
                                .getSingleResult());
                started.countDown();
                assertThat(mayLock.await(4, TimeUnit.SECONDS)).isTrue();
            }
            return invocation.proceed();
        });
        ExecutorService executor = Executors.newSingleThreadExecutor();
        try (Connection owner = dataSource.getConnection()) {
            owner.setAutoCommit(false);
            try (PreparedStatement lock = owner
                    .prepareStatement("SELECT uuid FROM ai_runtime_run WHERE uuid = ? FOR UPDATE")) {
                lock.setObject(1, before.spec().runId());
                try (ResultSet row = lock.executeQuery()) {
                    assertThat(row.next()).isTrue();
                }
            }
            Future<Transition<Claim>> future = executor.submit(() -> waiting.bootstrap(expected(before), FIRST));
            assertThat(started.await(4, TimeUnit.SECONDS)).isTrue();
            Instant deadline;
            try (PreparedStatement update = owner.prepareStatement("""
                    UPDATE ai_runtime_attempt SET launch_deadline = clock_timestamp() + interval '150 milliseconds'
                    WHERE uuid = ? RETURNING launch_deadline
                    """)) {
                update.setObject(1, before.attempt().spec().attemptId());
                try (ResultSet row = update.executeQuery()) {
                    assertThat(row.next()).isTrue();
                    deadline = row.getTimestamp(1).toInstant();
                }
            }
            assertThat(transactionStart.get()).isBefore(deadline);
            mayLock.countDown();
            awaitDatabaseDeadline(owner, deadline);
            owner.commit();

            Transition<Claim> result = future.get(8, TimeUnit.SECONDS);

            assertThat(result.status()).isEqualTo(Status.EXPIRED);
            assertThat(result.value()).isEmpty();
            assertThat(current().revision()).isEqualTo(before.revision());
            assertThat(current().attempt().spec().launchDeadline()).isEqualTo(deadline);
            assertClaimRows(0, 0);
        } finally {
            mayLock.countDown();
            executor.shutdownNow();
            assertThat(executor.awaitTermination(8, TimeUnit.SECONDS)).isTrue();
        }
    }

    private static void awaitDatabaseDeadline(Connection connection, Instant deadline) throws Exception {
        long stop = System.nanoTime() + TimeUnit.SECONDS.toNanos(1);
        try (PreparedStatement statement = connection.prepareStatement("SELECT clock_timestamp()")) {
            statement.setQueryTimeout(1);
            do {
                try (ResultSet row = statement.executeQuery()) {
                    assertThat(row.next()).isTrue();
                    if (!row.getTimestamp(1).toInstant().isBefore(deadline)) {
                        return;
                    }
                }
            } while (System.nanoTime() < stop);
        }
        throw new AssertionError("Database deadline was not reached within the bounded test wait");
    }

    private RunSnapshot pendingAtExhaustionBoundary() {
        observe(FIRST, false);
        observe(SECOND, true);
        for (int count = 1; count <= 11; count++) {
            Transition<Claim> pending = kernel.bootstrap(expected(current()), FIRST);
            assertThat(pending.status()).isEqualTo(Status.PENDING);
            assertThat(pending.value()).isEmpty();
            assertThat(row(current(), FIRST).pendingReturns()).isEqualTo(count);
        }
        return current();
    }

    private void observe(WorkloadRef ref, boolean registered) {
        assertThat(kernel.observe(observation(current(), ref, 1, registered)).status()).isEqualTo(Status.APPLIED);
    }

    private RunSnapshot current() {
        return kernel.snapshot(created.spec().runId()).orElseThrow();
    }

    private WorkloadSnapshot row(RunSnapshot snapshot, WorkloadRef ref) {
        return snapshot.workloads().stream().filter(workload -> workload.ref().equals(ref)).findFirst().orElseThrow();
    }

    private AiRuntimeKernel replica(MethodInterceptor gate) {
        AiRuntimeWriter writer = transactionalProxy(new AiRuntimeWriter(repository), AiRuntimeWriter.class, gate);
        return transactionalProxy(new AiRuntimeKernel(repository, writer, new AiFeatureGate(true)),
                AiRuntimeKernel.class, null);
    }

    private <T> T transactionalProxy(T target, Class<T> type, MethodInterceptor gate) {
        TransactionInterceptor transactions = new TransactionInterceptor();
        transactions.setTransactionManager(transactionManager);
        transactions.setTransactionAttributeSource(new AnnotationTransactionAttributeSource());
        ProxyFactory factory = new ProxyFactory(target);
        factory.setProxyTargetClass(true);
        factory.addAdvice(transactions);
        if (gate != null) {
            factory.addAdvice(gate);
        }
        return type.cast(factory.getProxy());
    }

    private RaceResult<Claim, Claim> race(String method, boolean firstCommitsFirst,
            Function<AiRuntimeKernel, Transition<Claim>> firstCall,
            Function<AiRuntimeKernel, Transition<Claim>> secondCall) throws Exception {
        return race(Set.of(method), firstCommitsFirst, firstCall, secondCall);
    }

    private <A, B> RaceResult<A, B> race(Set<String> methods, boolean firstCommitsFirst,
            Function<AiRuntimeKernel, Transition<A>> firstCall, Function<AiRuntimeKernel, Transition<B>> secondCall)
            throws Exception {
        RaceGate gate = new RaceGate(methods, firstCommitsFirst);
        AiRuntimeKernel firstReplica = replica(gate.interceptor(true));
        AiRuntimeKernel secondReplica = replica(gate.interceptor(false));
        ExecutorService executor = Executors.newFixedThreadPool(2);
        try {
            Future<Transition<A>> first = executor.submit(() -> firstCall.apply(firstReplica));
            Future<Transition<B>> second = executor.submit(() -> secondCall.apply(secondReplica));
            assertThat(gate.entered.await(4, TimeUnit.SECONDS))
                    .as("both independent writer transactions started")
                    .isTrue();
            gate.release.countDown();
            Transition<A> firstResult = first.get(10, TimeUnit.SECONDS);
            Transition<B> secondResult = second.get(10, TimeUnit.SECONDS);
            assertThat(gate.backends).as("distinct PostgreSQL writer connections").hasSize(2);
            return new RaceResult<>(firstResult, secondResult);
        } finally {
            gate.release.countDown();
            gate.committed.countDown();
            executor.shutdownNow();
            assertThat(executor.awaitTermination(10, TimeUnit.SECONDS)).as("race workers terminated").isTrue();
        }
    }

    private void assertClaimRows(int claims, int consumed) throws Exception {
        try (Connection connection = dataSource.getConnection();
                PreparedStatement statement = connection
                        .prepareStatement(
                                """
                                        SELECT (SELECT count(*) FROM ai_runtime_attempt WHERE run_uuid = ? AND claim_uuid IS NOT NULL),
                                               (SELECT count(*) FROM ai_runtime_workload w JOIN ai_runtime_attempt a ON a.uuid = w.attempt_uuid
                                                WHERE a.run_uuid = ? AND w.bootstrap_consumed_at IS NOT NULL)
                                        """)) {
            statement.setObject(1, created.spec().runId());
            statement.setObject(2, created.spec().runId());
            try (ResultSet rows = statement.executeQuery()) {
                assertThat(rows.next()).isTrue();
                assertThat(rows.getInt(1)).isEqualTo(claims);
                assertThat(rows.getInt(2)).isEqualTo(consumed);
            }
        }
    }

    private record RaceResult<A, B>(Transition<A> first, Transition<B> second) {
    }

    private final class RaceGate {
        private final Set<String> methods;
        private final boolean ordered;
        private final CountDownLatch entered = new CountDownLatch(2);
        private final CountDownLatch release = new CountDownLatch(1);
        private final CountDownLatch committed = new CountDownLatch(1);
        private final Set<Integer> backends = new ConcurrentSkipListSet<>();

        private RaceGate(Set<String> methods, boolean ordered) {
            this.methods = methods;
            this.ordered = ordered;
        }

        private MethodInterceptor interceptor(boolean leader) {
            return invocation -> {
                if (!methods.contains(invocation.getMethod().getName())) {
                    return invocation.proceed();
                }
                assertThat(TransactionSynchronizationManager.isActualTransactionActive()).isTrue();
                backends
                        .add(((Number) entityManager.createNativeQuery("SELECT pg_backend_pid()").getSingleResult())
                                .intValue());
                entered.countDown();
                assertThat(release.await(4, TimeUnit.SECONDS)).as("race dispatch released").isTrue();
                if (ordered && !leader) {
                    assertThat(committed.await(4, TimeUnit.SECONDS)).as("first writer committed").isTrue();
                }
                if (ordered && leader) {
                    TransactionSynchronizationManager.registerSynchronization(new TransactionSynchronization() {
                        @Override
                        public void afterCommit() {
                            committed.countDown();
                        }
                    });
                }
                return invocation.proceed();
            };
        }
    }
}
