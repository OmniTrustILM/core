package com.otilm.core.integration.service;

import com.otilm.core.dao.repository.ai.AiModelDispatchRepository;
import com.otilm.core.dao.repository.ai.AiRuntimeRepository;
import com.otilm.core.model.ai.AiModelDispatchState.ConnectionVersion;
import com.otilm.core.model.ai.AiModelDispatchState.ExactPayload;
import com.otilm.core.model.ai.AiModelDispatchState.RunPreparation;
import com.otilm.core.model.ai.AiModelDispatchState.RunRedemption;
import com.otilm.core.model.ai.AiRuntimeState.Claim;
import com.otilm.core.model.ai.AiRuntimeState.RunSnapshot;
import com.otilm.core.model.ai.AiRuntimeState.Status;
import com.otilm.core.model.ai.AiRuntimeState.WorkloadRef;
import com.otilm.core.service.ai.AiRuntimeKernel;
import com.otilm.core.service.ai.AiRuntimeOperationBudget;
import com.otilm.core.service.writer.ai.AiModelDispatchWriter;
import com.otilm.core.util.AiModelDispatchFixture;
import com.otilm.core.util.AiRuntimeFixture;
import com.otilm.core.util.ai.BaseAiSpringBootTest;
import jakarta.persistence.EntityManager;
import java.sql.Connection;
import java.time.Duration;
import java.time.Instant;
import java.util.UUID;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicInteger;
import javax.sql.DataSource;
import org.aopalliance.intercept.MethodInterceptor;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.aop.framework.ProxyFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.transaction.PlatformTransactionManager;
import org.springframework.transaction.TransactionDefinition;
import org.springframework.transaction.TransactionStatus;
import org.springframework.transaction.TransactionSystemException;
import org.springframework.transaction.annotation.AnnotationTransactionAttributeSource;
import org.springframework.transaction.interceptor.TransactionInterceptor;

import static com.otilm.core.util.AiRuntimeFixture.expected;
import static com.otilm.core.util.AiRuntimeFixture.observation;
import static org.assertj.core.api.Assertions.assertThat;

/** Real DB barriers/physical sessions; no actual modelUSE/native gateway claim is derived from fixture facts. */
class AiModelDispatchRaceITest extends BaseAiSpringBootTest {
    private static final ExactPayload PAYLOAD = AiModelDispatchFixture.payload(32, "fixture");
    @Autowired
    private DataSource source;
    @Autowired
    private EntityManager entityManager;
    @Autowired
    private PlatformTransactionManager transactions;
    @Autowired
    private AiRuntimeKernel kernel;
    @Autowired
    private AiRuntimeRepository runtimeRepository;
    @Autowired
    private AiModelDispatchRepository repository;
    private ConnectionVersion model;
    private RunSnapshot created;
    private Claim claim;

    @BeforeEach
    void installPersistenceFacts() throws Exception {
        AiModelDispatchFixture.drop(source);
        AiRuntimeFixture.install(source);
        model = AiModelDispatchFixture.approvedModel(source);
        Instant now = AiRuntimeFixture.now(source);
        var control = AiRuntimeFixture.enableTestControl(kernel, now);
        created = kernel.create(control, AiRuntimeFixture.run(now), AiRuntimeFixture.attempt(now));
        var workload = new WorkloadRef("cluster-one", UUID.randomUUID().toString());
        kernel.observe(observation(current(), workload, 1, true));
        claim = kernel.bootstrap(expected(current()), workload).value().orElseThrow();
        AiModelDispatchFixture.runBudget(source, created.spec().runId(), model, 3, 128);
    }

    @Test
    void concurrentGatewayReplicasYieldExactlyOneConsumeWithMeasuredLockWaiter() throws Exception {
        var normal = writer(runtimeRepository, repository);
        RunPreparation preparation = preparation(AiRuntimeFixture.now(source).plusSeconds(30));
        assertThat(normal.prepareRun(preparation, budget()).status()).isEqualTo(Status.APPLIED);
        var firstEntered = new CountDownLatch(1);
        var release = new CountDownLatch(1);
        var firstPid = new AtomicInteger();
        var secondPid = new AtomicInteger();
        var runtime = runtimeProxy(call -> {
            Object result = call.proceed();
            if (call.getMethod().getName().equals("configureTransaction")) {
                int pid = ((Number) entityManager.createNativeQuery("SELECT pg_backend_pid()").getSingleResult())
                        .intValue();
                if (Thread.currentThread().getName().equals("f04-consume-first")) {
                    firstPid.set(pid);
                } else if (Thread.currentThread().getName().equals("f04-consume-second")) {
                    secondPid.set(pid);
                }
            }
            return result;
        });
        var selected = modelProxy(call -> {
            if (call.getMethod().getName().equals("consumeRunIntent")
                    && Thread.currentThread().getName().equals("f04-consume-first")) {
                firstEntered.countDown();
                assertThat(release.await(4, TimeUnit.SECONDS)).isTrue();
            }
            return call.proceed();
        });
        var bounded = writer(runtime, selected);
        var first = Executors.newSingleThreadExecutor(task -> new Thread(task, "f04-consume-first"));
        var second = Executors.newSingleThreadExecutor(task -> new Thread(task, "f04-consume-second"));
        try (Connection observer = source.getConnection()) {
            observer.setAutoCommit(true);
            var resultOne = first.submit(() -> bounded.consumeRun(redemption(preparation), budget()));
            assertThat(firstEntered.await(2, TimeUnit.SECONDS)).isTrue();
            var resultTwo = second.submit(() -> bounded.consumeRun(redemption(preparation), budget()));
            assertThat(firstPid.get()).isPositive();
            awaitBlocked(observer, firstPid.get(), secondPid);
            assertThat(secondPid.get()).isPositive().isNotEqualTo(firstPid.get());
            release.countDown();
            int positives = (resultOne.get(4, TimeUnit.SECONDS).isPresent() ? 1 : 0)
                    + (resultTwo.get(4, TimeUnit.SECONDS).isPresent() ? 1 : 0);
            assertThat(positives).isEqualTo(1);
            assertThat(AiModelDispatchFixture.consumed(source, preparation.intentId(), false)).isTrue();
            assertThat(AiModelDispatchFixture.reservedCalls(source, created.spec().runId())).isEqualTo(1);
            System.out.println("F04_CONSUME_RACE distinctPhysicalWriters=true exactBlockerWaiter=true positives=1");
        } finally {
            release.countDown();
            first.shutdownNow();
            second.shutdownNow();
            assertThat(first.awaitTermination(5, TimeUnit.SECONDS)).isTrue();
            assertThat(second.awaitTermination(5, TimeUnit.SECONDS)).isTrue();
        }
    }

    @Test
    void expiryAtFinalInsertRollsBackTheAlreadyObservedReservation() throws Exception {
        Instant expires = AiRuntimeFixture.now(source).plusSeconds(2);
        RunPreparation preparation = preparation(expires);
        var entered = new CountDownLatch(1);
        var release = new CountDownLatch(1);
        var reservationObserved = new AtomicBoolean();
        var selected = modelProxy(call -> {
            if (call.getMethod().getName().equals("insertRunIntent")) {
                Number count = (Number) entityManager
                        .createNativeQuery("SELECT reserved_calls FROM core.ai_model_run_budget WHERE run_uuid = :run")
                        .setParameter("run", created.spec().runId())
                        .getSingleResult();
                reservationObserved.set(count.longValue() == 1);
                entered.countDown();
                assertThat(release.await(4, TimeUnit.SECONDS)).isTrue();
            }
            return call.proceed();
        });
        var bounded = writer(runtimeRepository, selected);
        String before = AiModelDispatchFixture.fingerprint(source);
        var executor = Executors.newSingleThreadExecutor();
        try (Connection observer = source.getConnection()) {
            observer.setAutoCommit(true);
            var result = executor.submit(() -> {
                try {
                    bounded.prepareRun(preparation, budget());
                    return (Throwable) null;
                } catch (RuntimeException failure) {
                    return failure;
                }
            });
            assertThat(entered.await(2, TimeUnit.SECONDS)).isTrue();
            assertThat(reservationObserved.get()).isTrue();
            awaitExpiry(observer, expires);
            release.countDown();
            assertThat(result.get(3, TimeUnit.SECONDS)).isInstanceOf(AiModelDispatchWriter.Rejected.class);
            assertThat(AiModelDispatchFixture.fingerprint(source)).isEqualTo(before);
            assertThat(AiModelDispatchFixture.count(source, "ai_model_run_intent")).isZero();
            System.out
                    .println(
                            "F04_RESERVATION_ROLLBACK observedWrite=true finalExpired=true allModelStateUnchanged=true");
        } finally {
            release.countDown();
            executor.shutdownNow();
            assertThat(executor.awaitTermination(5, TimeUnit.SECONDS)).isTrue();
        }
    }

    @Test
    void actualCommitThenFailureLeavesConsumeDurableAndPropagatesUncertainty() throws Exception {
        RunPreparation preparation = preparation(AiRuntimeFixture.now(source).plusSeconds(30));
        assertThat(writer(runtimeRepository, repository).prepareRun(preparation, budget()).status())
                .isEqualTo(Status.APPLIED);
        var committed = new AtomicBoolean();
        var physicalWriter = new AtomicInteger();
        var runtime = runtimeProxy(call -> {
            Object value = call.proceed();
            if (call.getMethod().getName().equals("configureTransaction")) {
                physicalWriter
                        .set(((Number) entityManager.createNativeQuery("SELECT pg_backend_pid()").getSingleResult())
                                .intValue());
            }
            return value;
        });
        PlatformTransactionManager uncertain = new PlatformTransactionManager() {
            @Override
            public TransactionStatus getTransaction(TransactionDefinition definition) {
                return transactions.getTransaction(definition);
            }

            @Override
            public void rollback(TransactionStatus status) {
                transactions.rollback(status);
            }

            @Override
            public void commit(TransactionStatus status) {
                assertThat(status.isNewTransaction()).isTrue();
                transactions.commit(status);
                committed.set(true);
                throw new TransactionSystemException("Controlled synthetic postcommit failure");
            }
        };
        var factory = new ProxyFactory(new AiModelDispatchWriter(runtime, repository));
        factory.setProxyTargetClass(true);
        factory.addAdvice(new TransactionInterceptor(uncertain, new AnnotationTransactionAttributeSource()));
        var bounded = (AiModelDispatchWriter) factory.getProxy();
        try (Connection observer = source.getConnection()) {
            observer.setAutoCommit(true);
            int observerPid;
            try (var statement = observer.createStatement();
                    var rows = statement.executeQuery("SELECT pg_backend_pid()")) {
                assertThat(rows.next()).isTrue();
                observerPid = rows.getInt(1);
            }
            Throwable outcome = null;
            try {
                bounded.consumeRun(redemption(preparation), budget());
            } catch (RuntimeException failure) {
                outcome = failure;
            }
            assertThat(committed.get()).isTrue();
            assertThat(physicalWriter.get()).isPositive().isNotEqualTo(observerPid);
            try (var statement = observer.prepareStatement("""
                    SELECT state = 'CONSUMED' AND consumed_at IS NOT NULL AND gateway_correlation IS NOT NULL
                    FROM core.ai_model_run_intent WHERE uuid = ?
                    """)) {
                statement.setObject(1, preparation.intentId());
                try (var rows = statement.executeQuery()) {
                    assertThat(rows.next()).isTrue();
                    assertThat(rows.getBoolean(1)).isTrue();
                }
            }
            assertThat(AiModelDispatchFixture.reservedCalls(source, created.spec().runId())).isEqualTo(1);
            assertThat(AiModelDispatchFixture.reservedTokens(source, created.spec().runId(), false)).isEqualTo(32);
            System.out.println("F04_POSTCOMMIT_CONTROL distinctPhysicalSessions=true durableConsume=true");
            assertThat(outcome).isInstanceOf(TransactionSystemException.class);
            assertThat(writer(runtimeRepository, repository).consumeRun(redemption(preparation), budget())).isEmpty();
        }
    }

    private AiRuntimeRepository runtimeProxy(MethodInterceptor advice) {
        var factory = new ProxyFactory(runtimeRepository);
        factory.addAdvice(advice);
        return (AiRuntimeRepository) factory.getProxy();
    }

    private AiModelDispatchRepository modelProxy(MethodInterceptor advice) {
        var factory = new ProxyFactory(repository);
        factory.addAdvice(advice);
        return (AiModelDispatchRepository) factory.getProxy();
    }

    private AiModelDispatchWriter writer(AiRuntimeRepository runtime, AiModelDispatchRepository modelRepository) {
        var factory = new ProxyFactory(new AiModelDispatchWriter(runtime, modelRepository));
        factory.setProxyTargetClass(true);
        factory.addAdvice(new TransactionInterceptor(transactions, new AnnotationTransactionAttributeSource()));
        return (AiModelDispatchWriter) factory.getProxy();
    }

    private RunPreparation preparation(Instant expires) {
        return new RunPreparation(UUID.randomUUID(), UUID.randomUUID(), expected(current()), claim.binding(), model,
                PAYLOAD, 32, expires);
    }

    private RunRedemption redemption(RunPreparation preparation) {
        return new RunRedemption(preparation.intentId(), expected(current()), claim.binding(), model, PAYLOAD.sha256(),
                preparation.expiresAt(), UUID.randomUUID());
    }

    private RunSnapshot current() {
        return kernel.snapshot(created.spec().runId()).orElseThrow();
    }

    private static AiRuntimeOperationBudget budget() {
        return AiRuntimeOperationBudget.start();
    }

    private static void awaitBlocked(Connection observer, int holder, AtomicInteger waiter) {
        try {
            org.awaitility.Awaitility
                    .await("Exact owned backend lock waiter")
                    .pollInSameThread()
                    .pollDelay(Duration.ZERO)
                    .pollInterval(Duration.ofMillis(5))
                    .atMost(Duration.ofMillis(800))
                    .until(() -> {
                        if (waiter.get() <= 0) {
                            return false;
                        }
                        try (var statement = observer.prepareStatement("SELECT ? = ANY(pg_blocking_pids(?))")) {
                            statement.setInt(1, holder);
                            statement.setInt(2, waiter.get());
                            try (var rows = statement.executeQuery()) {
                                assertThat(rows.next()).isTrue();
                                return rows.getBoolean(1);
                            }
                        }
                    });
        } catch (org.awaitility.core.ConditionTimeoutException failure) {
            throw new AssertionError("The exact owned backend did not block", failure);
        }
    }

    private static void awaitExpiry(Connection observer, Instant deadline) {
        try {
            org.awaitility.Awaitility
                    .await("Owned database intent deadline")
                    .pollInSameThread()
                    .pollDelay(Duration.ZERO)
                    .pollInterval(Duration.ofMillis(5))
                    .atMost(Duration.ofSeconds(3))
                    .until(() -> {
                        try (var statement = observer.createStatement();
                                var rows = statement.executeQuery("SELECT clock_timestamp()")) {
                            assertThat(rows.next()).isTrue();
                            return !rows.getTimestamp(1).toInstant().isBefore(deadline);
                        }
                    });
        } catch (org.awaitility.core.ConditionTimeoutException failure) {
            throw new AssertionError("Owned database expiry was not observed", failure);
        }
    }
}
