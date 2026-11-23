package com.otilm.core.integration.service;

import com.otilm.core.dao.repository.ai.AiRuntimeRepository;
import com.otilm.core.model.ai.AiRuntimeState.ClaimBinding;
import com.otilm.core.model.ai.AiRuntimeState.RunSnapshot;
import com.otilm.core.model.ai.AiRuntimeState.RunState;
import com.otilm.core.model.ai.AiRuntimeState.Status;
import com.otilm.core.model.ai.AiRuntimeState.Transition;
import com.otilm.core.model.ai.AiRuntimeState.WorkloadRef;
import com.otilm.core.service.ai.AiFeatureGate;
import com.otilm.core.service.ai.AiRuntimeKernel;
import com.otilm.core.service.ai.AiRuntimeOperationBudget;
import com.otilm.core.service.writer.ai.AiRuntimeWriter;
import com.otilm.core.util.AiRuntimeFixture;
import com.otilm.core.util.ai.BaseAiSpringBootTest;
import java.sql.Connection;
import java.time.Duration;
import java.util.Optional;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicInteger;
import javax.sql.DataSource;
import org.aopalliance.intercept.MethodInterceptor;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.EnumSource;
import org.springframework.aop.framework.ProxyFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.transaction.PlatformTransactionManager;
import org.springframework.transaction.annotation.AnnotationTransactionAttributeSource;
import org.springframework.transaction.interceptor.TransactionInterceptor;
import org.springframework.transaction.support.TransactionSynchronizationManager;

import static com.otilm.core.util.AiRuntimeFixture.expected;
import static com.otilm.core.util.AiRuntimeFixture.observation;
import static org.assertj.core.api.Assertions.assertThat;
import static org.awaitility.Awaitility.await;

/** Real local SQL budget/rollback only; no independently observed deployment or remote authorization proof. */
class AiRuntimeObservationBudgetITest extends BaseAiSpringBootTest {
    private static final WorkloadRef POD = new WorkloadRef("cluster-one", "pod-one");
    @Autowired
    private DataSource source;
    @Autowired
    private AiRuntimeRepository repository;
    @Autowired
    private AiRuntimeKernel kernel;
    @Autowired
    private PlatformTransactionManager transactions;
    @Autowired
    private jakarta.persistence.EntityManager entityManager;
    private RunSnapshot created;

    @BeforeEach
    void createRegisteredRun() throws Exception {
        AiRuntimeFixture.install(source);
        var now = AiRuntimeFixture.now(source);
        var control = AiRuntimeFixture.enableTestControl(kernel, now);
        created = kernel.create(control, AiRuntimeFixture.run(now), AiRuntimeFixture.attempt(now));
        assertThat(kernel.observe(observation(created, POD, 1, true)).status()).isEqualTo(Status.APPLIED);
    }

    @ParameterizedTest
    @EnumSource(Operation.class)
    void preservesStoredBehavior_whenTheCallerBudgetIsLive(Operation operation) {
        // given
        Invocation request = prepare(operation);
        var budget = AiRuntimeOperationBudget.start();

        // when
        Object result = invoke(request, kernel, budget);

        // then
        if (operation == Operation.SNAPSHOT) {
            assertThat(result).isEqualTo(Optional.of(request.run()));
        } else if (operation == Operation.CONTROL) {
            assertThat(result).isEqualTo(kernel.control());
        } else {
            assertThat(((Transition<?>) result).status()).isEqualTo(Status.APPLIED);
        }
        if (operation == Operation.INVALIDATE) {
            assertThat(current().state()).isEqualTo(RunState.FAILED);
        }
    }

    @ParameterizedTest
    @EnumSource(value = Operation.class, names = {"SNAPSHOT", "CONTROL"})
    void readsWithinShortReadOnlyWriterTransaction_whenSnapshotIsBounded(Operation operation) {
        // given
        Invocation request = prepare(operation);
        var reached = new AtomicBoolean();
        var selected = proxy(call -> {
            if (call.getMethod().getName().equals(operation == Operation.SNAPSHOT ? "snapshot" : "control")) {
                assertThat(TransactionSynchronizationManager.isActualTransactionActive()).isTrue();
                assertThat(TransactionSynchronizationManager.isCurrentTransactionReadOnly()).isTrue();
                reached.set(true);
            }
            return call.proceed();
        });
        AiRuntimeKernel bounded = replica(selected);
        var budget = AiRuntimeOperationBudget.start();

        // when
        Object result = invoke(request, bounded, budget);

        // then
        assertThat(result).isInstanceOf(Optional.class);
        assertThat(((Optional<?>) result)).isPresent();
        assertThat(reached.get()).isTrue();
    }

    @ParameterizedTest
    @EnumSource(Operation.class)
    void boundsAnOwnedDatabaseWait_whenTheCallerAlreadySpentPartOfItsBudget(Operation operation) throws Exception {
        // given
        Invocation request = prepare(operation);
        String before = fingerprint();
        var pid = new AtomicInteger();
        var boundedConfigurations = new AtomicInteger();
        var selected = proxy(call -> {
            String method = call.getMethod().getName();
            if (method.equals("configureTransaction") && call.getArguments().length == 1) {
                long remaining = (long) call.getArguments()[0];
                assertThat(remaining).isBetween(1L, 400L);
                boundedConfigurations.incrementAndGet();
            }
            if (method.equals("snapshot") || method.equals("control") || method.equals("lockRun")
                    || method.equals("lockControl")) {
                pid
                        .compareAndSet(0,
                                ((Number) entityManager.createNativeQuery("SELECT pg_backend_pid()").getSingleResult())
                                        .intValue());
            }
            return call.proceed();
        });
        AiRuntimeKernel bounded = replica(selected);
        var executor = Executors.newSingleThreadExecutor();
        try (Connection holder = source.getConnection(); Connection observer = source.getConnection()) {
            holder.setAutoCommit(false);
            int holderPid = physicalPid(holder);
            try (var statement = holder.createStatement()) {
                if (operation == Operation.SNAPSHOT || operation == Operation.CONTROL) {
                    statement
                            .execute("LOCK TABLE core."
                                    + (operation == Operation.SNAPSHOT ? "ai_runtime_run" : "ai_runtime_control")
                                    + " IN ACCESS EXCLUSIVE MODE");
                } else {
                    try (var lock = holder
                            .prepareStatement("SELECT uuid FROM core.ai_runtime_run WHERE uuid=? FOR UPDATE")) {
                        lock.setObject(1, request.run().spec().runId());
                        try (var rows = lock.executeQuery()) {
                            assertThat(rows.next()).isTrue();
                        }
                    }
                }
            }
            var budget = AiRuntimeOperationBudget.start(Duration.ofMillis(600));
            await("Caller work spends part of the same operation budget")
                    .pollInSameThread()
                    .pollDelay(Duration.ZERO)
                    .pollInterval(Duration.ofMillis(2))
                    .atMost(Duration.ofMillis(450))
                    .until(() -> budget.remaining().toMillis() <= 400);

            // when
            var future = executor.submit(() -> capture(() -> invoke(request, bounded, budget)));
            try {
                await("Exact owned budget waiter")
                        .pollInSameThread()
                        .pollDelay(Duration.ZERO)
                        .pollInterval(Duration.ofMillis(2))
                        .atMost(Duration.ofMillis(250))
                        .until(() -> {
                            if (pid.get() <= 0) {
                                return false;
                            }
                            try (var statement = observer.prepareStatement("SELECT ?=ANY(pg_blocking_pids(?))")) {
                                statement.setInt(1, holderPid);
                                statement.setInt(2, pid.get());
                                try (var rows = statement.executeQuery()) {
                                    assertThat(rows.next()).isTrue();
                                    return rows.getBoolean(1);
                                }
                            }
                        });
            } catch (org.awaitility.core.ConditionTimeoutException unproven) {
                Outcome early = future.isDone() ? future.get(1, TimeUnit.SECONDS) : null;
                String status = early == null
                        ? "WORKER_PENDING"
                        : early.failure() == null
                                ? "WORKER_RETURNED"
                                : early.failure() instanceof AiRuntimeOperationBudget.Unavailable
                                        ? "BUDGET_UNAVAILABLE"
                                        : "STORAGE_FAILURE_" + sqlState(early.failure());
                throw new AssertionError("FIXTURE_WAITER_UNPROVEN status=" + status + " holderPid=" + holderPid
                        + " capturedPid=" + pid.get() + " boundedConfigurations=" + boundedConfigurations.get());
            }

            // then
            assertThat(pid.get()).isPositive().isNotEqualTo(holderPid);
            await("Remaining budget ends before old fixed lock timeout")
                    .pollInSameThread()
                    .pollDelay(Duration.ZERO)
                    .atMost(Duration.ofMillis(650))
                    .untilAsserted(() -> assertThat(future.isDone()).isTrue());
            Outcome result = future.get(1, TimeUnit.SECONDS);
            assertThat(result.failure()).isNotNull();
            assertThat(sqlState(result.failure())).isIn("55P03", "57014");
            assertThat(boundedConfigurations.get()).isPositive();
            holder.rollback();
            assertThat(fingerprint()).isEqualTo(before);
        } finally {
            executor.shutdownNow();
            assertThat(executor.awaitTermination(3, TimeUnit.SECONDS)).isTrue();
        }
    }

    @ParameterizedTest
    @EnumSource(Operation.class)
    void rejectsLateQueryReturnAndRollsBackAllWrites_whenTheCallerBudgetExpires(Operation operation) throws Exception {
        // given
        Invocation request = prepare(operation);
        String before = fingerprint();
        var entered = new CountDownLatch(1);
        var release = new CountDownLatch(1);
        var mutation = new AtomicBoolean();
        var returned = new AtomicBoolean();
        var selected = proxy(call -> {
            String method = call.getMethod().getName();
            if (method.equals("claimBefore") || method.equals("claim") || method.equals("heartbeatBefore")
                    || method.equals("heartbeat")) {
                mutation.set(true);
            }
            Object result = call.proceed();
            boolean target = switch (operation) {
                case SNAPSHOT -> method.equals("snapshot");
                case CONTROL -> method.equals("control");
                case OBSERVE -> method.equals("observe");
                case INVALIDATE -> method.equals("fence");
                case BOOTSTRAP, HEARTBEAT -> method.equals("snapshot") && mutation.get();
            };
            if (target) {
                if (operation == Operation.BOOTSTRAP || operation == Operation.HEARTBEAT) {
                    assertThat(((Optional<?>) result).orElseThrow()).isInstanceOf(RunSnapshot.class);
                    assertThat(((RunSnapshot) ((Optional<?>) result).orElseThrow()).attempt().claim()).isPresent();
                } else if (operation == Operation.OBSERVE || operation == Operation.INVALIDATE) {
                    assertThat(result).isEqualTo(1);
                }
                entered.countDown();
                assertThat(release.await(4, TimeUnit.SECONDS)).isTrue();
                returned.set(true);
            }
            return result;
        });
        AiRuntimeKernel bounded = replica(selected);
        var budget = AiRuntimeOperationBudget.start(Duration.ofMillis(600));
        var executor = Executors.newSingleThreadExecutor();
        try {
            // when
            var future = executor.submit(() -> capture(() -> invoke(request, bounded, budget)));
            assertThat(entered.await(2, TimeUnit.SECONDS)).isTrue();
            awaitExpired(budget);
            release.countDown();

            // then
            Outcome result = future.get(2, TimeUnit.SECONDS);
            assertThat(returned.get()).isTrue();
            assertThat(result.failure()).isInstanceOf(AiRuntimeOperationBudget.Unavailable.class);
            assertThat(fingerprint()).isEqualTo(before);
        } finally {
            release.countDown();
            executor.shutdownNow();
            assertThat(executor.awaitTermination(3, TimeUnit.SECONDS)).isTrue();
        }
    }

    // ── Helpers ───────────────────────────────────────────────────────────────

    private Invocation prepare(Operation operation) {
        ClaimBinding claim = null;
        if (operation == Operation.HEARTBEAT) {
            claim = kernel.bootstrap(expected(current()), POD).value().orElseThrow().binding();
        }
        return new Invocation(operation, current(), claim);
    }

    private static Object invoke(Invocation request, AiRuntimeKernel selected, AiRuntimeOperationBudget budget) {
        return switch (request.operation()) {
            case SNAPSHOT -> selected.snapshot(request.run().spec().runId(), budget);
            case CONTROL -> selected.control(budget);
            case OBSERVE -> selected.observe(observation(request.run(), POD, 2, true), budget);
            case INVALIDATE -> selected.invalidate(expected(request.run()), budget);
            case BOOTSTRAP -> selected.bootstrap(expected(request.run()), POD, budget);
            case HEARTBEAT -> selected.heartbeat(request.claim(), 1, budget);
        };
    }

    private AiRuntimeRepository proxy(MethodInterceptor interceptor) {
        var factory = new ProxyFactory(repository);
        factory.addAdvice(interceptor);
        return (AiRuntimeRepository) factory.getProxy();
    }

    private AiRuntimeKernel replica(AiRuntimeRepository selected) {
        var factory = new ProxyFactory(new AiRuntimeWriter(selected));
        factory.setProxyTargetClass(true);
        factory.addAdvice(new TransactionInterceptor(transactions, new AnnotationTransactionAttributeSource()));
        return new AiRuntimeKernel(selected, (AiRuntimeWriter) factory.getProxy(), new AiFeatureGate(true));
    }

    private RunSnapshot current() {
        return kernel.snapshot(created.spec().runId()).orElseThrow();
    }

    private String fingerprint() throws Exception {
        try (Connection connection = source.getConnection();
                var statement = connection.createStatement();
                var rows = statement
                        .executeQuery(
                                """
                                        SELECT encode(sha256(convert_to(
                                            (SELECT jsonb_agg(to_jsonb(r) ORDER BY uuid)::text FROM core.ai_runtime_run r)
                                            || (SELECT jsonb_agg(to_jsonb(a) ORDER BY uuid)::text FROM core.ai_runtime_attempt a)
                                            || (SELECT jsonb_agg(to_jsonb(l) ORDER BY attempt_uuid)::text FROM core.ai_runtime_launch l)
                                            || COALESCE((SELECT jsonb_agg(to_jsonb(w) ORDER BY cluster,pod_uid)::text FROM core.ai_runtime_workload w),'null'),
                                            'UTF8')),'hex')
                                        """)) {
            assertThat(rows.next()).isTrue();
            return rows.getString(1);
        }
    }

    private static int physicalPid(Connection connection) throws Exception {
        try (var statement = connection.createStatement();
                var rows = statement.executeQuery("SELECT pg_backend_pid()")) {
            assertThat(rows.next()).isTrue();
            return rows.getInt(1);
        }
    }

    private static Outcome capture(java.util.function.Supplier<?> action) {
        try {
            return new Outcome(action.get(), null);
        } catch (RuntimeException failure) {
            return new Outcome(null, failure);
        }
    }

    private static void awaitExpired(AiRuntimeOperationBudget budget) {
        await("Caller-owned operation expires")
                .pollInSameThread()
                .pollDelay(Duration.ZERO)
                .pollInterval(Duration.ofMillis(2))
                .atMost(Duration.ofSeconds(2))
                .until(() -> {
                    try {
                        budget.remaining();
                        return false;
                    } catch (AiRuntimeOperationBudget.Unavailable expired) {
                        return true;
                    }
                });
    }

    private static String sqlState(Throwable failure) {
        for (Throwable cause = failure; cause != null; cause = cause.getCause()) {
            if (cause instanceof java.sql.SQLException sql) {
                return sql.getSQLState();
            }
        }
        return "NO_SQL_STATE";
    }

    private enum Operation {
        SNAPSHOT,
        CONTROL,
        OBSERVE,
        INVALIDATE,
        BOOTSTRAP,
        HEARTBEAT
    }

    private record Invocation(Operation operation, RunSnapshot run, ClaimBinding claim) {
    }

    private record Outcome(Object value, RuntimeException failure) {
    }
}
