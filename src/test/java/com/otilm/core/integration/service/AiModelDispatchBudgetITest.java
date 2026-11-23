package com.otilm.core.integration.service;

import com.otilm.ai.runtime.protocol.ManagementAction;
import com.otilm.core.dao.repository.ai.AiModelDispatchRepository;
import com.otilm.core.dao.repository.ai.AiRuntimeRepository;
import com.otilm.core.model.ai.AiModelDispatchState.ConnectionVersion;
import com.otilm.core.model.ai.AiModelDispatchState.ExactPayload;
import com.otilm.core.model.ai.AiModelDispatchState.ManagementPreparation;
import com.otilm.core.model.ai.AiModelDispatchState.ManagementRedemption;
import com.otilm.core.model.ai.AiModelDispatchState.RunPreparation;
import com.otilm.core.model.ai.AiModelDispatchState.RunRedemption;
import com.otilm.core.model.ai.AiRuntimeState.Claim;
import com.otilm.core.model.ai.AiRuntimeState.RunSnapshot;
import com.otilm.core.model.ai.AiRuntimeState.Status;
import com.otilm.core.model.ai.AiRuntimeState.WorkloadRef;
import com.otilm.core.service.ai.AiRuntimeKernel;
import com.otilm.core.service.ai.AiRuntimeOperationBudget;
import com.otilm.core.service.writer.ai.AiModelDispatchWriter;
import com.otilm.core.service.writer.ai.AiModelRunInputWriter;
import com.otilm.core.util.AiModelDispatchFixture;
import com.otilm.core.util.AiRuntimeFixture;
import com.otilm.core.util.ai.BaseAiSpringBootTest;
import jakarta.persistence.EntityManager;
import java.sql.Connection;
import java.sql.SQLException;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;
import java.util.UUID;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.function.Supplier;
import javax.sql.DataSource;
import org.aopalliance.intercept.MethodInterceptor;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;
import org.junit.jupiter.params.provider.ValueSource;
import org.springframework.aop.framework.ProxyFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.transaction.PlatformTransactionManager;
import org.springframework.transaction.annotation.AnnotationTransactionAttributeSource;
import org.springframework.transaction.interceptor.TransactionInterceptor;

import static com.otilm.core.util.AiRuntimeFixture.expected;
import static com.otilm.core.util.AiRuntimeFixture.observation;
import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.catchThrowable;
import static org.awaitility.Awaitility.await;

/** Physical PostgreSQL timeouts and rollback, not remote authority/native admission proof. */
class AiModelDispatchBudgetITest extends BaseAiSpringBootTest {
    private static final ExactPayload PAYLOAD = AiModelDispatchFixture.payload(32, "budget-fixture");
    @Autowired
    private DataSource source;
    @Autowired
    private EntityManager entityManager;
    @Autowired
    private PlatformTransactionManager transactions;
    @Autowired
    private AiRuntimeKernel kernel;
    @Autowired
    private AiRuntimeRepository runtime;
    @Autowired
    private AiModelDispatchRepository modelRepository;
    private ConnectionVersion model;
    private RunSnapshot run;
    private Claim claim;
    private UUID actor;
    private UUID session;
    private Instant expires;

    @BeforeEach
    void installFacts() throws Exception {
        AiModelDispatchFixture.drop(source);
        AiRuntimeFixture.install(source);
        model = AiModelDispatchFixture.approvedModel(source);
        Instant now = AiRuntimeFixture.now(source);
        var control = AiRuntimeFixture.enableTestControl(kernel, now);
        run = kernel.create(control, AiRuntimeFixture.run(now), AiRuntimeFixture.attempt(now));
        var workload = new WorkloadRef("cluster-one", UUID.randomUUID().toString());
        kernel.observe(observation(current(), workload, 1, true));
        claim = kernel.bootstrap(expected(current()), workload).value().orElseThrow();
        AiModelDispatchFixture.runBudget(source, run.spec().runId(), model, 3, 128);
        actor = UUID.randomUUID();
        session = UUID.randomUUID();
        expires = AiRuntimeFixture.now(source).plusSeconds(30);
        AiModelDispatchFixture
                .managementSession(source, actor, session, model, ManagementAction.CONNECTION_CHECK, expires);
    }

    @Autowired
    private AiModelRunInputWriter inputs;
    @Autowired
    private AiModelDispatchWriter dispatch;

    @ParameterizedTest
    @ValueSource(strings = {"connection", "input", "run-key", "run-id", "management-key", "management-id"})
    void remainingBudgetBoundsActualDispatchPrerequisiteReads(String operation) throws Exception {
        String table = switch (operation) {
            case "connection" -> "ai_model_connection";
            case "input" -> "ai_model_run_input";
            case "run-key", "run-id" -> "ai_model_run_intent";
            default -> "ai_model_management_intent";
        };
        var executor = Executors.newSingleThreadExecutor();
        try (Connection holder = source.getConnection(); Connection observer = source.getConnection()) {
            holder.setAutoCommit(false);
            int holderPid = physicalPid(holder);
            try (var statement = holder.createStatement()) {
                statement.execute("LOCK TABLE " + table + " IN ACCESS EXCLUSIVE MODE");
            }
            try {
                var result = executor.submit(() -> catchThrowable(() -> {
                    var budget = AiRuntimeOperationBudget.start(Duration.ofMillis(800));
                    prerequisiteRead(operation, budget);
                    budget.remaining();
                }));
                await("Prerequisite SELECT is blocked on the exact holder")
                        .pollInSameThread()
                        .pollDelay(Duration.ZERO)
                        .pollInterval(Duration.ofMillis(2))
                        .atMost(Duration.ofMillis(250))
                        .until(() -> {
                            try (var statement = observer.prepareStatement("""
                                    SELECT EXISTS (SELECT 1 FROM pg_stat_activity
                                        WHERE datname=current_database() AND pid<>? AND ?=ANY(pg_blocking_pids(pid)))
                                    """)) {
                                statement.setInt(1, holderPid);
                                statement.setInt(2, holderPid);
                                try (var rows = statement.executeQuery()) {
                                    assertThat(rows.next()).isTrue();
                                    return rows.getBoolean(1);
                                }
                            }
                        });
                await("Remaining budget cancels the prerequisite SELECT")
                        .pollInSameThread()
                        .pollDelay(Duration.ZERO)
                        .atMost(Duration.ofMillis(1000))
                        .untilAsserted(() -> assertThat(result.isDone()).isTrue());
                assertThat(sqlState(result.get(1, TimeUnit.SECONDS))).isIn("55P03", "57014");
            } finally {
                holder.rollback();
            }
            var result = prerequisiteRead(operation, AiRuntimeOperationBudget.start());
            if (operation.equals("connection")) {
                assertThat(result.orElseThrow()).isEqualTo(model);
            } else {
                assertThat(result).isEmpty();
            }
        } finally {
            executor.shutdownNow();
            assertThat(executor.awaitTermination(3, TimeUnit.SECONDS)).isTrue();
        }
    }

    private Optional<?> prerequisiteRead(String operation, AiRuntimeOperationBudget budget) {
        UUID key = UUID.randomUUID();
        return switch (operation) {
            case "connection" -> inputs.connection(run.spec().runId(), budget);
            case "input" -> inputs.read(run.spec().runId(), model, budget);
            case "run-key" -> dispatch.preparedRunByKey(run.spec().runId(), key, budget);
            case "run-id" -> dispatch.preparedRunById(run.spec().runId(), key, budget);
            case "management-key" -> dispatch.preparedManagementByKey(session, key, budget);
            case "management-id" -> dispatch.preparedManagementById(session, key, budget);
            default -> throw new IllegalArgumentException(operation);
        };
    }

    @ParameterizedTest
    @ValueSource(booleans = {false, true})
    void remainingBudgetBoundsAnActualDistinctBackendRowLock(boolean management) throws Exception {
        var pid = new AtomicInteger();
        var selected = runtimeProxy(call -> {
            Object value = call.proceed();
            if (call.getMethod().getName().equals("configureTransaction")) {
                pid
                        .set(((Number) entityManager.createNativeQuery("SELECT pg_backend_pid()").getSingleResult())
                                .intValue());
            }
            return value;
        });
        var writer = writer(selected, modelRepository);
        RunPreparation runPreparation = runPreparation();
        ManagementPreparation managementPreparation = managementPreparation();
        String before = AiModelDispatchFixture.fingerprint(source);
        var executor = Executors.newSingleThreadExecutor();
        try (Connection holder = source.getConnection(); Connection observer = source.getConnection()) {
            holder.setAutoCommit(false);
            int holderPid;
            try (var statement = holder.createStatement();
                    var rows = statement.executeQuery("SELECT pg_backend_pid()")) {
                assertThat(rows.next()).isTrue();
                holderPid = rows.getInt(1);
            }
            String table = management ? "ai_model_connection" : "ai_runtime_run";
            UUID id = management ? model.id() : run.spec().runId();
            try (var statement = holder.prepareStatement("SELECT uuid FROM " + table + " WHERE uuid = ? FOR UPDATE")) {
                statement.setObject(1, id);
                try (var rows = statement.executeQuery()) {
                    assertThat(rows.next()).isTrue();
                }
            }
            var result = executor.submit(() -> catchThrowable(() -> {
                var budget = AiRuntimeOperationBudget.start(Duration.ofMillis(300));
                if (management) {
                    writer.prepareManagement(managementPreparation, budget);
                } else {
                    writer.prepareRun(runPreparation, budget);
                }
            }));
            await("Exact budget waiter")
                    .pollInSameThread()
                    .pollDelay(Duration.ZERO)
                    .pollInterval(Duration.ofMillis(2))
                    .atMost(Duration.ofMillis(250))
                    .until(() -> {
                        if (pid.get() <= 0) {
                            return false;
                        }
                        try (var statement = observer.prepareStatement("SELECT ? = ANY(pg_blocking_pids(?))")) {
                            statement.setInt(1, holderPid);
                            statement.setInt(2, pid.get());
                            try (var rows = statement.executeQuery()) {
                                assertThat(rows.next()).isTrue();
                                return rows.getBoolean(1);
                            }
                        }
                    });
            assertThat(pid.get()).isPositive().isNotEqualTo(holderPid);
            try {
                await("Budget terminates blocked query before legacy one-second lock timeout")
                        .pollInSameThread()
                        .pollDelay(Duration.ZERO)
                        .atMost(Duration.ofMillis(650))
                        .untilAsserted(() -> assertThat(result.isDone()).isTrue());
            } catch (org.awaitility.core.ConditionTimeoutException failure) {
                throw new AssertionError("Blocked SQL outlasted the remaining operation budget", failure);
            }
            Throwable failure = result.get(1, TimeUnit.SECONDS);
            assertThat(failure).isNotNull();
            assertThat(sqlState(failure)).isIn("55P03", "57014");
            assertThat(AiModelDispatchFixture.fingerprint(source)).isEqualTo(before);
        } finally {
            executor.shutdownNow();
            assertThat(executor.awaitTermination(3, TimeUnit.SECONDS)).isTrue();
        }
    }

    @ParameterizedTest
    @CsvSource({"false,false", "false,true", "true,false", "true,true"})
    void lateFinalSqlCannotCommitReservationOrConsumption(boolean management, boolean consume) throws Exception {
        var writer = writer(runtime, modelRepository);
        var runPreparation = runPreparation();
        var managementPreparation = managementPreparation();
        if (consume) {
            Status status = management
                    ? writer.prepareManagement(managementPreparation, AiRuntimeOperationBudget.start()).status()
                    : writer.prepareRun(runPreparation, AiRuntimeOperationBudget.start()).status();
            assertThat(status).isEqualTo(Status.APPLIED);
        }
        String table = management ? "ai_model_management_intent" : "ai_model_run_intent";
        try (var connection = source.getConnection(); var statement = connection.createStatement()) {
            statement
                    .execute(
                            "CREATE FUNCTION core.f04_budget_delay() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN PERFORM pg_sleep(1); RETURN NEW; END $$");
            statement
                    .execute("CREATE TRIGGER f04_budget_delay AFTER " + (consume ? "UPDATE" : "INSERT") + " ON core."
                            + table + " FOR EACH ROW EXECUTE FUNCTION core.f04_budget_delay()");
        }
        String before = AiModelDispatchFixture.fingerprint(source);
        Supplier<Object> operation = () -> {
            var budget = AiRuntimeOperationBudget.start(Duration.ofMillis(600));
            if (management) {
                return consume
                        ? writer.consumeManagement(managementRedemption(managementPreparation), budget)
                        : writer.prepareManagement(managementPreparation, budget);
            }
            return consume
                    ? writer.consumeRun(runRedemption(runPreparation), budget)
                    : writer.prepareRun(runPreparation, budget);
        };
        try {
            Throwable failure = catchThrowable(operation::get);
            assertThat(failure).isNotNull();
            assertThat(sqlState(failure)).isEqualTo("57014");
            assertThat(AiModelDispatchFixture.fingerprint(source)).isEqualTo(before);
        } finally {
            try (var connection = source.getConnection(); var statement = connection.createStatement()) {
                statement.execute("DROP TRIGGER f04_budget_delay ON core." + table);
                statement.execute("DROP FUNCTION core.f04_budget_delay()");
            }
        }
    }

    @Test
    void laterQueriesReceiveSmallerCurrentTransactionTimeouts() {
        List<Long> statementCaps = new ArrayList<>();
        var selectedRuntime = runtimeProxy(call -> {
            if (!call.getMethod().getName().equals("configureTransaction")) {
                recordTimeout(statementCaps);
            }
            Object result = call.proceed();
            if (call.getMethod().getName().equals("lockRun")) {
                entityManager.createNativeQuery("SELECT pg_sleep(0.08)").getSingleResult();
            }
            return result;
        });
        var selectedModel = modelProxy(call -> {
            recordTimeout(statementCaps);
            return call.proceed();
        });
        var preparation = runPreparation();
        assertThat(writer(selectedRuntime, selectedModel)
                .prepareRun(preparation, AiRuntimeOperationBudget.start(Duration.ofSeconds(2)))
                .status()).isEqualTo(Status.APPLIED);
        assertThat(statementCaps).hasSizeGreaterThan(10).allSatisfy(cap -> assertThat(cap).isBetween(1L, 2000L));
        assertThat(statementCaps.getLast()).isLessThan(statementCaps.getFirst() - 50);
    }

    private void recordTimeout(List<Long> values) {
        values
                .add(((Number) entityManager
                        .createNativeQuery("SELECT setting::bigint FROM pg_settings WHERE name='statement_timeout'")
                        .getSingleResult()).longValue());
    }

    private static String sqlState(Throwable failure) {
        for (Throwable current = failure; current != null; current = current.getCause()) {
            if (current instanceof SQLException sql) {
                return sql.getSQLState();
            }
        }
        return "NO_SQL_STATE";
    }

    private AiRuntimeRepository runtimeProxy(MethodInterceptor advice) {
        var factory = new ProxyFactory(runtime);
        factory.addAdvice(advice);
        return (AiRuntimeRepository) factory.getProxy();
    }

    private AiModelDispatchRepository modelProxy(MethodInterceptor advice) {
        var factory = new ProxyFactory(modelRepository);
        factory.addAdvice(advice);
        return (AiModelDispatchRepository) factory.getProxy();
    }

    private AiModelDispatchWriter writer(AiRuntimeRepository runtimeRepository, AiModelDispatchRepository repository) {
        var factory = new ProxyFactory(new AiModelDispatchWriter(runtimeRepository, repository));
        factory.setProxyTargetClass(true);
        factory.addAdvice(new TransactionInterceptor(transactions, new AnnotationTransactionAttributeSource()));
        return (AiModelDispatchWriter) factory.getProxy();
    }

    private RunPreparation runPreparation() {
        return new RunPreparation(UUID.randomUUID(), UUID.randomUUID(), expected(current()), claim.binding(), model,
                PAYLOAD, 32, expires);
    }

    private ManagementPreparation managementPreparation() {
        return new ManagementPreparation(UUID.randomUUID(), UUID.randomUUID(), actor, session,
                ManagementAction.CONNECTION_CHECK, model, PAYLOAD, 32, expires);
    }

    private RunRedemption runRedemption(RunPreparation request) {
        return new RunRedemption(request.intentId(), request.expected(), request.claim(), model, PAYLOAD.sha256(),
                expires, UUID.randomUUID());
    }

    private ManagementRedemption managementRedemption(ManagementPreparation request) {
        return new ManagementRedemption(request.intentId(), actor, session, request.action(), model, PAYLOAD.sha256(),
                expires, UUID.randomUUID());
    }

    private RunSnapshot current() {
        return kernel.snapshot(run.spec().runId()).orElseThrow();
    }

    @Autowired
    private jakarta.persistence.EntityManagerFactory entityManagerFactory;

    @ParameterizedTest
    @ValueSource(booleans = {false, true})
    void transactionLocalTimeoutsRestoreOnTheSamePhysicalConnection(boolean commit) throws Exception {
        var factory = entityManagerFactory.unwrap(org.hibernate.SessionFactory.class);
        try (Connection connection = source.getConnection();
                var session = factory.withOptions().connection(connection).openSession()) {
            var selected = new org.springframework.data.jpa.repository.support.JpaRepositoryFactory(session)
                    .getRepository(AiRuntimeRepository.class);
            long originalLock = setting(connection, "lock_timeout");
            long originalStatement = setting(connection, "statement_timeout");
            int pid = physicalPid(connection);
            var transaction = session.beginTransaction();
            selected.configureTransaction(37);
            assertThat(setting(connection, "lock_timeout")).isEqualTo(37);
            assertThat(setting(connection, "statement_timeout")).isEqualTo(37);
            if (commit) {
                transaction.commit();
            } else {
                transaction.rollback();
            }
            assertThat(physicalPid(connection)).isEqualTo(pid);
            assertThat(setting(connection, "lock_timeout")).isEqualTo(originalLock);
            assertThat(setting(connection, "statement_timeout")).isEqualTo(originalStatement);
            transaction = session.beginTransaction();
            selected.configureTransaction();
            assertThat(setting(connection, "lock_timeout")).isEqualTo(1000);
            assertThat(setting(connection, "statement_timeout")).isEqualTo(4000);
            transaction.rollback();
            assertThat(physicalPid(connection)).isEqualTo(pid);
            assertThat(setting(connection, "lock_timeout")).isEqualTo(originalLock);
            assertThat(setting(connection, "statement_timeout")).isEqualTo(originalStatement);
        }
    }

    @Test
    void boundedTimeoutConfigurationCannotDisableTimeoutsAndRetainsExistingMaxima() throws Exception {
        var factory = entityManagerFactory.unwrap(org.hibernate.SessionFactory.class);
        try (Connection connection = source.getConnection();
                var session = factory.withOptions().connection(connection).openSession()) {
            var selected = new org.springframework.data.jpa.repository.support.JpaRepositoryFactory(session)
                    .getRepository(AiRuntimeRepository.class);
            var transaction = session.beginTransaction();
            try {
                for (long remaining : new long[]{0, -1, Long.MIN_VALUE, Long.MAX_VALUE}) {
                    selected.configureTransaction(remaining);
                    long expected = remaining > 0 ? 4000 : 1;
                    assertThat(setting(connection, "statement_timeout")).isEqualTo(expected);
                    assertThat(setting(connection, "lock_timeout")).isEqualTo(Math.min(1000, expected));
                }
            } finally {
                transaction.rollback();
            }
        }
    }

    private static long setting(Connection connection, String name) throws Exception {
        try (var statement = connection.prepareStatement("SELECT setting::bigint FROM pg_settings WHERE name = ?")) {
            statement.setString(1, name);
            try (var rows = statement.executeQuery()) {
                assertThat(rows.next()).isTrue();
                return rows.getLong(1);
            }
        }
    }

    private static int physicalPid(Connection connection) throws Exception {
        try (var statement = connection.createStatement();
                var rows = statement.executeQuery("SELECT pg_backend_pid()")) {
            assertThat(rows.next()).isTrue();
            return rows.getInt(1);
        }
    }

    @ParameterizedTest
    @CsvSource({"false,false", "false,true", "true,false", "true,true"})
    void eachSqlBoundaryRestoresCurrentCapAfterPriorBoundaryChangesIt(boolean management, boolean consume) {
        var runPreparation = runPreparation();
        var managementPreparation = managementPreparation();
        if (consume) {
            var normal = writer(runtime, modelRepository);
            Status prepared = management
                    ? normal.prepareManagement(managementPreparation, AiRuntimeOperationBudget.start()).status()
                    : normal.prepareRun(runPreparation, AiRuntimeOperationBudget.start()).status();
            assertThat(prepared).isEqualTo(Status.APPLIED);
        }
        var observed = new AtomicInteger();
        MethodInterceptor boundary = call -> {
            if (call.getMethod().getName().equals("configureTransaction")) {
                return call.proceed();
            }
            long statementCap = ((Number) entityManager
                    .createNativeQuery("SELECT setting::bigint FROM pg_settings WHERE name='statement_timeout'")
                    .getSingleResult()).longValue();
            long lockCap = ((Number) entityManager
                    .createNativeQuery("SELECT setting::bigint FROM pg_settings WHERE name='lock_timeout'")
                    .getSingleResult()).longValue();
            assertThat(statementCap).as("Fresh cap at %s", call.getMethod().getName()).isBetween(1L, 2000L);
            assertThat(lockCap).as("Fresh lock cap at %s", call.getMethod().getName()).isBetween(1L, 1000L);
            Object result = call.proceed();
            observed.incrementAndGet();
            // Adversarial persistence-boundary state: a later call cannot inherit a safe previous cap by accident.
            entityManager
                    .createNativeQuery(
                            "SELECT set_config('statement_timeout','5000ms',true) || set_config('lock_timeout','5000ms',true)")
                    .getSingleResult();
            return result;
        };
        var selected = writer(runtimeProxy(boundary), modelProxy(boundary));
        var budget = AiRuntimeOperationBudget.start(Duration.ofSeconds(2));
        if (management) {
            if (consume) {
                assertThat(selected.consumeManagement(managementRedemption(managementPreparation), budget)).isPresent();
            } else {
                assertThat(selected.prepareManagement(managementPreparation, budget).status())
                        .isEqualTo(Status.APPLIED);
            }
        } else if (consume) {
            assertThat(selected.consumeRun(runRedemption(runPreparation), budget)).isPresent();
        } else {
            assertThat(selected.prepareRun(runPreparation, budget).status()).isEqualTo(Status.APPLIED);
        }
        assertThat(observed.get()).isGreaterThan(4);
    }

    @ParameterizedTest
    @CsvSource({"false,false", "false,true", "true,false", "true,true"})
    void successfulFinalWriteOrReadbackReturningLateRollsBack(boolean management, boolean readback) throws Exception {
        var runPreparation = runPreparation();
        var managementPreparation = managementPreparation();
        if (readback) {
            var normal = writer(runtime, modelRepository);
            Status prepared = management
                    ? normal.prepareManagement(managementPreparation, AiRuntimeOperationBudget.start()).status()
                    : normal.prepareRun(runPreparation, AiRuntimeOperationBudget.start()).status();
            assertThat(prepared).isEqualTo(Status.APPLIED);
        }
        String method = readback
                ? (management ? "managementDispatch" : "runDispatch")
                : (management ? "insertManagementIntent" : "insertRunIntent");
        var entered = new java.util.concurrent.CountDownLatch(1);
        var release = new java.util.concurrent.CountDownLatch(1);
        var selectedModel = modelProxy(call -> {
            Object result = call.proceed();
            if (call.getMethod().getName().equals(method)) {
                if (readback) {
                    assertThat((java.util.Optional<?>) result).isPresent();
                } else {
                    assertThat(result).isEqualTo(1);
                }
                entered.countDown();
                assertThat(release.await(3, TimeUnit.SECONDS)).isTrue();
            }
            return result;
        });
        var selected = writer(runtime, selectedModel);
        String before = AiModelDispatchFixture.fingerprint(source);
        var executor = Executors.newSingleThreadExecutor();
        var budget = AiRuntimeOperationBudget.start(Duration.ofSeconds(1));
        try {
            var result = executor.submit(() -> catchThrowable(() -> {
                if (management) {
                    if (readback) {
                        selected.consumeManagement(managementRedemption(managementPreparation), budget);
                    } else {
                        selected.prepareManagement(managementPreparation, budget);
                    }
                } else if (readback) {
                    selected.consumeRun(runRedemption(runPreparation), budget);
                } else {
                    selected.prepareRun(runPreparation, budget);
                }
            }));
            assertThat(entered.await(2, TimeUnit.SECONDS)).isTrue();
            await("Budget elapsed after successful final SQL")
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
            release.countDown();
            assertThat(result.get(2, TimeUnit.SECONDS)).isInstanceOf(AiRuntimeOperationBudget.Unavailable.class);
            assertThat(AiModelDispatchFixture.fingerprint(source)).isEqualTo(before);
        } finally {
            release.countDown();
            executor.shutdownNow();
            assertThat(executor.awaitTermination(3, TimeUnit.SECONDS)).isTrue();
        }
    }

}
