package com.otilm.core.integration.service;

import com.otilm.core.dao.repository.ai.AiRuntimeRepository;
import com.otilm.core.model.ai.AiRuntimeState.Claim;
import com.otilm.core.model.ai.AiRuntimeState.CleanupState;
import com.otilm.core.model.ai.AiRuntimeState.ControlSnapshot;
import com.otilm.core.model.ai.AiRuntimeState.ControlVersion;
import com.otilm.core.model.ai.AiRuntimeState.ReadinessObservation;
import com.otilm.core.model.ai.AiRuntimeState.RunSnapshot;
import com.otilm.core.model.ai.AiRuntimeState.Status;
import com.otilm.core.model.ai.AiRuntimeState.Transition;
import com.otilm.core.model.ai.AiRuntimeState.WorkloadRef;
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
import java.sql.Statement;
import java.time.Duration;
import java.time.Instant;
import java.util.Set;
import java.util.UUID;
import java.util.concurrent.ConcurrentSkipListSet;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.function.Function;
import javax.sql.DataSource;
import org.aopalliance.intercept.MethodInterceptor;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.EnumSource;
import org.springframework.aop.framework.ProxyFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.transaction.PlatformTransactionManager;
import org.springframework.transaction.annotation.AnnotationTransactionAttributeSource;
import org.springframework.transaction.interceptor.TransactionInterceptor;
import org.springframework.transaction.support.TransactionSynchronizationManager;
import org.springframework.transaction.support.TransactionTemplate;

import static com.otilm.core.util.AiRuntimeFixture.expected;
import static com.otilm.core.util.AiRuntimeFixture.observation;
import static org.assertj.core.api.Assertions.assertThat;

class AiRuntimeControlRaceITest extends BaseAiSpringBootTest {
    private static final WorkloadRef POD = new WorkloadRef("cluster-one", "pod-one");
    @Autowired
    private DataSource dataSource;
    @Autowired
    private AiRuntimeRepository repository;
    @Autowired
    private AiRuntimeKernel kernel;
    @Autowired
    private PlatformTransactionManager transactionManager;
    @PersistenceContext
    private EntityManager entityManager;
    private ControlVersion version;
    private RunSnapshot created;

    @BeforeEach
    void createRun() throws Exception {
        AiRuntimeFixture.install(dataSource);
        Instant at = now();
        version = AiRuntimeFixture.enableTestControl(kernel, at);
        created = kernel.create(version, AiRuntimeFixture.run(at), AiRuntimeFixture.attempt(at));
    }

    @ParameterizedTest
    @EnumSource(Admission.class)
    void disableBeforeAdmissionRejectsTheOldGeneration(Admission operation) throws Exception {
        Prepared call = prepare(operation);
        RunSnapshot before = current();

        Race result = ordered("disableControl", runtime -> runtime.disableControl(version), call.action());

        assertApplied(result.first());
        if (operation == Admission.CREATE) {
            assertThat(result.second().failure()).isInstanceOf(AiRuntimeWriter.Rejected.class);
            assertThat(kernel.snapshot(call.runId())).isEmpty();
        } else {
            assertEmpty(result.second(), Status.STALE);
        }
        assertThat(current()).isEqualTo(before);
        assertThat(kernel.control().orElseThrow().version().generation()).isEqualTo(version.generation() + 1);
    }

    @ParameterizedTest
    @EnumSource(Admission.class)
    void admissionBeforeDisableCannotGrantAnyLaterOperation(Admission operation) throws Exception {
        Prepared call = prepare(operation);

        Race result = ordered(call.query(), call.action(), runtime -> runtime.disableControl(version));

        assertThat(result.first().failure()).isNull();
        if (operation == Admission.CREATE) {
            assertThat(result.first().value()).isInstanceOf(RunSnapshot.class);
        } else {
            assertApplied(result.first());
        }
        assertApplied(result.second());
        RunSnapshot admitted = kernel.snapshot(call.runId()).orElseThrow();
        assertThat(admitted.controlGeneration()).isEqualTo(version.generation());
        assertThat(admitted.attempt().controlGeneration()).isEqualTo(version.generation());
        assertThat(kernel.observe(observation(admitted, POD, 2, true)).status()).isEqualTo(Status.STALE);
        assertThat(kernel.bootstrap(expected(admitted), POD).value()).isEmpty();
        admitted.attempt().claim().ifPresent(claim -> {
            Transition<Claim> stale = kernel.heartbeat(claim.binding(), 2);
            assertThat(stale.status()).isEqualTo(Status.STALE);
            assertThat(stale.value()).isEmpty();
        });
        assertThat(kernel.invalidate(expected(admitted)).status()).isEqualTo(Status.APPLIED);
        assertThat(kernel.snapshot(call.runId()).orElseThrow().launch().cleanup()).isEqualTo(CleanupState.DUE);
    }

    @ParameterizedTest
    @EnumSource(ExpiryBoundary.class)
    void expiryAtFinalSqlCannotPublishOrPartiallyMutate(ExpiryBoundary boundary) throws Exception {
        boolean claimedReplay = boundary == ExpiryBoundary.WINNER_REPLAY || boundary == ExpiryBoundary.HEARTBEAT_REPLAY;
        Instant claimCap = claimedReplay ? shortenEvidence() : null;
        Prepared call = prepareExpiry(boundary);
        Instant deadline = claimedReplay ? claimCap : shortenEvidence();
        if (claimedReplay) {
            assertThat(current().attempt().claim().orElseThrow().leaseUntil()).isEqualTo(deadline);
        }
        if (boundary == ExpiryBoundary.EVIDENCE_REPLAY) {
            ReadinessObservation exact = kernel.control().orElseThrow().observation().orElseThrow();
            call = new Prepared("controlEvidenceCurrent", runtime -> runtime.observeControl(exact),
                    created.spec().runId());
        }
        RunSnapshot before = current();
        ControlSnapshot controlBefore = kernel.control().orElseThrow();
        AtomicBoolean intercepted = new AtomicBoolean();
        String query = call.query();
        AiRuntimeRepository delayed = repositoryProxy(invocation -> {
            if (invocation.getMethod().getName().equals(query)) {
                assertThat(TransactionSynchronizationManager.isActualTransactionActive()).isTrue();
                intercepted.set(true);
                awaitDatabaseDeadline(deadline);
            }
            return invocation.proceed();
        });

        Outcome result = capture(call.action(), replica(delayed));

        assertThat(intercepted).isTrue();
        if (boundary == ExpiryBoundary.CREATE) {
            assertThat(result.failure()).isInstanceOf(AiRuntimeWriter.Rejected.class);
            assertThat(kernel.snapshot(call.runId())).isEmpty();
        } else {
            assertEmpty(result, boundary.status);
        }
        assertThat(current()).isEqualTo(before);
        assertThat(kernel.control()).contains(controlBefore);
    }

    @Test
    void detachedPrecheckCannotRestoreAConcurrentDisable() throws Exception {
        CountDownLatch entered = new CountDownLatch(1);
        CountDownLatch release = new CountDownLatch(1);
        AiRuntimeRepository delayed = repositoryProxy(invocation -> {
            Object result = invocation.proceed();
            if (invocation.getMethod().getName().equals("control")) {
                assertThat(TransactionSynchronizationManager.isActualTransactionActive()).isFalse();
                entered.countDown();
                assertThat(release.await(3, TimeUnit.SECONDS)).isTrue();
            }
            return result;
        });
        AiRuntimeKernel outside = transactional(new AiRuntimeKernel(delayed,
                transactional(new AiRuntimeWriter(repository), AiRuntimeWriter.class), new AiFeatureGate(true)),
                AiRuntimeKernel.class);
        ExecutorService executor = Executors.newSingleThreadExecutor();
        try {
            Future<Transition<ControlSnapshot>> worker = executor
                    .submit(() -> new TransactionTemplate(transactionManager).execute(tx -> {
                        ControlSnapshot precheck = outside.control().orElseThrow();
                        assertThat(TransactionSynchronizationManager.isActualTransactionActive()).isTrue();
                        return outside.changeControl(precheck.version(), precheck.pins().orElseThrow());
                    }));
            assertThat(entered.await(3, TimeUnit.SECONDS)).isTrue();
            assertThat(kernel.disableControl(version).status()).isEqualTo(Status.APPLIED);
            ControlSnapshot disabled = kernel.control().orElseThrow();
            release.countDown();
            assertThat(worker.get(8, TimeUnit.SECONDS).status()).isEqualTo(Status.STALE);
            assertThat(kernel.control()).contains(disabled);
        } finally {
            release.countDown();
            executor.shutdownNow();
            assertThat(executor.awaitTermination(8, TimeUnit.SECONDS)).isTrue();
        }
    }

    private Prepared prepare(Admission operation) throws Exception {
        if (operation == Admission.CREATE) {
            Instant at = now();
            var run = AiRuntimeFixture.run(at);
            var attempt = AiRuntimeFixture.attempt(at);
            return new Prepared("create", runtime -> runtime.create(version, run, attempt), run.runId());
        }
        register(true);
        if (operation == Admission.CLAIM) {
            var expected = expected(current());
            return new Prepared("claim", runtime -> runtime.bootstrap(expected, POD), created.spec().runId());
        }
        Claim claim = claim();
        return new Prepared("heartbeat", runtime -> runtime.heartbeat(claim.binding(), 1), created.spec().runId());
    }

    private Prepared prepareExpiry(ExpiryBoundary boundary) throws Exception {
        if (boundary == ExpiryBoundary.CREATE) {
            return prepare(Admission.CREATE);
        }
        if (boundary == ExpiryBoundary.OBSERVE) {
            var observed = observation(current(), POD, 1, true);
            return new Prepared("observe", runtime -> runtime.observe(observed), created.spec().runId());
        }
        if (boundary == ExpiryBoundary.PENDING) {
            register(false);
            var expected = expected(current());
            return new Prepared("pending", runtime -> runtime.bootstrap(expected, POD), created.spec().runId());
        }
        if (boundary == ExpiryBoundary.REPLACE) {
            try (Connection connection = dataSource.getConnection();
                    Statement statement = connection.createStatement()) {
                statement
                        .executeUpdate(
                                "UPDATE ai_runtime_attempt SET launch_deadline = clock_timestamp() - interval '1 second'");
            }
            assertThat(kernel.expire(expected(current())).status()).isEqualTo(Status.APPLIED);
            var expected = expected(current());
            var next = AiRuntimeFixture.attempt(now());
            return new Prepared("replace", runtime -> runtime.replace(expected, next), created.spec().runId());
        }
        if (boundary == ExpiryBoundary.REFRESH || boundary == ExpiryBoundary.EVIDENCE_REPLAY) {
            ControlSnapshot control = kernel.control().orElseThrow();
            Instant at = now();
            ReadinessObservation fresh = new ReadinessObservation(version, control.pins().orElseThrow(), 2,
                    UUID.randomUUID(), at, at.plusSeconds(90));
            return new Prepared("observeControl", runtime -> runtime.observeControl(fresh), created.spec().runId());
        }
        register(true);
        Claim claim = claim();
        if (boundary == ExpiryBoundary.WINNER_REPLAY) {
            var expected = expected(current());
            return new Prepared("admissionCurrent", runtime -> runtime.bootstrap(expected, POD),
                    created.spec().runId());
        }
        assertThat(kernel.heartbeat(claim.binding(), 1).status()).isEqualTo(Status.APPLIED);
        return new Prepared("admissionCurrent", runtime -> runtime.heartbeat(claim.binding(), 1),
                created.spec().runId());
    }

    private Race ordered(String firstQuery, Function<AiRuntimeKernel, Object> firstCall,
            Function<AiRuntimeKernel, Object> secondCall) throws Exception {
        CountDownLatch firstEntered = new CountDownLatch(1);
        CountDownLatch secondEntered = new CountDownLatch(1);
        CountDownLatch release = new CountDownLatch(1);
        AtomicInteger secondPid = new AtomicInteger();
        Set<Integer> backends = new ConcurrentSkipListSet<>();
        AiRuntimeRepository first = repositoryProxy(invocation -> {
            if (invocation.getMethod().getName().equals(firstQuery)) {
                backends.add(backend());
                firstEntered.countDown();
                assertThat(release.await(3, TimeUnit.SECONDS)).isTrue();
            }
            return invocation.proceed();
        });
        AiRuntimeRepository second = repositoryProxy(invocation -> {
            if (invocation.getMethod().getName().equals("lockControl")) {
                secondPid.set(backend());
                backends.add(secondPid.get());
                secondEntered.countDown();
            }
            return invocation.proceed();
        });
        ExecutorService executor = Executors.newFixedThreadPool(2);
        try {
            Future<Outcome> firstResult = executor.submit(() -> capture(firstCall, replica(first)));
            assertThat(firstEntered.await(3, TimeUnit.SECONDS)).isTrue();
            Future<Outcome> secondResult = executor.submit(() -> capture(secondCall, replica(second)));
            assertThat(secondEntered.await(3, TimeUnit.SECONDS)).isTrue();
            awaitBlockedControl(secondPid.get());
            release.countDown();
            Race result = new Race(firstResult.get(8, TimeUnit.SECONDS), secondResult.get(8, TimeUnit.SECONDS));
            assertThat(backends).hasSize(2);
            return result;
        } finally {
            release.countDown();
            executor.shutdownNow();
            assertThat(executor.awaitTermination(8, TimeUnit.SECONDS)).isTrue();
        }
    }

    private int backend() {
        assertThat(TransactionSynchronizationManager.isActualTransactionActive()).isTrue();
        return ((Number) entityManager.createNativeQuery("SELECT pg_backend_pid()").getSingleResult()).intValue();
    }

    private void awaitBlockedControl(int pid) throws Exception {
        try (Connection connection = dataSource.getConnection();
                PreparedStatement statement = connection.prepareStatement("""
                        SELECT EXISTS (SELECT 1 FROM pg_stat_activity WHERE pid = ? AND wait_event_type = 'Lock'
                            AND query LIKE '%ai_runtime_control%')
                        """)) {
            statement.setInt(1, pid);
            org.awaitility.Awaitility
                    .await("Second owned backend blocked on current control")
                    .pollInSameThread()
                    .pollDelay(Duration.ZERO)
                    .pollInterval(Duration.ofMillis(5))
                    .atMost(Duration.ofMillis(600))
                    .until(() -> {
                        try (ResultSet row = statement.executeQuery()) {
                            assertThat(row.next()).isTrue();
                            return row.getBoolean(1);
                        }
                    });
        }
    }

    private Instant shortenEvidence() throws Exception {
        try (Connection connection = dataSource.getConnection();
                Statement statement = connection.createStatement();
                ResultSet row = statement.executeQuery("""
                        UPDATE ai_runtime_control SET valid_until = clock_timestamp() + interval '1200 milliseconds'
                        RETURNING valid_until
                        """)) {
            assertThat(row.next()).isTrue();
            return row.getTimestamp(1).toInstant();
        }
    }

    private void awaitDatabaseDeadline(Instant deadline) throws Exception {
        try (Connection connection = dataSource.getConnection(); Statement statement = connection.createStatement()) {
            org.awaitility.Awaitility
                    .await("Owned database evidence deadline")
                    .pollInSameThread()
                    .pollDelay(Duration.ZERO)
                    .pollInterval(Duration.ofMillis(5))
                    .atMost(Duration.ofSeconds(3))
                    .until(() -> {
                        try (ResultSet row = statement.executeQuery("SELECT clock_timestamp()")) {
                            assertThat(row.next()).isTrue();
                            return !row.getTimestamp(1).toInstant().isBefore(deadline);
                        }
                    });
        } catch (org.awaitility.core.ConditionTimeoutException failure) {
            throw new AssertionError("The owned database evidence deadline was not reached", failure);
        }
    }

    private AiRuntimeKernel replica(AiRuntimeRepository selected) {
        AiRuntimeWriter writer = transactional(new AiRuntimeWriter(selected), AiRuntimeWriter.class);
        return transactional(new AiRuntimeKernel(repository, writer, new AiFeatureGate(true)), AiRuntimeKernel.class);
    }

    private AiRuntimeRepository repositoryProxy(MethodInterceptor interceptor) {
        ProxyFactory proxy = new ProxyFactory(repository);
        proxy.addAdvice(interceptor);
        return (AiRuntimeRepository) proxy.getProxy();
    }

    private <T> T transactional(T target, Class<T> type) {
        TransactionInterceptor transactions = new TransactionInterceptor();
        transactions.setTransactionManager(transactionManager);
        transactions.setTransactionAttributeSource(new AnnotationTransactionAttributeSource());
        ProxyFactory proxy = new ProxyFactory(target);
        proxy.setProxyTargetClass(true);
        proxy.addAdvice(transactions);
        return type.cast(proxy.getProxy());
    }

    private void register(boolean registered) {
        assertThat(kernel.observe(observation(current(), POD, 1, registered)).status()).isEqualTo(Status.APPLIED);
    }

    private Claim claim() {
        return kernel.bootstrap(expected(current()), POD).value().orElseThrow();
    }

    private RunSnapshot current() {
        return kernel.snapshot(created.spec().runId()).orElseThrow();
    }

    private Instant now() throws Exception {
        return AiRuntimeFixture.now(dataSource);
    }

    private static Outcome capture(Function<AiRuntimeKernel, Object> call, AiRuntimeKernel runtime) {
        try {
            return new Outcome(call.apply(runtime), null);
        } catch (RuntimeException failure) {
            return new Outcome(null, failure);
        }
    }

    private static void assertApplied(Outcome outcome) {
        assertThat(outcome.failure()).isNull();
        assertThat(((Transition<?>) outcome.value()).status()).isEqualTo(Status.APPLIED);
    }

    private static void assertEmpty(Outcome outcome, Status status) {
        assertThat(outcome.failure()).isNull();
        Transition<?> result = (Transition<?>) outcome.value();
        assertThat(result.status()).isEqualTo(status);
        assertThat(result.value()).isEmpty();
    }

    private record Prepared(String query, Function<AiRuntimeKernel, Object> action, UUID runId) {
    }

    private record Outcome(Object value, RuntimeException failure) {
    }

    private record Race(Outcome first, Outcome second) {
    }

    private enum Admission {
        CREATE,
        CLAIM,
        HEARTBEAT
    }

    private enum ExpiryBoundary {
        CREATE(Status.CONFLICT),
        OBSERVE(Status.CONFLICT),
        PENDING(Status.CONFLICT),
        REPLACE(Status.CONFLICT),
        REFRESH(Status.CONFLICT),
        WINNER_REPLAY(Status.EXPIRED),
        HEARTBEAT_REPLAY(Status.EXPIRED),
        EVIDENCE_REPLAY(Status.EXPIRED);

        private final Status status;

        ExpiryBoundary(Status status) {
            this.status = status;
        }
    }
}
