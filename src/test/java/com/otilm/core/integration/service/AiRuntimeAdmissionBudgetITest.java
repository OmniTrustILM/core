package com.otilm.core.integration.service;

import com.otilm.ai.runtime.protocol.BootstrapRequest;
import com.otilm.ai.runtime.protocol.ProtocolCodec;
import com.otilm.ai.runtime.protocol.RuntimeErrorCode;
import com.otilm.api.model.core.logging.enums.AuthMethod;
import com.otilm.core.dao.repository.ai.AiRuntimeRepository;
import com.otilm.core.model.ai.AiRuntimeState.Claim;
import com.otilm.core.model.ai.AiRuntimeState.RunSnapshot;
import com.otilm.core.model.ai.AiRuntimeState.RunSpec;
import com.otilm.core.model.ai.AiRuntimeState.Status;
import com.otilm.core.model.ai.AiRuntimeState.Transition;
import com.otilm.core.model.ai.AiRuntimeState.WorkloadRef;
import com.otilm.core.security.ai.RuntimeProxyCertificateClaims;
import com.otilm.core.security.ai.RuntimeProxyTransport;
import com.otilm.core.security.authn.client.AuthenticationInfo;
import com.otilm.core.security.authn.client.PlatformAuthenticationClient;
import com.otilm.core.service.ai.AiFeatureGate;
import com.otilm.core.service.ai.AiRuntimeKernel;
import com.otilm.core.service.ai.AiRuntimeOperationBudget;
import com.otilm.core.service.ai.AiRuntimeRunnerServiceImpl;
import com.otilm.core.service.writer.ai.AiRuntimeWriter;
import com.otilm.core.util.AiRuntimeFixture;
import com.otilm.core.util.ai.BaseAiSpringBootTest;
import jakarta.persistence.EntityManager;
import jakarta.persistence.PersistenceContext;
import java.io.ByteArrayInputStream;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.sql.Connection;
import java.time.Duration;
import java.time.Instant;
import java.util.HexFormat;
import java.util.List;
import java.util.Optional;
import java.util.UUID;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicReference;
import java.util.function.Supplier;
import javax.sql.DataSource;
import org.aopalliance.intercept.MethodInterceptor;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.EnumSource;
import org.springframework.aop.framework.ProxyFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.transaction.PlatformTransactionManager;
import org.springframework.transaction.TransactionDefinition;
import org.springframework.transaction.TransactionStatus;
import org.springframework.transaction.TransactionSystemException;
import org.springframework.transaction.annotation.AnnotationTransactionAttributeSource;
import org.springframework.transaction.interceptor.TransactionInterceptor;
import org.springframework.transaction.support.TransactionSynchronizationManager;

import static com.otilm.core.util.AiRuntimeFixture.expected;
import static com.otilm.core.util.AiRuntimeFixture.observation;
import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.mockStatic;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

class AiRuntimeAdmissionBudgetITest extends BaseAiSpringBootTest {
    private static final UUID POD = UUID.fromString("a3000000-0000-0000-0000-000000000001");
    private static final WorkloadRef WORKLOAD = new WorkloadRef("cluster-one", POD.toString());
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
    private RunSnapshot created;

    @BeforeEach
    void createRun() throws Exception {
        AiRuntimeFixture.install(dataSource);
        Instant at = AiRuntimeFixture.now(dataSource);
        var control = AiRuntimeFixture.enableTestControl(kernel, at);
        var base = AiRuntimeFixture.run(at);
        var run = new RunSpec(base.runId(), base.conversationRef(), base.actorId(), base.scopeMarker(),
                base.attemptLimit(), base.podLimit(), 30, base.runDeadline());
        created = kernel.create(control, run, AiRuntimeFixture.attempt(at));
    }

    @Test
    void liveBudgetClaimsAndBothReplayKindsDoNotExtendLease() {
        register(true);
        var first = kernel.bootstrap(expected(current()), WORKLOAD, AiRuntimeOperationBudget.start());
        assertThat(first.status()).isEqualTo(Status.APPLIED);
        Claim initial = first.value().orElseThrow();
        var same = kernel.bootstrap(expected(current()), WORKLOAD, AiRuntimeOperationBudget.start());
        assertThat(same.status()).isEqualTo(Status.REPLAY);
        assertThat(same.value()).contains(initial);
        var renewed = kernel.heartbeat(initial.binding(), 1, AiRuntimeOperationBudget.start());
        assertThat(renewed.status()).isEqualTo(Status.APPLIED);
        Claim latest = renewed.value().orElseThrow();
        var replay = kernel.heartbeat(latest.binding(), 1, AiRuntimeOperationBudget.start());
        assertThat(replay.status()).isEqualTo(Status.REPLAY);
        assertThat(replay.value()).contains(latest);
        assertThat(current().attempt().claim()).contains(latest);
    }

    @Test
    void liveBudgetPreservesDurablePendingThenRegistration() {
        register(false);
        assertThat(kernel.bootstrap(expected(current()), WORKLOAD, AiRuntimeOperationBudget.start()).status())
                .isEqualTo(Status.PENDING);
        assertThat(current().workloads().getFirst().pendingReturns()).isEqualTo(1);
        assertThat(kernel.observe(observation(current(), WORKLOAD, 2, true)).status()).isEqualTo(Status.APPLIED);
        assertThat(kernel.bootstrap(expected(current()), WORKLOAD, AiRuntimeOperationBudget.start()).status())
                .isEqualTo(Status.APPLIED);
    }

    @ParameterizedTest
    @EnumSource(value = Operation.class, names = {"CLAIM", "PENDING", "HEARTBEAT"})
    void finalDatabaseCutoffRejectsAndRollsBackEveryEarlierCteWrite(Operation operation) throws Exception {
        Prepared prepared = prepare(operation);
        var entered = new CountDownLatch(1);
        var release = new CountDownLatch(1);
        var affected = new AtomicReference<Object>();
        var cutoff = new AtomicReference<Instant>();
        var bounded = new AtomicBoolean();
        var selected = proxy(invocation -> {
            String method = invocation.getMethod().getName();
            if (!method.equals(prepared.query()) && !method.equals(prepared.query() + "Before")) {
                return invocation.proceed();
            }
            bounded.set(method.endsWith("Before"));
            if (bounded.get()) {
                cutoff.set((Instant) invocation.getArguments()[invocation.getArguments().length - 1]);
            }
            entered.countDown();
            assertThat(release.await(8, TimeUnit.SECONDS)).isTrue();
            Object result = invocation.proceed();
            affected.set(result);
            return result;
        });
        var runtime = replica(selected, transactionManager);
        var budget = AiRuntimeOperationBudget.start(Duration.ofSeconds(2));
        var executor = Executors.newSingleThreadExecutor();
        try (Connection observer = dataSource.getConnection()) {
            observer.setAutoCommit(true);
            String before = fingerprint(observer);
            var future = executor.submit(() -> capture(() -> prepared.action().apply(runtime, budget)));
            assertThat(entered.await(5, TimeUnit.SECONDS)).isTrue();
            awaitExpired(budget);
            assertThatThrownBy(budget::remaining)
                    .isInstanceOfSatisfying(AiRuntimeOperationBudget.Unavailable.class,
                            expired -> assertThat(expired.interrupted()).isFalse());
            if (cutoff.get() != null) {
                awaitDatabaseDeadline(observer, cutoff.get());
            }
            release.countDown();
            Outcome result = future.get(6, TimeUnit.SECONDS);
            boolean unchanged = before.equals(fingerprint(observer));
            System.out
                    .println("BUDGET_SQL_GATE operation=" + operation.name() + " affectedZero="
                            + Integer.valueOf(0).equals(affected.get()) + " unchanged=" + unchanged + " boundedVariant="
                            + bounded.get());
            assertThat(affected.get()).isEqualTo(0);
            assertThat(unchanged).isTrue();
            assertThat(bounded.get()).isTrue();
            assertThat(cutoff.get()).isNotNull();
            assertThat(result.failure()).isInstanceOf(AiRuntimeOperationBudget.Unavailable.class);
            assertThat(result.value()).isNull();
        } finally {
            release.countDown();
            executor.shutdownNow();
            assertThat(executor.awaitTermination(6, TimeUnit.SECONDS)).isTrue();
        }
    }

    @ParameterizedTest
    @EnumSource(value = Operation.class, names = {"BOOTSTRAP_REPLAY", "HEARTBEAT_REPLAY"})
    void expiredReplayCannotReturnClaimOrExtendAnyDurableState(Operation operation) throws Exception {
        Prepared prepared = prepare(operation);
        var entered = new CountDownLatch(1);
        var release = new CountDownLatch(1);
        var allowed = new AtomicReference<Object>();
        var bounded = new AtomicBoolean();
        var diagnosticAuthority = new AtomicReference<Object>();
        var unbudgetedDiagnosticReads = new AtomicInteger();
        var selected = proxy(invocation -> {
            String method = invocation.getMethod().getName();
            if (!method.equals("admissionCurrent") && !method.equals("admissionCurrentBefore")) {
                return invocation.proceed();
            }
            if (method.equals("admissionCurrent") && bounded.get()) {
                unbudgetedDiagnosticReads.incrementAndGet();
                Object current = invocation.proceed();
                diagnosticAuthority.set(current);
                return current;
            }
            bounded.set(method.endsWith("Before"));
            entered.countDown();
            assertThat(release.await(8, TimeUnit.SECONDS)).isTrue();
            Object result = invocation.proceed();
            allowed.set(result);
            return result;
        });
        var runtime = replica(selected, transactionManager);
        var budget = AiRuntimeOperationBudget.start(Duration.ofSeconds(2));
        var executor = Executors.newSingleThreadExecutor();
        try (Connection observer = dataSource.getConnection()) {
            observer.setAutoCommit(true);
            String before = fingerprint(observer);
            var future = executor.submit(() -> capture(() -> prepared.action().apply(runtime, budget)));
            assertThat(entered.await(5, TimeUnit.SECONDS)).isTrue();
            awaitExpired(budget);
            assertThatThrownBy(budget::remaining)
                    .isInstanceOfSatisfying(AiRuntimeOperationBudget.Unavailable.class,
                            expired -> assertThat(expired.interrupted()).isFalse());
            assertThat(leaseStillLive(observer)).isTrue();
            release.countDown();
            Outcome result = future.get(6, TimeUnit.SECONDS);
            assertThat(allowed.get()).isEqualTo(false);
            assertThat(bounded.get()).isTrue();
            assertThat(unbudgetedDiagnosticReads.get()).isZero();
            assertThat(diagnosticAuthority.get()).isNull();
            assertThat(result.failure()).isInstanceOf(AiRuntimeOperationBudget.Unavailable.class);
            assertThat(fingerprint(observer)).isEqualTo(before);
        } finally {
            release.countDown();
            executor.shutdownNow();
            assertThat(executor.awaitTermination(6, TimeUnit.SECONDS)).isTrue();
        }
    }

    @Test
    void slowActualDatabaseTimeResponseDoesNotResetBudgetBeforeMutation() throws Exception {
        register(true);
        var entered = new CountDownLatch(1);
        var release = new CountDownLatch(1);
        var mutationCalls = new AtomicInteger();
        var selected = proxy(invocation -> {
            String method = invocation.getMethod().getName();
            if (method.equals("claim") || method.equals("claimBefore")) {
                mutationCalls.incrementAndGet();
            }
            Object actual = invocation.proceed();
            if (method.equals("decisionTime")) {
                assertThat(actual).isInstanceOf(Instant.class);
                entered.countDown();
                assertThat(release.await(8, TimeUnit.SECONDS)).isTrue();
            }
            return actual;
        });
        var runtime = replica(selected, transactionManager);
        var budget = AiRuntimeOperationBudget.start(Duration.ofSeconds(2));
        var pinned = expected(current());
        var executor = Executors.newSingleThreadExecutor();
        try (Connection observer = dataSource.getConnection()) {
            observer.setAutoCommit(true);
            String before = fingerprint(observer);
            var future = executor.submit(() -> capture(() -> runtime.bootstrap(pinned, WORKLOAD, budget)));
            assertThat(entered.await(5, TimeUnit.SECONDS)).isTrue();
            awaitExpired(budget);
            release.countDown();
            Outcome result = future.get(6, TimeUnit.SECONDS);
            assertThat(result.failure()).isInstanceOf(AiRuntimeOperationBudget.Unavailable.class);
            assertThat(mutationCalls.get()).isZero();
            assertThat(fingerprint(observer)).isEqualTo(before);
        } finally {
            release.countDown();
            executor.shutdownNow();
            assertThat(executor.awaitTermination(6, TimeUnit.SECONDS)).isTrue();
        }
    }

    @Test
    void actualCommitThenTransactionFailureIsUnknownWithIndependentDurabilityProof() throws Exception {
        register(true);
        var committed = new AtomicBoolean();
        var writerPid = new AtomicInteger();
        var selected = proxy(invocation -> {
            if (invocation.getMethod().getName().equals("claim")
                    || invocation.getMethod().getName().equals("claimBefore")) {
                assertThat(TransactionSynchronizationManager.isActualTransactionActive()).isTrue();
                writerPid
                        .set(((Number) entityManager.createNativeQuery("SELECT pg_backend_pid()").getSingleResult())
                                .intValue());
            }
            return invocation.proceed();
        });
        PlatformTransactionManager failAfterRealCommit = new PlatformTransactionManager() {
            @Override
            public TransactionStatus getTransaction(TransactionDefinition definition) {
                return transactionManager.getTransaction(definition);
            }

            @Override
            public void rollback(TransactionStatus status) {
                transactionManager.rollback(status);
            }

            @Override
            public void commit(TransactionStatus status) {
                assertThat(status.isNewTransaction()).isTrue();
                boolean actualClaimTransaction = writerPid.get() > 0;
                transactionManager.commit(status);
                if (actualClaimTransaction) {
                    committed.set(true);
                    throw new TransactionSystemException("synthetic-private-commit-outcome");
                }
            }
        };
        var runtime = replica(selected, failAfterRealCommit);
        var auth = mock(PlatformAuthenticationClient.class);
        when(auth.authenticateByUserUuidAuthoritatively(eq(created.spec().actorId()), any()))
                .thenReturn(new AuthenticationInfo(AuthMethod.USER_PROXY, created.spec().actorId().toString(),
                        "synthetic", List.of(), "{}"));
        var service = new AiRuntimeRunnerServiceImpl(runtime, auth, new AiFeatureGate(true));
        var codec = new ProtocolCodec();
        try (Connection observer = dataSource.getConnection(); var peer = mockStatic(RuntimeProxyTransport.class)) {
            observer.setAutoCommit(true);
            assertThat(observer.getAutoCommit()).isTrue();
            int observerPid = backend(observer);
            peer
                    .when(RuntimeProxyTransport::currentPeer)
                    .thenReturn(Optional
                            .of(new RuntimeProxyCertificateClaims("cluster-one", "ai-proof", "runner", "runner-" + POD,
                                    POD)));
            var response = service
                    .bootstrap(new ByteArrayInputStream(codec
                            .writeBootstrapRequest(new BootstrapRequest(1, created.spec().runId(),
                                    created.attempt().spec().attemptId(), POD))));
            assertThat(committed.get()).isTrue();
            assertThat(writerPid.get()).isPositive().isNotEqualTo(observerPid);
            try (var statement = observer.prepareStatement("""
                    SELECT r.state = 'RUNNING' AND a.claim_uuid IS NOT NULL AND w.bootstrap_consumed_at IS NOT NULL
                    FROM core.ai_runtime_run r JOIN core.ai_runtime_attempt a ON a.uuid = r.current_attempt_uuid
                    JOIN core.ai_runtime_workload w ON w.attempt_uuid = a.uuid
                    WHERE r.uuid = ?
                    """)) {
                statement.setObject(1, created.spec().runId());
                try (var rows = statement.executeQuery()) {
                    assertThat(rows.next()).isTrue();
                    assertThat(rows.getBoolean(1)).isTrue();
                }
            }
            assertThat(repository.outstandingWorkloads(created.spec().runId())).isEqualTo(1);
            System.out.println("BUDGET_POSTCOMMIT_CONTROL distinctPhysicalSessions=true durableClaim=true");
            assertThat(codec.readRuntimeError(response.getBody()).code()).isEqualTo(RuntimeErrorCode.UNKNOWN_OUTCOME);
            assertThat(new String(response.getBody(), StandardCharsets.UTF_8))
                    .doesNotContain("synthetic-private-commit-outcome", created.spec().actorId().toString());
            verify(auth).authenticateByUserUuidAuthoritatively(eq(created.spec().actorId()), any());
        }
    }

    @ParameterizedTest
    @EnumSource(AuthorityExpiry.class)
    void freshBudgetRealAuthorityExpiryRemainsExpired(AuthorityExpiry expiryKind) throws Exception {
        Prepared prepared = prepare(
                expiryKind == AuthorityExpiry.LEASE ? Operation.HEARTBEAT_REPLAY : Operation.BOOTSTRAP_REPLAY);
        var entered = new CountDownLatch(1);
        var release = new CountDownLatch(1);
        var boundedAllowed = new AtomicReference<Object>();
        var cutoff = new AtomicReference<Instant>();
        var authorityRechecks = new AtomicInteger();
        var selected = proxy(invocation -> {
            String method = invocation.getMethod().getName();
            if (method.equals("admissionCurrentBefore")) {
                cutoff.set((Instant) invocation.getArguments()[1]);
                entered.countDown();
                assertThat(release.await(8, TimeUnit.SECONDS)).isTrue();
                Object allowed = invocation.proceed();
                boundedAllowed.set(allowed);
                return allowed;
            }
            if (method.equals("admissionCurrent")) {
                authorityRechecks.incrementAndGet();
            }
            return invocation.proceed();
        });
        var runtime = replica(selected, transactionManager);
        var executor = Executors.newSingleThreadExecutor();
        try (Connection observer = dataSource.getConnection()) {
            observer.setAutoCommit(true);
            Instant authorityDeadline = shortenAuthority(observer, expiryKind);
            String before = fingerprint(observer);
            var budget = AiRuntimeOperationBudget.start();
            var future = executor.submit(() -> capture(() -> prepared.action().apply(runtime, budget)));
            assertThat(entered.await(5, TimeUnit.SECONDS)).isTrue();
            assertThat(cutoff.get()).isAfter(authorityDeadline);
            awaitDatabaseDeadline(observer, authorityDeadline);
            assertThat(budget.remaining()).isGreaterThan(Duration.ofSeconds(1));
            release.countDown();
            Outcome result = future.get(6, TimeUnit.SECONDS);
            assertThat(boundedAllowed.get()).isEqualTo(false);
            assertThat(result.failure()).isNull();
            assertThat(((Transition<?>) result.value()).status()).isEqualTo(Status.EXPIRED);
            assertThat(authorityRechecks.get()).isEqualTo(1);
            assertThat(fingerprint(observer)).isEqualTo(before);
            System.out
                    .println("BUDGET_REAL_AUTHORITY_EXPIRY kind=" + expiryKind.name()
                            + " freshBudget=true resultExpired=true unchanged=true");
        } finally {
            release.countDown();
            executor.shutdownNow();
            assertThat(executor.awaitTermination(6, TimeUnit.SECONDS)).isTrue();
        }
    }

    @ParameterizedTest
    @EnumSource(value = Operation.class, names = {"CLAIM", "PENDING", "HEARTBEAT"})
    void retainsConflictAfterFinalSqlZero_whenTheOriginalBudgetIsStillFresh(Operation operation) throws Exception {
        // given
        Prepared prepared = prepare(operation);
        var affected = new AtomicReference<Object>();
        var reached = new AtomicBoolean();
        var selected = proxy(invocation -> {
            if (!invocation.getMethod().getName().equals(prepared.query() + "Before")) {
                return invocation.proceed();
            }
            assertThat(entityManager
                    .createNativeQuery("UPDATE core.ai_runtime_run SET revision=revision+1 WHERE uuid=:run")
                    .setParameter("run", created.spec().runId())
                    .executeUpdate()).isEqualTo(1);
            reached.set(true);
            Object actual = invocation.proceed();
            affected.set(actual);
            return actual;
        });
        AiRuntimeKernel runtime = replica(selected, transactionManager);
        var budget = AiRuntimeOperationBudget.start();
        String before;
        try (Connection observer = dataSource.getConnection()) {
            before = fingerprint(observer);

            // when
            Object result = prepared.action().apply(runtime, budget);

            // then
            assertThat(reached.get()).isTrue();
            assertThat(affected.get()).isEqualTo(0);
            assertThat(budget.remaining()).isGreaterThan(Duration.ofSeconds(1));
            assertThat(((Transition<?>) result).status()).isEqualTo(Status.CONFLICT);
            assertThat(fingerprint(observer)).isEqualTo(before);
        }
    }

    private Instant shortenAuthority(Connection observer, AuthorityExpiry kind) throws Exception {
        String sql = kind == AuthorityExpiry.LEASE ? """
                WITH deadline AS MATERIALIZED (SELECT clock_timestamp() + interval '2 seconds' AS at)
                UPDATE core.ai_runtime_attempt a
                SET lease_until = deadline.at, last_heartbeat_lease = deadline.at
                FROM deadline WHERE a.uuid = ? RETURNING a.lease_until
                """ : """
                UPDATE core.ai_runtime_workload
                SET observation_valid_until = clock_timestamp() + interval '2 seconds'
                WHERE attempt_uuid = ? AND cluster = ? AND pod_uid = ? RETURNING observation_valid_until
                """;
        try (var statement = observer.prepareStatement(sql)) {
            statement.setObject(1, created.attempt().spec().attemptId());
            if (kind == AuthorityExpiry.OBSERVATION) {
                statement.setString(2, WORKLOAD.cluster());
                statement.setString(3, WORKLOAD.podUid());
            }
            try (var rows = statement.executeQuery()) {
                assertThat(rows.next()).isTrue();
                return rows.getTimestamp(1).toInstant();
            }
        }
    }

    private Prepared prepare(Operation operation) {
        register(operation != Operation.PENDING);
        Claim claim = null;
        if (operation == Operation.HEARTBEAT || operation == Operation.BOOTSTRAP_REPLAY
                || operation == Operation.HEARTBEAT_REPLAY) {
            claim = kernel.bootstrap(expected(current()), WORKLOAD).value().orElseThrow();
        }
        if (operation == Operation.HEARTBEAT_REPLAY) {
            claim = kernel.heartbeat(claim.binding(), 1).value().orElseThrow();
        }
        Claim stored = claim;
        var pinned = expected(current());
        return switch (operation) {
            case CLAIM -> new Prepared("claim", (runtime, budget) -> runtime.bootstrap(pinned, WORKLOAD, budget));
            case PENDING -> new Prepared("pending", (runtime, budget) -> runtime.bootstrap(pinned, WORKLOAD, budget));
            case HEARTBEAT, HEARTBEAT_REPLAY ->
                new Prepared("heartbeat", (runtime, budget) -> runtime.heartbeat(stored.binding(), 1, budget));
            case BOOTSTRAP_REPLAY ->
                new Prepared("admissionCurrent", (runtime, budget) -> runtime.bootstrap(pinned, WORKLOAD, budget));
        };
    }

    private void register(boolean registered) {
        assertThat(kernel.observe(observation(current(), WORKLOAD, 1, registered)).status()).isEqualTo(Status.APPLIED);
    }

    private RunSnapshot current() {
        return kernel.snapshot(created.spec().runId()).orElseThrow();
    }

    private AiRuntimeRepository proxy(MethodInterceptor interceptor) {
        var factory = new ProxyFactory(repository);
        factory.addAdvice(interceptor);
        return (AiRuntimeRepository) factory.getProxy();
    }

    private AiRuntimeKernel replica(AiRuntimeRepository selected, PlatformTransactionManager manager) {
        var interceptor = new TransactionInterceptor(manager, new AnnotationTransactionAttributeSource());
        var factory = new ProxyFactory(new AiRuntimeWriter(selected));
        factory.setProxyTargetClass(true);
        factory.addAdvice(interceptor);
        return new AiRuntimeKernel(selected, (AiRuntimeWriter) factory.getProxy(), new AiFeatureGate(true));
    }

    private static Outcome capture(Supplier<?> action) {
        try {
            return new Outcome(action.get(), null);
        } catch (RuntimeException failure) {
            return new Outcome(null, failure);
        }
    }

    private static void awaitExpired(AiRuntimeOperationBudget budget) {
        org.awaitility.Awaitility
                .await("Owned monotonic budget expiry")
                .pollInSameThread()
                .pollDelay(Duration.ZERO)
                .pollInterval(Duration.ofMillis(5))
                .atMost(Duration.ofSeconds(4))
                .until(() -> {
                    try {
                        budget.remaining();
                        return false;
                    } catch (AiRuntimeOperationBudget.Unavailable expected) {
                        return true;
                    }
                });
    }

    private static void awaitDatabaseDeadline(Connection observer, Instant cutoff) {
        org.awaitility.Awaitility
                .await("Owned database cutoff")
                .pollInSameThread()
                .pollDelay(Duration.ZERO)
                .pollInterval(Duration.ofMillis(5))
                .atMost(Duration.ofSeconds(3))
                .until(() -> {
                    try (var statement = observer.createStatement();
                            var rows = statement.executeQuery("SELECT clock_timestamp()")) {
                        assertThat(rows.next()).isTrue();
                        return !rows.getTimestamp(1).toInstant().isBefore(cutoff);
                    }
                });
    }

    private static String fingerprint(Connection observer) throws Exception {
        var digest = MessageDigest.getInstance("SHA-256");
        for (String table : List
                .of("ai_runtime_run", "ai_runtime_attempt", "ai_runtime_launch", "ai_runtime_workload",
                        "ai_runtime_control")) {
            digest.update(table.getBytes(StandardCharsets.UTF_8));
            try (var statement = observer.createStatement();
                    var rows = statement
                            .executeQuery(
                                    "SELECT row_to_json(recorded)::text FROM core." + table + " recorded ORDER BY 1")) {
                while (rows.next()) {
                    digest.update(rows.getString(1).getBytes(StandardCharsets.UTF_8));
                    digest.update((byte) '\n');
                }
            }
        }
        return HexFormat.of().formatHex(digest.digest());
    }

    private boolean leaseStillLive(Connection observer) throws Exception {
        try (var statement = observer.prepareStatement("""
                SELECT a.lease_until > clock_timestamp()
                FROM core.ai_runtime_run r JOIN core.ai_runtime_attempt a ON a.uuid = r.current_attempt_uuid
                WHERE r.uuid = ?
                """)) {
            statement.setObject(1, created.spec().runId());
            try (var rows = statement.executeQuery()) {
                assertThat(rows.next()).isTrue();
                return rows.getBoolean(1);
            }
        }
    }

    private static int backend(Connection observer) throws Exception {
        try (var statement = observer.createStatement(); var rows = statement.executeQuery("SELECT pg_backend_pid()")) {
            assertThat(rows.next()).isTrue();
            return rows.getInt(1);
        }
    }

    private enum AuthorityExpiry {
        LEASE,
        OBSERVATION
    }

    private enum Operation {
        CLAIM,
        PENDING,
        HEARTBEAT,
        BOOTSTRAP_REPLAY,
        HEARTBEAT_REPLAY
    }

    private record Prepared(String query, BoundedCall action) {
    }

    private record Outcome(Object value, RuntimeException failure) {
    }

    @FunctionalInterface
    private interface BoundedCall {
        Object apply(AiRuntimeKernel kernel, AiRuntimeOperationBudget budget);
    }
}
