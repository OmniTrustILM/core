package com.otilm.core.integration.service;

import com.otilm.ai.runtime.protocol.ManagementAction;
import com.otilm.core.dao.repository.ai.AiModelDispatchRepository;
import com.otilm.core.dao.repository.ai.AiModelManagementSessionRepository;
import com.otilm.core.dao.repository.ai.AiRuntimeRepository;
import com.otilm.core.model.ai.AiModelDispatchState.ConnectionVersion;
import com.otilm.core.model.ai.AiModelDispatchState.ManagementPreparation;
import com.otilm.core.model.ai.AiModelManagementSession.Spec;
import com.otilm.core.model.ai.AiRuntimeState.Status;
import com.otilm.core.service.ai.AiFeatureGate;
import com.otilm.core.service.ai.AiRuntimeOperationBudget;
import com.otilm.core.service.writer.ai.AiModelDispatchWriter;
import com.otilm.core.service.writer.ai.AiModelManagementSessionWriter;
import com.otilm.core.util.AiModelDispatchFixture;
import com.otilm.core.util.AiRuntimeFixture;
import com.otilm.core.util.ai.BaseAiSpringBootTest;
import jakarta.persistence.EntityManager;
import java.nio.charset.StandardCharsets;
import java.sql.Connection;
import java.sql.SQLException;
import java.time.Duration;
import java.util.UUID;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;
import javax.sql.DataSource;
import org.aopalliance.intercept.MethodInterceptor;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.springframework.aop.framework.ProxyFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.core.io.ClassPathResource;
import org.springframework.transaction.PlatformTransactionManager;
import org.springframework.transaction.annotation.AnnotationTransactionAttributeSource;
import org.springframework.transaction.interceptor.TransactionInterceptor;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.catchThrowable;

/** Real finite storage facts only; actor/session construction is not Auth/CONNECT/native authority. */
class AiModelManagementSessionITest extends BaseAiSpringBootTest {
    @Autowired
    private DataSource source;
    @Autowired
    private AiModelManagementSessionWriter writer;
    @Autowired
    private AiModelDispatchWriter dispatch;
    @Autowired
    private AiRuntimeRepository runtime;
    @Autowired
    private AiModelDispatchRepository models;
    @Autowired
    private AiModelManagementSessionRepository sessions;
    @Autowired
    private EntityManager entityManager;
    @Autowired
    private PlatformTransactionManager transactions;
    private ConnectionVersion model;
    private Spec spec;

    @BeforeEach
    void schemaWithoutAnyRunOrActivationRecords() throws Exception {
        AiModelDispatchFixture.drop(source);
        AiRuntimeFixture.install(source);
        AiModelDispatchFixture.install(source);
        execute("DROP FUNCTION IF EXISTS ai_model_management_session_immutable_guard()");
        execute(new String(new ClassPathResource("db/migration/V202611061200__ai_model_management_session.sql")
                .getContentAsByteArray(), StandardCharsets.UTF_8));
        execute("DELETE FROM ai_runtime_control");
        model = AiModelDispatchFixture.approvedModel(source);
        spec = new Spec(UUID.randomUUID(), UUID.randomUUID(), model, ManagementAction.CONNECTION_CHECK,
                AiRuntimeFixture.now(source).plusSeconds(20), 1, 32);
        noRunRecords();
    }

    @Test
    void createsExactFiniteFactsAndReplaysWithoutAnyRuntimeControl() throws Exception {
        var created = writer.create(spec, budget());
        assertThat(created.status()).isEqualTo(Status.APPLIED);
        var facts = created.value().orElseThrow();
        assertThat(facts.sessionId()).isEqualTo(spec.sessionId());
        assertThat(facts.actorId()).isEqualTo(spec.actorId());
        assertThat(facts.connection()).isEqualTo(model);
        assertThat(facts.action()).isEqualTo(spec.action());
        assertThat(facts.expiresAt()).isEqualTo(spec.expiresAt());
        assertThat(facts.maxCalls()).isEqualTo(1);
        assertThat(facts.maxTokens()).isEqualTo(32);
        assertThat(facts.reservedCalls()).isZero();
        assertThat(facts.reservedTokens()).isZero();
        assertThat(writer.metadata(spec.sessionId(), budget())).contains(facts);
        assertThat(writer.create(spec, budget()).status()).isEqualTo(Status.REPLAY);
        assertThat(count("ai_model_management_session")).isEqualTo(1);
        noRunRecords();
    }

    @ParameterizedTest
    @ValueSource(strings = {"actor", "action", "expiry", "calls", "tokens"})
    void existingSessionCannotBeReboundByAnotherSpec(String field) throws Exception {
        assertThat(writer.create(spec, budget()).status()).isEqualTo(Status.APPLIED);
        var changed = new Spec(spec.sessionId(), field.equals("actor") ? UUID.randomUUID() : spec.actorId(), model,
                field.equals("action") ? ManagementAction.CAPABILITY_CHECK : spec.action(),
                field.equals("expiry") ? spec.expiresAt().plusSeconds(1) : spec.expiresAt(),
                field.equals("calls") ? 2 : 1, field.equals("tokens") ? 64 : 32);
        String before = AiModelDispatchFixture.fingerprint(source);
        assertThat(writer.create(changed, budget()).status()).isEqualTo(Status.CONFLICT);
        assertThat(AiModelDispatchFixture.fingerprint(source)).isEqualTo(before);
    }

    @Test
    void unknownAndUnapprovedConnectionsDoNotCreateAnEnabledSession() throws Exception {
        var unknown = new ConnectionVersion(UUID.randomUUID(), 1, 1, 1, "lab");
        var request = new Spec(spec.sessionId(), spec.actorId(), unknown, spec.action(), spec.expiresAt(), 1, 32);
        assertThat(writer.create(request, budget()).status()).isEqualTo(Status.DENIED);
        execute("UPDATE ai_model_connection SET approved_authentication_revision=NULL,approved_revision=NULL,approved_destination_revision=NULL");
        assertThat(writer.create(spec, budget()).status()).isEqualTo(Status.DENIED);
        assertThat(count("ai_model_management_session")).isZero();
    }

    @Test
    void closeIsTerminalAndCannotBeRecreatedOrRefundExistingReservation() throws Exception {
        assertThat(writer.create(spec, budget()).status()).isEqualTo(Status.APPLIED);
        var request = new ManagementPreparation(UUID.randomUUID(), UUID.randomUUID(), spec.actorId(), spec.sessionId(),
                spec.action(), model, AiModelDispatchFixture.payload(16, "fixed-management-check"), 16,
                spec.expiresAt());
        assertThat(dispatch.prepareManagement(request, budget()).status()).isEqualTo(Status.APPLIED);
        assertThat(writer.close(spec.sessionId(), budget()).status()).isEqualTo(Status.APPLIED);
        String closed = AiModelDispatchFixture.fingerprint(source);
        assertThat(writer.close(spec.sessionId(), budget()).status()).isEqualTo(Status.REPLAY);
        assertThat(writer.metadata(spec.sessionId(), budget())).isEmpty();
        assertThat(writer.create(spec, budget()).status()).isEqualTo(Status.DENIED);
        assertThat(AiModelDispatchFixture.fingerprint(source)).isEqualTo(closed);
        try (var c = source.getConnection();
                var s = c.createStatement();
                var rows = s
                        .executeQuery(
                                "SELECT enabled,reserved_calls,reserved_tokens FROM ai_model_management_session")) {
            assertThat(rows.next()).isTrue();
            assertThat(rows.getBoolean(1)).isFalse();
            assertThat(rows.getLong(2)).isEqualTo(1);
            assertThat(rows.getLong(3)).isEqualTo(16);
        }
        noRunRecords();
    }

    @ParameterizedTest
    @ValueSource(strings = {
            "actor",
            "configuration",
            "revision",
            "destination",
            "authentication",
            "action",
            "expiry",
            "caps",
            "enable",
            "delete",
            "truncate",
            "refund"})
    void directDmlCannotRewriteOrResurrectFiniteSession(String change) throws Exception {
        assertThat(writer.create(spec, budget()).status()).isEqualTo(Status.APPLIED);
        if (change.equals("enable")) {
            assertThat(writer.close(spec.sessionId(), budget()).status()).isEqualTo(Status.APPLIED);
        }
        if (change.equals("refund")) {
            var request = new ManagementPreparation(UUID.randomUUID(), UUID.randomUUID(), spec.actorId(),
                    spec.sessionId(), spec.action(), model,
                    AiModelDispatchFixture.payload(16, "fixed-management-check"), 16, spec.expiresAt());
            assertThat(dispatch.prepareManagement(request, budget()).status()).isEqualTo(Status.APPLIED);
        }
        String sql = switch (change) {
            case "actor" -> "UPDATE ai_model_management_session SET actor_uuid='00000000-0000-0000-0000-000000000001'";
            case "configuration" ->
                "UPDATE ai_model_management_session SET connection_uuid='00000000-0000-0000-0000-000000000002'";
            case "revision" -> "UPDATE ai_model_management_session SET configuration_revision=configuration_revision+1";
            case "destination" -> "UPDATE ai_model_management_session SET destination_revision=destination_revision+1";
            case "authentication" ->
                "UPDATE ai_model_management_session SET authentication_revision=authentication_revision+1";
            case "action" -> "UPDATE ai_model_management_session SET action='CAPABILITY_CHECK'";
            case "expiry" -> "UPDATE ai_model_management_session SET expires_at=expires_at+INTERVAL '1 second'";
            case "caps" -> "UPDATE ai_model_management_session SET max_calls=2";
            case "enable" -> "UPDATE ai_model_management_session SET enabled=TRUE";
            case "delete" -> "DELETE FROM ai_model_management_session";
            case "truncate" -> "TRUNCATE ai_model_management_session";
            default -> "UPDATE ai_model_management_session SET reserved_calls=0,reserved_tokens=0";
        };
        if (change.equals("truncate")) {
            execute("DROP TABLE ai_model_management_intent");
        }
        String before = sessionFingerprint();
        Throwable failure = catchThrowable(() -> execute(sql));
        assertThat(sqlState(failure)).isEqualTo("55000");
        assertThat(sessionFingerprint()).isEqualTo(before);
    }

    @Test
    void expiryAndChangedConfigurationCannotBeRefreshedInPlace() throws Exception {
        var now = AiRuntimeFixture.now(source);
        var shortSpec = new Spec(spec.sessionId(), spec.actorId(), model, spec.action(), now.plusMillis(150), 1, 32);
        assertThat(writer.create(shortSpec, budget()).status()).isEqualTo(Status.APPLIED);
        org.awaitility.Awaitility
                .await("Actual finite session expiry")
                .pollInSameThread()
                .pollDelay(Duration.ZERO)
                .pollInterval(Duration.ofMillis(5))
                .atMost(Duration.ofSeconds(1))
                .until(() -> !AiRuntimeFixture.now(source).isBefore(shortSpec.expiresAt()));
        assertThat(writer.metadata(spec.sessionId(), budget())).isEmpty();
        assertThat(writer.create(shortSpec, budget()).status()).isEqualTo(Status.DENIED);
        assertThat(writer.close(spec.sessionId(), budget()).status()).isEqualTo(Status.APPLIED);
        execute("UPDATE ai_model_connection SET revision=revision+1,enabled=FALSE");
        assertThat(writer.create(spec, budget()).status()).isEqualTo(Status.DENIED);
        assertThat(writer.metadata(spec.sessionId(), budget())).isEmpty();
    }

    @Test
    void capabilityCheckKeepsItsExactActionThroughExistingManagementReservationWithoutARun() throws Exception {
        var capability = new Spec(spec.sessionId(), spec.actorId(), model, ManagementAction.CAPABILITY_CHECK,
                spec.expiresAt(), 1, 32);
        var result = writer.create(capability, budget());
        assertThat(result.status()).isEqualTo(Status.APPLIED);
        assertThat(result.value().orElseThrow().action()).isEqualTo(ManagementAction.CAPABILITY_CHECK);
        var request = new ManagementPreparation(UUID.randomUUID(), UUID.randomUUID(), capability.actorId(),
                capability.sessionId(), capability.action(), model,
                AiModelDispatchFixture.payload(16, "fixed-capability-check"), 16, capability.expiresAt());
        assertThat(dispatch.prepareManagement(request, budget()).status()).isEqualTo(Status.APPLIED);
        assertThat(writer.metadata(capability.sessionId(), budget()).orElseThrow().reservedTokens()).isEqualTo(16);
        assertThat(writer.metadata(capability.sessionId(), budget()).orElseThrow().reservedCalls()).isEqualTo(1);
        noRunRecords();
    }

    @Test
    void closedSessionRemainsHousekeepingAccessibleAfterConfigurationDisable() throws Exception {
        assertThat(writer.create(spec, budget()).status()).isEqualTo(Status.APPLIED);
        execute("UPDATE ai_model_connection SET revision=revision+1,enabled=FALSE");
        assertThat(writer.connection(model.id(), budget())).isEmpty();
        assertThat(writer.metadata(spec.sessionId(), budget())).isEmpty();
        assertThat(writer.close(spec.sessionId(), budget()).status()).isEqualTo(Status.APPLIED);
        assertThat(writer.close(spec.sessionId(), budget()).status()).isEqualTo(Status.REPLAY);
        assertThat(writer.create(spec, budget()).status()).isEqualTo(Status.DENIED);
        noRunRecords();
    }

    @Test
    void metadataNeverReturnsPayloadCredentialOriginOrAnEnabledGrant() throws Exception {
        assertThat(writer.create(spec, budget()).status()).isEqualTo(Status.APPLIED);
        var facts = writer.metadata(spec.sessionId(), budget()).orElseThrow();
        assertThat(java.util.Arrays.stream(facts.getClass().getRecordComponents()).map(c -> c.getName()))
                .containsExactly("sessionId", "actorId", "connection", "action", "expiresAt", "maxCalls", "maxTokens",
                        "reservedCalls", "reservedTokens");
        assertThat(facts.toString())
                .doesNotContain(spec.actorId().toString(), "ilm-f04-provider-v1", "https://provider.invalid");
        assertThat(writer.connection(UUID.randomUUID(), budget())).isEmpty();
        assertThat(writer.metadata(UUID.randomUUID(), budget())).isEmpty();
        assertThat(writer.close(UUID.randomUUID(), budget()).status()).isEqualTo(Status.DENIED);
    }

    @Test
    void actualSpringBeginSuspendsAmbientTransactionAndFinalWriterRejectsConfigurationChangedAtAuthorityBoundary()
            throws Exception {
        var authority = org.mockito.Mockito.mock(com.otilm.core.security.ai.AiModelManagementAuthorization.class);
        org.mockito.Mockito.doAnswer(call -> {
            assertThat(org.springframework.transaction.support.TransactionSynchronizationManager
                    .isActualTransactionActive()).isFalse();
            execute("UPDATE ai_model_connection SET revision=revision+1,enabled=FALSE");
            return null;
        })
                .when(authority)
                .requireConnect(org.mockito.ArgumentMatchers.eq(spec.actorId()),
                        org.mockito.ArgumentMatchers.eq(model.id()), org.mockito.ArgumentMatchers.any());
        var factory = new ProxyFactory(new com.otilm.core.service.ai.AiModelManagementSessionService(writer, authority,
                new AiFeatureGate(true)));
        factory.setProxyTargetClass(true);
        factory.addAdvice(new TransactionInterceptor(transactions, new AnnotationTransactionAttributeSource()));
        var service = (com.otilm.core.service.ai.AiModelManagementSessionService) factory.getProxy();
        var request = new com.otilm.core.model.ai.AiModelManagementSession.Request(spec.sessionId(), spec.actorId(),
                model.id(), spec.action(), spec.expiresAt(), spec.maxCalls(), spec.maxTokens());
        var result = new org.springframework.transaction.support.TransactionTemplate(transactions).execute(tx -> {
            assertThat(org.springframework.transaction.support.TransactionSynchronizationManager
                    .isActualTransactionActive()).isTrue();
            var denied = service.begin(request, budget());
            assertThat(org.springframework.transaction.support.TransactionSynchronizationManager
                    .isActualTransactionActive()).isTrue();
            return denied;
        });
        assertThat(result).isNotNull();
        assertThat(result.status()).isEqualTo(Status.DENIED);
        assertThat(count("ai_model_management_session")).isZero();
        noRunRecords();
    }

    @Test
    void actualRemainingBudgetTerminatesDistinctBackendModelLockWithoutAnySessionWrite() throws Exception {
        var pid = new AtomicInteger();
        var runtimeProxy = new ProxyFactory(runtime);
        runtimeProxy.setInterfaces(AiRuntimeRepository.class);
        runtimeProxy.addAdvice((MethodInterceptor) call -> {
            Object result = call.proceed();
            if (call.getMethod().getName().equals("configureTransaction")) {
                pid
                        .set(((Number) entityManager.createNativeQuery("SELECT pg_backend_pid()").getSingleResult())
                                .intValue());
            }
            return result;
        });
        var selected = transactionalWriter((AiRuntimeRepository) runtimeProxy.getProxy());
        String before = AiModelDispatchFixture.fingerprint(source);
        var executor = Executors.newSingleThreadExecutor();
        try (Connection holder = source.getConnection(); Connection observer = source.getConnection()) {
            holder.setAutoCommit(false);
            int holderPid;
            try (var q = holder.createStatement(); var rows = q.executeQuery("SELECT pg_backend_pid()")) {
                assertThat(rows.next()).isTrue();
                holderPid = rows.getInt(1);
            }
            try (var q = holder.prepareStatement("SELECT uuid FROM ai_model_connection WHERE uuid=? FOR UPDATE")) {
                q.setObject(1, model.id());
                try (var rows = q.executeQuery()) {
                    assertThat(rows.next()).isTrue();
                }
            }
            var result = executor.submit(() -> {
                var remaining = AiRuntimeOperationBudget.start(Duration.ofMillis(300));
                return catchThrowable(() -> selected.create(spec, remaining));
            });
            org.awaitility.Awaitility
                    .await("Exact management model-lock waiter")
                    .pollInSameThread()
                    .pollDelay(Duration.ZERO)
                    .pollInterval(Duration.ofMillis(2))
                    .atMost(Duration.ofMillis(250))
                    .until(() -> {
                        if (pid.get() <= 0) {
                            return false;
                        }
                        try (var q = observer.prepareStatement("SELECT ? = ANY(pg_blocking_pids(?))")) {
                            q.setInt(1, holderPid);
                            q.setInt(2, pid.get());
                            try (var rows = q.executeQuery()) {
                                assertThat(rows.next()).isTrue();
                                return rows.getBoolean(1);
                            }
                        }
                    });
            assertThat(pid.get()).isPositive().isNotEqualTo(holderPid);
            org.awaitility.Awaitility
                    .await("Remaining operation timeout ends the held SQL wait")
                    .pollInSameThread()
                    .pollDelay(Duration.ZERO)
                    .atMost(Duration.ofMillis(650))
                    .until(result::isDone);
            assertThat(sqlState(result.get(1, TimeUnit.SECONDS))).isIn("55P03", "57014");
            assertThat(AiModelDispatchFixture.fingerprint(source)).isEqualTo(before);
        } finally {
            executor.shutdownNow();
            assertThat(executor.awaitTermination(3, TimeUnit.SECONDS)).isTrue();
        }
    }

    @ParameterizedTest
    @ValueSource(booleans = {false, true})
    void twoRealReplicaTransactionsCannotOverwriteFirstSessionOwnership(boolean foreignActor) throws Exception {
        var ready = new java.util.concurrent.CountDownLatch(2);
        var pids = java.util.concurrent.ConcurrentHashMap.<Integer>newKeySet();
        var firstCall = ThreadLocal.withInitial(() -> true);
        var selectedRuntime = new ProxyFactory(runtime);
        selectedRuntime.setInterfaces(AiRuntimeRepository.class);
        selectedRuntime.addAdvice((MethodInterceptor) call -> {
            Object value = call.proceed();
            if (call.getMethod().getName().equals("configureTransaction") && Boolean.TRUE.equals(firstCall.get())) {
                firstCall.set(false);
                pids
                        .add(((Number) entityManager.createNativeQuery("SELECT pg_backend_pid()").getSingleResult())
                                .intValue());
                ready.countDown();
                assertThat(ready.await(2, TimeUnit.SECONDS)).isTrue();
            }
            return value;
        });
        var first = transactionalWriter((AiRuntimeRepository) selectedRuntime.getProxy());
        var second = transactionalWriter((AiRuntimeRepository) selectedRuntime.getProxy());
        var other = new Spec(spec.sessionId(), foreignActor ? UUID.randomUUID() : spec.actorId(), model, spec.action(),
                spec.expiresAt(), 1, 32);
        var executor = Executors.newFixedThreadPool(2);
        try {
            var a = executor.submit(() -> first.create(spec, budget()));
            var b = executor.submit(() -> second.create(other, budget()));
            var results = java.util.List.of(a.get(4, TimeUnit.SECONDS), b.get(4, TimeUnit.SECONDS));
            assertThat(pids).hasSize(2);
            assertThat(results)
                    .extracting(value -> value.status())
                    .containsExactlyInAnyOrder(Status.APPLIED, foreignActor ? Status.CONFLICT : Status.REPLAY);
            var winner = results
                    .stream()
                    .filter(value -> value.status() == Status.APPLIED)
                    .findFirst()
                    .orElseThrow()
                    .value()
                    .orElseThrow();
            assertThat(writer.metadata(spec.sessionId(), budget())).contains(winner);
            assertThat(count("ai_model_management_session")).isEqualTo(1);
            noRunRecords();
        } finally {
            executor.shutdownNow();
            assertThat(executor.awaitTermination(3, TimeUnit.SECONDS)).isTrue();
        }
    }

    @Test
    void delayedActualInsertCannotCommitAfterTheOperationBudget() throws Exception {
        execute("CREATE FUNCTION core.management_session_delay() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN PERFORM pg_sleep(1); RETURN NEW; END $$");
        execute("CREATE TRIGGER management_session_delay AFTER INSERT ON ai_model_management_session FOR EACH ROW EXECUTE FUNCTION core.management_session_delay()");
        try {
            String before = AiModelDispatchFixture.fingerprint(source);
            var remaining = AiRuntimeOperationBudget.start(Duration.ofMillis(800));
            Throwable failure = catchThrowable(() -> writer.create(spec, remaining));
            assertThat(sqlState(failure)).isIn("55P03", "57014");
            assertThat(AiModelDispatchFixture.fingerprint(source)).isEqualTo(before);
            assertThat(count("ai_model_management_session")).isZero();
        } finally {
            execute("DROP TRIGGER management_session_delay ON ai_model_management_session");
            execute("DROP FUNCTION core.management_session_delay()");
        }
    }

    private AiModelManagementSessionWriter transactionalWriter(AiRuntimeRepository selected) {
        var factory = new ProxyFactory(new AiModelManagementSessionWriter(selected, models, sessions));
        factory.setProxyTargetClass(true);
        factory.addAdvice(new TransactionInterceptor(transactions, new AnnotationTransactionAttributeSource()));
        return (AiModelManagementSessionWriter) factory.getProxy();
    }

    private String sessionFingerprint() throws Exception {
        try (var c = source.getConnection();
                var q = c.createStatement();
                var rows = q.executeQuery("SELECT row_to_json(s)::text FROM ai_model_management_session s")) {
            assertThat(rows.next()).isTrue();
            return java.util.HexFormat
                    .of()
                    .formatHex(java.security.MessageDigest
                            .getInstance("SHA-256")
                            .digest(rows.getString(1).getBytes(StandardCharsets.UTF_8)));
        }
    }

    private void noRunRecords() throws Exception {
        for (String table : new String[]{
                "ai_runtime_control",
                "ai_runtime_run",
                "ai_runtime_attempt",
                "ai_runtime_launch",
                "ai_runtime_workload"}) {
            assertThat(count(table)).as(table + " must not supply management authority").isZero();
        }
    }

    private long count(String table) throws Exception {
        String sql = switch (table) {
            case "ai_runtime_control" -> "SELECT count(*) FROM ai_runtime_control";
            case "ai_runtime_run" -> "SELECT count(*) FROM ai_runtime_run";
            case "ai_runtime_attempt" -> "SELECT count(*) FROM ai_runtime_attempt";
            case "ai_runtime_launch" -> "SELECT count(*) FROM ai_runtime_launch";
            case "ai_runtime_workload" -> "SELECT count(*) FROM ai_runtime_workload";
            case "ai_model_management_session" -> "SELECT count(*) FROM ai_model_management_session";
            default -> throw new IllegalArgumentException();
        };
        try (var c = source.getConnection(); var s = c.createStatement(); var r = s.executeQuery(sql)) {
            assertThat(r.next()).isTrue();
            return r.getLong(1);
        }
    }

    private void execute(String sql) throws Exception {
        try (var c = source.getConnection(); var s = c.createStatement()) {
            s.execute(sql);
        }
    }

    private static String sqlState(Throwable t) {
        for (Throwable c = t; c != null; c = c.getCause()) {
            if (c instanceof SQLException q) {
                return q.getSQLState();
            }
        }
        return "NO_SQL_STATE";
    }

    private static AiRuntimeOperationBudget budget() {
        return AiRuntimeOperationBudget.start();
    }
}
