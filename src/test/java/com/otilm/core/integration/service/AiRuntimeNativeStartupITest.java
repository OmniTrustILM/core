package com.otilm.core.integration.service;

import com.otilm.core.model.ai.AiRuntimeState.ControlSnapshot;
import com.otilm.core.model.ai.AiRuntimeState.Status;
import com.otilm.core.service.ai.AiRuntimeKernel;
import com.otilm.core.service.ai.AiRuntimeOperationBudget;
import com.otilm.core.service.writer.ai.AiRuntimeNativeStartupWriter;
import com.otilm.core.util.AiRuntimeFixture;
import com.otilm.core.util.ai.BaseAiSpringBootTest;
import java.time.Duration;
import javax.sql.DataSource;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatCode;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/** Actual local control denial only, not native listener, issuer or readiness acceptance. */
class AiRuntimeNativeStartupITest extends BaseAiSpringBootTest {
    @Autowired
    private DataSource source;
    @Autowired
    private AiRuntimeKernel kernel;
    @Autowired
    private AiRuntimeNativeStartupWriter startup;
    @Autowired
    private com.otilm.core.dao.repository.ai.AiRuntimeRepository runtime;
    @Autowired
    private jakarta.persistence.EntityManager entityManager;
    @Autowired
    private org.springframework.transaction.PlatformTransactionManager transactions;
    @Autowired
    private com.otilm.core.service.writer.ai.AiRuntimeManagementGatewayWriter management;
    @Autowired
    private com.otilm.core.dao.repository.ai.AiRuntimeManagementGatewayRepository gateways;
    private ControlSnapshot initial;

    @BeforeEach
    void enabledFixtureControl() throws Exception {
        AiRuntimeFixture.install(source);
        AiRuntimeFixture.enableTestControl(kernel, AiRuntimeFixture.now(source));
        initial = kernel.control().orElseThrow();
        assertThat(initial.enabled()).isTrue();
    }

    @Test
    void disablesRuntime_whenExistingAuthorityIsEnabled() {
        // given
        var budget = AiRuntimeOperationBudget.start();

        var logger = (ch.qos.logback.classic.Logger) org.slf4j.LoggerFactory
                .getLogger(AiRuntimeNativeStartupWriter.class);
        var original = logger.getLevel();
        var logs = new ch.qos.logback.core.read.ListAppender<ch.qos.logback.classic.spi.ILoggingEvent>();
        logs.start();
        logger.addAppender(logs);
        logger.setLevel(ch.qos.logback.classic.Level.DEBUG);
        try {
            // when
            startup.disableAndConfirm(budget);

            // then
            ControlSnapshot after = kernel.control().orElseThrow();
            assertThat(after.enabled()).isFalse();
            assertThat(after.version().generation()).isEqualTo(initial.version().generation() + 1);
            assertThat(after.observation()).isEmpty();
            assertThat(logs.list).hasSize(1).allSatisfy(event -> {
                assertThat(event.getFormattedMessage()).isEqualTo("AI runtime operation=startup-disable status=STAGED");
                assertThat(event.getThrowableProxy()).isNull();
            });
        } finally {
            logger.detachAppender(logs);
            logger.setLevel(original);
            logs.stop();
        }
    }

    @Test
    void confirmsWithoutMutation_whenRuntimeIsAlreadyDisabled() throws Exception {
        // given
        assertThat(kernel.disableControl(initial.version()).status()).isEqualTo(Status.APPLIED);
        String before = fingerprint();
        var budget = AiRuntimeOperationBudget.start();

        // when
        startup.disableAndConfirm(budget);

        // then
        assertThat(runtime.control().orElseThrow().enabled()).isFalse();
        assertThat(fingerprint()).isEqualTo(before);
    }

    @Test
    void confirmsUnconfigured_whenRuntimeRowIsAbsent() throws Exception {
        // given
        execute("DELETE FROM ai_runtime_control");
        String before = fingerprint();
        var budget = AiRuntimeOperationBudget.start();

        // when
        startup.disableAndConfirm(budget);

        // then
        assertThat(kernel.control()).isEmpty();
        assertThat(fingerprint()).isEqualTo(before);
    }

    @Test
    void throwsUnavailable_whenStartupBudgetHasExpired() throws Exception {
        // given
        var budget = AiRuntimeOperationBudget.start(Duration.ofNanos(1));
        org.awaitility.Awaitility
                .await()
                .pollInSameThread()
                .atMost(Duration.ofSeconds(1))
                .untilAsserted(() -> assertThatThrownBy(budget::remaining)
                        .isInstanceOf(AiRuntimeOperationBudget.Unavailable.class));
        String before = fingerprint();

        // when
        org.assertj.core.api.ThrowableAssert.ThrowingCallable confirm = () -> startup.disableAndConfirm(budget);

        // then
        assertThatThrownBy(confirm).isInstanceOf(AiRuntimeOperationBudget.Unavailable.class);
        assertThat(fingerprint()).isEqualTo(before);
    }

    @Test
    void failsWithFixedDiagnostics_whenControlLockFails() throws Exception {
        // given
        String before = fingerprint();
        var selected = runtimeProxy(call -> {
            Object value = call.proceed();
            if (call.getMethod().getName().equals("lockControl")) {
                throw new IllegalStateException("SYNTHETIC_STARTUP_PRIVATE_CANARY");
            }
            return value;
        });
        var writer = writer(selected);
        var budget = AiRuntimeOperationBudget.start();
        var logger = (ch.qos.logback.classic.Logger) org.slf4j.LoggerFactory
                .getLogger(AiRuntimeNativeStartupWriter.class);
        var original = logger.getLevel();
        var logs = new ch.qos.logback.core.read.ListAppender<ch.qos.logback.classic.spi.ILoggingEvent>();
        logs.start();
        logger.addAppender(logs);
        logger.setLevel(ch.qos.logback.classic.Level.DEBUG);
        try {

            // when
            org.assertj.core.api.ThrowableAssert.ThrowingCallable confirm = () -> writer.disableAndConfirm(budget);

            // then
            assertThatThrownBy(confirm)
                    .isInstanceOf(AiRuntimeOperationBudget.Unavailable.class)
                    .hasMessageContaining("Runtime operation unavailable")
                    .hasNoCause();
            assertThat(logs.list).isNotEmpty().allSatisfy(event -> {
                assertThat(event.getFormattedMessage()).isEqualTo("AI runtime operation=startup-disable status=FAILED");
                assertThat(event.getThrowableProxy()).isNull();
            });
        } finally {
            logger.detachAppender(logs);
            logger.setLevel(original);
            logs.stop();
        }
        assertThat(fingerprint()).isEqualTo(before);
        assertThat(kernel.control().orElseThrow().enabled()).isTrue();
    }

    @Test
    void rollsBackRuntimeDenial_whenFinalControlReadFails() throws Exception {
        // given
        String before = fingerprint();
        var reads = new java.util.concurrent.atomic.AtomicInteger();
        var reached = new java.util.concurrent.atomic.AtomicBoolean();
        var selected = runtimeProxy(call -> {
            Object value = call.proceed();
            if (call.getMethod().getName().equals("control") && reads.incrementAndGet() == 2) {
                var observed = (ControlSnapshot) ((java.util.Optional<?>) value).orElseThrow();
                assertThat(observed.enabled()).isFalse();
                assertThat(observed.version().generation()).isEqualTo(initial.version().generation() + 1);
                reached.set(true);
                throw new IllegalStateException("SYNTHETIC_FINAL_READ_CANARY");
            }
            return value;
        });
        var writer = writer(selected);
        var budget = AiRuntimeOperationBudget.start();

        // when
        org.assertj.core.api.ThrowableAssert.ThrowingCallable confirm = () -> writer.disableAndConfirm(budget);

        // then
        assertThatThrownBy(confirm).isInstanceOf(AiRuntimeOperationBudget.Unavailable.class);
        assertThat(reached.get()).isTrue();
        assertThat(reads.get()).isEqualTo(2);
        assertThat(fingerprint()).isEqualTo(before);
        assertThat(kernel.control().orElseThrow().enabled()).isTrue();
    }

    @Test
    void rejectsConfirmation_whenLockedGenerationDiffers() throws Exception {
        // given
        String before = fingerprint();
        var reads = new java.util.concurrent.atomic.AtomicInteger();
        var selected = runtimeProxy(call -> {
            if (call.getMethod().getName().equals("control") && reads.incrementAndGet() == 1) {
                entityManager
                        .createNativeQuery("UPDATE core.ai_runtime_control SET generation=generation+1 WHERE id=1")
                        .executeUpdate();
            }
            return call.proceed();
        });
        var writer = writer(selected);
        var budget = AiRuntimeOperationBudget.start();

        // when
        org.assertj.core.api.ThrowableAssert.ThrowingCallable confirm = () -> writer.disableAndConfirm(budget);

        // then
        assertThatThrownBy(confirm).isInstanceOf(AiRuntimeOperationBudget.Unavailable.class);
        assertThat(reads.get()).isEqualTo(1);
        assertThat(fingerprint()).isEqualTo(before);
    }

    @Test
    void disablesWithoutOverflow_whenRuntimeGenerationIsMaximum() throws Exception {
        // given
        execute("UPDATE ai_runtime_control SET generation=9223372036854775807 WHERE id=1");
        var budget = AiRuntimeOperationBudget.start();

        // when
        startup.disableAndConfirm(budget);

        // then
        ControlSnapshot after = kernel.control().orElseThrow();
        assertThat(after.version().generation()).isEqualTo(Long.MAX_VALUE);
        assertThat(after.enabled()).isFalse();
        assertThat(after.observation()).isEmpty();
    }

    @Test
    void preservesObservation_whenRuntimeIsAlreadyDisabled() throws Exception {
        // given
        var configured = kernel.changeControl(initial.version(), initial.pins().orElseThrow()).value().orElseThrow();
        var now = AiRuntimeFixture.now(source);
        var evidence = new com.otilm.core.model.ai.AiRuntimeState.ReadinessObservation(configured.version(),
                configured.pins().orElseThrow(), 1, java.util.UUID.randomUUID(), now, now.plusSeconds(30));
        assertThat(kernel.observeControl(evidence).status()).isEqualTo(Status.APPLIED);
        String before = fingerprint();
        var budget = AiRuntimeOperationBudget.start();

        // when
        startup.disableAndConfirm(budget);

        // then
        assertThat(runtime.control().orElseThrow().enabled()).isFalse();
        assertThat(kernel.control().orElseThrow().observation()).contains(evidence);
        assertThat(fingerprint()).isEqualTo(before);
    }

    @Test
    void boundsSqlWait_whenOwnedControlRowIsLocked() throws Exception {
        // given
        var pid = new java.util.concurrent.atomic.AtomicInteger();
        var selected = runtimeProxy(call -> {
            Object value = call.proceed();
            if (call.getMethod().getName().equals("configureTransaction")) {
                pid
                        .set(((Number) entityManager.createNativeQuery("SELECT pg_backend_pid()").getSingleResult())
                                .intValue());
            }
            return value;
        });
        var writer = writer(selected);
        String before = fingerprint();
        var executor = java.util.concurrent.Executors.newSingleThreadExecutor();
        try (var holder = source.getConnection(); var observer = source.getConnection()) {
            holder.setAutoCommit(false);
            int holderPid;
            try (var statement = holder.createStatement();
                    var rows = statement.executeQuery("SELECT pg_backend_pid()")) {
                assertThat(rows.next()).isTrue();
                holderPid = rows.getInt(1);
            }
            try (var statement = holder.createStatement();
                    var rows = statement.executeQuery("SELECT id FROM core.ai_runtime_control WHERE id=1 FOR UPDATE")) {
                assertThat(rows.next()).isTrue();
            }

            // when
            java.util.concurrent.Future<Throwable> result = executor
                    .submit(() -> org.assertj.core.api.Assertions
                            .catchThrowable(() -> writer
                                    .disableAndConfirm(AiRuntimeOperationBudget.start(Duration.ofSeconds(2)))));
            org.awaitility.Awaitility
                    .await("Owned startup control waiter")
                    .pollInSameThread()
                    .pollDelay(Duration.ZERO)
                    .pollInterval(Duration.ofMillis(2))
                    .atMost(Duration.ofMillis(1800))
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

            // then
            assertThat(pid.get()).isPositive().isNotEqualTo(holderPid);
            org.awaitility.Awaitility
                    .await("Startup waiter fails before old fixed timeout")
                    .pollInSameThread()
                    .pollDelay(Duration.ZERO)
                    .atMost(Duration.ofMillis(2500))
                    .untilAsserted(() -> assertThat(result.isDone()).isTrue());
            assertThat(result.get(3, java.util.concurrent.TimeUnit.SECONDS))
                    .isInstanceOf(AiRuntimeOperationBudget.Unavailable.class);
            assertThat(fingerprint()).isEqualTo(before);
        } finally {
            executor.shutdownNow();
            assertThat(executor.awaitTermination(3, java.util.concurrent.TimeUnit.SECONDS)).isTrue();
        }
    }

    @Test
    void invalidatesManagementMembership_whenNativeStartupIsConfirmed() throws Exception {
        // given
        var facts = currentManagementFixture();
        assertThat(kernel.disableControl(initial.version()).status()).isEqualTo(Status.APPLIED);
        var jdbc = new org.springframework.jdbc.core.JdbcTemplate(source);
        String disabledRuntime = jdbc
                .queryForObject("SELECT to_jsonb(c)::text FROM core.ai_runtime_control c", String.class);
        assertThat(management.current(facts.peer(), AiRuntimeOperationBudget.start())).isPresent();
        var budget = AiRuntimeOperationBudget.start();

        // when
        startup.disableAndConfirm(budget);

        // then
        assertThat(management.current(facts.peer(), AiRuntimeOperationBudget.start())).isEmpty();
        assertThat(runtime.control().orElseThrow().enabled()).isFalse();
        assertThat(jdbc.queryForObject("SELECT to_jsonb(c)::text FROM core.ai_runtime_control c", String.class))
                .isEqualTo(disabledRuntime);
        assertThat(jdbc.queryForObject("""
                SELECT NOT configured AND image_digest IS NULL AND cluster IS NULL AND namespace_name IS NULL
                    AND namespace_uid IS NULL AND service_account_name IS NULL AND service_account_uid IS NULL
                    AND template_digest IS NULL AND runtime_class IS NULL
                FROM core.ai_management_gateway_deployment WHERE id=1
                """, Boolean.class)).isTrue();
    }

    @Test
    void invalidatesManagementMembership_whenRuntimeControlIsAbsent() throws Exception {
        // given
        var facts = currentManagementFixture();
        execute("DELETE FROM ai_runtime_control");
        var budget = AiRuntimeOperationBudget.start();

        // when
        startup.disableAndConfirm(budget);

        // then
        assertThat(management.current(facts.peer(), AiRuntimeOperationBudget.start())).isEmpty();
        assertThat(kernel.control()).isEmpty();
    }

    @Test
    void requiresExplicitConfiguration_whenStartupInvalidatedManagement() throws Exception {
        // given
        var facts = currentManagementFixture();
        var budget = AiRuntimeOperationBudget.start();

        // when
        startup.disableAndConfirm(budget);

        // then
        var now = AiRuntimeFixture.now(source);
        var fresh = new com.otilm.core.model.ai.AiRuntimeManagementGatewayState.Observation(facts.deployment(),
                facts.peer().subject(), 2, java.util.UUID.randomUUID(), now, now.plusSeconds(10));
        assertThat(management.observe(fresh, AiRuntimeOperationBudget.start()).status()).isEqualTo(Status.DENIED);
        long disabledRevision = management.revision(AiRuntimeOperationBudget.start());
        assertThat(disabledRevision).isEqualTo(facts.deployment().revision() + 1);
        var configured = management
                .configure(disabledRevision, facts.deployment().pins(), AiRuntimeOperationBudget.start())
                .value()
                .orElseThrow();
        now = AiRuntimeFixture.now(source);
        var verified = new com.otilm.core.model.ai.AiRuntimeManagementGatewayState.Observation(configured,
                facts.peer().subject(), 1, java.util.UUID.randomUUID(), now, now.plusSeconds(10));
        assertThat(management.observe(verified, AiRuntimeOperationBudget.start()).status()).isEqualTo(Status.APPLIED);
        assertThat(management.current(facts.peer(), AiRuntimeOperationBudget.start())).isPresent();
    }

    @Test
    void disablesRuntime_whenManagementDeploymentIsAbsent() throws Exception {
        // given
        execute("DELETE FROM ai_management_gateway_deployment");
        var budget = AiRuntimeOperationBudget.start();

        // when
        startup.disableAndConfirm(budget);

        // then
        assertThat(runtime.control().orElseThrow().enabled()).isFalse();
        assertThat(new org.springframework.jdbc.core.JdbcTemplate(source)
                .queryForObject("SELECT count(*) FROM core.ai_management_gateway_deployment", Integer.class)).isZero();
    }

    @Test
    void disablesManagementWithoutOverflow_whenRevisionIsMaximum() throws Exception {
        // given
        var facts = currentManagementFixture();
        execute("UPDATE ai_management_gateway_deployment SET revision=9223372036854775807");
        var budget = AiRuntimeOperationBudget.start();

        // when
        startup.disableAndConfirm(budget);

        // then
        assertThat(management.revision(AiRuntimeOperationBudget.start())).isEqualTo(Long.MAX_VALUE);
        assertThat(management.current(facts.peer(), AiRuntimeOperationBudget.start())).isEmpty();
        var jdbc = new org.springframework.jdbc.core.JdbcTemplate(source);
        assertThat(jdbc.queryForObject("SELECT configured FROM core.ai_management_gateway_deployment", Boolean.class))
                .isFalse();
        assertThat(jdbc.queryForObject("SELECT count(*) FROM core.ai_management_gateway_registration", Integer.class))
                .isZero();
        String after = fingerprint();
        assertThatCode(() -> startup.disableAndConfirm(AiRuntimeOperationBudget.start())).doesNotThrowAnyException();
        assertThat(fingerprint()).isEqualTo(after);
    }

    @Test
    void rollsBackBothAudiences_whenFinalManagementReadFails() throws Exception {
        // given
        var facts = currentManagementFixture();
        String before = fingerprint();
        var reads = new java.util.concurrent.atomic.AtomicInteger();
        var reached = new java.util.concurrent.atomic.AtomicBoolean();
        var selected = managementProxy(call -> {
            Object value = call.proceed();
            if (call.getMethod().getName().equals("configured") && reads.incrementAndGet() == 2) {
                assertThat(value).isEqualTo(java.util.Optional.of(false));
                assertThat(runtime.control().orElseThrow().enabled()).isFalse();
                assertThat(entityManager
                        .createNativeQuery("SELECT count(*) FROM core.ai_management_gateway_registration")
                        .getSingleResult()).isEqualTo(0L);
                reached.set(true);
                throw new IllegalStateException("SYNTHETIC_MANAGEMENT_FINAL_READ_CANARY");
            }
            return value;
        });
        var selectedWriter = writer(runtime, selected);
        var budget = AiRuntimeOperationBudget.start();

        // when
        org.assertj.core.api.ThrowableAssert.ThrowingCallable confirm = () -> selectedWriter.disableAndConfirm(budget);

        // then
        assertThatThrownBy(confirm).isInstanceOf(AiRuntimeOperationBudget.Unavailable.class).hasNoCause();
        assertThat(reached.get()).isTrue();
        assertThat(fingerprint()).isEqualTo(before);
        assertThat(management.current(facts.peer(), AiRuntimeOperationBudget.start())).isPresent();
    }

    @Test
    void rollsBackRuntimeDenial_whenManagementReadFails() throws Exception {
        // given
        currentManagementFixture();
        String before = fingerprint();
        var reached = new java.util.concurrent.atomic.AtomicBoolean();
        var selected = managementProxy(call -> {
            if (call.getMethod().getName().equals("lockDeployment")) {
                assertThat(runtime.control().orElseThrow().enabled()).isFalse();
                reached.set(true);
                throw new IllegalStateException("SYNTHETIC_MANAGEMENT_LOCK_CANARY");
            }
            return call.proceed();
        });
        var selectedWriter = writer(runtime, selected);
        var budget = AiRuntimeOperationBudget.start();

        // when
        org.assertj.core.api.ThrowableAssert.ThrowingCallable confirm = () -> selectedWriter.disableAndConfirm(budget);

        // then
        assertThatThrownBy(confirm).isInstanceOf(AiRuntimeOperationBudget.Unavailable.class).hasNoCause();
        assertThat(reached.get()).isTrue();
        assertThat(fingerprint()).isEqualTo(before);
    }

    @Test
    void boundsBothAudienceDenial_whenOwnedManagementRowIsLocked() throws Exception {
        // given
        currentManagementFixture();
        var pid = new java.util.concurrent.atomic.AtomicInteger();
        var reached = new java.util.concurrent.atomic.AtomicBoolean();
        var selectedRuntime = runtimeProxy(call -> {
            Object value = call.proceed();
            if (call.getMethod().getName().equals("configureTransaction")) {
                pid
                        .set(((Number) entityManager.createNativeQuery("SELECT pg_backend_pid()").getSingleResult())
                                .intValue());
            }
            return value;
        });
        var selectedManagement = managementProxy(call -> {
            if (call.getMethod().getName().equals("lockDeployment")) {
                assertThat(runtime.control().orElseThrow().enabled()).isFalse();
                reached.set(true);
            }
            return call.proceed();
        });
        var selectedWriter = writer(selectedRuntime, selectedManagement);
        String before = fingerprint();
        var executor = java.util.concurrent.Executors.newSingleThreadExecutor();
        try (var holder = source.getConnection(); var observer = source.getConnection()) {
            holder.setAutoCommit(false);
            int holderPid;
            try (var statement = holder.createStatement();
                    var rows = statement.executeQuery("SELECT pg_backend_pid()")) {
                assertThat(rows.next()).isTrue();
                holderPid = rows.getInt(1);
            }
            try (var statement = holder.createStatement();
                    var rows = statement
                            .executeQuery(
                                    "SELECT id FROM core.ai_management_gateway_deployment WHERE id=1 FOR UPDATE")) {
                assertThat(rows.next()).isTrue();
            }

            // when
            java.util.concurrent.Future<Throwable> result = executor
                    .submit(() -> org.assertj.core.api.Assertions
                            .catchThrowable(() -> selectedWriter
                                    .disableAndConfirm(AiRuntimeOperationBudget.start(Duration.ofSeconds(2)))));
            org.awaitility.Awaitility
                    .await("Owned management startup waiter")
                    .pollInSameThread()
                    .pollDelay(Duration.ZERO)
                    .pollInterval(Duration.ofMillis(2))
                    .atMost(Duration.ofMillis(1800))
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

            // then
            assertThat(reached.get()).isTrue();
            assertThat(pid.get()).isPositive().isNotEqualTo(holderPid);
            org.awaitility.Awaitility
                    .await("Management waiter rolls back both audiences")
                    .pollInSameThread()
                    .pollDelay(Duration.ZERO)
                    .atMost(Duration.ofMillis(2500))
                    .untilAsserted(() -> assertThat(result.isDone()).isTrue());
            assertThat(result.get(3, java.util.concurrent.TimeUnit.SECONDS))
                    .isInstanceOf(AiRuntimeOperationBudget.Unavailable.class);
            assertThat(fingerprint()).isEqualTo(before);
        } finally {
            executor.shutdownNow();
            assertThat(executor.awaitTermination(3, java.util.concurrent.TimeUnit.SECONDS)).isTrue();
        }
    }

    // ── Helpers ───────────────────────────────────────────────────────────────

    private com.otilm.core.dao.repository.ai.AiRuntimeRepository runtimeProxy(
            org.aopalliance.intercept.MethodInterceptor advice) {
        var factory = new org.springframework.aop.framework.ProxyFactory(runtime);
        factory.addAdvice(advice);
        return (com.otilm.core.dao.repository.ai.AiRuntimeRepository) factory.getProxy();
    }

    private AiRuntimeNativeStartupWriter writer(com.otilm.core.dao.repository.ai.AiRuntimeRepository selected) {
        return writer(selected, gateways);
    }

    private AiRuntimeNativeStartupWriter writer(com.otilm.core.dao.repository.ai.AiRuntimeRepository selected,
            com.otilm.core.dao.repository.ai.AiRuntimeManagementGatewayRepository selectedGateways) {
        var factory = new org.springframework.aop.framework.ProxyFactory(
                new AiRuntimeNativeStartupWriter(selected, selectedGateways));
        factory.setProxyTargetClass(true);
        factory
                .addAdvice(new org.springframework.transaction.interceptor.TransactionInterceptor(transactions,
                        new org.springframework.transaction.annotation.AnnotationTransactionAttributeSource()));
        return (AiRuntimeNativeStartupWriter) factory.getProxy();
    }

    private com.otilm.core.dao.repository.ai.AiRuntimeManagementGatewayRepository managementProxy(
            org.aopalliance.intercept.MethodInterceptor advice) {
        var factory = new org.springframework.aop.framework.ProxyFactory(gateways);
        factory.addAdvice(advice);
        return (com.otilm.core.dao.repository.ai.AiRuntimeManagementGatewayRepository) factory.getProxy();
    }

    private ManagementFacts currentManagementFixture() throws Exception {
        var now = AiRuntimeFixture.now(source);
        var pins = new com.otilm.core.model.ai.AiRuntimeManagementGatewayState.Pins(AiRuntimeFixture.IMAGE,
                AiRuntimeFixture.attempt(now).launch());
        var deployment = management.configure(0, pins, AiRuntimeOperationBudget.start()).value().orElseThrow();
        var launch = pins.launch();
        var peer = new com.otilm.core.security.ai.RuntimePeer(
                com.otilm.core.security.ai.RuntimePeerRole.GATEWAY_MANAGEMENT,
                new com.otilm.core.security.ai.RuntimeProxyCertificateClaims(launch.cluster(), launch.namespaceName(),
                        launch.serviceAccountName(), "management-pod", java.util.UUID.randomUUID()));
        now = AiRuntimeFixture.now(source);
        var evidence = new com.otilm.core.model.ai.AiRuntimeManagementGatewayState.Observation(deployment,
                peer.subject(), 1, java.util.UUID.randomUUID(), now, now.plusSeconds(10));
        assertThat(management.observe(evidence, AiRuntimeOperationBudget.start()).status()).isEqualTo(Status.APPLIED);
        assertThat(management.current(peer, AiRuntimeOperationBudget.start())).isPresent();
        return new ManagementFacts(deployment, peer);
    }

    private record ManagementFacts(com.otilm.core.model.ai.AiRuntimeManagementGatewayState.Deployment deployment,
            com.otilm.core.security.ai.RuntimePeer peer) {
    }

    private void execute(String sql) throws Exception {
        try (var c = source.getConnection(); var statement = c.createStatement()) {
            statement.execute(sql);
        }
    }

    private String fingerprint() throws Exception {
        try (var c = source.getConnection(); var statement = c.createStatement(); var rows = statement.executeQuery("""
                SELECT encode(sha256(convert_to(COALESCE(
                    (SELECT jsonb_agg(to_jsonb(c) ORDER BY id) FROM ai_runtime_control c),'null'::jsonb
                )::text || COALESCE((SELECT jsonb_agg(to_jsonb(d) ORDER BY id)
                    FROM ai_management_gateway_deployment d),'null'::jsonb)::text
                || COALESCE((SELECT jsonb_agg(to_jsonb(w) ORDER BY pod_uid)
                    FROM ai_management_gateway_registration w),'null'::jsonb)::text,'UTF8')),'hex')
                """)) {
            assertThat(rows.next()).isTrue();
            return rows.getString(1);
        }
    }
}
