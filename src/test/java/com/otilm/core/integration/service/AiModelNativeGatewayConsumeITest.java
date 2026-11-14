package com.otilm.core.integration.service;

import com.otilm.ai.runtime.protocol.RunBinding;
import com.otilm.ai.runtime.protocol.RunDispatchEnvelope;
import com.otilm.core.dao.repository.ai.AiModelDispatchRepository;
import com.otilm.core.dao.repository.ai.AiRuntimeRepository;
import com.otilm.core.model.ai.AiModelDispatchState.ConnectionVersion;
import com.otilm.core.model.ai.AiModelDispatchState.RunPreparation;
import com.otilm.core.model.ai.AiModelDispatchState.RunRedemption;
import com.otilm.core.model.ai.AiModelRunInput;
import com.otilm.core.model.ai.AiRuntimeGatewayState.Deployment;
import com.otilm.core.model.ai.AiRuntimeGatewayState.Observation;
import com.otilm.core.model.ai.AiRuntimeState;
import com.otilm.core.model.ai.AiRuntimeState.Claim;
import com.otilm.core.model.ai.AiRuntimeState.ControlPins;
import com.otilm.core.model.ai.AiRuntimeState.ReadinessObservation;
import com.otilm.core.model.ai.AiRuntimeState.RunSnapshot;
import com.otilm.core.model.ai.AiRuntimeState.Status;
import com.otilm.core.security.ai.AiModelCertificateContext;
import com.otilm.core.security.ai.AiModelUseAuthorization;
import com.otilm.core.security.ai.CertificateReadScope;
import com.otilm.core.security.ai.RuntimePeer;
import com.otilm.core.security.ai.RuntimePeerRole;
import com.otilm.core.security.ai.RuntimeProxyCertificateClaims;
import com.otilm.core.service.ai.AiFeatureGate;
import com.otilm.core.service.ai.AiModelRunDispatchService;
import com.otilm.core.service.ai.AiRuntimeKernel;
import com.otilm.core.service.ai.AiRuntimeOperationBudget;
import com.otilm.core.service.writer.ai.AiModelDispatchWriter;
import com.otilm.core.service.writer.ai.AiModelRunInputWriter;
import com.otilm.core.service.writer.ai.AiModelRunOutcomeWriter;
import com.otilm.core.service.writer.ai.AiRuntimeGatewayRegistrationWriter;
import com.otilm.core.util.AiModelDispatchFixture;
import com.otilm.core.util.AiRuntimeFixture;
import com.otilm.core.util.ai.BaseAiSpringBootTest;
import jakarta.persistence.EntityManager;
import java.nio.charset.StandardCharsets;
import java.sql.Connection;
import java.time.Duration;
import java.time.Instant;
import java.util.List;
import java.util.Set;
import java.util.UUID;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;
import javax.sql.DataSource;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.springframework.aop.framework.ProxyFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.core.io.ClassPathResource;
import org.springframework.transaction.PlatformTransactionManager;
import org.springframework.transaction.TransactionManager;
import org.springframework.transaction.annotation.AnnotationTransactionAttributeSource;
import org.springframework.transaction.interceptor.TransactionInterceptor;
import org.springframework.transaction.support.TransactionSynchronizationManager;

import static com.otilm.core.util.AiRuntimeFixture.expected;
import static com.otilm.core.util.AiRuntimeFixture.observation;
import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.doAnswer;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/** Real final SQL/transactions; mocked business-authority boundaries are NOT maintained Auth or TLS proof. */
class AiModelNativeGatewayConsumeITest extends BaseAiSpringBootTest {
    @Autowired
    private DataSource source;
    @Autowired
    private AiRuntimeKernel kernel;
    @Autowired
    private AiModelDispatchWriter writer;
    @Autowired
    private AiModelDispatchRepository intents;
    @Autowired
    private AiModelRunInputWriter inputs;
    @Autowired
    private AiModelRunOutcomeWriter assignments;
    @Autowired
    private AiRuntimeGatewayRegistrationWriter registrations;
    @Autowired
    private AiRuntimeRepository runtime;
    @Autowired
    private EntityManager entityManager;
    @Autowired
    private PlatformTransactionManager transactions;
    private RuntimePeer selected;
    private RuntimePeer foreign;
    private Deployment deployment;
    private RunSnapshot run;
    private Claim claim;
    private ConnectionVersion model;
    private RunPreparation preparation;

    @BeforeEach
    void realStoredRunInputIntentAndCurrentGatewayFacts() throws Exception {
        AiModelDispatchFixture.drop(source);
        AiRuntimeFixture.install(source);
        AiModelDispatchFixture.install(source);
        install("db/migration/V202611051300__ai_model_run_input.sql");
        install("db/migration/V202611051400__ai_runtime_gateway_registration.sql");
        install("db/migration/V202611051500__ai_model_run_outcome.sql");
        Instant now = AiRuntimeFixture.now(source);
        var attempt = AiRuntimeFixture.attempt(now);
        var pins = ControlPins.forAttempt(attempt);
        var version = kernel
                .changeControl(kernel.control().orElseThrow().version(), pins)
                .value()
                .orElseThrow()
                .version();
        deployment = new Deployment(RuntimePeerRole.GATEWAY_RUN, version.generation(), AiRuntimeFixture.IMAGE,
                new AiRuntimeState.LaunchSpec("cluster-one", "gateways", "gateway-namespace", "gateway",
                        "gateway-account", AiRuntimeFixture.TEMPLATE, "sandbox"));
        selected = new RuntimePeer(RuntimePeerRole.GATEWAY_RUN, new RuntimeProxyCertificateClaims("cluster-one",
                "gateways", "gateway", "selected-gateway", UUID.randomUUID()));
        foreign = new RuntimePeer(RuntimePeerRole.GATEWAY_RUN, new RuntimeProxyCertificateClaims("cluster-one",
                "gateways", "gateway", "foreign-gateway", UUID.randomUUID()));
        assertThat(registrations.configure(deployment, budget())).isTrue();
        for (RuntimePeer peer : new RuntimePeer[]{selected, foreign}) {
            assertThat(registrations
                    .observe(
                            new Observation(deployment, peer.subject(), 1, UUID.randomUUID(), now, now.plusSeconds(25)),
                            budget()))
                    .isTrue();
        }
        assertThat(kernel
                .observeControl(new ReadinessObservation(version, pins, 1, UUID.randomUUID(), now, now.plusSeconds(30)))
                .status()).isEqualTo(Status.APPLIED);
        assertThat(kernel.enableControl(version).status()).isEqualTo(Status.APPLIED);
        run = kernel.create(version, AiRuntimeFixture.run(now), attempt);
        var workload = new AiRuntimeState.WorkloadRef("cluster-one", UUID.randomUUID().toString());
        assertThat(kernel.observe(observation(current(), workload, 1, true)).status()).isEqualTo(Status.APPLIED);
        claim = kernel.bootstrap(expected(current()), workload).value().orElseThrow();
        run = current();
        model = AiModelDispatchFixture.approvedModel(source);
        AiModelDispatchFixture.runBudget(source, run.spec().runId(), model, 3, 128);
        assertThat(inputs
                .store(new AiModelRunInput(run.spec().runId(), UUID.randomUUID(), Set.of(), "fixture instructions",
                        "fixture prompt", 32))
                .status()).isEqualTo(Status.APPLIED);
        preparation = new RunPreparation(UUID.randomUUID(), UUID.randomUUID(), expected(run), claim.binding(), model,
                AiModelDispatchFixture.payload(32, "fixture"), 32, AiRuntimeFixture.now(source).plusSeconds(20));
        assertThat(writer.prepareRun(preparation, run.spec().actorId(), budget()).status()).isEqualTo(Status.APPLIED);
    }

    @Test
    void actualAssignedPeerConsumesExactlyOnceWithItsOwnCorrelation() throws Exception {
        assignSelected();
        var request = redemption();
        var beforeRun = current();
        var dispatch = writer.consumeRun(request, run.spec().actorId(), selected, budget()).orElseThrow();
        assertThat(dispatch.intentId()).isEqualTo(preparation.intentId());
        assertThat(dispatch.gatewayCorrelation()).isEqualTo(request.gatewayCorrelation());
        assertThat(dispatch.payload()).isEqualTo(preparation.payload());
        assertThat(dispatch.outputTokens()).isEqualTo(32);
        assertThat(writer.consumeRun(redemption(), run.spec().actorId(), selected, budget())).isEmpty();
        assertThat(current()).isEqualTo(beforeRun);
        retainedReservation();
    }

    @ParameterizedTest
    @ValueSource(strings = {"unassigned", "foreign", "revoked", "expired", "wrong-role"})
    void finalNativeWriterNeverFallsBackToUnassignedOrStalePeer(String change) throws Exception {
        RuntimePeer actual = selected;
        if (!change.equals("unassigned")) {
            assignSelected();
            assignments.requireAssigned(preparation.intentId(), selected, budget());
        }
        switch (change) {
            case "foreign" -> {
                assertThat(registrations.current(foreign, budget())).isPresent();
                actual = foreign;
            }
            case "revoked" -> assertThat(registrations.revoke(selected, budget())).isTrue();
            case "expired" -> awaitExpiry(shortenRegistration(Duration.ofMillis(150)));
            case "wrong-role" -> actual = new RuntimePeer(RuntimePeerRole.RUNNER_PROXY, selected.subject());
            case "unassigned" -> actual = selected;
            default -> throw new IllegalArgumentException("Unknown native gate fixture");
        }
        String before = AiModelDispatchFixture.fingerprint(source);
        assertThat(writer.consumeRun(redemption(), run.spec().actorId(), actual, budget())).isEmpty();
        assertThat(AiModelDispatchFixture.fingerprint(source)).isEqualTo(before);
        assertThat(AiModelDispatchFixture.consumed(source, preparation.intentId(), false)).isFalse();
        retainedReservation();
    }

    @ParameterizedTest
    @ValueSource(booleans = {true, false})
    void nativeServicePropagatesActualPeerThroughBusinessAuthority(boolean assigned) throws Exception {
        assignSelected();
        var models = mock(AiModelUseAuthorization.class);
        var contexts = mock(AiModelCertificateContext.class);
        when(contexts
                .read(eq(run.spec().actorId()), eq(model.id()), any(CertificateReadScope.class),
                        any(AiRuntimeOperationBudget.class)))
                .thenAnswer(call -> {
                    assertThat(TransactionSynchronizationManager.isActualTransactionActive()).isFalse();
                    return List.of();
                });
        var service = service(models, contexts);
        String before = AiModelDispatchFixture.fingerprint(source);
        var result = service.consume(envelope(), UUID.randomUUID(), assigned ? selected : foreign, budget());
        assertThat(result.isPresent()).isEqualTo(assigned);
        verify(models).requireUse(eq(run.spec().actorId()), eq(model.id()), any(AiRuntimeOperationBudget.class));
        verify(contexts)
                .read(eq(run.spec().actorId()), eq(model.id()), any(CertificateReadScope.class),
                        any(AiRuntimeOperationBudget.class));
        if (!assigned) {
            assertThat(AiModelDispatchFixture.fingerprint(source)).isEqualTo(before);
            assertThat(AiModelDispatchFixture.consumed(source, preparation.intentId(), false)).isFalse();
        }
        retainedReservation();
    }

    @ParameterizedTest
    @ValueSource(strings = {"revoked", "expired"})
    void authorityBoundaryChangeAfterEarlyAssignmentCheckCannotConsume(String change) throws Exception {
        assignSelected();
        assignments.requireAssigned(preparation.intentId(), selected, budget());
        var enteredAuthority = new CountDownLatch(1);
        var returnAuthority = new CountDownLatch(1);
        var models = mock(AiModelUseAuthorization.class);
        var contexts = mock(AiModelCertificateContext.class);
        doAnswer(call -> {
            assertThat(TransactionSynchronizationManager.isActualTransactionActive()).isFalse();
            enteredAuthority.countDown();
            assertThat(returnAuthority.await(2, TimeUnit.SECONDS)).isTrue();
            return null;
        }).when(models).requireUse(eq(run.spec().actorId()), eq(model.id()), any(AiRuntimeOperationBudget.class));
        when(contexts
                .read(eq(run.spec().actorId()), eq(model.id()), any(CertificateReadScope.class),
                        any(AiRuntimeOperationBudget.class)))
                .thenReturn(List.of());
        var service = service(models, contexts);
        var executor = Executors.newSingleThreadExecutor();
        try {
            var result = executor.submit(() -> service.consume(envelope(), UUID.randomUUID(), selected, budget()));
            assertThat(enteredAuthority.await(1, TimeUnit.SECONDS)).isTrue();
            if (change.equals("revoked")) {
                assertThat(registrations.revoke(selected, budget())).isTrue();
            } else {
                awaitExpiry(shortenRegistration(Duration.ofMillis(150)));
            }
            assertThat(registrations.current(selected, budget())).isEmpty();
            String before = AiModelDispatchFixture.fingerprint(source);
            returnAuthority.countDown();
            assertThat(result.get(3, TimeUnit.SECONDS)).isEmpty();
            verify(contexts)
                    .read(eq(run.spec().actorId()), eq(model.id()), any(CertificateReadScope.class),
                            any(AiRuntimeOperationBudget.class));
            assertThat(AiModelDispatchFixture.fingerprint(source)).isEqualTo(before);
            assertThat(AiModelDispatchFixture.consumed(source, preparation.intentId(), false)).isFalse();
            retainedReservation();
        } finally {
            returnAuthority.countDown();
            executor.shutdownNow();
            assertThat(executor.awaitTermination(5, TimeUnit.SECONDS)).isTrue();
        }
    }

    @Test
    void actualControlLockWaitCrossingPeerExpiryStillDeniesAtFinalSql() throws Exception {
        assignSelected();
        var pid = new AtomicInteger();
        var runtimeProxy = new ProxyFactory(runtime);
        runtimeProxy.addAdvice((org.aopalliance.intercept.MethodInterceptor) call -> {
            if (call.getMethod().getName().equals("lockControl")) {
                pid
                        .set(((Number) entityManager.createNativeQuery("SELECT pg_backend_pid()").getSingleResult())
                                .intValue());
            }
            return call.proceed();
        });
        var proxy = new ProxyFactory(new AiModelDispatchWriter((AiRuntimeRepository) runtimeProxy.getProxy(), intents));
        proxy.setProxyTargetClass(true);
        proxy
                .addAdvice(new TransactionInterceptor((TransactionManager) transactions,
                        new AnnotationTransactionAttributeSource()));
        var replica = (AiModelDispatchWriter) proxy.getProxy();
        var request = redemption();
        String before = AiModelDispatchFixture.fingerprint(source);
        var executor = Executors.newSingleThreadExecutor();
        try (var holder = source.getConnection(); var observer = source.getConnection()) {
            holder.setAutoCommit(false);
            int holderPid;
            try (var statement = holder.createStatement();
                    var rows = statement.executeQuery("SELECT pg_backend_pid()")) {
                assertThat(rows.next()).isTrue();
                holderPid = rows.getInt(1);
            }
            Instant expiry = shortenRegistration(Duration.ofMillis(500));
            assertThat(registrations.current(selected, budget())).isPresent();
            try (var statement = holder.createStatement();
                    var rows = statement
                            .executeQuery("SELECT generation FROM ai_runtime_control WHERE id=1 FOR UPDATE")) {
                assertThat(rows.next()).isTrue();
            }
            var result = executor.submit(() -> replica.consumeRun(request, run.spec().actorId(), selected, budget()));
            org.awaitility.Awaitility
                    .await("Exact native writer backend waiting on owned control holder")
                    .pollInSameThread()
                    .pollDelay(Duration.ZERO)
                    .pollInterval(Duration.ofMillis(2))
                    .atMost(Duration.ofMillis(300))
                    .until(() -> pid.get() > 0 && blocked(observer, holderPid, pid.get()));
            assertThat(pid.get()).isNotEqualTo(holderPid);
            awaitExpiry(expiry);
            holder.rollback();
            assertThat(result.get(3, TimeUnit.SECONDS)).isEmpty();
            assertThat(AiModelDispatchFixture.fingerprint(source)).isEqualTo(before);
            assertThat(AiModelDispatchFixture.consumed(source, preparation.intentId(), false)).isFalse();
            retainedReservation();
        } finally {
            executor.shutdownNow();
            assertThat(executor.awaitTermination(5, TimeUnit.SECONDS)).isTrue();
        }
    }

    @Test
    void assignedIntentCannotSubstituteForAnotherPreparedIntentInFinalSql() throws Exception {
        assignSelected();
        var other = new RunPreparation(UUID.randomUUID(), UUID.randomUUID(), expected(current()), claim.binding(),
                model, AiModelDispatchFixture.payload(32, "other-intent"), 32, preparation.expiresAt());
        assertThat(writer.prepareRun(other, run.spec().actorId(), budget()).status()).isEqualTo(Status.APPLIED);
        assignments.requireAssigned(preparation.intentId(), selected, budget());
        assertThat(registrations.current(selected, budget())).isPresent();
        var redemption = new RunRedemption(other.intentId(), expected(current()), claim.binding(), model,
                other.payload().sha256(), other.expiresAt(), UUID.randomUUID());
        String before = AiModelDispatchFixture.fingerprint(source);
        var queryBudget = budget();
        var rows = new org.springframework.transaction.support.TransactionTemplate(transactions).execute(status -> {
            runtime.configureTransaction(queryBudget.remaining().toMillis());
            assertThat(runtime.lockControl()).isPresent();
            return intents
                    .consumeAssignedRunIntent(redemption, redemption.expected(), preparation.intentId(),
                            selected.role().name(), selected.subject(),
                            queryBudget.databaseCutoff(runtime.decisionTime()));
        });
        assertThat(rows).isZero();
        assertThat(AiModelDispatchFixture.fingerprint(source)).isEqualTo(before);
        assertThat(writer.consumeRun(redemption, run.spec().actorId(), selected, budget())).isEmpty();
        assertThat(AiModelDispatchFixture.fingerprint(source)).isEqualTo(before);
        assertThat(AiModelDispatchFixture.consumed(source, preparation.intentId(), false)).isFalse();
        assertThat(AiModelDispatchFixture.consumed(source, other.intentId(), false)).isFalse();
        assertThat(AiModelDispatchFixture.reservedCalls(source, run.spec().runId())).isEqualTo(2);
        assertThat(AiModelDispatchFixture.reservedTokens(source, run.spec().runId(), false)).isEqualTo(64);
    }

    private AiModelRunDispatchService service(AiModelUseAuthorization models, AiModelCertificateContext contexts) {
        return new AiModelRunDispatchService(kernel, inputs, writer, models, contexts, new AiFeatureGate(true));
    }

    private RunDispatchEnvelope envelope() {
        return new RunDispatchEnvelope(1, preparation.intentId(), preparation.payload().sha256(),
                new RunBinding(claim.binding().runId(), claim.binding().attemptId(),
                        UUID.fromString(claim.binding().workload().podUid()), claim.binding().claimId(),
                        claim.binding().fence(), preparation.expiresAt()));
    }

    private RunRedemption redemption() {
        return new RunRedemption(preparation.intentId(), expected(current()), claim.binding(), model,
                preparation.payload().sha256(), preparation.expiresAt(), UUID.randomUUID());
    }

    private void assignSelected() {
        assertThat(assignments.assign(preparation.intentId(), selected, budget()).status()).isEqualTo(Status.APPLIED);
    }

    private Instant shortenRegistration(Duration duration) throws Exception {
        Instant now = AiRuntimeFixture.now(source);
        Instant expiry = now.plus(duration);
        assertThat(registrations
                .observe(new Observation(deployment, selected.subject(), 2, UUID.randomUUID(), now, expiry), budget()))
                .isTrue();
        return expiry;
    }

    private void awaitExpiry(Instant expiry) {
        org.awaitility.Awaitility
                .await("Actual database gateway registration expiry")
                .pollInSameThread()
                .pollDelay(Duration.ZERO)
                .pollInterval(Duration.ofMillis(5))
                .atMost(Duration.ofSeconds(1))
                .until(() -> !AiRuntimeFixture.now(source).isBefore(expiry));
    }

    private void retainedReservation() throws Exception {
        assertThat(AiModelDispatchFixture.reservedCalls(source, run.spec().runId())).isEqualTo(1);
        assertThat(AiModelDispatchFixture.reservedTokens(source, run.spec().runId(), false)).isEqualTo(32);
    }

    private void install(String resource) throws Exception {
        try (var connection = source.getConnection(); var statement = connection.createStatement()) {
            statement
                    .execute(new String(new ClassPathResource(resource).getContentAsByteArray(),
                            StandardCharsets.UTF_8));
        }
    }

    private RunSnapshot current() {
        return kernel.snapshot(run.spec().runId()).orElseThrow();
    }

    private static AiRuntimeOperationBudget budget() {
        return AiRuntimeOperationBudget.start();
    }

    private static boolean blocked(Connection observer, int holder, int waiter) throws Exception {
        try (var statement = observer.prepareStatement("SELECT ? = ANY(pg_blocking_pids(?))")) {
            statement.setInt(1, holder);
            statement.setInt(2, waiter);
            try (var rows = statement.executeQuery()) {
                assertThat(rows.next()).isTrue();
                return rows.getBoolean(1);
            }
        }
    }
}
