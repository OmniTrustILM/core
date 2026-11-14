package com.otilm.core.integration.service.ai;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.otilm.ai.runtime.protocol.ManagementAction;
import com.otilm.ai.runtime.protocol.ManagementBinding;
import com.otilm.ai.runtime.protocol.ManagementDispatchEnvelope;
import com.otilm.ai.runtime.protocol.ProtocolCodec;
import com.otilm.ai.runtime.protocol.RunBinding;
import com.otilm.ai.runtime.protocol.RunDispatchEnvelope;
import com.otilm.ai.runtime.protocol.RuntimeErrorCode;
import com.otilm.core.model.ai.AiModelDispatchState.ManagementPreparation;
import com.otilm.core.model.ai.AiModelDispatchState.ManagementRedemption;
import com.otilm.core.model.ai.AiModelDispatchState.RunPreparation;
import com.otilm.core.model.ai.AiModelDispatchState.RunRedemption;
import com.otilm.core.model.ai.AiModelManagementSession.Spec;
import com.otilm.core.model.ai.AiRuntimeState.ControlPins;
import com.otilm.core.model.ai.AiRuntimeState.ReadinessObservation;
import com.otilm.core.model.ai.AiRuntimeState.Status;
import com.otilm.core.model.ai.AiRuntimeState.WorkloadRef;
import com.otilm.core.security.ai.AiRuntimeGatewayAuthority;
import com.otilm.core.security.ai.AiRuntimeManagementGatewayAuthority;
import com.otilm.core.security.ai.RuntimePeer;
import com.otilm.core.security.ai.RuntimeProxyTransport;
import com.otilm.core.service.ai.AiFeatureGate;
import com.otilm.core.service.ai.AiModelManagementDispatchService;
import com.otilm.core.service.ai.AiModelRunDispatchService;
import com.otilm.core.service.ai.AiRuntimeControllerRegistrationServiceTest;
import com.otilm.core.service.ai.AiRuntimeGatewayServiceImpl;
import com.otilm.core.service.ai.AiRuntimeKernel;
import com.otilm.core.service.ai.AiRuntimeManagementGatewayServiceImpl;
import com.otilm.core.service.ai.AiRuntimeOperationBudget;
import com.otilm.core.service.writer.ai.AiModelDispatchWriter;
import com.otilm.core.service.writer.ai.AiModelManagementGatewayWriter;
import com.otilm.core.service.writer.ai.AiModelManagementOutcomeWriter;
import com.otilm.core.service.writer.ai.AiModelManagementSessionWriter;
import com.otilm.core.service.writer.ai.AiModelRunOutcomeWriter;
import com.otilm.core.service.writer.ai.AiRuntimeGatewayRegistrationWriter;
import com.otilm.core.service.writer.ai.AiRuntimeManagementGatewayWriter;
import com.otilm.core.util.AiModelDispatchFixture;
import com.otilm.core.util.AiRuntimeFixture;
import com.otilm.core.util.ai.BaseAiSpringBootTest;
import java.io.ByteArrayInputStream;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.time.Duration;
import java.time.Instant;
import java.util.Optional;
import java.util.UUID;
import javax.sql.DataSource;
import org.assertj.core.api.ThrowableAssert.ThrowingCallable;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.io.TempDir;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.core.io.ClassPathResource;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.AccessDeniedException;

import static com.otilm.core.util.AiRuntimeFixture.expected;
import static com.otilm.core.util.AiRuntimeFixture.observation;
import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.awaitility.Awaitility.await;
import static org.mockito.Mockito.mockStatic;

/** Real registry, authority and outcome transactions with synthetic controller/API facts; no native attestation. */
class AiGatewaySafetyRefreshITest extends BaseAiSpringBootTest {
    private static final ObjectMapper JSON = new ObjectMapper();
    private final AiFeatureGate disabled = new AiFeatureGate(false);
    @TempDir
    Path directory;
    @Autowired
    private DataSource source;
    @Autowired
    private AiRuntimeKernel kernel;
    @Autowired
    private AiRuntimeGatewayRegistrationWriter runRegistry;
    @Autowired
    private AiRuntimeManagementGatewayWriter managementRegistry;
    @Autowired
    private AiModelDispatchWriter dispatches;
    @Autowired
    private AiModelManagementSessionWriter sessions;
    @Autowired
    private AiModelRunOutcomeWriter runOutcomes;
    @Autowired
    private AiModelManagementOutcomeWriter managementOutcomes;
    @Autowired
    private AiModelManagementGatewayWriter managementAssignments;
    @Autowired
    private AiModelRunDispatchService runDispatch;
    @Autowired
    private AiModelManagementDispatchService managementDispatch;

    @BeforeEach
    void installPrivateDatabaseFixtures() throws Exception {
        AiModelDispatchFixture.drop(source);
        AiRuntimeFixture.install(source);
        AiModelDispatchFixture.install(source);
        for (String migration : new String[]{
                "V202611051400__ai_runtime_gateway_registration.sql",
                "V202611051500__ai_model_run_outcome.sql",
                "V202611061200__ai_model_management_session.sql",
                "V202611061300__ai_management_gateway.sql",
                "V202611061400__ai_model_management_outcome.sql"}) {
            try (var connection = source.getConnection(); var statement = connection.createStatement()) {
                statement
                        .execute(new String(new ClassPathResource("db/migration/" + migration).getContentAsByteArray(),
                                StandardCharsets.UTF_8));
            }
        }
        var at = AiRuntimeFixture.now(source);
        kernel
                .changeControl(kernel.control().orElseThrow().version(),
                        ControlPins.forAttempt(AiRuntimeFixture.attempt(at)))
                .value()
                .orElseThrow();
    }

    @ParameterizedTest
    @ValueSource(booleans = {false, true})
    void recordsAnAdmittedOutcomeAfterOldCutoff_whenDisabledGatewayIdentityWasRefreshed(boolean management)
            throws Exception {
        // given
        try (var fixture = new AiRuntimeControllerRegistrationServiceTest.Fixture(directory, runRegistry,
                managementRegistry); var transport = mockStatic(RuntimeProxyTransport.class)) {
            fixture.configureRegistries();
            RuntimePeer peer = fixture.gatewayPeer(management);
            Instant oldCutoff = seedShortRegistration(fixture, management, peer);
            Prepared prepared = prepareConsumed(management, peer);
            assertCurrent(management, peer);
            assertThat(AiRuntimeFixture.now(source)).isBefore(oldCutoff);
            transport
                    .when(RuntimeProxyTransport::currentWorkloadPeer)
                    .thenReturn(Optional.of(fixture.controllerPeer()));

            // when
            ResponseEntity<byte[]> refreshed = fixture.observe(management);

            // then
            assertThat(refreshed.getStatusCode().value()).isEqualTo(200);
            crossDatabaseCutoff(oldCutoff);
            assertCurrent(management, peer);
            transport.when(RuntimeProxyTransport::currentWorkloadPeer).thenReturn(Optional.of(peer));
            assertDisabledAdmissions(management);
            ResponseEntity<byte[]> recorded = outcome(management, prepared.report());
            assertThat(recorded.getStatusCode().value()).isEqualTo(200);
            assertThat(outcomeCount(management, prepared.intent())).isEqualTo(1);
        }
    }

    @ParameterizedTest
    @ValueSource(booleans = {false, true})
    void rejectsExpiredIdentityAndOutcome_whenDisabledGatewayWasNotRefreshed(boolean management) throws Exception {
        // given
        try (var fixture = new AiRuntimeControllerRegistrationServiceTest.Fixture(directory, runRegistry,
                managementRegistry); var transport = mockStatic(RuntimeProxyTransport.class)) {
            fixture.configureRegistries();
            RuntimePeer peer = fixture.gatewayPeer(management);
            Instant oldCutoff = seedShortRegistration(fixture, management, peer);
            Prepared prepared = prepareConsumed(management, peer);
            assertCurrent(management, peer);

            // when
            crossDatabaseCutoff(oldCutoff);
            ThrowingCallable current = () -> assertCurrent(management, peer);

            // then
            assertThatThrownBy(current).isInstanceOf(AccessDeniedException.class);
            transport.when(RuntimeProxyTransport::currentWorkloadPeer).thenReturn(Optional.of(peer));
            ResponseEntity<byte[]> rejected = outcome(management, prepared.report());
            assertThat(rejected.getStatusCode().value()).isEqualTo(403);
            assertThat(new ProtocolCodec().readRuntimeError(rejected.getBody()).code())
                    .isEqualTo(RuntimeErrorCode.DENIED);
            assertThat(outcomeCount(management, prepared.intent())).isZero();
            transport
                    .when(RuntimeProxyTransport::currentWorkloadPeer)
                    .thenReturn(Optional.of(fixture.controllerPeer()));
            assertThat(fixture.observe(management).getStatusCode().is2xxSuccessful()).isFalse();
            assertThatThrownBy(current).isInstanceOf(AccessDeniedException.class);
        }
    }

    private Instant seedShortRegistration(AiRuntimeControllerRegistrationServiceTest.Fixture fixture,
            boolean management, RuntimePeer peer) throws Exception {
        Instant now = AiRuntimeFixture.now(source);
        Instant until = now.plusSeconds(5);
        if (management) {
            assertThat(managementRegistry
                    .observe(new com.otilm.core.model.ai.AiRuntimeManagementGatewayState.Observation(
                            fixture.managementDeployment(), peer.subject(), 1, UUID.randomUUID(), now.minusSeconds(2),
                            until), budget())
                    .status()).isEqualTo(Status.APPLIED);
        } else {
            assertThat(runRegistry
                    .observe(new com.otilm.core.model.ai.AiRuntimeGatewayState.Observation(fixture.runDeployment(),
                            peer.subject(), 1, UUID.randomUUID(), now.minusSeconds(2), until), budget()))
                    .isTrue();
        }
        return until;
    }

    private Prepared prepareConsumed(boolean management, RuntimePeer peer) throws Exception {
        var now = AiRuntimeFixture.now(source);
        var model = AiModelDispatchFixture.approvedModel(source);
        var payload = AiModelDispatchFixture.payload(32, "bounded synthetic request");
        UUID intent = UUID.randomUUID();
        UUID correlation = UUID.randomUUID();
        Instant expires = now.plusSeconds(20);
        byte[] envelope;
        if (management) {
            UUID actor = UUID.randomUUID();
            UUID session = UUID.randomUUID();
            var spec = new Spec(session, actor, model, ManagementAction.CONNECTION_CHECK, expires, 3, 96);
            assertThat(sessions.create(spec, budget()).status()).isEqualTo(Status.APPLIED);
            var prepared = new ManagementPreparation(intent, UUID.randomUUID(), actor, session, spec.action(), model,
                    payload, 32, expires);
            assertThat(dispatches.prepareManagement(prepared, budget()).status()).isEqualTo(Status.APPLIED);
            assertThat(managementAssignments.assign(intent, peer, budget()).status()).isEqualTo(Status.APPLIED);
            assertThat(dispatches
                    .consumeManagement(new ManagementRedemption(intent, actor, session, spec.action(), model,
                            payload.sha256(), expires, correlation), actor, peer, budget()))
                    .isPresent();
            envelope = new ProtocolCodec()
                    .writeDispatch(new ManagementDispatchEnvelope(1, intent, payload.sha256(), new ManagementBinding(
                            actor, session, model.id(), model.configuration(), spec.action(), expires)));
        } else {
            var control = kernel.control().orElseThrow();
            assertThat(kernel
                    .observeControl(new ReadinessObservation(control.version(), control.pins().orElseThrow(), 1,
                            UUID.randomUUID(), now, now.plusSeconds(90)))
                    .status()).isEqualTo(Status.APPLIED);
            assertThat(kernel.enableControl(control.version()).status()).isEqualTo(Status.APPLIED);
            var run = kernel.create(control.version(), AiRuntimeFixture.run(now), AiRuntimeFixture.attempt(now));
            var pod = new WorkloadRef("cluster-one", UUID.randomUUID().toString());
            assertThat(kernel.observe(observation(run, pod, 1, true)).status()).isEqualTo(Status.APPLIED);
            var claimed = kernel.snapshot(run.spec().runId()).orElseThrow();
            var claim = kernel.bootstrap(expected(claimed), pod).value().orElseThrow();
            var current = kernel.snapshot(run.spec().runId()).orElseThrow();
            AiModelDispatchFixture.runBudget(source, run.spec().runId(), model, 3, 96);
            var prepared = new RunPreparation(intent, UUID.randomUUID(), expected(current), claim.binding(), model,
                    payload, 32, expires);
            assertThat(dispatches.prepareRun(prepared, budget()).status()).isEqualTo(Status.APPLIED);
            assertThat(runOutcomes.assign(intent, peer, budget()).status()).isEqualTo(Status.APPLIED);
            assertThat(dispatches
                    .consumeRun(new RunRedemption(intent, expected(current), claim.binding(), model, payload.sha256(),
                            expires, correlation), run.spec().actorId(), peer, budget()))
                    .isPresent();
            envelope = new ProtocolCodec()
                    .writeDispatch(new RunDispatchEnvelope(1, intent, payload.sha256(),
                            new RunBinding(claim.binding().runId(), claim.binding().attemptId(),
                                    UUID.fromString(claim.binding().workload().podUid()), claim.binding().claimId(),
                                    claim.binding().fence(), expires)));
        }
        var report = JSON
                .createObjectNode()
                .put("protocolVersion", 1)
                .put("kind", management ? "management-outcome" : "run-outcome")
                .put("intentId", intent.toString())
                .put("gatewayCorrelation", correlation.toString());
        report.set("binding", JSON.readTree(envelope).get("binding"));
        report
                .put("payloadSha256", payload.sha256())
                .put("transportCode", "UNKNOWN")
                .putNull("responseBase64")
                .putNull("responseSha256")
                .put("responseByteCount", 0);
        report.putObject("usage").put("kind", "unknown");
        return new Prepared(intent, JSON.writeValueAsBytes(report));
    }

    private void assertCurrent(boolean management, RuntimePeer peer) {
        if (management) {
            new AiRuntimeManagementGatewayAuthority(managementRegistry).requireCurrent(peer, budget());
        } else {
            new AiRuntimeGatewayAuthority(runRegistry).requireCurrent(peer, budget());
        }
    }

    private void assertDisabledAdmissions(boolean management) throws Exception {
        ResponseEntity<byte[]> registration = management
                ? managementGateway().registration()
                : runGateway().registration();
        assertThat(registration.getStatusCode().value()).isEqualTo(200);
        assertThat(JSON.readTree(registration.getBody()).path("kind").asText())
                .isEqualTo(management ? "management-gateway-registration-pending" : "run-gateway-registration-pending");
        InputStream unread = new InputStream() {
            @Override
            public int read() {
                throw new AssertionError("Disabled gateway read a new dispatch body");
            }
        };
        ResponseEntity<byte[]> rejected = management ? managementGateway().redeem(unread) : runGateway().redeem(unread);
        assertThat(rejected.getStatusCode().value()).isEqualTo(403);
        assertThat(new ProtocolCodec().readRuntimeError(rejected.getBody()).code()).isEqualTo(RuntimeErrorCode.DENIED);
    }

    private ResponseEntity<byte[]> outcome(boolean management, byte[] report) {
        return management
                ? managementGateway().outcome(new ByteArrayInputStream(report))
                : runGateway().outcome(new ByteArrayInputStream(report));
    }

    private AiRuntimeGatewayServiceImpl runGateway() {
        return new AiRuntimeGatewayServiceImpl(new AiRuntimeGatewayAuthority(runRegistry), runDispatch, runOutcomes,
                disabled);
    }

    private AiRuntimeManagementGatewayServiceImpl managementGateway() {
        return new AiRuntimeManagementGatewayServiceImpl(new AiRuntimeManagementGatewayAuthority(managementRegistry),
                managementDispatch, managementAssignments, managementOutcomes, disabled);
    }

    private void crossDatabaseCutoff(Instant cutoff) {
        await()
                .pollInSameThread()
                .pollDelay(Duration.ZERO)
                .pollInterval(Duration.ofMillis(20))
                .atMost(Duration.ofSeconds(6))
                .until(() -> !AiRuntimeFixture.now(source).isBefore(cutoff));
    }

    private long outcomeCount(boolean management, UUID intent) throws Exception {
        String table = management ? "ai_model_management_outcome" : "ai_model_run_outcome";
        try (var connection = source.getConnection();
                var statement = connection.prepareStatement("SELECT count(*) FROM " + table + " WHERE intent_uuid=?")) {
            statement.setObject(1, intent);
            try (var rows = statement.executeQuery()) {
                assertThat(rows.next()).isTrue();
                return rows.getLong(1);
            }
        }
    }

    private AiRuntimeOperationBudget budget() {
        return AiRuntimeOperationBudget.start(Duration.ofSeconds(2));
    }

    private record Prepared(UUID intent, byte[] report) {
    }
}
