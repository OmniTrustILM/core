package com.otilm.core.integration.service;

import com.otilm.core.model.ai.AiRuntimeGatewayState.Deployment;
import com.otilm.core.model.ai.AiRuntimeGatewayState.Observation;
import com.otilm.core.model.ai.AiRuntimeState.ControlVersion;
import com.otilm.core.model.ai.AiRuntimeState.LaunchSpec;
import com.otilm.core.security.ai.AiRuntimeGatewayAuthority;
import com.otilm.core.security.ai.RuntimePeer;
import com.otilm.core.security.ai.RuntimePeerRole;
import com.otilm.core.security.ai.RuntimeProxyCertificateClaims;
import com.otilm.core.service.ai.AiRuntimeKernel;
import com.otilm.core.service.ai.AiRuntimeOperationBudget;
import com.otilm.core.service.writer.ai.AiRuntimeGatewayRegistrationWriter;
import com.otilm.core.util.AiRuntimeFixture;
import com.otilm.core.util.ai.BaseAiSpringBootTest;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.time.Instant;
import java.util.UUID;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import javax.sql.DataSource;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.core.io.ClassPathResource;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.assertj.core.api.Assertions.catchThrowable;

class AiRuntimeGatewayRegistrationITest extends BaseAiSpringBootTest {
    @Autowired
    private DataSource source;
    @Autowired
    private AiRuntimeKernel kernel;
    @Autowired
    private AiRuntimeGatewayRegistrationWriter writer;
    @Autowired
    private AiRuntimeGatewayAuthority authority;
    private ControlVersion control;
    private Deployment deployment;
    private RuntimeProxyCertificateClaims subject;
    private Instant now;

    @BeforeEach
    void storedApprovedDeploymentAndActualDatabaseClock() throws Exception {
        AiRuntimeFixture.install(source);
        try (var connection = source.getConnection(); var statement = connection.createStatement()) {
            statement
                    .execute(new String(
                            new ClassPathResource("db/migration/V202611051400__ai_runtime_gateway_registration.sql")
                                    .getContentAsByteArray(),
                            StandardCharsets.UTF_8));
        }
        now = AiRuntimeFixture.now(source);
        control = AiRuntimeFixture.enableTestControl(kernel, now);
        assertThat(kernel.disableControl(control).status())
                .isEqualTo(com.otilm.core.model.ai.AiRuntimeState.Status.APPLIED);
        control = kernel.control().orElseThrow().version();
        var attempt = AiRuntimeFixture.attempt(now);
        var pins = com.otilm.core.model.ai.AiRuntimeState.ControlPins.forAttempt(attempt);
        control = kernel.changeControl(control, pins).value().orElseThrow().version();
        deployment = new Deployment(RuntimePeerRole.GATEWAY_RUN, control.generation(), AiRuntimeFixture.IMAGE,
                new LaunchSpec("cluster-one", "gateways", "namespace-gateway", "gateway", "account-gateway",
                        AiRuntimeFixture.TEMPLATE, "sandbox"));
        subject = new RuntimeProxyCertificateClaims("cluster-one", "gateways", "gateway", "gateway-one",
                UUID.randomUUID());
    }

    @Test
    void requiresApprovedObservedGatewayAndExplicitEnabledFreshGlobalControl() {
        assertDenied(new RuntimePeer(RuntimePeerRole.GATEWAY_RUN, subject));
        assertThat(writer.configure(deployment, budget())).isTrue();
        assertDenied(new RuntimePeer(RuntimePeerRole.GATEWAY_RUN, subject));
        assertThat(writer.observe(observation(1), budget())).isTrue();
        assertDenied(new RuntimePeer(RuntimePeerRole.GATEWAY_RUN, subject));
        enable();

        var registration = authority.requireCurrent(new RuntimePeer(RuntimePeerRole.GATEWAY_RUN, subject), budget());
        assertThat(registration.subject()).isEqualTo(subject);
        assertThat(registration.controlGeneration()).isEqualTo(control.generation());
        assertThat(registration.observationSequence()).isEqualTo(1);
        assertThat(registration.toString()).isEqualTo("GatewayRegistration[role=GATEWAY_RUN]");
        assertThat(writer.configure(deployment, budget())).isFalse();
    }

    @Test
    void wrongRolesAndEveryForeignIdentityTupleAreDenied() {
        assertThat(writer.configure(deployment, budget())).isTrue();
        assertThat(writer.observe(observation(1), budget())).isTrue();
        enable();
        assertDenied(null);
        for (var role : RuntimePeerRole.values()) {
            if (role != RuntimePeerRole.GATEWAY_RUN) {
                assertDenied(new RuntimePeer(role, subject));
            }
        }
        for (var foreign : new RuntimeProxyCertificateClaims[]{
                new RuntimeProxyCertificateClaims("other", subject.namespace(), subject.serviceAccount(),
                        subject.podName(), subject.podUid()),
                new RuntimeProxyCertificateClaims(subject.cluster(), "other", subject.serviceAccount(),
                        subject.podName(), subject.podUid()),
                new RuntimeProxyCertificateClaims(subject.cluster(), subject.namespace(), "other", subject.podName(),
                        subject.podUid()),
                new RuntimeProxyCertificateClaims(subject.cluster(), subject.namespace(), subject.serviceAccount(),
                        "other", subject.podUid()),
                new RuntimeProxyCertificateClaims(subject.cluster(), subject.namespace(), subject.serviceAccount(),
                        subject.podName(), UUID.randomUUID())}) {
            assertDenied(new RuntimePeer(RuntimePeerRole.GATEWAY_RUN, foreign));
        }
    }

    @Test
    void expiryCannotBeRenewedWithoutAdministratorReset() throws Exception {
        assertThat(writer.configure(deployment, budget())).isTrue();
        assertThat(writer.observe(observation(1), budget())).isTrue();
        enable();
        expireRegistration();
        assertDenied(new RuntimePeer(RuntimePeerRole.GATEWAY_RUN, subject));
        assertThat(writer.observe(observation(2), budget())).isFalse();
        assertThat(writer.configure(deployment, budget())).isFalse();
        assertThat(kernel.disableControl(control).status())
                .isEqualTo(com.otilm.core.model.ai.AiRuntimeState.Status.APPLIED);
        control = kernel.control().orElseThrow().version();
        deployment = new Deployment(deployment.role(), control.generation(), deployment.imageDigest(),
                deployment.launch());
        assertThat(writer.configure(deployment, budget())).isTrue();
        assertThat(writer.observe(observation(1), budget())).isTrue();
        enable();
        assertThat(authority.requireCurrent(new RuntimePeer(RuntimePeerRole.GATEWAY_RUN, subject), budget()).subject())
                .isEqualTo(subject);
    }

    @Test
    void wrongImageOrConfigurationCannotPublishAndObservationCannotReplayOrGoBackwards() {
        assertThat(writer.configure(deployment, budget())).isTrue();
        var wrongImage = new Deployment(deployment.role(), deployment.controlGeneration(), "sha256:" + "c".repeat(64),
                deployment.launch());
        assertThat(writer
                .observe(new Observation(wrongImage, subject, 1, UUID.randomUUID(), now, now.plusSeconds(20)),
                        budget()))
                .isFalse();
        assertThat(writer.observe(observation(1), budget())).isTrue();
        assertThat(writer.observe(observation(1), budget())).isFalse();
        assertThat(writer.observe(observation(2), budget())).isTrue();
        enable();
        kernel.disableControl(control);
        assertDenied(new RuntimePeer(RuntimePeerRole.GATEWAY_RUN, subject));
        assertThat(writer.observe(observation(3), budget())).isFalse();
    }

    @Test
    void configurationSerializesWithTheRealControlRowWithinTheRemainingBudget() throws Exception {
        var executor = Executors.newSingleThreadExecutor();
        try (var holder = source.getConnection()) {
            holder.setAutoCommit(false);
            try (var statement = holder.createStatement();
                    var rows = statement
                            .executeQuery("SELECT generation FROM ai_runtime_control WHERE id = 1 FOR UPDATE")) {
                assertThat(rows.next()).isTrue();
                assertThat(rows.getLong(1)).isEqualTo(control.generation());
            }
            var future = executor
                    .submit(() -> catchThrowable(() -> writer
                            .configure(deployment, AiRuntimeOperationBudget.start(Duration.ofMillis(800)))));
            Throwable failure = future.get(2, TimeUnit.SECONDS);
            assertThat(failure).as("A held control row must prevent gateway reconfiguration").isNotNull();
            String sqlState = "NO_SQL_STATE";
            for (Throwable cause = failure; cause != null; cause = cause.getCause()) {
                if (cause instanceof java.sql.SQLException sql) {
                    sqlState = sql.getSQLState();
                }
            }
            assertThat(sqlState).isIn("55P03", "57014");
        } finally {
            executor.shutdownNow();
            assertThat(executor.awaitTermination(3, TimeUnit.SECONDS)).isTrue();
        }
    }

    @Test
    void independentlyRegisteredGatewayReplicasKeepSeparateCurrentIdentities() {
        assertThat(writer.configure(deployment, budget())).isTrue();
        assertThat(writer.observe(observation(1), budget())).isTrue();
        var replica = new RuntimeProxyCertificateClaims(subject.cluster(), subject.namespace(),
                subject.serviceAccount(), "gateway-two", UUID.randomUUID());
        assertThat(writer
                .observe(new Observation(deployment, replica, 1, UUID.randomUUID(), now, now.plusSeconds(20)),
                        budget()))
                .isTrue();
        enable();
        assertThat(authority.requireCurrent(new RuntimePeer(RuntimePeerRole.GATEWAY_RUN, subject), budget()).subject())
                .isEqualTo(subject);
        assertThat(authority.requireCurrent(new RuntimePeer(RuntimePeerRole.GATEWAY_RUN, replica), budget()).subject())
                .isEqualTo(replica);
    }

    @Test
    void reconfigurationClearsObservedPodsEvenWhenTheControlGenerationIsUnchanged() {
        assertThat(writer.configure(deployment, budget())).isTrue();
        assertThat(writer.observe(observation(1), budget())).isTrue();
        deployment = new Deployment(deployment.role(), control.generation(), "sha256:" + "d".repeat(64),
                deployment.launch());
        assertThat(writer.configure(deployment, budget())).isTrue();
        enable();
        assertDenied(new RuntimePeer(RuntimePeerRole.GATEWAY_RUN, subject));
    }

    @Test
    void freshControlEvidenceWithoutAdministratorEnablementIsInsufficient() {
        assertThat(writer.configure(deployment, budget())).isTrue();
        assertThat(writer.observe(observation(1), budget())).isTrue();
        publishControlEvidence();
        assertDenied(new RuntimePeer(RuntimePeerRole.GATEWAY_RUN, subject));
        assertThat(kernel.enableControl(control).status())
                .isEqualTo(com.otilm.core.model.ai.AiRuntimeState.Status.APPLIED);
        assertThat(authority.requireCurrent(new RuntimePeer(RuntimePeerRole.GATEWAY_RUN, subject), budget()).subject())
                .isEqualTo(subject);
    }

    @Test
    void enabledControlWithExpiredEvidenceIsInsufficient() throws Exception {
        assertThat(writer.configure(deployment, budget())).isTrue();
        assertThat(writer.observe(observation(1), budget())).isTrue();
        enable();
        execute("UPDATE ai_runtime_control SET observed_at = clock_timestamp() - interval '2 seconds', valid_until = clock_timestamp() - interval '1 second'");
        assertThat(kernel.control().orElseThrow().enabled()).isTrue();
        assertDenied(new RuntimePeer(RuntimePeerRole.GATEWAY_RUN, subject));
    }

    @Test
    void revokedPodCannotRenewAndOtherReplicaRemainsCurrent() {
        assertThat(writer.configure(deployment, budget())).isTrue();
        assertThat(writer.observe(observation(1), budget())).isTrue();
        var replica = new RuntimeProxyCertificateClaims(subject.cluster(), subject.namespace(),
                subject.serviceAccount(), "gateway-two", UUID.randomUUID());
        assertThat(writer
                .observe(new Observation(deployment, replica, 1, UUID.randomUUID(), now, now.plusSeconds(20)),
                        budget()))
                .isTrue();
        enable();
        assertThat(writer.revoke(new RuntimePeer(RuntimePeerRole.GATEWAY_RUN, subject), budget())).isTrue();
        assertDenied(new RuntimePeer(RuntimePeerRole.GATEWAY_RUN, subject));
        assertThat(writer.observe(observation(2), budget())).isFalse();
        assertThat(authority.requireCurrent(new RuntimePeer(RuntimePeerRole.GATEWAY_RUN, replica), budget()).subject())
                .isEqualTo(replica);
    }

    @Test
    void observationsCannotDecreaseSequenceOrTimestamp() {
        assertThat(writer.configure(deployment, budget())).isTrue();
        assertThat(writer.observe(observation(3), budget())).isTrue();
        assertThat(writer.observe(observation(2), budget())).isFalse();
        assertThat(writer
                .observe(new Observation(deployment, subject, 4, UUID.randomUUID(), now.minusMillis(1),
                        now.plusSeconds(20)), budget()))
                .isFalse();
    }

    private void enable() {
        publishControlEvidence();
        assertThat(kernel.enableControl(control).status())
                .isEqualTo(com.otilm.core.model.ai.AiRuntimeState.Status.APPLIED);
    }

    private void publishControlEvidence() {
        var pins = com.otilm.core.model.ai.AiRuntimeState.ControlPins.forAttempt(AiRuntimeFixture.attempt(now));
        var observation = new com.otilm.core.model.ai.AiRuntimeState.ReadinessObservation(control, pins, 1,
                UUID.randomUUID(), now, now.plusSeconds(25));
        assertThat(kernel.observeControl(observation).status())
                .isEqualTo(com.otilm.core.model.ai.AiRuntimeState.Status.APPLIED);
    }

    private void expireRegistration() throws Exception {
        try (var connection = source.getConnection();
                var statement = connection
                        .prepareStatement(
                                "UPDATE ai_runtime_gateway_registration SET observed_at = ?, valid_until = ?")) {
            statement.setTimestamp(1, java.sql.Timestamp.from(now.minusSeconds(3)));
            statement.setTimestamp(2, java.sql.Timestamp.from(now.minusSeconds(2)));
            assertThat(statement.executeUpdate()).isEqualTo(1);
        }
    }

    private Observation observation(long sequence) {
        return new Observation(deployment, subject, sequence, UUID.randomUUID(), now, now.plusSeconds(20));
    }

    private void assertDenied(RuntimePeer peer) {
        assertThatThrownBy(() -> authority.requireCurrent(peer, budget()))
                .isInstanceOf(org.springframework.security.access.AccessDeniedException.class)
                .hasMessage("Current gateway registration required")
                .hasNoCause();
    }

    private void execute(String sql) throws Exception {
        try (var connection = source.getConnection(); var statement = connection.createStatement()) {
            statement.execute(sql);
        }
    }

    private static AiRuntimeOperationBudget budget() {
        return AiRuntimeOperationBudget.start();
    }
}
