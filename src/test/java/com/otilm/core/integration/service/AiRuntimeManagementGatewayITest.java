package com.otilm.core.integration.service;

import com.otilm.core.model.ai.AiRuntimeManagementGatewayState.Deployment;
import com.otilm.core.model.ai.AiRuntimeManagementGatewayState.Observation;
import com.otilm.core.model.ai.AiRuntimeManagementGatewayState.Pins;
import com.otilm.core.model.ai.AiRuntimeState.LaunchSpec;
import com.otilm.core.model.ai.AiRuntimeState.Status;
import com.otilm.core.security.ai.RuntimePeer;
import com.otilm.core.security.ai.RuntimePeerRole;
import com.otilm.core.security.ai.RuntimeProxyCertificateClaims;
import com.otilm.core.service.ai.AiRuntimeOperationBudget;
import com.otilm.core.service.writer.ai.AiRuntimeManagementGatewayWriter;
import com.otilm.core.util.AiModelDispatchFixture;
import com.otilm.core.util.AiRuntimeFixture;
import com.otilm.core.util.ai.BaseAiSpringBootTest;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.time.Instant;
import java.util.UUID;
import javax.sql.DataSource;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.core.io.ClassPathResource;

import static org.assertj.core.api.Assertions.assertThat;

/** Own PostgreSQL transport-lease facts only. They are not real Pod enforcement/issuer attestation. */
class AiRuntimeManagementGatewayITest extends BaseAiSpringBootTest {
    @Autowired
    private DataSource source;
    @Autowired
    private AiRuntimeManagementGatewayWriter writer;
    private Pins pins;
    private RuntimePeer peer;

    @BeforeEach
    void noRunOrGlobalActivationNeeded() throws Exception {
        execute("DROP TABLE IF EXISTS ai_management_gateway_registration,ai_management_gateway_deployment");
        AiModelDispatchFixture.drop(source);
        AiRuntimeFixture.install(source);
        AiModelDispatchFixture.install(source);
        execute("DELETE FROM ai_runtime_control");
        execute(new String(
                new ClassPathResource("db/migration/V202611061300__ai_management_gateway.sql").getContentAsByteArray(),
                StandardCharsets.UTF_8));
        pins = new Pins("sha256:" + "a".repeat(64), new LaunchSpec("cluster-one", "ai-proof", "namespace-one",
                "gateway-account", "account-one", "sha256:" + "b".repeat(64), "sandbox"));
        peer = new RuntimePeer(RuntimePeerRole.GATEWAY_MANAGEMENT, new RuntimeProxyCertificateClaims("cluster-one",
                "ai-proof", "gateway-account", "management-gateway", UUID.randomUUID()));
        assertThat(writer.revision(budget())).isZero();
        assertThat(writer.current(peer, budget())).isEmpty();
        zeroRunState();
    }

    @Test
    void explicitConfigurationAndMatchingFreshEvidenceSupplyOnlyCurrentManagementTransport() throws Exception {
        var configured = writer.configure(0, pins, budget());
        assertThat(configured.status()).isEqualTo(Status.APPLIED);
        var deployment = configured.value().orElseThrow();
        assertThat(deployment.revision()).isEqualTo(1);
        assertThat(writer.current(peer, budget())).isEmpty();
        var evidence = observation(deployment, 1, Duration.ofSeconds(5));
        assertThat(writer.observe(evidence, budget()).status()).isEqualTo(Status.APPLIED);
        var current = writer.current(peer, budget()).orElseThrow();
        assertThat(current.subject()).isEqualTo(peer.subject());
        assertThat(current.deploymentRevision()).isEqualTo(deployment.revision());
        assertThat(current.observationSequence()).isEqualTo(1);
        assertThat(current.evidenceId()).isEqualTo(evidence.evidenceId());
        assertThat(current.validUntil()).isEqualTo(evidence.validUntil());
        assertThat(writer.observe(evidence, budget()).status()).isEqualTo(Status.REPLAY);
        zeroRunState();
    }

    @ParameterizedTest
    @ValueSource(strings = {"image", "namespace-uid", "account-uid", "template", "runtime"})
    void observationCannotLaunderDifferentPinnedDeploymentFields(String changed) throws Exception {
        var deployment = writer.configure(0, pins, budget()).value().orElseThrow();
        var l = pins.launch();
        var other = new Pins(changed.equals("image") ? "sha256:" + "c".repeat(64) : pins.imageDigest(),
                new LaunchSpec(l.cluster(), l.namespaceName(),
                        changed.equals("namespace-uid") ? "foreign" : l.namespaceUid(), l.serviceAccountName(),
                        changed.equals("account-uid") ? "foreign" : l.serviceAccountUid(),
                        changed.equals("template") ? "sha256:" + "c".repeat(64) : l.templateDigest(),
                        changed.equals("runtime") ? "foreign" : l.runtimeClass()));
        String before = fingerprint();
        var evidence = observation(new Deployment(deployment.revision(), other), 1, Duration.ofSeconds(5));
        assertThat(writer.observe(evidence, budget()).status()).isEqualTo(Status.DENIED);
        assertThat(writer.current(peer, budget())).isEmpty();
        assertThat(fingerprint()).isEqualTo(before);
    }

    @Test
    void distinctNativeRolesAndSubjectsCannotBorrowCurrentManagementRow() throws Exception {
        var deployment = writer.configure(0, pins, budget()).value().orElseThrow();
        assertThat(writer.observe(observation(deployment, 1, Duration.ofSeconds(5)), budget()).status())
                .isEqualTo(Status.APPLIED);
        for (var role : RuntimePeerRole.values()) {
            if (role != RuntimePeerRole.GATEWAY_MANAGEMENT) {
                assertThat(writer.current(new RuntimePeer(role, peer.subject()), budget())).isEmpty();
            }
        }
        var other = new RuntimePeer(RuntimePeerRole.GATEWAY_MANAGEMENT, new RuntimeProxyCertificateClaims("cluster-one",
                "ai-proof", "gateway-account", "management-gateway", UUID.randomUUID()));
        assertThat(writer.current(other, budget())).isEmpty();
        assertThat(writer.current(null, budget())).isEmpty();
        assertThat(writer.current(peer, budget())).isPresent();
    }

    @Test
    void disableAndExplicitNewRevisionInvalidateOldObservationWithoutRebindingOldGeneration() throws Exception {
        var deployment = writer.configure(0, pins, budget()).value().orElseThrow();
        var old = observation(deployment, 1, Duration.ofSeconds(5));
        assertThat(writer.observe(old, budget()).status()).isEqualTo(Status.APPLIED);
        assertThat(writer.disable(deployment.revision(), budget()).value()).contains(2L);
        assertThat(writer.current(peer, budget())).isEmpty();
        assertThat(writer.observe(old, budget()).status()).isEqualTo(Status.DENIED);
        var fresh = writer.configure(2, pins, budget()).value().orElseThrow();
        assertThat(fresh.revision()).isEqualTo(3);
        assertThat(writer.current(peer, budget())).isEmpty();
        assertThat(writer.observe(observation(fresh, 1, Duration.ofSeconds(5)), budget()).status())
                .isEqualTo(Status.APPLIED);
        assertThat(writer.current(peer, budget()).orElseThrow().deploymentRevision()).isEqualTo(3);
        zeroRunState();
    }

    @Test
    void revokedPodCannotRenewEvenWithLaterSequence() throws Exception {
        var deployment = writer.configure(0, pins, budget()).value().orElseThrow();
        assertThat(writer.observe(observation(deployment, 1, Duration.ofSeconds(5)), budget()).status())
                .isEqualTo(Status.APPLIED);
        assertThat(writer.revoke(peer, budget()).status()).isEqualTo(Status.APPLIED);
        assertThat(writer.current(peer, budget())).isEmpty();
        String before = fingerprint();
        assertThat(writer.observe(observation(deployment, 2, Duration.ofSeconds(5)), budget()).status())
                .isEqualTo(Status.DENIED);
        assertThat(fingerprint()).isEqualTo(before);
        assertThat(writer.revoke(peer, budget()).status()).isEqualTo(Status.REPLAY);
    }

    @Test
    void expiryCannotBeRefreshedInPlaceButNewConfiguredRevisionCanVerifyAgain() throws Exception {
        var deployment = writer.configure(0, pins, budget()).value().orElseThrow();
        var shortProof = observation(deployment, 1, Duration.ofMillis(150));
        assertThat(writer.observe(shortProof, budget()).status()).isEqualTo(Status.APPLIED);
        org.awaitility.Awaitility
                .await("Actual management peer evidence expiry")
                .pollInSameThread()
                .pollDelay(Duration.ZERO)
                .pollInterval(Duration.ofMillis(2))
                .atMost(Duration.ofSeconds(1))
                .until(() -> !AiRuntimeFixture.now(source).isBefore(shortProof.validUntil()));
        assertThat(writer.current(peer, budget())).isEmpty();
        String before = fingerprint();
        assertThat(writer.observe(observation(deployment, 2, Duration.ofSeconds(5)), budget()).status())
                .isEqualTo(Status.DENIED);
        assertThat(fingerprint()).isEqualTo(before);
        var fresh = writer.configure(deployment.revision(), pins, budget()).value().orElseThrow();
        assertThat(writer.observe(observation(fresh, 1, Duration.ofSeconds(5)), budget()).status())
                .isEqualTo(Status.APPLIED);
        assertThat(writer.current(peer, budget())).isPresent();
    }

    @Test
    void liveHigherSequenceRefreshUpdatesExactEvidenceWithoutResettingDeployment() throws Exception {
        var deployment = writer.configure(0, pins, budget()).value().orElseThrow();
        Instant now = AiRuntimeFixture.now(source);
        var original = new Observation(deployment, peer.subject(), 1, UUID.randomUUID(), now.minusSeconds(1),
                now.plusSeconds(5));
        assertThat(writer.observe(original, budget()).status()).isEqualTo(Status.APPLIED);
        String before = fingerprint();
        Instant later = AiRuntimeFixture.now(source);
        var fresh = new Observation(deployment, peer.subject(), 2, UUID.randomUUID(), later, later.plusSeconds(3));
        assertThat(writer.observe(fresh, budget()).status()).isEqualTo(Status.APPLIED);
        assertThat(fingerprint()).isNotEqualTo(before);
        var current = writer.current(peer, budget()).orElseThrow();
        assertThat(current.deploymentRevision()).isEqualTo(deployment.revision());
        assertThat(current.observationSequence()).isEqualTo(2);
        assertThat(current.evidenceId()).isEqualTo(fresh.evidenceId());
        assertThat(current.validUntil()).isEqualTo(fresh.validUntil());
        assertThat(writer.observe(fresh, budget()).status()).isEqualTo(Status.REPLAY);
        zeroRunState();
    }

    @ParameterizedTest
    @ValueSource(strings = {"same-sequence", "lower-sequence", "changed-pod-name", "earlier-observed-at"})
    void aLiveRowRejectsEachIndependentStaleOrForeignRefreshWithoutMutation(String changed) throws Exception {
        var deployment = writer.configure(0, pins, budget()).value().orElseThrow();
        Instant now = AiRuntimeFixture.now(source);
        var original = new Observation(deployment, peer.subject(), 2, UUID.randomUUID(), now.minusSeconds(1),
                now.plusSeconds(5));
        assertThat(writer.observe(original, budget()).status()).isEqualTo(Status.APPLIED);
        String before = fingerprint();
        long sequence = changed.equals("same-sequence") ? 2 : changed.equals("lower-sequence") ? 1 : 3;
        var subject = changed.equals("changed-pod-name")
                ? new RuntimeProxyCertificateClaims(peer.subject().cluster(), peer.subject().namespace(),
                        peer.subject().serviceAccount(), "foreign-name", peer.subject().podUid())
                : peer.subject();
        Instant at = changed.equals("earlier-observed-at")
                ? original.observedAt().minusMillis(1)
                : AiRuntimeFixture.now(source);
        var candidate = new Observation(deployment, subject, sequence, UUID.randomUUID(), at, original.validUntil());
        assertThat(writer.observe(candidate, budget()).status()).isEqualTo(Status.DENIED);
        assertThat(fingerprint()).isEqualTo(before);
        var current = writer.current(peer, budget()).orElseThrow();
        assertThat(current.observationSequence()).isEqualTo(2);
        assertThat(current.evidenceId()).isEqualTo(original.evidenceId());
        zeroRunState();
    }

    private Observation observation(Deployment d, long sequence, Duration duration) throws Exception {
        Instant now = AiRuntimeFixture.now(source);
        return new Observation(d, peer.subject(), sequence, UUID.randomUUID(), now, now.plus(duration));
    }

    private void zeroRunState() throws Exception {
        try (var c = source.getConnection();
                var q = c.createStatement();
                var rows = q
                        .executeQuery(
                                "SELECT (SELECT count(*) FROM ai_runtime_control)+(SELECT count(*) FROM ai_runtime_run)+(SELECT count(*) FROM ai_runtime_attempt)+(SELECT count(*) FROM ai_runtime_launch)+(SELECT count(*) FROM ai_runtime_workload)")) {
            assertThat(rows.next()).isTrue();
            assertThat(rows.getLong(1)).isZero();
        }
    }

    private String fingerprint() throws Exception {
        try (var c = source.getConnection();
                var q = c.createStatement();
                var rows = q
                        .executeQuery(
                                "SELECT json_build_object('deployment',(SELECT json_agg(d ORDER BY id) FROM ai_management_gateway_deployment d),'registration',(SELECT json_agg(w ORDER BY pod_uid) FROM ai_management_gateway_registration w))::text")) {
            assertThat(rows.next()).isTrue();
            return rows.getString(1);
        }
    }

    private void execute(String sql) throws Exception {
        try (var c = source.getConnection(); var q = c.createStatement()) {
            q.execute(sql);
        }
    }

    private static AiRuntimeOperationBudget budget() {
        return AiRuntimeOperationBudget.start();
    }
}
