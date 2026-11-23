package com.otilm.core.model.ai;

import com.otilm.core.model.ai.AiRuntimeManagementGatewayState.Deployment;
import com.otilm.core.model.ai.AiRuntimeManagementGatewayState.Observation;
import com.otilm.core.model.ai.AiRuntimeManagementGatewayState.Pins;
import com.otilm.core.security.ai.RuntimeProxyCertificateClaims;
import java.time.Instant;
import java.util.UUID;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/** Data invariants only. Constructing these records does not verify or admit a workload. */
class AiRuntimeManagementGatewayStateTest {
    private static final AiRuntimeState.LaunchSpec LAUNCH = new AiRuntimeState.LaunchSpec("cluster-one", "ai-proof",
            "namespace-one", "gateway-account", "account-one", "sha256:" + "b".repeat(64), "sandbox");
    private static final Pins PINS = new Pins("sha256:" + "a".repeat(64), LAUNCH);
    private static final Deployment DEPLOYMENT = new Deployment(1, PINS);
    private static final RuntimeProxyCertificateClaims SUBJECT = new RuntimeProxyCertificateClaims("cluster-one",
            "ai-proof", "gateway-account", "management-gateway", UUID.randomUUID());
    private static final Instant NOW = Instant.parse("2030-01-01T00:00:00.123456Z");

    @Test
    void fixedManagementMetadataContainsNoRunOrGlobalControlIdentity() {
        var observed = new Observation(DEPLOYMENT, SUBJECT, 1, UUID.randomUUID(), NOW, NOW.plusSeconds(30));
        assertThat(observed.deployment()).isEqualTo(DEPLOYMENT);
        assertThat(observed.subject()).isEqualTo(SUBJECT);
        assertThat(observed.observedAt()).isEqualTo(NOW);
        assertThat(observed.validUntil()).isEqualTo(NOW.plusSeconds(30));
        assertThat(java.util.Arrays.stream(Deployment.class.getRecordComponents()).map(c -> c.getName()))
                .containsExactly("revision", "pins");
        assertThat(observed.toString()).doesNotContain(SUBJECT.podUid().toString(), SUBJECT.podName());
    }

    @ParameterizedTest
    @ValueSource(longs = {0, -1})
    void unconfiguredRevisionCannotBePublishedAsADeployment(long invalid) {
        assertThatThrownBy(() -> new Deployment(invalid, PINS)).isInstanceOf(IllegalArgumentException.class);
    }

    @ParameterizedTest
    @ValueSource(strings = {"cluster", "namespace", "account", "sequence", "evidence", "past", "too-long"})
    void observationMustMatchExactFixedPinsAndBoundedEvidence(String invalid) {
        var subject = new RuntimeProxyCertificateClaims(invalid.equals("cluster") ? "foreign" : SUBJECT.cluster(),
                invalid.equals("namespace") ? "foreign" : SUBJECT.namespace(),
                invalid.equals("account") ? "foreign" : SUBJECT.serviceAccount(), SUBJECT.podName(), SUBJECT.podUid());
        var end = invalid.equals("past") ? NOW : NOW.plusSeconds(invalid.equals("too-long") ? 31 : 30);
        UUID evidence = invalid.equals("evidence") ? null : UUID.randomUUID();
        long sequence = invalid.equals("sequence") ? 0 : 1;
        assertThatThrownBy(() -> new Observation(DEPLOYMENT, subject, sequence, evidence, NOW, end))
                .isInstanceOf(IllegalArgumentException.class);
    }

    @ParameterizedTest
    @ValueSource(strings = {
            "null-image",
            "bad-image",
            "null-launch",
            "null-pins",
            "null-deployment",
            "null-subject",
            "null-start",
            "null-end",
            "submicro"})
    void invalidOrUnrepresentableTrustedMetadataCannotBecomeAnObservation(String field) {
        if (field.equals("null-image") || field.equals("bad-image") || field.equals("null-launch")) {
            String image = field.equals("null-image")
                    ? null
                    : field.equals("bad-image") ? "latest" : PINS.imageDigest();
            var launch = field.equals("null-launch") ? null : LAUNCH;
            assertThatThrownBy(() -> new Pins(image, launch)).isInstanceOf(IllegalArgumentException.class);
            return;
        }
        if (field.equals("null-pins")) {
            assertThatThrownBy(() -> new Deployment(1, null)).isInstanceOf(IllegalArgumentException.class);
            return;
        }
        var deployment = field.equals("null-deployment") ? null : DEPLOYMENT;
        var subject = field.equals("null-subject") ? null : SUBJECT;
        var start = field.equals("null-start") ? null : NOW;
        var end = field.equals("null-end") ? null : field.equals("submicro") ? NOW.plusNanos(1) : NOW.plusSeconds(1);
        UUID evidence = UUID.randomUUID();
        assertThatThrownBy(() -> new Observation(deployment, subject, 1, evidence, start, end))
                .isInstanceOf(IllegalArgumentException.class);
    }
}
