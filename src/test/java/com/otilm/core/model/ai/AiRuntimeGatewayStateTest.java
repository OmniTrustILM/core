package com.otilm.core.model.ai;

import com.otilm.core.model.ai.AiRuntimeGatewayState.Deployment;
import com.otilm.core.model.ai.AiRuntimeGatewayState.Observation;
import com.otilm.core.model.ai.AiRuntimeState.LaunchSpec;
import com.otilm.core.security.ai.RuntimePeerRole;
import com.otilm.core.security.ai.RuntimeProxyCertificateClaims;
import java.time.Instant;
import java.util.UUID;
import java.util.stream.Stream;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class AiRuntimeGatewayStateTest {
    private static final Instant NOW = Instant.parse("2026-11-05T12:00:00Z");
    private static final LaunchSpec LAUNCH = new LaunchSpec("cluster-one", "gateways", "namespace-one", "gateway",
            "account-one", "sha256:" + "a".repeat(64), "sandbox");
    private static final String IMAGE = "sha256:" + "b".repeat(64);
    private static final Deployment DEPLOYMENT = new Deployment(RuntimePeerRole.GATEWAY_RUN, 1, IMAGE, LAUNCH);
    private static final RuntimeProxyCertificateClaims SUBJECT = new RuntimeProxyCertificateClaims("cluster-one",
            "gateways", "gateway", "gateway-one", UUID.randomUUID());

    @Test
    void acceptsTheTwoFixedGatewayAudiencesAndThirtySecondObservation() {
        assertThat(new Deployment(RuntimePeerRole.GATEWAY_MANAGEMENT, 1, IMAGE, LAUNCH).role())
                .isEqualTo(RuntimePeerRole.GATEWAY_MANAGEMENT);
        var observation = new Observation(DEPLOYMENT, SUBJECT, 1, UUID.randomUUID(), NOW, NOW.plusSeconds(30));
        assertThat(observation.subject()).isEqualTo(SUBJECT);
    }

    @ParameterizedTest
    @MethodSource("invalidDeploymentInputs")
    void rejectsUnusableDeploymentPins(DeploymentInput input) {
        assertThatThrownBy(() -> new Deployment(input.role(), input.generation(), input.image(), input.launch()))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessage("Invalid gateway registration")
                .hasNoCause();
    }

    static Stream<DeploymentInput> invalidDeploymentInputs() {
        return Stream
                .of(new DeploymentInput(null, 1, IMAGE, LAUNCH),
                        new DeploymentInput(RuntimePeerRole.RUNNER_PROXY, 1, IMAGE, LAUNCH),
                        new DeploymentInput(RuntimePeerRole.CONTROLLER, 1, IMAGE, LAUNCH),
                        new DeploymentInput(RuntimePeerRole.GATEWAY_RUN, 0, IMAGE, LAUNCH),
                        new DeploymentInput(RuntimePeerRole.GATEWAY_RUN, 1, null, LAUNCH),
                        new DeploymentInput(RuntimePeerRole.GATEWAY_RUN, 1, "tag:latest", LAUNCH),
                        new DeploymentInput(RuntimePeerRole.GATEWAY_RUN, 1, IMAGE, null));
    }

    @ParameterizedTest
    @MethodSource("invalidObservations")
    void rejectsInvalidObservationScopeAndFreshness(ObservationInput input) {
        assertThatThrownBy(() -> new Observation(DEPLOYMENT, input.subject(), input.sequence(), input.evidence(),
                input.observed(), input.until()))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessage("Invalid gateway registration")
                .hasNoCause();
    }

    static Stream<ObservationInput> invalidObservations() {
        UUID evidence = UUID.randomUUID();
        return Stream
                .of(new ObservationInput(new RuntimeProxyCertificateClaims("other", "gateways", "gateway",
                        "gateway-one", SUBJECT.podUid()), 1, evidence, NOW, NOW.plusSeconds(1)),
                        new ObservationInput(new RuntimeProxyCertificateClaims("cluster-one", "other", "gateway",
                                "gateway-one", SUBJECT.podUid()), 1, evidence, NOW, NOW.plusSeconds(1)),
                        new ObservationInput(new RuntimeProxyCertificateClaims("cluster-one", "gateways", "other",
                                "gateway-one", SUBJECT.podUid()), 1, evidence, NOW, NOW.plusSeconds(1)),
                        new ObservationInput(SUBJECT, 0, evidence, NOW, NOW.plusSeconds(1)),
                        new ObservationInput(SUBJECT, 1, null, NOW, NOW.plusSeconds(1)),
                        new ObservationInput(SUBJECT, 1, evidence, null, NOW.plusSeconds(1)),
                        new ObservationInput(SUBJECT, 1, evidence, NOW, null),
                        new ObservationInput(SUBJECT, 1, evidence, NOW, NOW),
                        new ObservationInput(SUBJECT, 1, evidence, NOW, NOW.minusSeconds(1)),
                        new ObservationInput(SUBJECT, 1, evidence, NOW, NOW.plusSeconds(30).plusNanos(1)));
    }

    record DeploymentInput(RuntimePeerRole role, long generation, String image, LaunchSpec launch) {
    }

    record ObservationInput(RuntimeProxyCertificateClaims subject, long sequence, UUID evidence, Instant observed,
            Instant until) {
    }
}
