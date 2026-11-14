package com.otilm.core.model.ai;

import com.otilm.core.model.ai.AiRuntimeState.LaunchSpec;
import com.otilm.core.security.ai.RuntimePeerRole;
import com.otilm.core.security.ai.RuntimeProxyCertificateClaims;
import java.time.Duration;
import java.time.Instant;
import java.util.Objects;
import java.util.UUID;

/** Trusted publisher inputs; constructing an observation is not workload attestation. */
public final class AiRuntimeGatewayState {
    private AiRuntimeGatewayState() {
    }

    public record Deployment(RuntimePeerRole role, long controlGeneration, String imageDigest, LaunchSpec launch) {
        public Deployment {
            if ((role != RuntimePeerRole.GATEWAY_RUN && role != RuntimePeerRole.GATEWAY_MANAGEMENT)
                    || controlGeneration <= 0 || imageDigest == null || !imageDigest.matches("sha256:[0-9a-f]{64}")
                    || launch == null) {
                throw invalid();
            }
        }
    }

    public record Observation(Deployment deployment, RuntimeProxyCertificateClaims subject, long sequence,
            UUID evidenceId, Instant observedAt, Instant validUntil) {
        public Observation {
            Objects.requireNonNull(deployment);
            Objects.requireNonNull(subject);
            if (!subject.cluster().equals(deployment.launch().cluster())
                    || !subject.namespace().equals(deployment.launch().namespaceName())
                    || !subject.serviceAccount().equals(deployment.launch().serviceAccountName()) || sequence <= 0
                    || evidenceId == null || observedAt == null || validUntil == null
                    || !observedAt.isBefore(validUntil)
                    || Duration.between(observedAt, validUntil).compareTo(Duration.ofSeconds(30)) > 0) {
                throw invalid();
            }
        }
    }

    public record Registration(RuntimePeerRole role, RuntimeProxyCertificateClaims subject, long controlGeneration,
            long observationSequence, UUID evidenceId, Instant validUntil) {
        @Override
        public String toString() {
            return "GatewayRegistration[role=" + role + "]";
        }
    }

    private static IllegalArgumentException invalid() {
        return new IllegalArgumentException("Invalid gateway registration");
    }
}
