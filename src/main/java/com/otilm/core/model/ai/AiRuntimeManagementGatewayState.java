package com.otilm.core.model.ai;

import com.otilm.core.model.ai.AiRuntimeState.LaunchSpec;
import com.otilm.core.security.ai.RuntimeProxyCertificateClaims;
import java.time.Duration;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.UUID;

/** Trusted publisher data only. Constructing an observation does not attest or admit a workload. */
public final class AiRuntimeManagementGatewayState {
    private AiRuntimeManagementGatewayState() {
    }

    public record Pins(String imageDigest, LaunchSpec launch) {
        public Pins {
            if (imageDigest == null || !imageDigest.matches("sha256:[0-9a-f]{64}") || launch == null) {
                throw invalid();
            }
        }

        @Override
        public String toString() {
            return "ManagementGatewayPins[redacted]";
        }
    }

    public record Deployment(long revision, Pins pins) {
        public Deployment {
            if (revision < 1 || pins == null) {
                throw invalid();
            }
        }

        @Override
        public String toString() {
            return "ManagementGatewayDeployment[redacted]";
        }
    }

    public record Observation(Deployment deployment, RuntimeProxyCertificateClaims subject, long sequence,
            UUID evidenceId, Instant observedAt, Instant validUntil) {
        public Observation {
            if (deployment == null || subject == null || sequence < 1 || evidenceId == null || observedAt == null
                    || validUntil == null) {
                throw invalid();
            }
            observedAt = observedAt.truncatedTo(ChronoUnit.MICROS);
            validUntil = validUntil.truncatedTo(ChronoUnit.MICROS);
            var launch = deployment.pins().launch();
            if (!subject.cluster().equals(launch.cluster()) || !subject.namespace().equals(launch.namespaceName())
                    || !subject.serviceAccount().equals(launch.serviceAccountName()) || !observedAt.isBefore(validUntil)
                    || Duration.between(observedAt, validUntil).compareTo(Duration.ofSeconds(30)) > 0) {
                throw invalid();
            }
        }

        @Override
        public String toString() {
            return "ManagementGatewayObservation[redacted]";
        }
    }

    public record Registration(RuntimeProxyCertificateClaims subject, long deploymentRevision, long observationSequence,
            UUID evidenceId, Instant validUntil) {
        @Override
        public String toString() {
            return "ManagementGatewayRegistration[redacted]";
        }
    }

    private static IllegalArgumentException invalid() {
        return new IllegalArgumentException("Invalid management gateway data");
    }
}
