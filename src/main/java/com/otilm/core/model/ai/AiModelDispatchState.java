package com.otilm.core.model.ai;

import com.otilm.ai.runtime.protocol.ManagementAction;
import com.otilm.ai.runtime.protocol.PayloadFingerprint;
import com.otilm.core.model.ai.AiRuntimeState.ClaimBinding;
import com.otilm.core.model.ai.AiRuntimeState.Expected;
import java.net.URI;
import java.time.Instant;
import java.util.Arrays;
import java.util.Objects;
import java.util.UUID;

/** Persisted/reference structure only. Construction grants no model use, identity, approval or send authority. */
public final class AiModelDispatchState {
    private AiModelDispatchState() {
    }

    public record ConnectionVersion(UUID id, long configuration, long destination, long authentication,
            String modelIdentifier) {
        public ConnectionVersion {
            Objects.requireNonNull(id);
            positive(configuration);
            positive(destination);
            positive(authentication);
            if (!validModelIdentifier(modelIdentifier)) {
                throw invalid();
            }
        }
    }

    // Own exact bounded bytes. This is not JSON validation or authority.
    public record ExactPayload(byte[] bytes) {
        public ExactPayload {
            Objects.requireNonNull(bytes);
            if (bytes.length == 0 || bytes.length > 1048576) {
                throw invalid();
            }
            bytes = bytes.clone();
        }

        @Override
        public byte[] bytes() {
            return bytes.clone();
        }

        public String sha256() {
            return PayloadFingerprint.sha256(bytes);
        }

        @Override
        public boolean equals(Object other) {
            return other instanceof ExactPayload payload && Arrays.equals(bytes, payload.bytes);
        }

        @Override
        public int hashCode() {
            return Arrays.hashCode(bytes);
        }

        @Override
        public String toString() {
            return "ExactPayload[redacted]";
        }
    }

    public record RunPreparation(UUID intentId, UUID requestKey, Expected expected, ClaimBinding claim,
            ConnectionVersion connection, ExactPayload payload, int outputTokens, Instant expiresAt) {
        public RunPreparation {
            Objects.requireNonNull(intentId);
            Objects.requireNonNull(requestKey);
            sameClaim(expected, claim);
            Objects.requireNonNull(connection);
            Objects.requireNonNull(payload);
            positive(outputTokens);
            Objects.requireNonNull(expiresAt);
        }
    }

    public record ManagementPreparation(UUID intentId, UUID requestKey, UUID actorId, UUID sessionId,
            ManagementAction action, ConnectionVersion connection, ExactPayload payload, int outputTokens,
            Instant expiresAt) {
        public ManagementPreparation {
            Objects.requireNonNull(intentId);
            Objects.requireNonNull(requestKey);
            Objects.requireNonNull(actorId);
            Objects.requireNonNull(sessionId);
            Objects.requireNonNull(action);
            Objects.requireNonNull(connection);
            Objects.requireNonNull(payload);
            positive(outputTokens);
            Objects.requireNonNull(expiresAt);
        }
    }

    public record RunRedemption(UUID intentId, Expected expected, ClaimBinding claim, ConnectionVersion connection,
            String payloadSha256, Instant expiresAt, UUID gatewayCorrelation) {
        public RunRedemption {
            Objects.requireNonNull(intentId);
            sameClaim(expected, claim);
            Objects.requireNonNull(connection);
            digest(payloadSha256);
            Objects.requireNonNull(expiresAt);
            Objects.requireNonNull(gatewayCorrelation);
        }
    }

    public record RunIntent(UUID intentId, UUID actorId, ClaimBinding claim, ConnectionVersion connection,
            ExactPayload payload, int outputTokens, Instant expiresAt) {
        public RunIntent {
            Objects.requireNonNull(intentId);
            Objects.requireNonNull(actorId);
            Objects.requireNonNull(claim);
            Objects.requireNonNull(connection);
            Objects.requireNonNull(payload);
            Objects.requireNonNull(expiresAt);
            if (!AiModelDispatchPayload.hasModelAndOutputLimit(payload, outputTokens, connection.modelIdentifier())) {
                throw invalid();
            }
        }

        @Override
        public String toString() {
            return "RunIntent[redacted]";
        }
    }

    public record ManagementIntent(UUID intentId, UUID actorId, UUID sessionId, ManagementAction action,
            ConnectionVersion connection, ExactPayload payload, int outputTokens, Instant expiresAt) {
        public ManagementIntent {
            Objects.requireNonNull(intentId);
            Objects.requireNonNull(actorId);
            Objects.requireNonNull(sessionId);
            Objects.requireNonNull(action);
            Objects.requireNonNull(connection);
            Objects.requireNonNull(payload);
            Objects.requireNonNull(expiresAt);
            if (!AiModelDispatchPayload.hasModelAndOutputLimit(payload, outputTokens, connection.modelIdentifier())) {
                throw invalid();
            }
        }

        @Override
        public String toString() {
            return "ManagementIntent[redacted]";
        }
    }

    public record ManagementRedemption(UUID intentId, UUID actorId, UUID sessionId, ManagementAction action,
            ConnectionVersion connection, String payloadSha256, Instant expiresAt, UUID gatewayCorrelation) {
        public ManagementRedemption {
            Objects.requireNonNull(intentId);
            Objects.requireNonNull(actorId);
            Objects.requireNonNull(sessionId);
            Objects.requireNonNull(action);
            Objects.requireNonNull(connection);
            digest(payloadSha256);
            Objects.requireNonNull(expiresAt);
            Objects.requireNonNull(gatewayCorrelation);
        }
    }

    public record ResolvedDispatch(UUID intentId, ConnectionVersion connection, ExactPayload payload, int outputTokens,
            URI origin, String credentialReference, Instant expiresAt, UUID gatewayCorrelation) {
        public ResolvedDispatch {
            Objects.requireNonNull(intentId);
            Objects.requireNonNull(connection);
            Objects.requireNonNull(payload);
            positive(outputTokens);
            Objects.requireNonNull(origin);
            if (!AiModelDispatchPayload.hasModelAndOutputLimit(payload, outputTokens, connection.modelIdentifier())
                    || !"https".equals(origin.getScheme()) || origin.getHost() == null || origin.getHost().isBlank()
                    || origin.getRawUserInfo() != null || origin.getRawQuery() != null
                    || origin.getRawFragment() != null
                    || (origin.getRawPath() != null && !origin.getRawPath().isEmpty()
                            && !origin.getRawPath().equals("/"))
                    || (origin.getPort() != -1 && (origin.getPort() < 1 || origin.getPort() > 65535))) {
                throw invalid();
            }
            Objects.requireNonNull(credentialReference);
            Objects.requireNonNull(expiresAt);
            Objects.requireNonNull(gatewayCorrelation);
            if (!credentialReference.matches("[a-z][a-z0-9-]{0,63}")) {
                throw invalid();
            }
        }
    }

    static boolean validModelIdentifier(String value) {
        if (value == null || value.isBlank() || value.indexOf(0) >= 0
                || value.codePointCount(0, value.length()) > 255) {
            return false;
        }
        int index = 0;
        while (index < value.length()) {
            char current = value.charAt(index);
            if (Character.isHighSurrogate(current)) {
                if (index + 1 >= value.length() || !Character.isLowSurrogate(value.charAt(index + 1))) {
                    return false;
                }
                index += 2;
            } else if (Character.isLowSurrogate(current)) {
                return false;
            } else {
                index++;
            }
        }
        return true;
    }

    private static void sameClaim(Expected expected, ClaimBinding claim) {
        Objects.requireNonNull(expected);
        Objects.requireNonNull(claim);
        if (!expected.runId().equals(claim.runId()) || !expected.attemptId().equals(claim.attemptId())
                || expected.fence() != claim.fence()) {
            throw invalid();
        }
    }

    private static void digest(String value) {
        if (!Objects.requireNonNull(value).matches("[0-9a-f]{64}")) {
            throw invalid();
        }
    }

    private static void positive(long value) {
        if (value < 1) {
            throw invalid();
        }
    }

    private static IllegalArgumentException invalid() {
        return new IllegalArgumentException("Invalid model dispatch reference");
    }
}
