package com.otilm.core.model.ai;

import com.otilm.ai.runtime.protocol.ManagementAction;
import com.otilm.core.model.ai.AiModelDispatchState.ConnectionVersion;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.UUID;

/** Trusted Core operation data only. No construction, session identifier or field supplies CONNECT authority. */
public final class AiModelManagementSession {
    private AiModelManagementSession() {
    }

    public record Request(UUID sessionId, UUID actorId, UUID configurationId, ManagementAction action,
            Instant expiresAt, long maxCalls, long maxTokens) {
        public Request {
            if (configurationId == null) {
                throw invalid();
            }
            expiresAt = finite(sessionId, actorId, action, expiresAt, maxCalls, maxTokens);
        }

        @Override
        public String toString() {
            return "ManagementSessionRequest[redacted]";
        }
    }

    public record Spec(UUID sessionId, UUID actorId, ConnectionVersion connection, ManagementAction action,
            Instant expiresAt, long maxCalls, long maxTokens) {
        public Spec {
            if (connection == null) {
                throw invalid();
            }
            expiresAt = finite(sessionId, actorId, action, expiresAt, maxCalls, maxTokens);
        }

        @Override
        public String toString() {
            return "ManagementSessionSpec[redacted]";
        }
    }

    public record Facts(UUID sessionId, UUID actorId, ConnectionVersion connection, ManagementAction action,
            Instant expiresAt, long maxCalls, long maxTokens, long reservedCalls, long reservedTokens) {
        public Facts {
            if (connection == null) {
                throw invalid();
            }
            expiresAt = finite(sessionId, actorId, action, expiresAt, maxCalls, maxTokens);
            if (reservedCalls < 0 || reservedTokens < 0 || reservedCalls > maxCalls || reservedTokens > maxTokens) {
                throw invalid();
            }
        }

        @Override
        public String toString() {
            return "ManagementSessionFacts[redacted]";
        }
    }

    private static Instant finite(UUID session, UUID actor, ManagementAction action, Instant expiry, long calls,
            long tokens) {
        if (session == null || actor == null || action == null || expiry == null || calls < 1 || tokens < 1) {
            throw invalid();
        }
        return expiry.truncatedTo(ChronoUnit.MICROS);
    }

    private static IllegalArgumentException invalid() {
        return new IllegalArgumentException("Invalid management session data");
    }
}
