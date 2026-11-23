package com.otilm.core.service.ai;

import com.otilm.ai.runtime.protocol.ManagementAction;
import com.otilm.ai.runtime.protocol.ManagementBinding;
import com.otilm.ai.runtime.protocol.ManagementDispatchEnvelope;
import com.otilm.ai.runtime.protocol.RuntimeErrorCode;
import com.otilm.api.exception.PlatformException;
import com.otilm.core.aop.TraceMetadataOnly;
import com.otilm.core.model.ai.AiModelDispatchPayload;
import com.otilm.core.model.ai.AiModelDispatchState.ManagementIntent;
import com.otilm.core.model.ai.AiModelDispatchState.ManagementPreparation;
import com.otilm.core.model.ai.AiModelDispatchState.ManagementRedemption;
import com.otilm.core.model.ai.AiModelDispatchState.ResolvedDispatch;
import com.otilm.core.model.ai.AiModelManagementSession.Facts;
import com.otilm.core.model.ai.AiRuntimeState.Transition;
import com.otilm.core.security.ai.AiModelManagementAuthorization;
import com.otilm.core.security.ai.RuntimePeer;
import com.otilm.core.security.ai.RuntimePeerRole;
import com.otilm.core.service.writer.ai.AiModelDispatchWriter;
import com.otilm.core.service.writer.ai.AiModelManagementSessionWriter;
import java.util.Objects;
import java.util.Optional;
import java.util.UUID;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Propagation;
import org.springframework.transaction.annotation.Transactional;

/** Core-selected finite probes only. Every prepare/redemption requires the stored actor's fresh CONNECT. */
@Service
@TraceMetadataOnly
public class AiModelManagementDispatchService {
    private static final Logger LOG = LoggerFactory.getLogger(AiModelManagementDispatchService.class);
    private final AiFeatureGate feature;
    private final AiModelManagementSessionWriter sessions;
    private final AiModelDispatchWriter writer;
    private final AiModelManagementAuthorization auth;

    public AiModelManagementDispatchService(AiModelManagementSessionWriter sessions, AiModelDispatchWriter writer,
            AiModelManagementAuthorization auth, AiFeatureGate feature) {
        this.feature = Objects.requireNonNull(feature);
        this.sessions = Objects.requireNonNull(sessions);
        this.writer = Objects.requireNonNull(writer);
        this.auth = Objects.requireNonNull(auth);
    }

    @Transactional(propagation = Propagation.NOT_SUPPORTED)
    public Transition<ManagementDispatchEnvelope> prepare(UUID session, UUID key, AiRuntimeOperationBudget budget) {
        boolean writerStarted = false;
        try {
            feature.requireEnabled();
            Objects.requireNonNull(key);
            var facts = facts(session, budget);
            auth.requireConnect(facts.actorId(), facts.connection().id(), budget);
            budget.remaining();
            var previous = writer.preparedManagementByKey(session, key, budget);
            budget.remaining();
            ManagementIntent intent;
            if (previous.isPresent()) {
                intent = previous.orElseThrow();
                requireIntent(intent, facts);
            } else {
                int tokens = (int) Math.min(32, facts.maxTokens());
                var payload = AiModelDispatchPayload
                        .text(facts.connection().modelIdentifier(), tokens,
                                "Execute only this finite Core management probe.",
                                facts.action() == ManagementAction.CONNECTION_CHECK
                                        ? "Reply with OK."
                                        : "Reply with a short plain text confirmation.",
                                "");
                intent = new ManagementIntent(UUID.randomUUID(), facts.actorId(), session, facts.action(),
                        facts.connection(), payload, tokens, facts.expiresAt());
            }
            var q = new ManagementPreparation(intent.intentId(), key, facts.actorId(), session, facts.action(),
                    facts.connection(), intent.payload(), intent.outputTokens(), intent.expiresAt());
            var envelope = envelope(intent);
            budget.remaining();
            writerStarted = true;
            var result = writer.prepareManagement(q, facts.actorId(), budget);
            budget.remaining();
            LOG.debug("AI management operation=prepare code={}", result.status().name());
            return result.value().isEmpty()
                    ? Transition.empty(result.status())
                    : Transition
                            .value(result.status(), new ManagementDispatchEnvelope(1, result.value().orElseThrow(),
                                    envelope.payloadSha256(), envelope.binding()));
        } catch (RuntimeException failure) {
            throw failure("prepare", writerStarted, budget, failure);
        }
    }

    @Transactional(propagation = Propagation.NOT_SUPPORTED)
    public Optional<ResolvedDispatch> consume(ManagementDispatchEnvelope envelope, UUID correlation, RuntimePeer peer,
            AiRuntimeOperationBudget budget) {
        boolean writerStarted = false;
        try {
            feature.requireEnabled();
            if (peer == null || peer.role() != RuntimePeerRole.GATEWAY_MANAGEMENT) {
                throw denied();
            }
            Objects.requireNonNull(correlation);
            var wire = Objects.requireNonNull(envelope).binding();
            var facts = facts(wire.sessionId(), budget);
            if (!binding(facts).equals(wire)) {
                throw denied();
            }
            auth.requireConnect(facts.actorId(), facts.connection().id(), budget);
            budget.remaining();
            var intent = writer
                    .preparedManagementById(facts.sessionId(), envelope.intentId(), budget)
                    .orElseThrow(AiModelManagementDispatchService::denied);
            budget.remaining();
            requireIntent(intent, facts);
            if (!envelope(intent).equals(envelope)) {
                throw denied();
            }
            var q = new ManagementRedemption(intent.intentId(), facts.actorId(), facts.sessionId(), facts.action(),
                    facts.connection(), intent.payload().sha256(), intent.expiresAt(), correlation);
            budget.remaining();
            writerStarted = true;
            var result = writer.consumeManagement(q, facts.actorId(), peer, budget);
            budget.remaining();
            LOG.debug("AI management operation=consume code={}", result.isPresent() ? "CONSUMED" : "DENIED");
            return result;
        } catch (RuntimeException failure) {
            throw failure("consume", writerStarted, budget, failure);
        }
    }

    private Facts facts(UUID session, AiRuntimeOperationBudget budget) {
        budget.remaining();
        var facts = sessions
                .metadata(Objects.requireNonNull(session), budget)
                .orElseThrow(AiModelManagementDispatchService::denied);
        budget.remaining();
        if (!facts.sessionId().equals(session)) {
            throw denied();
        }
        return facts;
    }

    private static void requireIntent(ManagementIntent intent, Facts facts) {
        if (!intent.actorId().equals(facts.actorId()) || !intent.sessionId().equals(facts.sessionId())
                || intent.action() != facts.action() || !intent.connection().equals(facts.connection())
                || intent.outputTokens() != Math.min(32, facts.maxTokens())
                || !intent.expiresAt().equals(facts.expiresAt())) {
            throw denied();
        }
    }

    private static ManagementBinding binding(Facts facts) {
        return new ManagementBinding(facts.actorId(), facts.sessionId(), facts.connection().id(),
                facts.connection().configuration(), facts.action(), facts.expiresAt());
    }

    private static ManagementDispatchEnvelope envelope(ManagementIntent intent) {
        return new ManagementDispatchEnvelope(1, intent.intentId(), intent.payload().sha256(),
                new ManagementBinding(intent.actorId(), intent.sessionId(), intent.connection().id(),
                        intent.connection().configuration(), intent.action(), intent.expiresAt()));
    }

    private static AccessDeniedException denied() {
        return new AccessDeniedException("Management operation unavailable");
    }

    private static Failure failure(String operation, boolean writerStarted, AiRuntimeOperationBudget budget,
            RuntimeException failure) {
        RuntimeErrorCode code = RuntimeErrorCode.UNAVAILABLE;
        if (writerStarted) {
            code = RuntimeErrorCode.UNKNOWN_OUTCOME;
        } else if (Thread.currentThread().isInterrupted()) {
            code = RuntimeErrorCode.INTERRUPTED;
        } else {
            boolean exhausted = false;
            try {
                budget.remaining();
            } catch (AiRuntimeOperationBudget.Unavailable unavailable) {
                exhausted = true;
            }
            if (!exhausted && failure instanceof AccessDeniedException) {
                code = RuntimeErrorCode.DENIED;
            }
        }
        LOG.debug("AI management operation={} code={}", operation, code.name());
        return new Failure(code);
    }

    public static final class Failure extends RuntimeException implements PlatformException {
        private static final long serialVersionUID = 1L;
        private final RuntimeErrorCode code;

        private Failure(RuntimeErrorCode code) {
            super("Management operation unavailable", null, false, false);
            this.code = code;
        }

        public RuntimeErrorCode code() {
            return code;
        }
    }
}
