package com.otilm.core.service.ai;

import com.otilm.core.aop.TraceMetadataOnly;
import com.otilm.core.model.ai.AiModelManagementOutcome.Result;
import com.otilm.core.security.ai.AiModelManagementAuthorization;
import com.otilm.core.service.writer.ai.AiModelManagementOutcomeWriter;
import com.otilm.core.service.writer.ai.AiModelManagementSessionWriter;
import java.util.Objects;
import java.util.Optional;
import java.util.UUID;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Propagation;
import org.springframework.transaction.annotation.Transactional;

/**
 * Protected reader only, with no public history route. Closed/expired sessions fail closed in this finite prototype.
 */
@Service
@TraceMetadataOnly
public class AiModelManagementResultService {
    private final AiModelManagementSessionWriter sessions;
    private final AiModelManagementOutcomeWriter outcomes;
    private final AiModelManagementAuthorization auth;

    public AiModelManagementResultService(AiModelManagementSessionWriter sessions,
            AiModelManagementOutcomeWriter outcomes, AiModelManagementAuthorization auth) {
        this.sessions = Objects.requireNonNull(sessions);
        this.outcomes = Objects.requireNonNull(outcomes);
        this.auth = Objects.requireNonNull(auth);
    }

    @Transactional(propagation = Propagation.NOT_SUPPORTED)
    public Optional<Result> read(UUID session, UUID intent, UUID actor, AiRuntimeOperationBudget budget) {
        budget.remaining();
        if (session == null || intent == null || actor == null) {
            throw denied();
        }
        var facts = sessions.metadata(session, budget).orElseThrow(AiModelManagementResultService::denied);
        budget.remaining();
        if (!facts.sessionId().equals(session) || !facts.actorId().equals(actor)) {
            throw denied();
        }
        try {
            auth.requireConnect(actor, facts.connection().id(), budget);
        } catch (AccessDeniedException failure) {
            throw denied();
        }
        budget.remaining();
        var result = outcomes.read(session, intent, actor, budget);
        budget.remaining();
        return result;
    }

    private static AccessDeniedException denied() {
        return new AccessDeniedException("Management result unavailable");
    }
}
