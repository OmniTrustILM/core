package com.otilm.core.service.ai;

import com.otilm.core.aop.TraceMetadataOnly;
import com.otilm.core.model.ai.AiModelManagementSession.Facts;
import com.otilm.core.model.ai.AiModelManagementSession.Request;
import com.otilm.core.model.ai.AiModelManagementSession.Spec;
import com.otilm.core.model.ai.AiRuntimeState.Transition;
import com.otilm.core.security.ai.AiModelManagementAuthorization;
import com.otilm.core.service.writer.ai.AiModelManagementSessionWriter;
import java.util.Objects;
import java.util.UUID;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Propagation;
import org.springframework.transaction.annotation.Transactional;

/** Fresh CONNECT before short version-pinned session storage. No public route, profile or session publisher. */
@Service
@TraceMetadataOnly
public class AiModelManagementSessionService {
    private static final Logger LOG = LoggerFactory.getLogger(AiModelManagementSessionService.class);
    private static final String UNAVAILABLE_MESSAGE = "AI management session operation=begin code=UNAVAILABLE correlation={}";
    private final AiFeatureGate feature;
    private final AiModelManagementSessionWriter writer;
    private final AiModelManagementAuthorization authority;

    public AiModelManagementSessionService(AiModelManagementSessionWriter writer,
            AiModelManagementAuthorization authority, AiFeatureGate feature) {
        this.feature = Objects.requireNonNull(feature);
        this.writer = Objects.requireNonNull(writer);
        this.authority = Objects.requireNonNull(authority);
    }

    @Transactional(propagation = Propagation.NOT_SUPPORTED)
    public Transition<Facts> begin(Request request, AiRuntimeOperationBudget budget) {
        UUID correlation = UUID.randomUUID();
        Spec spec;
        try {
            feature.requireEnabled();
            Objects.requireNonNull(request);
            budget.remaining();
            var connection = writer
                    .connection(request.configurationId(), budget)
                    .orElseThrow(AiModelManagementSessionService::denied);
            budget.remaining();
            authority.requireConnect(request.actorId(), connection.id(), budget);
            budget.remaining();
            spec = new Spec(request.sessionId(), request.actorId(), connection, request.action(), request.expiresAt(),
                    request.maxCalls(), request.maxTokens());
        } catch (AccessDeniedException failure) {
            LOG.debug("AI management session operation=begin code=DENIED correlation={}", correlation);
            throw denied();
        } catch (AiRuntimeOperationBudget.Unavailable failure) {
            LOG.debug(UNAVAILABLE_MESSAGE, correlation);
            throw failure;
        } catch (RuntimeException failure) {
            LOG.warn(UNAVAILABLE_MESSAGE, correlation);
            throw failure;
        }
        try {
            var result = writer.create(spec, budget);
            budget.remaining();
            LOG
                    .debug("AI management session operation=begin code={} correlation={}", result.status().name(),
                            correlation);
            return result;
        } catch (RuntimeException failure) {
            LOG.warn(UNAVAILABLE_MESSAGE, correlation);
            // Internal persistence failure is not an Auth denial; future HTTP callers must map it to fixed errors.
            throw failure;
        }
    }

    private static AccessDeniedException denied() {
        return new AccessDeniedException("Management session authority unavailable");
    }
}
