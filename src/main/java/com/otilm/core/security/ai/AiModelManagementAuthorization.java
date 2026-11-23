package com.otilm.core.security.ai;

import com.otilm.api.model.core.auth.Resource;
import com.otilm.core.aop.TraceMetadataOnly;
import com.otilm.core.model.auth.ResourceAction;
import com.otilm.core.security.authn.client.PlatformAuthenticationClient;
import com.otilm.core.security.authz.AuthorizationEnforcer;
import com.otilm.core.security.authz.ExternalAuthorizationProgrammatic;
import com.otilm.core.service.ai.AiRuntimeOperationBudget;
import java.util.Objects;
import java.util.UUID;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.stereotype.Component;

/** Checks current model CONNECT only; session, current native management peer and fixed probe remain separate gates. */
@Component
@TraceMetadataOnly
public final class AiModelManagementAuthorization {
    private static final Logger LOG = LoggerFactory.getLogger(AiModelManagementAuthorization.class);
    private final PlatformAuthenticationClient authentication;
    private final AuthorizationEnforcer authorization;

    public AiModelManagementAuthorization(PlatformAuthenticationClient authentication,
            AuthorizationEnforcer authorization) {
        this.authentication = Objects.requireNonNull(authentication);
        this.authorization = Objects.requireNonNull(authorization);
    }

    @ExternalAuthorizationProgrammatic(resource = Resource.AI_MODEL, action = ResourceAction.CONNECT)
    public void requireConnect(UUID actor, UUID model, AiRuntimeOperationBudget budget) {
        UUID correlation = UUID.randomUUID();
        try {
            Objects.requireNonNull(actor);
            Objects.requireNonNull(model);
            var principal = authentication.authenticateByUserUuidAuthoritatively(actor, budget.remaining());
            budget.remaining();
            authorization.enforce(Resource.AI_MODEL, ResourceAction.CONNECT, principal, model, budget.remaining());
            budget.remaining();
            LOG.debug("AI model authorization operation=connect code=AUTHORIZED correlation={}", correlation);
        } catch (Exception failure) {
            LOG.debug("AI model authorization operation=connect code=DENIED correlation={}", correlation);
            throw denied();
        }
    }

    private static AccessDeniedException denied() {
        return new AccessDeniedException("Model connection authority unavailable");
    }
}
