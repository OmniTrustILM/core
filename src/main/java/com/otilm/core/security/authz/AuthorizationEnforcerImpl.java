package com.otilm.core.security.authz;

import com.otilm.api.model.core.auth.Resource;
import com.otilm.core.model.auth.ResourceAction;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.authorization.AuthorizationDecision;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Component;

import java.util.Arrays;
import java.util.List;

@Component
public class AuthorizationEnforcerImpl implements AuthorizationEnforcer {

    private final ExternalAuthorizationCore core;

    public AuthorizationEnforcerImpl(ExternalAuthorizationCore core) {
        this.core = core;
    }

    @Override
    public void enforce(Resource resource, ResourceAction action, SecuredUUID... objectUuids) {
        enforce(resource, action, Arrays.asList(objectUuids));
    }

    @Override
    public void enforce(Resource resource, ResourceAction action, List<SecuredUUID> objectUuids) {
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        AuthorizationRequest request = AuthorizationRequest.forDirectCheck(resource, action, objectUuids);
        AuthorizationDecision decision = core.decide(authentication, request);
        if (!decision.isGranted()) {
            throw new AccessDeniedException("Access denied to %s:%s".formatted(resource.getCode(), action.getCode()));
        }
    }
}
