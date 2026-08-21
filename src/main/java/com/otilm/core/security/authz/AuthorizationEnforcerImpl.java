package com.otilm.core.security.authz;

import com.otilm.api.model.core.auth.Resource;
import com.otilm.core.logging.LoggingHelper;
import com.otilm.core.model.auth.ResourceAction;
import com.otilm.core.security.authn.PlatformAuthenticationToken;
import com.otilm.core.security.authn.PlatformUserDetails;
import com.otilm.core.security.authn.client.AuthenticationInfo;
import com.otilm.core.security.authn.client.PlatformAuthenticationClient;
import java.util.Arrays;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.context.annotation.Lazy;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.authorization.AuthorizationDecision;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Component;

@Component
public class AuthorizationEnforcerImpl implements AuthorizationEnforcer {

    private static final Logger logger = LoggerFactory.getLogger(AuthorizationEnforcerImpl.class);

    private final ExternalAuthorizationCore core;
    private final PlatformAuthenticationClient authenticationClient;

    public AuthorizationEnforcerImpl(ExternalAuthorizationCore core,
            @Lazy PlatformAuthenticationClient authenticationClient) {
        this.core = core;
        this.authenticationClient = authenticationClient;
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

    @Override
    public boolean isAuthorizedAs(UUID userUuid, Resource resource, ResourceAction action, SecuredUUID objectUuid) {
        Authentication authentication = resolvePrincipal(userUuid);
        if (authentication == null) {
            return false;
        }
        AuthorizationRequest request = AuthorizationRequest.forDirectCheck(resource, action, List.of(objectUuid));
        return core.decide(authentication, request).isGranted();
    }

    /**
     * Resolving somebody replays their actor MDC, which would otherwise attribute the caller's own audited records to
     * the user being checked, so the caller's actor info is restored afterwards. A user the auth service answers for
     * anonymously no longer exists as a principal and gets no decision of their own.
     */
    private Authentication resolvePrincipal(UUID userUuid) {
        Map<String, String> callerActor = LoggingHelper.snapshotActorInfo();
        try {
            AuthenticationInfo info = authenticationClient.authenticateByUserUuid(userUuid);
            return info.isAnonymous() ? null : new PlatformAuthenticationToken(new PlatformUserDetails(info));
        } catch (Exception e) {
            logger.warn("Could not resolve user {} to authorize them: {}", userUuid, e.getMessage());
            return null;
        } finally {
            LoggingHelper.restoreActorInfo(callerActor);
        }
    }
}
