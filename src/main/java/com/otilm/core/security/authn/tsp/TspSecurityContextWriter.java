package com.otilm.core.security.authn.tsp;

import com.otilm.api.model.core.logging.enums.ActorType;
import com.otilm.core.logging.LoggingHelper;
import com.otilm.core.security.authn.PlatformAuthenticationToken;
import com.otilm.core.security.authn.PlatformUserDetails;
import com.otilm.core.security.authn.client.AuthenticationInfo;
import com.otilm.core.util.AuthHelper;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;

import java.util.UUID;

/**
 * Writes the authenticated identity into the {@link SecurityContext} on behalf of the TSP authenticators.
 * Centralizes the two ways a TSP request gains an authenticated principal: directly from an authenticated identity
 * (certificate / bearer token), or by proxying as a pre-configured mapped user (Basic password).
 */
public class TspSecurityContextWriter {

    private static final Logger log = LoggerFactory.getLogger(TspSecurityContextWriter.class);

    private final AuthHelper authHelper;

    public TspSecurityContextWriter(AuthHelper authHelper) {
        this.authHelper = authHelper;
    }

    /**
     * Populates the context from auth-service-resolved {@link AuthenticationInfo}.
     * Returns {@code false} (context untouched) for anonymous/empty info.
     */
    public boolean setFromAuthInfo(AuthenticationInfo authInfo) {
        if (authInfo == null || authInfo.isAnonymous()) {
            return false;
        }
        SecurityContext securityContext = SecurityContextHolder.createEmptyContext();
        securityContext.setAuthentication(new PlatformAuthenticationToken(new PlatformUserDetails(authInfo)));
        SecurityContextHolder.setContext(securityContext);
        // Attribute the TSP audit actor to the authenticated principal rather than a system user.
        LoggingHelper.putActorInfoWhenNull(ActorType.USER, authInfo.getUserUuid(), authInfo.getUsername());
        return true;
    }

    /**
     * Authenticates as the mapped user via the user-proxy. Returns {@code false} (and clears the context) if the proxy call fails.
     */
    public boolean authenticateAsUser(UUID mappedUserUuid) {
        try {
            authHelper.authenticateAsUser(mappedUserUuid);
            return true;
        } catch (RuntimeException e) {
            // The credential matched, but the user-proxy authentication call failed (e.g. auth service outage).
            // Leave the context unauthenticated and drop the actor attribution that authenticateAsUser set before
            // the failing proxy call, so the failure is not misattributed to the mapped user.
            SecurityContextHolder.clearContext();
            LoggingHelper.clearActorInfo();
            log.warn("TSP authentication: user-proxy authentication failed after credential match: {}", e.getMessage());
            return false;
        }
    }
}
