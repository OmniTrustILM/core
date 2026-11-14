package com.otilm.core.security.authz;

import com.otilm.api.model.core.auth.Resource;
import com.otilm.core.model.auth.ResourceAction;
import com.otilm.core.security.authn.client.AuthenticationInfo;
import java.time.Duration;
import java.util.List;
import java.util.UUID;
import org.springframework.security.access.AccessDeniedException;

/**
 * Imperative front door to the platform authorization check.
 *
 * <p>
 * The session-based methods use the same OPA policy and group/owner-association fallback as the declarative
 * {@code @ExternalAuthorization} path. The bounded current-principal overload requires fresh method and exact-object
 * votes without that fallback. Methods throw {@link AccessDeniedException} on denial and return normally on grant.
 *
 * <p>
 * <b>Runtime cost:</b> every call performs a blocking outbound HTTP request to OPA, and a denied direct check falls
 * back to owner/group repository reads plus one additional OPA request per object UUID. Do not hold a database row lock
 * or long transaction across a call.
 */
public interface AuthorizationEnforcer {

    /**
     * Authorizes {@code action} on {@code resource} for the given object UUIDs; with no UUIDs, checks the
     * resource-level permission only.
     */
    void enforce(Resource resource, ResourceAction action, SecuredUUID... objectUuids) throws AccessDeniedException;

    /**
     * Authorizes the whole set together in a single check: if access to any of the {@code objectUuids} is denied, the
     * check fails.
     */
    void enforce(Resource resource, ResourceAction action, List<SecuredUUID> objectUuids) throws AccessDeniedException;

    /**
     * Checks method and exact-object votes within the caller's remaining budget, without session, cache or owner/group
     * fallback. The caller must freshly resolve and verify the supplied principal before each call.
     */
    void enforce(Resource resource, ResourceAction action, AuthenticationInfo currentPrincipal, UUID objectUuid,
            Duration timeout) throws AccessDeniedException;

    /**
     * Whether {@code userUuid} may perform {@code action} on the object. For the current principal the decision is made
     * against its own authentication; for anybody else, against a principal resolved for them, and a user the auth
     * service can no longer resolve is denied.
     *
     * <p>
     * A principal resolved for somebody else leaves the current security context and the actor MDC untouched, so this
     * is safe to call while acting as somebody else. On top of the cost noted above, resolving a user asks the auth
     * service (cached).
     */
    boolean isAuthorizedAs(UUID userUuid, Resource resource, ResourceAction action, SecuredUUID objectUuid);
}
