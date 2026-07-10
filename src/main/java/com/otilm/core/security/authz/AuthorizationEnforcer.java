package com.otilm.core.security.authz;

import com.otilm.api.model.core.auth.Resource;
import com.otilm.core.model.auth.ResourceAction;
import org.springframework.security.access.AccessDeniedException;

import java.util.List;

/**
 * Imperative front door to the platform authorization check.
 *
 * <p>Verifies that the currently authenticated principal may perform {@code action} on {@code resource} for the given
 * object UUIDs, using the same OPA {@code method} policy and group/owner-association fallback as the declarative
 * {@code @ExternalAuthorization} path. Throws {@link AccessDeniedException} on denial; returns normally on grant.
 *
 * <p><b>Runtime cost:</b> every call performs a blocking outbound HTTP request to OPA, and a denied direct check falls
 * back to owner/group repository reads plus one additional OPA request per object UUID. Do not hold a database row
 * lock or long transaction across a call (see CLAUDE.md, "Transactions and external calls").
 */
public interface AuthorizationEnforcer {

    /**
     * Authorizes {@code action} on {@code resource} for the given object UUIDs; with no UUIDs, checks the
     * resource-level permission only.
     */
    void enforce(Resource resource, ResourceAction action, SecuredUUID... objectUuids) throws AccessDeniedException;

    /**
     * Authorizes the whole set together in a single check: if access to any of the {@code objectUuids} is denied,
     * the check fails.
     */
    void enforce(Resource resource, ResourceAction action, List<SecuredUUID> objectUuids) throws AccessDeniedException;
}
