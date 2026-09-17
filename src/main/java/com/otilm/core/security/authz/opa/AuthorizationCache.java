package com.otilm.core.security.authz.opa;

import com.otilm.core.security.authz.opa.dto.OpaObjectAccessResult;
import com.otilm.core.security.authz.opa.dto.OpaRequestDetails;
import com.otilm.core.security.authz.opa.dto.OpaRequestedResource;
import com.otilm.core.security.authz.opa.dto.OpaResourceAccessResult;
import java.util.function.Supplier;

/**
 * Serves OPA decisions from memory, invoking {@code loader} only on a miss.
 *
 * <p>
 * Entries are keyed by the caller's effective permissions rather than their identity, so two callers holding different
 * roles that grant the same access share one entry. See {@link AuthorizationCacheKeys} for what that reduction assumes
 * about the policies.
 */
public interface AuthorizationCache {

    OpaResourceAccessResult getOrCheckResourceAccess(String policyName, OpaRequestedResource resource, String principal,
            OpaRequestDetails details, Supplier<OpaResourceAccessResult> loader);

    OpaObjectAccessResult getOrCheckObjectAccess(String policyName, OpaRequestedResource resource, String principal,
            OpaRequestDetails details, Supplier<OpaObjectAccessResult> loader);

    /**
     * Clears both decision caches. The principal-digest memo is left alone: it maps a profile to its digest, so a
     * changed profile is a new entry rather than a stale one.
     *
     * <p>
     * Not required for correctness — a permission change alters the digest and makes existing entries unreachable on
     * its own. This bounds how long unreachable entries occupy memory, and gives an operator a lever that matches the
     * expectation that changing a role takes effect at once.
     */
    void evictAll();
}
