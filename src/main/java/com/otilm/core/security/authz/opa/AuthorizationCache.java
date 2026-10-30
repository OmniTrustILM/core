package com.otilm.core.security.authz.opa;

import com.otilm.core.security.authz.opa.dto.OpaObjectAccessResult;
import com.otilm.core.security.authz.opa.dto.OpaRequestDetails;
import com.otilm.core.security.authz.opa.dto.OpaRequestedResource;
import com.otilm.core.security.authz.opa.dto.OpaResourceAccessResult;
import java.util.function.Supplier;

/**
 * Serves OPA decisions from memory, invoking the loader only on a miss.
 *
 * <p>
 * <b>Keying.</b> Entries are keyed by the caller's effective permissions rather than their identity, so two callers
 * holding different roles that grant the same access share one entry. The key omits {@code principal.user} and
 * {@code principal.roles} because the method and object policies read only the effective permissions and the anonymous
 * username; a policy that starts reading further user fields requires revisiting the key.
 *
 * <p>
 * <b>Loading.</b> Concurrent misses on one key run the loader once and share its result. A loader that throws or
 * returns {@code null} leaves the entry absent, so the next caller loads again.
 *
 * <p>
 * <b>Bypass.</b> A {@code null} principal, a principal that is not a single JSON document, and a request that cannot be
 * rendered as a key all go straight to the loader without touching the cache.
 *
 * <p>
 * <b>Ownership.</b> Every returned object is a copy. The cached instance never leaves the cache, so a caller may mutate
 * what it receives without affecting other callers.
 */
public interface AuthorizationCache {

    /**
     * Returns the {@code method}-policy verdict for the request from the resource-decision cache, loading it on a miss.
     *
     * @param policyName OPA policy the decision belongs to
     * @param resource resource the decision is requested for
     * @param principal the caller's user profile as JSON; {@code null} bypasses the cache
     * @param details per-request details the policy may read
     * @param loader called on a miss to fetch the decision from OPA
     * @return the verdict, as a copy that is not the cached instance
     */
    OpaResourceAccessResult getOrCheckResourceAccess(String policyName, OpaRequestedResource resource, String principal,
            OpaRequestDetails details, Supplier<OpaResourceAccessResult> loader);

    /**
     * Returns the {@code objects}-policy filter for the request from the object-decision cache, loading it on a miss.
     *
     * @param policyName OPA policy the decision belongs to
     * @param resource resource the decision is requested for
     * @param principal the caller's user profile as JSON; {@code null} bypasses the cache
     * @param details per-request details the policy may read
     * @param loader called on a miss to fetch the filter from OPA
     * @return the object filter, as a copy that is not the cached instance
     */
    OpaObjectAccessResult getOrCheckObjectAccess(String policyName, OpaRequestedResource resource, String principal,
            OpaRequestDetails details, Supplier<OpaObjectAccessResult> loader);

    /**
     * Clears both decision caches.
     *
     * <p>
     * Not required for correctness — a permission change alters the digest and makes existing entries unreachable on
     * its own. This bounds how long unreachable entries occupy memory, and gives an operator a lever that matches the
     * expectation that changing a role takes effect at once.
     */
    void evictAll();
}
