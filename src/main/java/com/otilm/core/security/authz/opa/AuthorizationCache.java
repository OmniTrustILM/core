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
 * roles that grant the same access share one entry. The key omits {@code principal.user} and {@code principal.roles}
 * because the method and object policies read only the effective permissions and the anonymous username; a policy that
 * starts reading further user fields requires revisiting the key.
 */
public interface AuthorizationCache {

    /**
     * Returns the verdict held for this policy, permission set, requested resource and request details, or invokes
     * {@code loader} and holds its result in the resource-decision cache. Concurrent misses on one key run
     * {@code loader} once and share its result. A {@code loader} that throws or returns {@code null} leaves the entry
     * absent, so the next caller loads again. A {@code null} principal, a principal that is not a single JSON document,
     * and a request that cannot be rendered as a key all go straight to {@code loader} without touching the cache. The
     * returned object is a copy the caller may mutate.
     *
     * @param policyName OPA policy the decision belongs to
     * @param resource resource the decision is requested for
     * @param principal the caller's user profile as JSON; {@code null} bypasses the cache
     * @param details per-request details the policy may read
     * @param loader called on a miss to fetch the decision from OPA
     * @return the decision, as a copy that is not the cached instance
     */
    OpaResourceAccessResult getOrCheckResourceAccess(String policyName, OpaRequestedResource resource, String principal,
            OpaRequestDetails details, Supplier<OpaResourceAccessResult> loader);

    /**
     * Returns the object filter held for this policy, permission set, requested resource and request details, or
     * invokes {@code loader} and holds its result in the object-decision cache. Concurrent misses on one key run
     * {@code loader} once and share its result. A {@code loader} that throws or returns {@code null} leaves the entry
     * absent, so the next caller loads again. A {@code null} principal, a principal that is not a single JSON document,
     * and a request that cannot be rendered as a key all go straight to {@code loader} without touching the cache. The
     * returned object is a copy the caller may mutate.
     *
     * @param policyName OPA policy the decision belongs to
     * @param resource resource the decision is requested for
     * @param principal the caller's user profile as JSON; {@code null} bypasses the cache
     * @param details per-request details the policy may read
     * @param loader called on a miss to fetch the decision from OPA
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
