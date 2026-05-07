package com.czertainly.core.security.authn.client;

import java.util.UUID;
import java.util.function.Supplier;

public interface AuthenticationCache {

    /**
     * Returns cached authentication for a system user, or invokes {@code loader} and caches the result.
     * Cached by username. System usernames (superadmin, acme, scep, …) are stable identifiers
     * that never change, so the cache entry remains valid for its full TTL.
     *
     * @param username system username used as the cache key
     * @param loader   called on a cache miss to produce the {@link AuthenticationInfo}
     * @return the cached or freshly loaded {@link AuthenticationInfo}
     */
    AuthenticationInfo getOrAuthenticateSystemUser(String username, Supplier<AuthenticationInfo> loader);

    /**
     * Returns cached authentication for a user identified by UUID, or invokes {@code loader} and caches the result.
     * Effective for repeated internal impersonation calls within the TTL window.
     *
     * @param userUuid UUID of the user, used as the cache key
     * @param loader   called on a cache miss to produce the {@link AuthenticationInfo}
     * @return the cached or freshly loaded {@link AuthenticationInfo}
     */
    AuthenticationInfo getOrAuthenticateByUserUuid(UUID userUuid, Supplier<AuthenticationInfo> loader);

    /**
     * Returns cached authentication for a client-certificate request, or invokes {@code loader} and caches the result.
     * Cached by SHA-256 of the DER-encoded certificate bytes (computed in CzertainlyAuthenticationFilter),
     * matching the DB {@code certificate.fingerprint} field. All requests carrying the same client certificate
     * share one cache entry. The entry is evicted immediately on revocation via CertificateServiceImpl.
     *
     * @param thumbprint SHA-256 fingerprint of the client certificate, used as the cache key
     * @param loader     called on a cache miss to produce the {@link AuthenticationInfo}
     * @return the cached or freshly loaded {@link AuthenticationInfo}
     */
    AuthenticationInfo getOrAuthenticateByCertificate(String thumbprint, Supplier<AuthenticationInfo> loader);

    /**
     * Returns cached authentication for a bearer-token request, or invokes {@code loader} and caches the result.
     * Cached by the {@code jti} claim, which is unique per token issuance. All requests that carry the same
     * access token share one cache entry for its lifetime. When the token is refreshed, a new {@code jti}
     * causes a cache miss, triggering a fresh auth-service call. Tokens without a {@code jti} are never cached.
     *
     * @param jti    the {@code jti} claim of the access token, used as the cache key; {@code null} skips caching
     * @param loader called on a cache miss to produce the {@link AuthenticationInfo}
     * @return the cached or freshly loaded {@link AuthenticationInfo}
     */
    AuthenticationInfo getOrAuthenticateByToken(String jti, Supplier<AuthenticationInfo> loader);

    /**
     * Evicts all auth cache entries for a single user: their UUID entry, all token entries tracked
     * in the jti index, and their certificate entry tracked in the certificate index.
     * Use this for user-scoped changes (role assignment, disable, delete, certificate revocation)
     * where only one user is affected and the system-user cache can be left untouched.
     *
     * @param userUuid UUID of the user whose cache entries should be evicted
     */
    void evictByUserUuid(UUID userUuid);

    /**
     * Evicts only the certificate-based auth cache entry for the given fingerprint.
     * Use this when a certificate is disassociated from a user but the user's identity and
     * roles are unchanged — their UUID and token cache entries remain valid.
     *
     * @param certFingerprint SHA-256 fingerprint of the certificate to evict
     */
    void evictByCertificateFingerprint(String certFingerprint);

    /**
     * Clears all four auth caches and the jti index (the per-user map of {@code jti} claims used to
     * find and evict token cache entries when a user is modified). Use this for role-level mutations
     * (permission changes, role deletion) that may affect any user, including system accounts.
     */
    void evictAll();
}
