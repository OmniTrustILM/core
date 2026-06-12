package com.otilm.core.security.authn.client;

import java.util.Optional;
import java.util.UUID;

/**
 * Positive-only, peppered verification cache for TSP credential authentication.
 *
 * <p>Only successful authentication verifications are stored; callers must never invoke {@link #putSuccess}
 * on a failed authentication. The cache key is an HMAC-SHA-256 over {@code secretUuid + ":" + password}
 * using a per-process pepper (never persisted), so raw passwords are never stored or reconstructable from cache state.</p>
 *
 * <p><b>Staleness contract.</b> Method {@link #getMappedUser} does <b>not</b> re-check per-request liveness of the
 * mapped user. Eviction is tied to credential lifecycle only: password rotation, mapped-user reassignment,
 * credential deletion, and secret-content updates (see {@link #evictBySecretUuid}). Account-level changes that do
 * not touch the credential — notably a mapped user being <b>disabled or deprovisioned</b> — are NOT evicted.
 * This is a deliberately accepted, TTL-bounded trade-off: user-disable is rare and a per-request liveness check on the
 * signing hot-path is not affordable.</p>
 */
public interface CredentialVerificationCache {

    /**
     * @return resolved mapped user UUID if this exact (secret, password) was verified
     *         successfully and is still cached; empty if not cached or already evicted.
     */
    Optional<UUID> getMappedUser(UUID secretUuid, String password);

    /**
     * Cache a SUCCESSFUL verification only. Never call on failure.
     *
     * @param secretUuid    the credential secret UUID
     * @param password      the raw password (used only to derive the HMAC key; not stored)
     * @param mappedUserUuid the user UUID resolved during the successful verification
     */
    void putSuccess(UUID secretUuid, String password, UUID mappedUserUuid);

    /**
     * Evict all cache entries associated with the given secret UUID.
     * Called whenever the verified mapping could change: password rotation, mapped-user reassignment,
     * credential deletion, and secret-content updates — so stale positive hits are cleared immediately.
     */
    void evictBySecretUuid(UUID secretUuid);
}
