package com.czertainly.core.security.authn.client;

import com.github.benmanes.caffeine.cache.RemovalCause;
import com.github.benmanes.caffeine.cache.RemovalListener;
import org.springframework.stereotype.Component;

import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Secondary index: userUuid → certificate fingerprint cached for that user.
 * Enables per-user certificate eviction when only the userUuid is known.
 * Kept in sync automatically via the Caffeine removal listener registered in CacheConfig.
 */
@Component
public class UserCertificateIndex implements RemovalListener<Object, Object> {

    private final ConcurrentHashMap<UUID, String> index = new ConcurrentHashMap<>();

    /** Called by Caffeine on every certificate cache eviction (TTL, size pressure, explicit, replace). */
    @Override
    public void onRemoval(Object key, Object value, RemovalCause cause) {
        if (!(key instanceof String fingerprint) || !(value instanceof AuthenticationInfo info) || info.getUserUuid() == null) return;
        index.computeIfPresent(UUID.fromString(info.getUserUuid()), (uuid, fp) -> fp.equals(fingerprint) ? null : fp);
    }

    public void add(UUID userUuid, String fingerprint) {
        if (userUuid == null) {
            throw new IllegalStateException("Authenticated result must contain a non-null userUuid");
        }
        index.put(userUuid, fingerprint);
    }

    /** Removes and returns the fingerprint for the given user, or null if none. */
    public String removeUser(UUID userUuid) {
        return index.remove(userUuid);
    }

    public void clear() {
        index.clear();
    }
}
