package com.czertainly.core.security.authn.client;

import com.github.benmanes.caffeine.cache.RemovalCause;
import com.github.benmanes.caffeine.cache.RemovalListener;
import org.springframework.stereotype.Component;

import java.util.Set;
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Secondary index: userUuid → set of JTI claims cached for that user.
 * Enables per-user token eviction when only the userUuid is known.
 * Kept in sync automatically via the Caffeine removal listener registered in CacheConfig.
 */
@Component
public class TokenJtiIndex implements RemovalListener<Object, Object> {

    private final ConcurrentHashMap<UUID, Set<String>> index = new ConcurrentHashMap<>();

    /** Called by Caffeine on every token cache eviction (TTL, size pressure, explicit, replace). */
    @Override
    public void onRemoval(Object key, Object value, RemovalCause cause) {
        if (!(key instanceof String jti) || !(value instanceof AuthenticationInfo info) || info.getUserUuid() == null) return;
        index.computeIfPresent(UUID.fromString(info.getUserUuid()), (uuid, jtis) -> {
            jtis.remove(jti);
            return jtis.isEmpty() ? null : jtis;
        });
    }

    public void add(UUID userUuid, String jti) {
        if (userUuid == null) {
            throw new IllegalStateException("Authenticated result must contain a non-null userUuid");
        }
        index.computeIfAbsent(userUuid, k -> ConcurrentHashMap.newKeySet()).add(jti);
    }

    /** Removes and returns all JTIs for the given user, or null if none. */
    public Set<String> removeUser(UUID userUuid) {
        return index.remove(userUuid);
    }

    public void clear() {
        index.clear();
    }
}
