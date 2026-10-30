package com.otilm.core.security.authn.client;

import com.github.benmanes.caffeine.cache.RemovalCause;
import com.github.benmanes.caffeine.cache.RemovalListener;
import java.util.Set;
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;
import org.springframework.stereotype.Component;

/**
 * Secondary index: userUuid → set of opaque token-cache keys cached for that user. Each key is the settings-generation,
 * issuer and {@code jti} composite built by {@link PlatformAuthenticationCache}; this index treats it as an opaque
 * string and never parses it. Enables per-user token eviction when only the userUuid is known. Kept in sync
 * automatically via the Caffeine removal listener registered in CacheConfig.
 */
@Component
public class TokenJtiIndex implements RemovalListener<Object, Object> {

    private final ConcurrentHashMap<UUID, Set<String>> index = new ConcurrentHashMap<>();

    /** Called by Caffeine on every token cache eviction (TTL, size pressure, explicit, replace). */
    @Override
    public void onRemoval(Object key, Object value, RemovalCause cause) {
        if (!(key instanceof String cacheKey) || !(value instanceof AuthenticationInfo info)
                || info.getUserUuid() == null) {
            return;
        }
        index.computeIfPresent(UUID.fromString(info.getUserUuid()), (uuid, cacheKeys) -> {
            cacheKeys.remove(cacheKey);
            return cacheKeys.isEmpty() ? null : cacheKeys;
        });
    }

    public void add(UUID userUuid, String cacheKey) {
        if (userUuid == null) {
            throw new IllegalStateException("Authenticated result must contain a non-null userUuid");
        }
        index.computeIfAbsent(userUuid, k -> ConcurrentHashMap.newKeySet()).add(cacheKey);
    }

    /** Removes and returns all composite cache keys for the given user, or null if none. */
    public Set<String> removeUser(UUID userUuid) {
        return index.remove(userUuid);
    }

    public void clear() {
        index.clear();
    }
}
