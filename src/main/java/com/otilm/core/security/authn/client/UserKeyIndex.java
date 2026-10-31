package com.otilm.core.security.authn.client;

import com.github.benmanes.caffeine.cache.RemovalCause;
import com.github.benmanes.caffeine.cache.RemovalListener;
import java.util.Collections;
import java.util.HashMap;
import java.util.IdentityHashMap;
import java.util.Map;
import java.util.Set;
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Secondary index: userUuid → the cache keys of that user's results, each with the results its loads produced. Enables
 * per-user eviction when only the userUuid is known.
 */
public abstract class UserKeyIndex implements RemovalListener<Object, Object> {

    private final ConcurrentHashMap<UUID, Map<String, Set<AuthenticationInfo>>> index = new ConcurrentHashMap<>();

    /**
     * Unlists the key once every load that listed it is removed. A load dropped while running reports its removal only
     * on completing, when a newer load may have listed the same key.
     */
    @Override
    public void onRemoval(Object key, Object value, RemovalCause cause) {
        if (!(key instanceof String cacheKey) || !(value instanceof AuthenticationInfo info)
                || info.getUserUuid() == null) {
            return;
        }
        index.computeIfPresent(UUID.fromString(info.getUserUuid()), (uuid, listed) -> {
            listed.computeIfPresent(cacheKey, (k, results) -> {
                results.remove(info);
                return results.isEmpty() ? null : results;
            });
            return listed.isEmpty() ? null : listed;
        });
    }

    public void add(String cacheKey, AuthenticationInfo info) {
        index.compute(userOf(info), (uuid, listed) -> {
            Map<String, Set<AuthenticationInfo>> keys = listed == null ? new HashMap<>() : listed;
            keys.computeIfAbsent(cacheKey, k -> identitySet()).add(info);
            return keys;
        });
    }

    /** Removes and returns the cache keys listed for the given user, or null if none. */
    public Set<String> removeUser(UUID userUuid) {
        Map<String, Set<AuthenticationInfo>> listed = index.remove(userUuid);
        return listed == null ? null : listed.keySet();
    }

    public void clear() {
        index.clear();
    }

    private static UUID userOf(AuthenticationInfo info) {
        if (info.getUserUuid() == null) {
            throw new IllegalStateException("Authenticated result must contain a non-null userUuid");
        }
        return UUID.fromString(info.getUserUuid());
    }

    private static Set<AuthenticationInfo> identitySet() {
        return Collections.newSetFromMap(new IdentityHashMap<>());
    }
}
