package com.otilm.core.security.authn.client;

import com.github.benmanes.caffeine.cache.RemovalCause;
import com.github.benmanes.caffeine.cache.RemovalListener;
import org.jspecify.annotations.NonNull;
import org.springframework.stereotype.Component;

import java.util.Set;
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Secondary index: secretUuid → set of HMAC cache keys registered for that secret.
 */
@Component
public class SecretRefIndex implements RemovalListener<Object, Object> {

    private final ConcurrentHashMap<UUID, Set<String>> index = new ConcurrentHashMap<>();

    /** Called by Caffeine on every credential cache eviction (TTL, size pressure, explicit, replace). */
    @Override
    public void onRemoval(Object key, Object value, @NonNull RemovalCause cause) {
        if (!(key instanceof String hmacKey) || !(value instanceof SecretRefEntry entry)) return;
        index.computeIfPresent(entry.secretUuid(), (uuid, keys) -> {
            keys.remove(hmacKey);
            return keys.isEmpty() ? null : keys;
        });
    }

    /**
     * Register an HMAC cache key under its owning secretUuid.
     */
    public void add(UUID secretUuid, String hmacKey) {
        if (secretUuid == null) {
            throw new IllegalStateException("Verified credential must contain a non-null secretUuid");
        }
        index.computeIfAbsent(secretUuid, k -> ConcurrentHashMap.newKeySet()).add(hmacKey);
    }

    /**
     * Remove and return all HMAC keys registered for the given secretUuid, or null if none.
     */
    public Set<String> removeSecret(UUID secretUuid) {
        return index.remove(secretUuid);
    }

    public void clear() {
        index.clear();
    }
}
