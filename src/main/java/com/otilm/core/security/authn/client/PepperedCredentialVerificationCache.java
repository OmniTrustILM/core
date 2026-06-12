package com.otilm.core.security.authn.client;

import com.otilm.core.config.cache.CacheConfig;
import jakarta.annotation.PostConstruct;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.cache.Cache;
import org.springframework.cache.CacheManager;
import org.springframework.stereotype.Component;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.util.HexFormat;
import java.util.Objects;
import java.util.Optional;
import java.util.Set;
import java.util.UUID;

/**
 * Positive-only peppered credential verification cache backed by Caffeine.
 *
 * <p>Cache key: {@code HMAC-SHA-256(pepper, secretUuid + ":" + password)} rendered as hex.
 * The pepper is generated from {@link SecureRandom} at application startup and never persisted,
 * so cache state is opaque and cannot be reversed to recover raw passwords.</p>
 *
 * <p>Cache value: {@link SecretRefEntry} (secretUuid + mappedUserUuid). The secretUuid in the
 * value lets {@link SecretRefIndex} — a Caffeine removal listener — maintain a secondary index
 * ({@code secretUuid → Set<hmacKey>}) enabling {@link #evictBySecretUuid} to clear all
 * password-keyed entries for a rotated or deleted secret in one call.</p>
 */
@Component
class PepperedCredentialVerificationCache implements CredentialVerificationCache {

    private static final String HMAC_ALGORITHM = "HmacSHA256";

    private final CacheManager cacheManager;
    private final SecretRefIndex secretRefIndex;

    private Cache cache;
    private byte[] pepper;

    @Autowired
    PepperedCredentialVerificationCache(CacheManager cacheManager, SecretRefIndex secretRefIndex) {
        this.cacheManager = cacheManager;
        this.secretRefIndex = secretRefIndex;
    }

    @PostConstruct
    void init() {
        this.cache = Objects.requireNonNull(
                cacheManager.getCache(CacheConfig.CREDENTIAL_VERIFICATION_CACHE),
                "CREDENTIAL_VERIFICATION_CACHE must be registered in CacheConfig");
        byte[] randomPepper = new byte[32];
        new SecureRandom().nextBytes(randomPepper);
        this.pepper = randomPepper;
    }

    @Override
    public Optional<UUID> getMappedUser(UUID secretUuid, String password) {
        String hmacKey = hmac(secretUuid, password);
        Cache.ValueWrapper wrapped = cache.get(hmacKey);
        if (wrapped == null || !(wrapped.get() instanceof SecretRefEntry entry)) {
            return Optional.empty();
        }
        return Optional.of(entry.mappedUserUuid());
    }

    @Override
    public void putSuccess(UUID secretUuid, String password, UUID mappedUserUuid) {
        String hmacKey = hmac(secretUuid, password);
        cache.put(hmacKey, new SecretRefEntry(secretUuid, mappedUserUuid));
        secretRefIndex.add(secretUuid, hmacKey);
    }

    @Override
    public void evictBySecretUuid(UUID secretUuid) {
        // Known, accepted trade-off (same as TokenJtiIndex): a putSuccess that interleaves between removeSecret and the
        // evict loop can leave a fresh positive entry that this call misses. The window is tiny and the entry is bounded
        // by the cache TTL.
        Set<String> hmacKeys = secretRefIndex.removeSecret(secretUuid);
        if (hmacKeys == null) return;
        hmacKeys.forEach(cache::evict);
    }

    /**
     * Derives a deterministic, non-reversible cache key for the given (secretUuid, password) pair.
     * Uses HMAC-SHA-256 with the per-process pepper so the raw password is never stored.
     */
    private String hmac(UUID secretUuid, String password) {
        Objects.requireNonNull(secretUuid, "secretUuid must not be null");
        Objects.requireNonNull(password, "password must not be null");

        try {
            Mac mac = Mac.getInstance(HMAC_ALGORITHM);
            mac.init(new SecretKeySpec(pepper, HMAC_ALGORITHM));
            mac.update(secretUuid.toString().getBytes(StandardCharsets.UTF_8));
            mac.update((byte) ':');
            mac.update(password.getBytes(StandardCharsets.UTF_8));
            return HexFormat.of().formatHex(mac.doFinal());
        } catch (Exception e) {
            throw new IllegalStateException("HMAC-SHA-256 unavailable", e);
        }
    }
}
