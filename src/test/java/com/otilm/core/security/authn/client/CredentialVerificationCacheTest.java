package com.otilm.core.security.authn.client;

import com.otilm.core.config.cache.CacheConfig;
import com.otilm.core.util.BaseSpringBootTest;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.cache.Cache;
import org.springframework.cache.CacheManager;

import java.util.Optional;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;

class CredentialVerificationCacheTest extends BaseSpringBootTest {

    @Autowired
    private CredentialVerificationCache cache;

    @Autowired
    private CacheManager cacheManager;

    @Autowired
    private SecretRefIndex secretRefIndex;

    @BeforeEach
    void resetCacheState() {
        Cache verificationCache = cacheManager.getCache(CacheConfig.CREDENTIAL_VERIFICATION_CACHE);
        if (verificationCache != null) {
            verificationCache.clear();
        }
        secretRefIndex.clear();
    }

    @Test
    void returnsEmpty_whenNoEntryStored() {
        // given — nothing has been cached for this secret
        var secret = UUID.randomUUID();

        // when / then
        assertThat(cache.getMappedUser(secret, "pw")).isEmpty();
    }

    @Test
    void returnsMappedUser_whenEntryStored() {
        // given
        var secret = UUID.randomUUID();
        var mappedUser = UUID.randomUUID();
        var password = "pw";

        // when
        cache.putSuccess(secret, password, mappedUser);

        // then
        assertThat(cache.getMappedUser(secret, password)).isEqualTo(Optional.of(mappedUser));
    }

    @Test
    void clearsEveryPasswordKeyedEntryForSecret_andLeavesUnrelatedSecretsUntouched() {
        // given — two distinct passwords for one secret, both registered under the same secretUuid in the secondary index.
        var secret = UUID.randomUUID();
        var otherSecret = UUID.randomUUID();
        var userA = UUID.randomUUID();
        var userB = UUID.randomUUID();
        var userC = UUID.randomUUID();
        cache.putSuccess(secret, "pw1", userA);
        cache.putSuccess(secret, "pw2", userB);
        cache.putSuccess(otherSecret, "pw3", userC);
        assertThat(cache.getMappedUser(secret, "pw1")).isEqualTo(Optional.of(userA));
        assertThat(cache.getMappedUser(secret, "pw2")).isEqualTo(Optional.of(userB));

        // when — a single eviction by secret
        cache.evictBySecretUuid(secret);

        // then — every password-keyed entry for that secret is gone in one call
        assertThat(cache.getMappedUser(secret, "pw1")).isEmpty();
        assertThat(cache.getMappedUser(secret, "pw2")).isEmpty();
        // and an unrelated secret is untouched
        assertThat(cache.getMappedUser(otherSecret, "pw3")).isEqualTo(Optional.of(userC));
    }

    @Test
    void returnsEmpty_whenDifferentPassword() {
        // given
        var secret = UUID.randomUUID();
        var correctPassword = "right";
        cache.putSuccess(secret, correctPassword, UUID.randomUUID());

        // when / then
        assertThat(cache.getMappedUser(secret, "wrong")).isEmpty();
    }
}
