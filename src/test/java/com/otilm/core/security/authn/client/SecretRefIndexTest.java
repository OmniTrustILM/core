package com.otilm.core.security.authn.client;

import com.github.benmanes.caffeine.cache.RemovalCause;
import org.junit.jupiter.api.Test;

import java.util.Set;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatNullPointerException;

class SecretRefIndexTest {

    private final SecretRefIndex index = new SecretRefIndex();

    @Test
    void onRemoval_dropsKeyFromIndex_onCaffeineDrivenRemoval() {
        // given — a registered key whose backing cache entry Caffeine later evicts (TTL / size pressure)
        UUID secretUuid = UUID.randomUUID();
        index.add(secretUuid, "hmac-1");
        index.add(secretUuid, "hmac-2");

        // when — Caffeine reports the eviction of one key (any cause other than REPLACED)
        index.onRemoval("hmac-1", new SecretRefEntry(secretUuid, UUID.randomUUID()), RemovalCause.EXPIRED);

        // then — only that key is gone; the secret still maps to the surviving key
        Set<String> remaining = index.removeSecret(secretUuid);
        assertThat(remaining).containsExactly("hmac-2");
    }

    @Test
    void onRemoval_dropsSecretEntirely_whenLastKeyRemoved() {
        // given — a secret with a single registered key
        UUID secretUuid = UUID.randomUUID();
        index.add(secretUuid, "hmac-1");

        // when — its only key is evicted by Caffeine
        index.onRemoval("hmac-1", new SecretRefEntry(secretUuid, UUID.randomUUID()), RemovalCause.SIZE);

        // then — the now-empty set is removed, leaving no mapping for the secret
        assertThat(index.removeSecret(secretUuid)).isNull();
    }

    @Test
    void onRemoval_isNoOp_onReplaced() {
        // given — a registered key
        UUID secretUuid = UUID.randomUUID();
        index.add(secretUuid, "hmac-1");

        // when — a put overwrites the live key (REPLACED); the index mapping must be left intact
        index.onRemoval("hmac-1", new SecretRefEntry(secretUuid, UUID.randomUUID()), RemovalCause.REPLACED);

        // then — the key is still indexed, so a later evictBySecretUuid would still find it
        assertThat(index.removeSecret(secretUuid)).containsExactly("hmac-1");
    }

    @Test
    void onRemoval_isNoOp_whenKeyOrValueTypeUnexpected() {
        // given — a registered key
        UUID secretUuid = UUID.randomUUID();
        index.add(secretUuid, "hmac-1");

        // when — Caffeine reports a removal whose key/value are not the expected (String, SecretRefEntry) types
        index.onRemoval(123, "not-an-entry", RemovalCause.EXPIRED);

        // then — nothing is touched
        assertThat(index.removeSecret(secretUuid)).containsExactly("hmac-1");
    }

    @Test
    void add_rejectsNullSecretUuid() {
        // when / then — same null-secretUuid invariant the cache enforces, surfaced as NPE
        assertThatNullPointerException()
                .isThrownBy(() -> index.add(null, "hmac-1"))
                .withMessageContaining("non-null secretUuid");
    }
}
