package com.otilm.core.integration.migration;

import com.otilm.api.model.common.enums.cryptography.KeyAlgorithm;
import com.otilm.core.dao.entity.CryptographicKey;
import com.otilm.core.dao.entity.TokenProfile;
import com.otilm.core.model.crypto.RemoteKeyReference.MetadataReference;
import com.otilm.core.util.seeders.CryptographicKeySeeder;
import com.otilm.core.util.seeders.TokenProfileSeeder;
import db.migration.V202611251201__BackfillKeyHandleDigests;
import java.sql.Connection;
import java.util.UUID;
import javax.sql.DataSource;
import org.flywaydb.core.api.migration.Context;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.jdbc.core.JdbcTemplate;

import static com.otilm.core.util.KeyMetaFixtures.keyIdMeta;
import static com.otilm.core.util.seeders.CryptographicKeySeeder.KeyItemSpec.signingPrivateKey;
import static com.otilm.core.util.seeders.CryptographicKeySeeder.KeyItemSpec.verifyingPublicKey;
import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

class BackfillKeyHandleDigestsMigrationITest extends BaseMigrationTest {

    @Autowired
    private DataSource dataSource;
    @Autowired
    private JdbcTemplate jdbcTemplate;
    @Autowired
    private CryptographicKeySeeder keySeeder;
    @Autowired
    private TokenProfileSeeder tokenProfileSeeder;

    private TokenProfile token;

    @BeforeEach
    void seedToken() {
        token = tokenProfileSeeder.seedTokenProfile();
    }

    @Test
    void storesTheDigestCoreStoresForANewKey_whenTheTokenHoldsThePrivateKey() throws Exception {
        // given
        var keyId = "a1b2";
        UUID key = seedKeyPair(token, keyId);

        // when
        migrate();

        // then
        assertThat(readHandleDigest(key)).isNotNull().isEqualTo(new MetadataReference(keyIdMeta(keyId)).digest());
    }

    @Test
    void storesTheSameDigestOnEachToken_whenKeysOnTwoTokensShareAHandle() throws Exception {
        // given
        var keyId = "a1b2";
        UUID key = seedKeyPair(token, keyId);
        UUID keyElsewhere = seedKeyPair(tokenProfileSeeder.seedTokenProfile(), keyId);

        // when
        migrate();

        // then
        assertThat(readHandleDigest(key)).isNotNull().isEqualTo(readHandleDigest(keyElsewhere));
    }

    @Test
    void leavesTheDigestUnset_whenThePrivateKeyIsDestroyed() throws Exception {
        // given
        UUID key = seedKeyPair(token, "a1b2");
        jdbcTemplate
                .update("UPDATE cryptographic_key_item SET state = 'DESTROYED' WHERE key_uuid = ? AND type = 'PRIVATE_KEY'",
                        key);

        // when
        migrate();

        // then
        assertThat(readHandleDigest(key)).isNull();
    }

    @Test
    void leavesTheDigestUnset_whenThePrivateKeyHasNoMetadata() throws Exception {
        // given
        UUID key = keySeeder
                .seedKey("v1-key", token, token.getTokenInstanceReference(), signingPrivateKey(KeyAlgorithm.RSA))
                .getUuid();

        // when
        migrate();

        // then
        assertThat(readHandleDigest(key)).isNull();
    }

    @Test
    void leavesTheDigestUnset_whenThePrivateKeysOfTheKeyNameTwoHandles() throws Exception {
        // given
        UUID key = keySeeder
                .seedKey("two-handles", token, token.getTokenInstanceReference(),
                        signingPrivateKey(KeyAlgorithm.RSA).withKeyMeta(keyIdMeta("a1b2")),
                        signingPrivateKey(KeyAlgorithm.RSA).withKeyMeta(keyIdMeta("c3d4")))
                .getUuid();

        // when
        migrate();

        // then
        assertThat(readHandleDigest(key)).isNull();
    }

    @Test
    void leavesTheDigestUnset_whenAKeyWithTwoHandlesAlsoNamesIt() throws Exception {
        // given
        var sharedKeyId = "a1b2";
        keySeeder
                .seedKey("two-handles", token, token.getTokenInstanceReference(),
                        signingPrivateKey(KeyAlgorithm.RSA).withKeyMeta(keyIdMeta(sharedKeyId)),
                        signingPrivateKey(KeyAlgorithm.RSA).withKeyMeta(keyIdMeta("c3d4")));
        UUID key = seedKeyPair(token, sharedKeyId);

        // when
        migrate();

        // then
        assertThat(readHandleDigest(key)).isNull();
    }

    @Test
    void leavesBothDigestsUnset_whenTwoKeysOnTheTokenShareAHandle() throws Exception {
        // given
        var sharedKeyId = "a1b2";
        UUID key = seedKeyPair(token, sharedKeyId);
        UUID twin = seedKeyPair(token, sharedKeyId);

        // when
        migrate();

        // then
        assertThat(readHandleDigest(key)).isNull();
        assertThat(readHandleDigest(twin)).isNull();
    }

    @Test
    void leavesTheDigestUnset_whenAnotherKeyOnTheTokenHoldsIt() throws Exception {
        // given
        var sharedKeyId = "a1b2";
        UUID holder = seedKeyPair(token, sharedKeyId);
        String heldDigest = new MetadataReference(keyIdMeta(sharedKeyId)).digest();
        jdbcTemplate.update("UPDATE cryptographic_key SET handle_digest = ? WHERE uuid = ?", heldDigest, holder);
        UUID key = seedKeyPair(token, sharedKeyId);

        // when
        migrate();

        // then
        assertThat(readHandleDigest(key)).isNull();
        assertThat(readHandleDigest(holder)).isEqualTo(heldDigest);
    }

    @Test
    void keepsTheStoredDigests_whenRunAgain() throws Exception {
        // given
        UUID key = seedKeyPair(token, "a1b2");
        migrate();
        String storedDigest = readHandleDigest(key);

        // when
        migrate();

        // then
        assertThat(readHandleDigest(key)).isNotNull().isEqualTo(storedDigest);
    }

    // ── Helpers ───────────────────────────────────────────────────────────────

    private UUID seedKeyPair(TokenProfile tokenProfile, String keyId) {
        CryptographicKey key = keySeeder
                .seedKey("key-" + keyId, tokenProfile, tokenProfile.getTokenInstanceReference(),
                        signingPrivateKey(KeyAlgorithm.RSA).withKeyMeta(keyIdMeta(keyId)),
                        verifyingPublicKey(KeyAlgorithm.RSA).withKeyMeta(keyIdMeta(keyId)));
        return key.getUuid();
    }

    private String readHandleDigest(UUID keyUuid) {
        return jdbcTemplate
                .queryForObject("SELECT handle_digest FROM cryptographic_key WHERE uuid = ?", String.class, keyUuid);
    }

    /** Runs the migration in one transaction and commits it, as Flyway does. */
    private void migrate() throws Exception {
        try (Connection connection = dataSource.getConnection()) {
            connection.setAutoCommit(false);
            try {
                Context context = mock(Context.class);
                when(context.getConnection()).thenReturn(connection);
                new V202611251201__BackfillKeyHandleDigests().migrate(context);
                connection.commit();
            } finally {
                connection.rollback();
                connection.setAutoCommit(true);
            }
        }
    }
}
