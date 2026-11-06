package com.otilm.core.integration.dao.entity;

import com.otilm.api.model.common.enums.cryptography.KeyType;
import com.otilm.core.dao.entity.CryptographicKey;
import com.otilm.core.dao.entity.CryptographicKeyItem;
import com.otilm.core.dao.repository.CryptographicKeyItemRepository;
import com.otilm.core.dao.repository.CryptographicKeyRepository;
import com.otilm.core.util.BaseSpringBootTest;
import com.otilm.core.util.SqlCapture;
import jakarta.persistence.EntityManager;
import jakarta.persistence.PersistenceContext;
import java.util.List;
import java.util.UUID;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.transaction.PlatformTransactionManager;
import org.springframework.transaction.support.TransactionTemplate;

import static com.otilm.core.util.KeyMetaFixtures.keyIdMeta;
import static com.otilm.core.util.builders.CryptographicKeyBuilder.aCryptographicKey;
import static com.otilm.core.util.builders.CryptographicKeyItemBuilder.aKeyItem;
import static org.assertj.core.api.Assertions.assertThat;

/**
 * A key item's {@code key_meta} is written when the item is given new metadata, and never because a request loaded the
 * item: the metadata's attribute properties have no value equality, so a copy of them never equals what was loaded.
 */
class CryptographicKeyItemKeyMetaITest extends BaseSpringBootTest {

    @Autowired
    private CryptographicKeyRepository keyRepository;
    @Autowired
    private CryptographicKeyItemRepository keyItemRepository;
    @Autowired
    private PlatformTransactionManager transactionManager;
    @Autowired
    private JdbcTemplate jdbcTemplate;
    @PersistenceContext
    private EntityManager entityManager;

    @Test
    void sendsNoUpdate_whenAnItemWithKeyMetaIsLoaded() throws Exception {
        // given
        UUID itemUuid = persistItemWithKeyMeta("provider-key-id");

        // when
        List<String> statements = SqlCapture
                .during(() -> new TransactionTemplate(transactionManager)
                        .execute(status -> entityManager.find(CryptographicKeyItem.class, itemUuid)))
                .statements();

        // then
        assertThat(statements).noneMatch(sql -> sql.startsWith("update core.cryptographic_key_item"));
    }

    @Test
    void storesTheNewKeyMeta_whenALoadedItemIsGivenNewKeyMeta() {
        // given
        UUID itemUuid = persistItemWithKeyMeta("provider-key-id");
        var reissuedKeyId = "reissued-provider-key-id";

        // when
        new TransactionTemplate(transactionManager)
                .executeWithoutResult(status -> entityManager
                        .find(CryptographicKeyItem.class, itemUuid)
                        .setKeyMeta(keyIdMeta(reissuedKeyId)));

        // then
        assertThat(storedKeyId(itemUuid)).isEqualTo(reissuedKeyId);
    }

    // ── Helpers ───────────────────────────────────────────────────────────────

    private UUID persistItemWithKeyMeta(String keyId) {
        CryptographicKey key = keyRepository.save(aCryptographicKey().withName("provider-held-key").build());
        CryptographicKeyItem item = aKeyItem().withType(KeyType.PRIVATE_KEY).withKeyMeta(keyIdMeta(keyId)).build();
        item.setKey(key);
        return keyItemRepository.save(item).getUuid();
    }

    private String storedKeyId(UUID itemUuid) {
        return jdbcTemplate
                .queryForObject("SELECT key_meta->0->'content'->0->>'data' FROM " + dbSchema
                        + ".cryptographic_key_item WHERE uuid = ?", String.class, itemUuid);
    }
}
