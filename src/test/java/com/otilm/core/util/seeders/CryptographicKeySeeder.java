package com.otilm.core.util.seeders;

import com.otilm.api.model.common.enums.cryptography.KeyAlgorithm;
import com.otilm.api.model.common.enums.cryptography.KeyFormat;
import com.otilm.api.model.common.enums.cryptography.KeyType;
import com.otilm.api.model.core.cryptography.key.KeyState;
import com.otilm.api.model.core.cryptography.key.KeyUsage;
import com.otilm.core.dao.entity.CryptographicKey;
import com.otilm.core.dao.entity.CryptographicKeyItem;
import com.otilm.core.dao.entity.TokenInstanceReference;
import com.otilm.core.dao.entity.TokenProfile;
import com.otilm.core.dao.repository.CryptographicKeyItemRepository;
import com.otilm.core.dao.repository.CryptographicKeyRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

import java.util.HashSet;
import java.util.List;
import java.util.Set;

/**
 * Seeds a {@link CryptographicKey} and its {@link CryptographicKeyItem}s into the test database.
 * <p>
 * Persisting a key item correctly requires a two-phase save — the item is saved once to obtain a UUID,
 * then re-saved with {@code keyReferenceUuid} pointing at itself — which is easy to get wrong and was
 * duplicated across several tests. This seeder centralises that procedure and the per-item defaults
 * every test shares (2048-bit length, {@code ACTIVE} state, enabled). Callers describe only the fields
 * that vary via {@link KeyItemSpec}.
 */
@Component
public class CryptographicKeySeeder {

    private static final int DEFAULT_KEY_LENGTH = 2048;

    @Autowired
    private CryptographicKeyRepository cryptographicKeyRepository;

    @Autowired
    private CryptographicKeyItemRepository cryptographicKeyItemRepository;

    /**
     * In-memory description of one key item. The seeder fills in the persistence-only fields (length,
     * state, enabled, the self-referential {@code keyReferenceUuid}); the caller specifies only the
     * type, algorithm, usage, and — when the test needs real key material — the format and key data.
     */
    public record KeyItemSpec(KeyType type, KeyAlgorithm algorithm, List<KeyUsage> usage,
                              KeyFormat format, String keyData) {

        public static KeyItemSpec signingPrivateKey(KeyAlgorithm algorithm) {
            return new KeyItemSpec(KeyType.PRIVATE_KEY, algorithm, List.of(KeyUsage.SIGN), null, null);
        }

        public static KeyItemSpec verifyingPublicKey(KeyAlgorithm algorithm) {
            return new KeyItemSpec(KeyType.PUBLIC_KEY, algorithm, List.of(KeyUsage.VERIFY), null, null);
        }

        public KeyItemSpec withMaterial(KeyFormat format, String keyData) {
            return new KeyItemSpec(type, algorithm, usage, format, keyData);
        }
    }

    /**
     * Persists a {@link CryptographicKey} bound to the token profile/instance together with its items,
     * and returns the saved key with the items attached.
     */
    public CryptographicKey seedKey(String name, TokenProfile tokenProfile,
                                    TokenInstanceReference tokenInstanceReference, KeyItemSpec... items) {
        CryptographicKey key = new CryptographicKey();
        key.setName(name);
        key.setTokenProfile(tokenProfile);
        key.setTokenInstanceReference(tokenInstanceReference);
        key = cryptographicKeyRepository.saveAndFlush(key);

        Set<CryptographicKeyItem> savedItems = new HashSet<>();
        for (KeyItemSpec spec : items) {
            savedItems.add(seedItem(key, spec));
        }
        key.setItems(savedItems);
        return cryptographicKeyRepository.saveAndFlush(key);
    }

    private CryptographicKeyItem seedItem(CryptographicKey key, KeyItemSpec spec) {
        CryptographicKeyItem item = new CryptographicKeyItem();
        item.setKey(key);
        item.setKeyUuid(key.getUuid());
        item.setType(spec.type());
        item.setKeyAlgorithm(spec.algorithm());
        item.setUsage(spec.usage());
        item.setLength(DEFAULT_KEY_LENGTH);
        item.setState(KeyState.ACTIVE);
        item.setEnabled(true);
        if (spec.format() != null) {
            item.setFormat(spec.format());
        }
        if (spec.keyData() != null) {
            item.setKeyData(spec.keyData());
        }
        item = cryptographicKeyItemRepository.saveAndFlush(item);
        item.setKeyReferenceUuid(item.getUuid());
        return cryptographicKeyItemRepository.saveAndFlush(item);
    }
}
