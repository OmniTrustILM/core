package com.otilm.core.service.writer;

import com.otilm.api.model.common.enums.cryptography.KeyAlgorithm;
import com.otilm.api.model.common.enums.cryptography.KeyType;
import com.otilm.api.model.core.cryptography.key.KeyState;
import com.otilm.core.dao.entity.CryptographicKey;
import com.otilm.core.dao.entity.CryptographicKeyItem;
import com.otilm.core.dao.repository.CryptographicKeyItemRepository;
import com.otilm.core.dao.repository.CryptographicKeyRepository;
import com.otilm.core.util.CertificateUtil;
import com.otilm.core.util.CryptographyUtil;
import java.security.PublicKey;
import java.time.LocalDateTime;
import java.time.ZoneId;
import java.util.Base64;
import java.util.UUID;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Service
public class CertificateKeyWriter {

    private final CryptographicKeyRepository keyRepository;
    private final CryptographicKeyItemRepository itemRepository;

    public CertificateKeyWriter(CryptographicKeyRepository keyRepository,
            CryptographicKeyItemRepository itemRepository) {
        this.keyRepository = keyRepository;
        this.itemRepository = itemRepository;
    }

    /**
     * Imports a public key Core holds without a token — a certificate's, or one a discovery found on its own — adopting
     * the existing parent when its fingerprint is already stored. Parent creation, item insertion, and unused-parent
     * cleanup commit or roll back together with the caller.
     *
     * @param name name for a newly created parent and public-key item
     * @param publicKey non-null public key to import
     * @param keyLength public-key length in bits
     * @param fingerprint non-null fingerprint identifying the public key
     * @return UUID of the parent containing the public-key item
     * @throws IllegalStateException if a conflicting fingerprint no longer identifies an existing item
     */
    @Transactional
    public UUID uploadCertificatePublicKey(String name, PublicKey publicKey, int keyLength, String fingerprint) {
        CryptographicKey parent = new CryptographicKey();
        parent.setName(name);
        keyRepository.save(parent);
        CryptographicKeyItem item = publicKeyItem(parent, publicKey, keyLength, fingerprint);
        // No key_meta: it is a token's reference to the key, and a key held without a token has none.
        if (itemRepository.insertWithFingerprintConflictResolve(item, null) == 1) {
            return parent.getUuid();
        }

        UUID survivingKeyUuid = itemRepository
                .findByFingerprint(fingerprint)
                .map(CryptographicKeyItem::getKeyUuid)
                .orElseThrow(() -> new IllegalStateException(
                        "Public key with the same fingerprint was committed concurrently but could no longer be read"));
        keyRepository.delete(parent);
        return survivingKeyUuid;
    }

    private CryptographicKeyItem publicKeyItem(CryptographicKey parent, PublicKey publicKey, int keyLength,
            String fingerprint) {
        LocalDateTime now = LocalDateTime.now(ZoneId.systemDefault());
        byte[] encodedKey = publicKey.getEncoded();
        CryptographicKeyItem item = new CryptographicKeyItem();
        item.setUuid(UUID.randomUUID());
        item.setName(parent.getName());
        item.setType(KeyType.PUBLIC_KEY);
        item.setKey(parent);
        KeyAlgorithm algorithm;
        try {
            algorithm = CertificateUtil.getKeyAlgorithmEnumFromProviderName(publicKey.getAlgorithm());
        } catch (IllegalArgumentException e) {
            algorithm = KeyAlgorithm.UNKNOWN;
        }
        item.setKeyAlgorithm(algorithm);
        item.setKeyData(Base64.getEncoder().encodeToString(encodedKey));
        item.setFormat(CryptographyUtil.getPublicKeyFormat(encodedKey));
        item.setLength(keyLength);
        item.setFingerprint(fingerprint);
        item.setState(KeyState.ACTIVE);
        item.setEnabled(true);
        item.setCreatedAt(now);
        item.setUpdatedAt(now);
        return item;
    }
}
