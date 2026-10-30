package com.otilm.core.service.handler;

import com.otilm.api.model.common.enums.cryptography.KeyType;
import com.otilm.api.model.core.cryptography.key.KeyState;
import com.otilm.core.dao.entity.Certificate;
import com.otilm.core.dao.entity.CryptographicKey;
import com.otilm.core.dao.entity.CryptographicKeyItem;
import java.util.Objects;
import java.util.Optional;

/**
 * The key pair a certificate's key holds in the platform.
 *
 * @param key the certificate's key
 * @param privateItem the key's private key item
 * @param publicItem the key's public key item, or {@code null} when the key holds none
 */
public record CertificateKeyPair(CryptographicKey key, CryptographicKeyItem privateItem,
        CryptographicKeyItem publicItem) {

    /**
     * The key pair of the certificate's key, when the key holds a private key.
     *
     * @param certificate the certificate
     * @return the key pair, or empty when the certificate has no key or its key no private key
     */
    public static Optional<CertificateKeyPair> of(Certificate certificate) {
        CryptographicKey key = certificate.getKey();
        if (key == null) {
            return Optional.empty();
        }
        return itemOf(key, KeyType.PRIVATE_KEY)
                .map(privateItem -> new CertificateKeyPair(key, privateItem,
                        itemOf(key, KeyType.PUBLIC_KEY).orElse(null)));
    }

    /**
     * Whether the key holds the certificate's public key, as the fingerprint linking decides.
     *
     * @param certificate the certificate
     * @return whether the public key item's fingerprint is the certificate's public key fingerprint
     */
    public boolean holds(Certificate certificate) {
        return publicItem != null && Objects.equals(publicItem.getFingerprint(), certificate.getPublicKeyFingerprint());
    }

    /**
     * Whether the private key can be exported now: created or imported as exportable, active and enabled.
     *
     * @return whether the private key item passes the export's own checks on the key
     */
    public boolean exportableNow() {
        return privateItem.isExportable() && privateItem.getState() == KeyState.ACTIVE && privateItem.isEnabled();
    }

    private static Optional<CryptographicKeyItem> itemOf(CryptographicKey key, KeyType type) {
        return key.getItems().stream().filter(item -> item.getType() == type).findFirst();
    }
}
