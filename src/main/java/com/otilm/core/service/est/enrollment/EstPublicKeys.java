package com.otilm.core.service.est.enrollment;

import com.otilm.core.util.CryptographyUtil;
import java.security.GeneralSecurityException;
import java.security.PublicKey;
import java.util.Optional;
import lombok.extern.slf4j.Slf4j;

/**
 * Reads public keys as BouncyCastle reads them from their encoding, whose equality compares the key material whatever
 * provider made the key.
 */
@Slf4j
final class EstPublicKeys {

    private EstPublicKeys() {
    }

    /**
     * @param encoded the {@code SubjectPublicKeyInfo} of the key
     * @return the key, or empty when BouncyCastle does not read it
     */
    static Optional<PublicKey> read(byte[] encoded) {
        try {
            return Optional.of(CryptographyUtil.decodePublicKey(encoded));
        } catch (GeneralSecurityException e) {
            log.debug("A public key cannot be read: {}", e.getClass().getSimpleName());
            return Optional.empty();
        }
    }
}
