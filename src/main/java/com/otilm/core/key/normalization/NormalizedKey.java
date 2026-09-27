package com.otilm.core.key.normalization;

import com.otilm.api.model.common.enums.cryptography.KeyAlgorithm;
import com.otilm.api.model.core.secret.Passphrase;
import java.util.Arrays;
import java.util.Base64;
import java.util.Set;

/**
 * An uploaded key, protected for its connector.
 *
 * @param algorithm the key's algorithm
 * @param subjectPublicKeyInfo the DER {@code SubjectPublicKeyInfo} of the key's public key, encoded as a connector
 * returns it
 * @param encryptedPrivateKeyInfo the DER PKCS#8 {@code EncryptedPrivateKeyInfo} in the contract's pinned profile
 * @param transportPassphrase the passphrase the envelope is protected under, generated for this key alone
 */
// S6218: nothing compares, hashes or prints this value; it only carries the key to the connector call.
@SuppressWarnings("java:S6218")
public record NormalizedKey(KeyAlgorithm algorithm, byte[] subjectPublicKeyInfo, byte[] encryptedPrivateKeyInfo,
        Passphrase transportPassphrase) {

    /** The transport passphrase and the envelope as the connector receives them, which no answer may carry back. */
    public Set<String> transportSecrets() {
        char[] passphrase = transportPassphrase.characters();
        try {
            return Set.of(new String(passphrase), Base64.getEncoder().encodeToString(encryptedPrivateKeyInfo));
        } finally {
            Arrays.fill(passphrase, '\0');
        }
    }

    /** Overwrites the envelope and the transport passphrase. Call it once the connector call has returned. */
    public void clear() {
        Arrays.fill(encryptedPrivateKeyInfo, (byte) 0);
        transportPassphrase.clear();
    }
}
