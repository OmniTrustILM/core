package com.otilm.core.keystore;

import java.util.List;

/**
 * What goes into one keystore: a key, protected as its connector exported it, and the certificates that go with it.
 *
 * @param keyName the name the key is known by, which the key and its certificate carry as their friendly name
 * @param encryptedPrivateKeyInfo the DER-encoded PKCS#8 EncryptedPrivateKeyInfo, protected under the keystore's
 * passphrase with PBES2 and PBKDF2
 * @param leaf the DER of the certificate that carries the key's public key
 * @param issuers the DER of the leaf's issuers, nearest first, without a trust anchor
 */
// S6218: nothing compares, hashes or prints an entry; it only carries what the keystore holds to the assembler.
@SuppressWarnings("java:S6218")
public record KeystoreEntry(String keyName, byte[] encryptedPrivateKeyInfo, byte[] leaf, List<byte[]> issuers) {

    public KeystoreEntry {
        issuers = List.copyOf(issuers);
    }
}
