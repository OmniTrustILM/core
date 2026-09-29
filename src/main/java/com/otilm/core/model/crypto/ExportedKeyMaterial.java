package com.otilm.core.model.crypto;

/**
 * A key item's protected material as its connector exported it, with the name to offer it under.
 *
 * @param keyItemName name of the exported key item
 * @param encryptedPrivateKeyInfo the DER-encoded PKCS#8 EncryptedPrivateKeyInfo, protected under the caller's
 * passphrase
 */
// S6218: nothing compares, hashes or prints this value; it only carries the material to the download.
@SuppressWarnings("java:S6218")
public record ExportedKeyMaterial(String keyItemName, byte[] encryptedPrivateKeyInfo) {
}
