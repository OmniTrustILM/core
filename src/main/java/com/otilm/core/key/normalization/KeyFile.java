package com.otilm.core.key.normalization;

import org.bouncycastle.asn1.pkcs.EncryptedPrivateKeyInfo;
import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;

/** What an uploaded key file holds: a private key, or one that a passphrase has to open. */
sealed interface KeyFile {

    /**
     * A private key without protection.
     *
     * @param privateKeyInfo the key
     */
    record Plain(PrivateKeyInfo privateKeyInfo) implements KeyFile {
    }

    /**
     * A PKCS#8 key under a protection scheme already checked against the accepted set.
     *
     * @param envelope the protected key
     */
    record Pkcs8Protected(EncryptedPrivateKeyInfo envelope) implements KeyFile {
    }

    /**
     * An OpenSSL traditional PEM key under an accepted cipher.
     *
     * @param kind the key the block holds
     * @param cipher the cipher, as the {@code DEK-Info} header names it
     * @param iv the initialization vector from the {@code DEK-Info} header
     * @param cipherText the protected key
     */
    // S6218: nothing compares, hashes or prints this value; it only carries the block to its decryption.
    @SuppressWarnings("java:S6218")
    record TraditionalProtected(TraditionalKey kind, String cipher, byte[] iv, byte[] cipherText) implements KeyFile {
    }

    /**
     * A secret key as a JCEKS store seals it, its key derivation already charged to the file's budget.
     *
     * @param sealed the sealed key
     */
    record JceksSealed(JceksSealedKey sealed) implements KeyFile {
    }

    /**
     * An {@code openssh-key-v1} key, its header already checked for an accepted cipher, KDF and key count.
     *
     * @param blob the decoded content of the block
     */
    // S6218: nothing compares, hashes or prints this value; it only carries the block to its decryption.
    @SuppressWarnings("java:S6218")
    record OpenSsh(byte[] blob) implements KeyFile {
    }
}
