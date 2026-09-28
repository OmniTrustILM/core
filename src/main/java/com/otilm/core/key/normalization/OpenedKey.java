package com.otilm.core.key.normalization;

import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;

/** What an uploaded key file holds once its protection is opened. */
sealed interface OpenedKey {

    /**
     * A key in its PKCS#8 form, the form every key the platform reads takes.
     *
     * @param privateKeyInfo the key, whose private key is overwritten once it is used
     */
    record Pkcs8(PrivateKeyInfo privateKeyInfo) implements OpenedKey {
    }

    /**
     * A secret key that a JDK store names by an algorithm other than AES, which no PKCS#8 form here identifies.
     *
     * @param algorithm the algorithm's name, as the store gives it
     */
    record UnsupportedSecret(String algorithm) implements OpenedKey {
    }
}
