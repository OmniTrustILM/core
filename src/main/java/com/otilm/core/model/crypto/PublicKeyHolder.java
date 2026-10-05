package com.otilm.core.model.crypto;

import java.util.UUID;

/**
 * The key that holds a public key an import brings.
 *
 * @param key the key as it is now
 * @param publicKeyItemUuid the key's item that is the public key
 * @param holding how the key holds the public key
 */
public record PublicKeyHolder(CryptographicKeyFullModel key, UUID publicKeyItemUuid, Holding holding) {

    /** How a key holds the public key. */
    public enum Holding {
        /** As a public-key-only record, in no token, which an import may adopt. */
        PUBLIC_KEY_ONLY,
        /** With its private key, as a key of its own. */
        KEY_PAIR,
        /** In a token, without its private key. */
        PUBLIC_KEY_IN_TOKEN
    }
}
