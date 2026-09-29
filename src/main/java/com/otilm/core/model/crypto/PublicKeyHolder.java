package com.otilm.core.model.crypto;

import java.util.UUID;

/**
 * The key that holds a public key an import brings.
 *
 * @param key the key as it is now
 * @param publicKeyItemUuid the key's item that is the public key
 * @param publicKeyOnly whether the key is a public-key-only record an import may adopt, rather than a key of its own
 */
public record PublicKeyHolder(CryptographicKeyFullModel key, UUID publicKeyItemUuid, boolean publicKeyOnly) {
}
