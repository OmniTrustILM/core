package com.otilm.core.model.crypto;

import com.otilm.core.model.crypto.PublicKeyHolder.Holding;
import java.util.UUID;

/**
 * The key that holds a public key.
 *
 * @param keyUuid the key's UUID
 * @param keyName the key's name
 * @param tokenInstanceUuid the UUID of the key's token, or null for a key in no token
 * @param holding how the key holds the public key
 * @param active whether every item of the key is active, or yet to become so
 */
public record PublicKeyHolderSummary(UUID keyUuid, String keyName, UUID tokenInstanceUuid, Holding holding,
        boolean active) {
}
