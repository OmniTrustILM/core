package com.otilm.core.model.crypto;

import com.otilm.core.model.crypto.PublicKeyHolder.Holding;
import java.util.UUID;

/**
 * The key that holds a public key, by its UUID and name alone.
 *
 * @param keyUuid the key's UUID
 * @param keyName the key's name
 * @param holding how the key holds the public key
 * @param active whether every item of the key is active, or yet to become so
 */
public record PublicKeyHolderSummary(UUID keyUuid, String keyName, Holding holding, boolean active) {
}
