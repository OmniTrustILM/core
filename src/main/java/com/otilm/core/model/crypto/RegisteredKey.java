package com.otilm.core.model.crypto;

import com.otilm.api.model.client.certificate.ImportOutcome;
import java.util.UUID;

/**
 * A key an import registered.
 *
 * @param uuid the key's UUID
 * @param outcome {@link ImportOutcome#CREATED} for a key of its own, {@link ImportOutcome#ADOPTED} for the
 * public-key-only record the import adopted
 */
public record RegisteredKey(UUID uuid, ImportOutcome outcome) {
}
