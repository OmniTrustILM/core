package com.otilm.core.model.crypto;

import com.otilm.api.model.client.certificate.ImportOutcome;

/**
 * The key an import ended in.
 *
 * @param key the registered key
 * @param outcome what the import did: registered a key of its own, adopted a public-key-only record for it, or found it
 * in the inventory and changed nothing
 */
public record ImportedKey(CryptographicKeyFullModel key, ImportOutcome outcome) {
}
