package com.otilm.core.model.crypto;

import com.otilm.api.model.client.certificate.ImportOutcome;
import com.otilm.api.model.core.cryptography.key.KeyDetailDto;

/**
 * The key an import ended in, as the caller may see it.
 *
 * @param detail the key's detail
 * @param outcome what the import did: registered a key of its own, adopted a public-key-only record for it, or found it
 * in the inventory and changed nothing
 */
public record ImportedKeyDetail(KeyDetailDto detail, ImportOutcome outcome) {
}
