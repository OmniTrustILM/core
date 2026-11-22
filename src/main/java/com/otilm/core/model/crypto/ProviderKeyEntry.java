package com.otilm.core.model.crypto;

import com.otilm.api.model.common.enums.cryptography.KeyAlgorithm;
import com.otilm.api.model.connector.cryptography.v2.key.KeyEntryStatus;

/**
 * The connector's entry for one listing position or one requested handle.
 *
 * @param diagnostic the connector's text naming the cause behind the status, or null
 * @param storageName the token's name for the key, or null
 * @param keyPair the key pair, present exactly when the status carries a key
 * @param algorithm the algorithm of a key the entry carries without its key pair, or null when the connector cannot
 * read it
 * @param length key length in bits of a key the entry carries without its key pair, or null when the connector cannot
 * read it or the algorithm does not require a length
 */
public record ProviderKeyEntry(KeyEntryStatus status, String diagnostic, String storageName, ProviderKeyPair keyPair,
        KeyAlgorithm algorithm, Integer length) {
}
