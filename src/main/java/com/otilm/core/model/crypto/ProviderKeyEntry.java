package com.otilm.core.model.crypto;

import com.otilm.api.model.common.enums.cryptography.KeyAlgorithm;
import com.otilm.api.model.connector.cryptography.v2.key.KeyEntryStatus;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;

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
 * @param algorithmIdentifier AlgorithmIdentifier naming the parameters of a key the entry carries without its key pair,
 * or null when the connector cannot read them
 */
public record ProviderKeyEntry(KeyEntryStatus status, String diagnostic, String storageName, ProviderKeyPair keyPair,
        KeyAlgorithm algorithm, Integer length, AlgorithmIdentifier algorithmIdentifier) {

    /** An entry whose key, if any, the connector states by algorithm and length alone. */
    public ProviderKeyEntry(KeyEntryStatus status, String diagnostic, String storageName, ProviderKeyPair keyPair,
            KeyAlgorithm algorithm, Integer length) {
        this(status, diagnostic, storageName, keyPair, algorithm, length, null);
    }
}
