package com.otilm.core.model.crypto;

import com.otilm.api.model.client.cryptography.key.KeyRequestType;
import com.otilm.api.model.common.enums.cryptography.KeyAlgorithm;
import java.util.Set;

/**
 * A key type a connector can move out of a token profile, with the algorithms it accepts for that type, in the shape
 * the connector declares it.
 */
public record TransferableKeyType(KeyRequestType keyRequestType, Set<KeyAlgorithm> algorithms) {

    public TransferableKeyType {
        algorithms = Set.copyOf(algorithms);
    }
}
