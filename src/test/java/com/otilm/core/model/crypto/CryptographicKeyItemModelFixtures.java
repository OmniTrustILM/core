package com.otilm.core.model.crypto;

import com.otilm.api.model.common.enums.cryptography.KeyAlgorithm;
import com.otilm.api.model.common.enums.cryptography.KeyType;
import com.otilm.api.model.core.cryptography.key.KeyState;
import com.otilm.api.model.core.cryptography.key.KeyUsage;

import java.util.List;
import java.util.UUID;

/**
 * Test factory for {@link CryptographicKeyItemOperationModel} snapshots used on the signing path.
 */
public final class CryptographicKeyItemModelFixtures {

    private CryptographicKeyItemModelFixtures() {
    }

    public static CryptographicKeyItemOperationModel keyItem(KeyType type, KeyAlgorithm algorithm, KeyState state,
            List<KeyUsage> usage) {
        return keyItem(type, algorithm, state, usage, null);
    }

    public static CryptographicKeyItemOperationModel keyItem(KeyType type, KeyAlgorithm algorithm, KeyState state,
            List<KeyUsage> usage, String pqcParameterSpecName) {
        RemoteKeyReference reference = new RemoteKeyReference.UuidReference(UUID.randomUUID());
        return new CryptographicKeyItemOperationModel(UUID.randomUUID(), true, algorithm, state, type, usage,
                pqcParameterSpecName, reference, UUID.randomUUID(), UUID.randomUUID());
    }

    /** An ACTIVE private-key item carrying the SIGN usage. */
    public static CryptographicKeyItemOperationModel activeSigningPrivateKey(KeyAlgorithm algorithm) {
        return keyItem(KeyType.PRIVATE_KEY, algorithm, KeyState.ACTIVE, List.of(KeyUsage.SIGN));
    }

    /** An ACTIVE public-key item carrying the VERIFY usage. */
    public static CryptographicKeyItemOperationModel publicKey(KeyAlgorithm algorithm) {
        return keyItem(KeyType.PUBLIC_KEY, algorithm, KeyState.ACTIVE, List.of(KeyUsage.VERIFY));
    }

    /** An ACTIVE PQC public-key item with a pre-computed parameter-spec name. */
    public static CryptographicKeyItemOperationModel publicKey(KeyAlgorithm algorithm, String pqcParameterSpecName) {
        return keyItem(KeyType.PUBLIC_KEY, algorithm, KeyState.ACTIVE, List.of(KeyUsage.VERIFY), pqcParameterSpecName);
    }
}
