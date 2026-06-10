package com.czertainly.core.model.crypto;

import com.otilm.api.model.common.enums.cryptography.KeyAlgorithm;
import com.otilm.api.model.common.enums.cryptography.KeyType;
import com.otilm.api.model.core.cryptography.key.KeyState;
import com.otilm.api.model.core.cryptography.key.KeyUsage;

import java.util.List;
import java.util.UUID;

/**
 * Immutable snapshot of a {@code CryptographicKeyItem} used on the signing / crypto hot path.
 */
public record CryptographicKeyItemModel(
        UUID keyItemUuid,
        boolean enabled,
        KeyAlgorithm keyAlgorithm,
        KeyState keyState,
        KeyType keyType,
        List<KeyUsage> keyUsage,
        String pqcParameterSpecName,   // set only for PQC public keys
        UUID keyReferenceUuid,
        UUID connectorUuid,
        UUID tokenInstanceUuid
) {}
