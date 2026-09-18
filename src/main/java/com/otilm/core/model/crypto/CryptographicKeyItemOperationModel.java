package com.otilm.core.model.crypto;

import com.otilm.api.model.client.connector.v2.ConnectorInterface;
import com.otilm.api.model.common.enums.cryptography.KeyAlgorithm;
import com.otilm.api.model.common.enums.cryptography.KeyType;
import com.otilm.api.model.core.cryptography.key.KeyState;
import com.otilm.api.model.core.cryptography.key.KeyUsage;
import com.otilm.core.model.IdentifiableModel;

import java.util.List;
import java.util.UUID;

/**
 * Immutable snapshot of a {@code CryptographicKeyItem} used on the signing / crypto hot path.
 */
public record CryptographicKeyItemOperationModel(UUID keyItemUuid, boolean enabled, KeyAlgorithm keyAlgorithm,
        KeyState keyState, KeyType keyType, List<KeyUsage> keyUsage, String pqcParameterSpecName, // set only for PQC
                                                                                                  // public keys
        RemoteKeyReference reference, UUID connectorUuid, UUID tokenInstanceUuid, UUID keyUuid,
        ConnectorInterface connectorInterfaceCode, String connectorInterfaceVersion) implements IdentifiableModel {

    @Override
    public UUID uuid() {
        return keyItemUuid;
    }

    /** A token without an interface association is served by a legacy v1 provider. */
    public boolean hasConnectorInterface() {
        return connectorInterfaceCode != null;
    }
}
