package com.otilm.core.model.crypto;

import com.otilm.api.model.client.connector.v2.ConnectorInterface;
import com.otilm.api.model.common.attribute.common.MetadataAttribute;
import com.otilm.api.model.common.enums.cryptography.KeyAlgorithm;
import com.otilm.api.model.common.enums.cryptography.KeyType;
import com.otilm.api.model.core.cryptography.key.KeyState;
import com.otilm.api.model.core.cryptography.key.KeyUsage;
import com.otilm.core.util.CryptographyUtil;
import java.util.List;
import java.util.UUID;

/** Flat projection of a key item with its key, token and connector-interface routing columns. */
public record CryptographicKeyItemOperationRow(UUID keyItemUuid, boolean enabled, KeyAlgorithm keyAlgorithm,
        KeyState keyState, KeyType keyType, int usageBitmask, String keyData, UUID keyReferenceUuid,
        List<MetadataAttribute> keyMeta, UUID keyUuid, UUID connectorUuid, String tokenInstanceUuid,
        ConnectorInterface connectorInterfaceCode, String connectorInterfaceVersion) {

    public CryptographicKeyItemOperationModel toModel() {
        RemoteKeyReference reference = keyMeta == null
                ? new RemoteKeyReference.UuidReference(keyReferenceUuid)
                : new RemoteKeyReference.MetadataReference(keyMeta);
        String pqcParameterSpecName = keyType == KeyType.PUBLIC_KEY
                ? CryptographyUtil.resolvePqcParameterSpecName(keyAlgorithm, keyData)
                : null;
        List<KeyUsage> usages = KeyUsage.convertBitMaskToSet(usageBitmask).stream().toList();
        UUID remoteTokenUuid = tokenInstanceUuid == null ? null : UUID.fromString(tokenInstanceUuid);
        return new CryptographicKeyItemOperationModel(keyItemUuid, enabled, keyAlgorithm, keyState, keyType, usages,
                pqcParameterSpecName, reference, connectorUuid, remoteTokenUuid, keyUuid, connectorInterfaceCode,
                connectorInterfaceVersion);
    }
}
