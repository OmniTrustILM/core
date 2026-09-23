package com.otilm.core.model.crypto;

import com.otilm.api.model.client.cryptography.key.KeyCompromiseReason;
import com.otilm.api.model.common.enums.cryptography.KeyAlgorithm;
import com.otilm.api.model.common.enums.cryptography.KeyFormat;
import com.otilm.api.model.common.enums.cryptography.KeyType;
import com.otilm.api.model.core.compliance.ComplianceStatus;
import com.otilm.api.model.core.cryptography.key.KeyState;
import com.otilm.api.model.core.cryptography.key.KeyUsage;
import com.otilm.core.dao.entity.CryptographicKeyItem;
import com.otilm.core.model.NamedModel;
import java.util.List;
import java.util.UUID;

/** Key-item snapshot for API mapping, without a reference back to the wrapper entity. */
public record CryptographicKeyItemBasicModel(UUID uuid, UUID parentKeyUuid, String name, RemoteKeyReference reference,
        KeyType type, KeyAlgorithm algorithm, KeyFormat format, String keyData, int length, KeyState state,
        boolean enabled, List<KeyUsage> usages, KeyCompromiseReason reason, ComplianceStatus complianceStatus,
        boolean exportable) implements NamedModel {

    public CryptographicKeyItemBasicModel {
        usages = List.copyOf(usages);
    }

    public static CryptographicKeyItemBasicModel from(CryptographicKeyItem item) {
        RemoteKeyReference reference = item.getKeyMeta() == null
                ? new RemoteKeyReference.UuidReference(item.getKeyReferenceUuid())
                : new RemoteKeyReference.MetadataReference(item.getKeyMeta());
        return new CryptographicKeyItemBasicModel(item.getUuid(), item.getKeyUuid(), item.getName(), reference,
                item.getType(), item.getKeyAlgorithm(), item.getFormat(), item.getKeyData(), item.getLength(),
                item.getState(), item.isEnabled(), item.getUsage(), item.getReason(), item.getComplianceStatus(),
                item.isExportable());
    }
}
