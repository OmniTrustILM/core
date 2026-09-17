package com.otilm.core.model.crypto;

import com.otilm.api.model.common.attribute.common.MetadataAttribute;
import com.otilm.api.model.common.enums.cryptography.KeyAlgorithm;
import com.otilm.api.model.common.enums.cryptography.KeyType;
import java.util.List;

/**
 * Created or discovered provider key item before Core assigns its identity and wrapper.
 *
 * @param name provider name, or null when Core must assign one
 * @param reference provider reference, independent of Core's item UUID
 * @param material returned key material for key, or null when the key should stay private
 * @param metadata descriptive metadata, separate from the remote key reference
 * @param association provider grouping identifier for related items; null or empty for an individual item
 */
public record ProviderKeyItem(String name, KeyType type, KeyAlgorithm algorithm, int length,
        RemoteKeyReference reference, KeyMaterial material, List<MetadataAttribute> metadata, String association) {

    public ProviderKeyItem(String name, KeyType type, KeyAlgorithm algorithm, int length, RemoteKeyReference reference,
            KeyMaterial material, List<MetadataAttribute> metadata) {
        this(name, type, algorithm, length, reference, material, metadata, null);
    }
}
