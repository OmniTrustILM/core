package com.otilm.core.model.crypto;

import com.otilm.api.model.common.attribute.common.MetadataAttribute;
import com.otilm.api.model.common.enums.cryptography.KeyAlgorithm;
import com.otilm.api.model.common.enums.cryptography.KeyType;
import com.otilm.core.key.description.DescribedKey;
import java.util.List;

/**
 * Created or discovered provider key item before Core assigns its identity and wrapper.
 *
 * @param name provider name, or null when Core must assign one
 * @param type kind of key item
 * @param algorithm provider-reported algorithm, or the one Core derived once the item is described
 * @param parameterSet curve or post-quantum parameter set Core derived, or null
 * @param length key length in bits the provider stated, or the size Core derived once the item is described
 * @param reference provider reference, independent of Core's item UUID
 * @param material the representation Core stores for the item, or null
 * @param metadata descriptive metadata, separate from the remote key reference
 * @param association provider grouping identifier for related items; null or empty for an individual item
 */
public record ProviderKeyItem(String name, KeyType type, KeyAlgorithm algorithm, String parameterSet, Integer length,
        RemoteKeyReference reference, KeyMaterial material, List<MetadataAttribute> metadata, String association) {

    /** An item as the provider stated it, before Core describes it. */
    public ProviderKeyItem(String name, KeyType type, KeyAlgorithm algorithm, Integer length,
            RemoteKeyReference reference, KeyMaterial material, List<MetadataAttribute> metadata, String association) {
        this(name, type, algorithm, null, length, reference, material, metadata, association);
    }

    /** Describes an individual provider key item, one with no association. */
    public ProviderKeyItem(String name, KeyType type, KeyAlgorithm algorithm, Integer length,
            RemoteKeyReference reference, KeyMaterial material, List<MetadataAttribute> metadata) {
        this(name, type, algorithm, length, reference, material, metadata, null);
    }

    public ProviderKeyItem describedAs(DescribedKey description) {
        return new ProviderKeyItem(name, type, description.algorithm(), description.parameterSet(),
                description.length(), reference, material, metadata, association);
    }

    public ProviderKeyItem withMaterial(KeyMaterial material) {
        return new ProviderKeyItem(name, type, algorithm, parameterSet, length, reference, material, metadata,
                association);
    }
}
