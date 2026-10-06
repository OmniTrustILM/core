package com.otilm.core.model.crypto;

import com.otilm.api.model.common.attribute.common.MetadataAttribute;
import com.otilm.api.model.common.enums.cryptography.KeyAlgorithm;
import com.otilm.api.model.common.enums.cryptography.KeyType;
import java.util.List;

/**
 * Created or discovered provider key item before Core assigns its identity and wrapper.
 *
 * @param name provider name, or null when Core must assign one
 * @param type kind of key item
 * @param algorithm provider-reported algorithm
 * @param length key length in bits, or null when the algorithm does not require a length
 * @param reference provider reference, independent of Core's item UUID
 * @param material returned key material for key, or null when the key should stay private
 * @param metadata descriptive metadata, separate from the remote key reference
 * @param association provider grouping identifier for related items; null or empty for an individual item
 */
public record ProviderKeyItem(String name, KeyType type, KeyAlgorithm algorithm, Integer length,
        RemoteKeyReference reference, KeyMaterial material, List<MetadataAttribute> metadata, String association) {

    /**
     * Describes an individual provider key without a grouping identifier.
     *
     * @param name provider name, or null when Core assigns one
     * @param type kind of key item
     * @param algorithm provider-reported algorithm
     * @param length key length in bits, or null when not required
     * @param reference provider handle
     * @param material public material, or null
     * @param metadata descriptive provider metadata
     */
    public ProviderKeyItem(String name, KeyType type, KeyAlgorithm algorithm, Integer length,
            RemoteKeyReference reference, KeyMaterial material, List<MetadataAttribute> metadata) {
        this(name, type, algorithm, length, reference, material, metadata, null);
    }
}
