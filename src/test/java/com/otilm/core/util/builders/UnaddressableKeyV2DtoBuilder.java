package com.otilm.core.util.builders;

import com.otilm.api.model.common.attribute.common.MetadataAttribute;
import com.otilm.api.model.common.enums.cryptography.KeyAlgorithm;
import com.otilm.api.model.connector.cryptography.v2.key.PrivateKeyDataV2Dto;
import com.otilm.api.model.connector.cryptography.v2.key.UnaddressableKeyV2Dto;
import java.util.List;

/**
 * Builds a key a connector lists without an ID unique to it: a 2048-bit RSA private key labelled "legacy", without
 * metadata. Tests override only what their scenario turns on.
 */
public final class UnaddressableKeyV2DtoBuilder {

    private String label = "legacy";
    private KeyAlgorithm algorithm = KeyAlgorithm.RSA;
    private Integer length = 2048;
    private List<MetadataAttribute> metadata = List.of();

    public static UnaddressableKeyV2DtoBuilder anUnaddressableKey() {
        return new UnaddressableKeyV2DtoBuilder();
    }

    public UnaddressableKeyV2DtoBuilder withLabel(String label) {
        this.label = label;
        return this;
    }

    public UnaddressableKeyV2DtoBuilder withAlgorithm(KeyAlgorithm algorithm) {
        this.algorithm = algorithm;
        return this;
    }

    public UnaddressableKeyV2DtoBuilder withLength(Integer length) {
        this.length = length;
        return this;
    }

    public UnaddressableKeyV2DtoBuilder withMetadata(List<MetadataAttribute> metadata) {
        this.metadata = metadata;
        return this;
    }

    public UnaddressableKeyV2Dto build() {
        PrivateKeyDataV2Dto descriptor = new PrivateKeyDataV2Dto();
        descriptor.setAlgorithm(algorithm);
        descriptor.setLength(length);
        descriptor.setMetadata(metadata);
        UnaddressableKeyV2Dto key = new UnaddressableKeyV2Dto();
        key.setLabel(label);
        key.setKeyData(descriptor);
        return key;
    }
}
