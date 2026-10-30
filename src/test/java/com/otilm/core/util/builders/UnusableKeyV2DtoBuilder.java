package com.otilm.core.util.builders;

import com.otilm.api.model.common.attribute.common.MetadataAttribute;
import com.otilm.api.model.common.enums.cryptography.KeyAlgorithm;
import com.otilm.api.model.connector.cryptography.v2.key.PrivateKeyDataV2Dto;
import com.otilm.api.model.connector.cryptography.v2.key.UnusableKeyReason;
import com.otilm.api.model.connector.cryptography.v2.key.UnusableKeyV2Dto;
import java.util.List;

/**
 * Builds a key a connector lists as unusable: a 2048-bit RSA private key labelled "legacy" that has no ID unique to it,
 * without metadata. Tests override only what their scenario turns on.
 */
public final class UnusableKeyV2DtoBuilder {

    private String label = "legacy";
    private UnusableKeyReason reason = UnusableKeyReason.UNADDRESSABLE;
    private boolean keyDataRead = true;
    private KeyAlgorithm algorithm = KeyAlgorithm.RSA;
    private Integer length = 2048;
    private List<MetadataAttribute> metadata = List.of();

    public static UnusableKeyV2DtoBuilder anUnusableKey() {
        return new UnusableKeyV2DtoBuilder();
    }

    public UnusableKeyV2DtoBuilder withLabel(String label) {
        this.label = label;
        return this;
    }

    public UnusableKeyV2DtoBuilder withReason(UnusableKeyReason reason) {
        this.reason = reason;
        return this;
    }

    public UnusableKeyV2DtoBuilder withAlgorithm(KeyAlgorithm algorithm) {
        this.algorithm = algorithm;
        return this;
    }

    public UnusableKeyV2DtoBuilder withLength(Integer length) {
        this.length = length;
        return this;
    }

    public UnusableKeyV2DtoBuilder withMetadata(List<MetadataAttribute> metadata) {
        this.metadata = metadata;
        return this;
    }

    /** The connector could not read the key's type. */
    public UnusableKeyV2DtoBuilder withoutKeyData() {
        this.keyDataRead = false;
        return this;
    }

    public UnusableKeyV2Dto build() {
        UnusableKeyV2Dto key = new UnusableKeyV2Dto();
        key.setLabel(label);
        key.setReason(reason);
        if (keyDataRead) {
            key.setKeyData(descriptor());
        }
        return key;
    }

    private PrivateKeyDataV2Dto descriptor() {
        PrivateKeyDataV2Dto descriptor = new PrivateKeyDataV2Dto();
        descriptor.setAlgorithm(algorithm);
        descriptor.setLength(length);
        descriptor.setMetadata(metadata);
        return descriptor;
    }
}
