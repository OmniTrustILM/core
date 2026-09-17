package com.otilm.core.util.builders;

import com.otilm.api.model.common.enums.cryptography.KeyAlgorithm;
import com.otilm.api.model.common.enums.cryptography.KeyType;
import com.otilm.core.model.crypto.KeyMaterial;
import com.otilm.core.model.crypto.ProviderKeyItem;
import com.otilm.core.model.crypto.RemoteKeyReference;
import java.util.List;
import java.util.UUID;

public class ProviderKeyItemBuilder {

    private String name = "provider-item";
    private String association;
    private RemoteKeyReference reference = new RemoteKeyReference.UuidReference(UUID.randomUUID());
    private KeyMaterial material;

    public static ProviderKeyItemBuilder aProviderKeyItem() {
        return new ProviderKeyItemBuilder();
    }

    public ProviderKeyItemBuilder withName(String name) {
        this.name = name;
        return this;
    }

    public ProviderKeyItemBuilder withAssociation(String association) {
        this.association = association;
        return this;
    }

    public ProviderKeyItemBuilder withReference(RemoteKeyReference reference) {
        this.reference = reference;
        return this;
    }

    public ProviderKeyItemBuilder withMaterial(KeyMaterial material) {
        this.material = material;
        return this;
    }

    public ProviderKeyItem build() {
        return new ProviderKeyItem(name, KeyType.PRIVATE_KEY, KeyAlgorithm.RSA, 2048, reference, material, List.of(),
                association);
    }
}
