package com.otilm.core.util.builders;

import com.otilm.api.model.client.attribute.RequestAttribute;
import com.otilm.api.model.client.cryptography.key.KeyRequestDto;

import java.util.List;

public class KeyPairRequestDtoBuilder {

    private String name = "test-key-pair";
    private String description = null;
    private boolean enabled = true;
    private List<String> groupUuids = List.of();
    private List<RequestAttribute> attributes = List.of();
    private List<RequestAttribute> customAttributes = List.of();

    public static KeyPairRequestDtoBuilder aKeyPairRequest() {
        return new KeyPairRequestDtoBuilder();
    }

    public KeyPairRequestDtoBuilder withName(String name) {
        this.name = name;
        return this;
    }

    public KeyPairRequestDtoBuilder withDescription(String description) {
        this.description = description;
        return this;
    }

    public KeyPairRequestDtoBuilder withEnabled(boolean enabled) {
        this.enabled = enabled;
        return this;
    }

    public KeyPairRequestDtoBuilder withGroupUuids(List<String> groupUuids) {
        this.groupUuids = groupUuids;
        return this;
    }

    public KeyPairRequestDtoBuilder withAttributes(List<RequestAttribute> attributes) {
        this.attributes = attributes;
        return this;
    }

    public KeyPairRequestDtoBuilder withCustomAttributes(List<RequestAttribute> customAttributes) {
        this.customAttributes = customAttributes;
        return this;
    }

    public KeyRequestDto build() {
        KeyRequestDto dto = new KeyRequestDto();
        dto.setName(name);
        dto.setDescription(description);
        dto.setEnabled(enabled);
        dto.setGroupUuids(groupUuids);
        dto.setAttributes(attributes);
        dto.setCustomAttributes(customAttributes);
        return dto;
    }
}
