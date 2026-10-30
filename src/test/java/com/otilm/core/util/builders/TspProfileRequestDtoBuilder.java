package com.otilm.core.util.builders;

import com.otilm.api.model.client.attribute.RequestAttribute;
import com.otilm.api.model.client.signing.protocols.tsp.TspProfileRequestDto;

import java.util.List;
import java.util.UUID;

public class TspProfileRequestDtoBuilder {

    private String name = "test-tsp-profile";
    private String description = null;
    private UUID defaultSigningProfileUuid = null;
    private List<RequestAttribute> customAttributes = List.of();

    public static TspProfileRequestDtoBuilder aTspProfileRequest() {
        return new TspProfileRequestDtoBuilder();
    }

    public TspProfileRequestDtoBuilder withName(String name) {
        this.name = name;
        return this;
    }

    public TspProfileRequestDtoBuilder withDescription(String description) {
        this.description = description;
        return this;
    }

    public TspProfileRequestDtoBuilder withDefaultSigningProfile(UUID signingProfileUuid) {
        this.defaultSigningProfileUuid = signingProfileUuid;
        return this;
    }

    public TspProfileRequestDtoBuilder withCustomAttributes(List<RequestAttribute> attrs) {
        this.customAttributes = attrs;
        return this;
    }

    public TspProfileRequestDto build() {
        TspProfileRequestDto dto = new TspProfileRequestDto();
        dto.setName(name);
        dto.setDescription(description);
        dto.setDefaultSigningProfileUuid(defaultSigningProfileUuid);
        dto.setCustomAttributes(customAttributes);
        return dto;
    }
}
