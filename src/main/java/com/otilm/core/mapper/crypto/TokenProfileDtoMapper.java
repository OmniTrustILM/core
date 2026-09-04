package com.otilm.core.mapper.crypto;

import com.otilm.api.model.core.cryptography.tokenprofile.TokenProfileDetailDto;
import com.otilm.api.model.core.cryptography.tokenprofile.TokenProfileDto;
import com.otilm.core.model.crypto.TokenProfileFullModel;

public final class TokenProfileDtoMapper {

    private TokenProfileDtoMapper() {
    }

    public static TokenProfileDto mapToDto(TokenProfileFullModel model) {
        TokenProfileDto dto = new TokenProfileDto();
        dto.setEnabled(model.enabled());
        dto.setUuid(model.uuid().toString());
        dto.setName(model.name());
        dto.setDescription(model.description());
        dto.setTokenInstanceName(model.tokenInstanceName());
        dto
                .setTokenInstanceUuid(model.tokenInstanceReferenceUuid() == null
                        ? null
                        : model.tokenInstanceReferenceUuid().toString());
        dto.setTokenInstanceStatus(model.tokenInstanceStatus());
        dto.setUsages(model.usages());
        return dto;
    }

    public static TokenProfileDetailDto mapToDetailDto(TokenProfileFullModel model) {
        TokenProfileDetailDto dto = new TokenProfileDetailDto();
        dto.setEnabled(model.enabled());
        dto.setUuid(model.uuid().toString());
        dto.setName(model.name());
        dto.setDescription(model.description());
        dto.setTokenInstanceName(model.tokenInstanceName());
        dto
                .setTokenInstanceUuid(model.tokenInstanceReferenceUuid() == null
                        ? null
                        : model.tokenInstanceReferenceUuid().toString());
        dto.setTokenInstanceStatus(model.tokenInstanceStatus());
        dto.setUsages(model.usages());
        return dto;
    }
}
