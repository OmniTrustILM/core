package com.otilm.core.mapper.crypto;

import com.otilm.api.model.core.cryptography.token.TokenInstanceDetailDto;
import com.otilm.api.model.core.cryptography.token.TokenInstanceDto;
import com.otilm.api.model.core.cryptography.token.TokenInstanceStatusDetailDto;
import com.otilm.core.model.crypto.TokenInstanceBasicModel;

public final class TokenInstanceDtoMapper {

    private TokenInstanceDtoMapper() {
    }

    public static TokenInstanceDto mapToDto(TokenInstanceBasicModel model) {
        TokenInstanceDto dto = new TokenInstanceDto();
        dto.setName(model.name());
        dto.setStatus(model.status());
        dto.setUuid(model.uuid().toString());
        dto.setTokenProfiles(Math.toIntExact(model.tokenProfileCount()));
        dto.setConnectorName(model.connectorName());
        dto.setConnectorUuid(model.connectorUuid() == null ? null : model.connectorUuid().toString());
        dto.setKind(model.kind());
        return dto;
    }

    public static TokenInstanceDetailDto mapToDetailDto(TokenInstanceBasicModel model) {
        TokenInstanceDetailDto dto = new TokenInstanceDetailDto();
        dto.setName(model.name());
        dto.setStatus(new TokenInstanceStatusDetailDto(model.status()));
        dto.setUuid(model.uuid().toString());
        dto.setTokenProfiles(Math.toIntExact(model.tokenProfileCount()));
        dto.setConnectorName(model.connectorName());
        dto.setConnectorUuid(model.connectorUuid() == null ? null : model.connectorUuid().toString());
        dto.setKind(model.kind());
        return dto;
    }
}
