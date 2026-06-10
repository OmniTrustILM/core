package com.czertainly.core.util.builders;

import com.otilm.api.model.client.cryptography.token.TokenInstanceRequestDto;

import java.util.List;

public class TokenInstanceRequestDtoBuilder {

    private String name = "test-token-instance";
    private String connectorUuid = null;
    private String kind = "SOFT";

    public static TokenInstanceRequestDtoBuilder aTokenInstanceRequest() {
        return new TokenInstanceRequestDtoBuilder();
    }

    public TokenInstanceRequestDtoBuilder withName(String name) {
        this.name = name;
        return this;
    }

    public TokenInstanceRequestDtoBuilder withConnector(String uuid) {
        this.connectorUuid = uuid;
        return this;
    }

    public TokenInstanceRequestDtoBuilder withKind(String kind) {
        this.kind = kind;
        return this;
    }

    public TokenInstanceRequestDto build() {
        TokenInstanceRequestDto dto = new TokenInstanceRequestDto();
        dto.setName(name);
        dto.setConnectorUuid(connectorUuid);
        dto.setKind(kind);
        dto.setCustomAttributes(List.of());
        dto.setAttributes(List.of());
        return dto;
    }
}
