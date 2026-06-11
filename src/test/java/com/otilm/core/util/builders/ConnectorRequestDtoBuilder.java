package com.otilm.core.util.builders;

import com.otilm.api.model.client.connector.v2.ConnectorVersion;
import com.otilm.api.model.core.connector.AuthType;
import com.otilm.api.model.core.connector.v2.ConnectorRequestDto;

public class ConnectorRequestDtoBuilder {

    private String name = "test-connector";
    private String url = null;
    private ConnectorVersion version = ConnectorVersion.V2;
    private AuthType authType = AuthType.NONE;

    public static ConnectorRequestDtoBuilder aConnectorRequest() {
        return new ConnectorRequestDtoBuilder();
    }

    public static ConnectorRequestDtoBuilder aV1ConnectorRequest() {
        return new ConnectorRequestDtoBuilder().withVersion(ConnectorVersion.V1);
    }

    public static ConnectorRequestDtoBuilder aV2ConnectorRequest() {
        return new ConnectorRequestDtoBuilder().withVersion(ConnectorVersion.V2);
    }

    public ConnectorRequestDtoBuilder withName(String name) {
        this.name = name;
        return this;
    }

    public ConnectorRequestDtoBuilder withUrl(String url) {
        this.url = url;
        return this;
    }

    public ConnectorRequestDtoBuilder withVersion(ConnectorVersion v) {
        this.version = v;
        return this;
    }

    public ConnectorRequestDtoBuilder withAuthType(AuthType type) {
        this.authType = type;
        return this;
    }

    public ConnectorRequestDto build() {
        ConnectorRequestDto dto = new ConnectorRequestDto();
        dto.setName(name);
        dto.setUrl(url);
        dto.setVersion(version);
        dto.setAuthType(authType);
        return dto;
    }
}
