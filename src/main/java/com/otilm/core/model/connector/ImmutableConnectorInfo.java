package com.otilm.core.model.connector;

import com.otilm.api.clients.ApiClientConnectorInfo;
import com.otilm.api.model.client.attribute.ResponseAttribute;
import com.otilm.api.model.common.attribute.common.BaseAttribute;
import com.otilm.api.model.core.connector.AuthType;
import com.otilm.api.model.core.connector.ConnectorStatus;
import com.otilm.api.model.core.proxy.ProxyDto;
import com.otilm.core.attribute.engine.AttributeEngine;
import com.otilm.core.dao.entity.Connector;
import com.otilm.core.dao.entity.Proxy;
import com.otilm.core.util.AttributeDefinitionUtils;
import java.util.List;
import org.jspecify.annotations.Nullable;

/** Immutable connector data required to route an API client call. */
public record ImmutableConnectorInfo(String uuid, String name, String url, ConnectorStatus status, AuthType authType,
        List<ResponseAttribute> authAttributes, ProxyDto proxy) implements ApiClientConnectorInfo {

    public ImmutableConnectorInfo {
        authAttributes = List.copyOf(authAttributes);
    }

    public static ImmutableConnectorInfo of(Connector connector) {
        List<ResponseAttribute> attributes = deserializeAuthAttributes(connector.getAuthAttributes());
        return new ImmutableConnectorInfo(connector.getUuid().toString(), connector.getName(), connector.getUrl(),
                connector.getStatus(), connector.getAuthType(), attributes,
                connector.getProxy() == null ? null : connector.getProxy().mapToDtoSimple());
    }

    public ImmutableConnectorInfo routedOver(String url, AuthType authType, String serializedAuthAttributes,
            @Nullable Proxy proxy) {
        return new ImmutableConnectorInfo(uuid, name, url, status, authType,
                deserializeAuthAttributes(serializedAuthAttributes), proxy == null ? null : proxy.mapToDtoSimple());
    }

    private static List<ResponseAttribute> deserializeAuthAttributes(String authAttributes) {
        List<ResponseAttribute> attributes = AttributeEngine
                .getResponseAttributesFromBaseAttributes(
                        AttributeDefinitionUtils.deserialize(authAttributes, BaseAttribute.class));
        return attributes == null ? List.of() : attributes;
    }

    @Override
    public String getUuid() {
        return uuid;
    }

    @Override
    public String getName() {
        return name;
    }

    @Override
    public String getUrl() {
        return url;
    }

    @Override
    public ConnectorStatus getStatus() {
        return status;
    }

    @Override
    public AuthType getAuthType() {
        return authType;
    }

    @Override
    public List<ResponseAttribute> getAuthAttributes() {
        return authAttributes;
    }

    @Override
    public ProxyDto getProxy() {
        return proxy;
    }
}
