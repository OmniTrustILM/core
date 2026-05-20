package com.czertainly.core.service.v2.impl;

import com.czertainly.api.clients.ApiClientConnectorInfo;
import com.czertainly.api.model.client.attribute.ResponseAttribute;
import com.czertainly.api.model.common.attribute.common.BaseAttribute;
import com.czertainly.api.model.core.connector.AuthType;
import com.czertainly.api.model.core.connector.ConnectorStatus;
import com.czertainly.api.model.core.proxy.ProxyDto;
import com.czertainly.core.attribute.engine.AttributeEngine;
import com.czertainly.core.dao.entity.Connector;
import com.czertainly.core.util.AttributeDefinitionUtils;

import java.util.List;

/**
 * Immutable snapshot (shallow) of the connector fields required to route an API client call.
 * The cache returns shared instances, so this type must not expose setters — any mutation of a
 * cached value would silently affect every other caller in the JVM.
 */
record ImmutableConnectorInfo(
        String uuid,
        String name,
        String url,
        ConnectorStatus status,
        AuthType authType,
        List<ResponseAttribute> authAttributes,
        ProxyDto proxy
) implements ApiClientConnectorInfo {

    static ImmutableConnectorInfo of(Connector connector) {
        List<ResponseAttribute> attrs = AttributeEngine.getResponseAttributesFromBaseAttributes(
                AttributeDefinitionUtils.deserialize(connector.getAuthAttributes(), BaseAttribute.class));
        return new ImmutableConnectorInfo(
                connector.getUuid().toString(),
                connector.getName(),
                connector.getUrl(),
                connector.getStatus(),
                connector.getAuthType(),
                attrs == null ? List.of() : List.copyOf(attrs),
                connector.getProxy() == null ? null : connector.getProxy().mapToDtoSimple());
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
