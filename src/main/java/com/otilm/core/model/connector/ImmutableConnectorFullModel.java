package com.otilm.core.model.connector;

import com.otilm.api.clients.ApiClientConnectorInfo;
import com.otilm.api.model.client.attribute.ResponseAttribute;
import com.otilm.api.model.client.connector.v2.ConnectorVersion;
import com.otilm.api.model.common.attribute.common.BaseAttribute;
import com.otilm.api.model.core.connector.AuthType;
import com.otilm.api.model.core.connector.ConnectorStatus;
import com.otilm.api.model.core.proxy.ProxyDto;
import com.otilm.core.attribute.engine.AttributeEngine;
import com.otilm.core.dao.entity.Connector;
import com.otilm.core.util.AttributeDefinitionUtils;
import java.util.List;
import java.util.UUID;

/** Immutable connector snapshot for routing decisions outside a persistence transaction. */
public record ImmutableConnectorFullModel(UUID uuid, String name, ConnectorVersion version, String url,
        AuthType authType, List<ResponseAttribute> authAttributes, ConnectorStatus status, ProxyDto proxy,
        List<ImmutableConnectorInterface> connectorInterfaces,
        List<ConnectorFunctionGroupModel> functionGroups) implements ConnectorFullModel, ApiClientConnectorInfo {

    public static ImmutableConnectorFullModel from(Connector connector) {
        return new ImmutableConnectorFullModel(connector.getUuid(), connector.getName(), connector.getVersion(),
                connector.getUrl(), connector.getAuthType(), deserializeAuthAttributes(connector.getAuthAttributes()),
                connector.getStatus(), connector.getProxy() == null ? null : connector.getProxy().mapToDtoSimple(),
                connector.getInterfaces().stream().map(ImmutableConnectorInterface::from).toList(),
                connector.getFunctionGroups().stream().map(ConnectorFunctionGroupModel::from).toList());
    }

    private static List<ResponseAttribute> deserializeAuthAttributes(String authAttributes) {
        List<ResponseAttribute> attributes = AttributeEngine
                .getResponseAttributesFromBaseAttributes(
                        AttributeDefinitionUtils.deserialize(authAttributes, BaseAttribute.class));
        return attributes == null ? List.of() : attributes;
    }

    @Override
    public String getUuid() {
        return uuid.toString();
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
