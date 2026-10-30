package com.otilm.core.model.connector;

import com.otilm.api.model.client.connector.v2.ConnectorVersion;
import com.otilm.api.model.core.connector.AuthType;
import com.otilm.core.dao.entity.Connector;
import com.otilm.core.dao.entity.UniquelyIdentified;
import java.util.List;
import java.util.UUID;

/** Immutable connector identity snapshot with UUID-only association references. */
public record ImmutableConnectorBasicModel(UUID uuid, String name, ConnectorVersion version, String url,
        AuthType authType, UUID proxyUuid, List<UUID> connectorInterfaceUuids,
        List<UUID> functionGroupUuids) implements ConnectorBasicModel {

    public static ImmutableConnectorBasicModel from(Connector connector) {
        return new ImmutableConnectorBasicModel(connector.getUuid(), connector.getName(), connector.getVersion(),
                connector.getUrl(), connector.getAuthType(),
                connector.getProxy() == null ? null : connector.getProxy().getUuid(),
                connector.getInterfaces().stream().map(UniquelyIdentified::getUuid).toList(),
                connector
                        .getFunctionGroups()
                        .stream()
                        .map(functionGroup -> functionGroup.getFunctionGroup().getUuid())
                        .toList());
    }
}
