package com.otilm.core.model.connector;

import com.otilm.api.model.client.connector.v2.ConnectorInterface;
import com.otilm.api.model.client.connector.v2.FeatureFlag;
import com.otilm.core.dao.entity.ConnectorInterfaceEntity;
import java.util.List;
import java.util.UUID;

/** Immutable connector-interface snapshot. */
public record ImmutableConnectorInterface(UUID uuid, ConnectorInterface code, String version,
        List<FeatureFlag> features) {

    public static ImmutableConnectorInterface from(ConnectorInterfaceEntity connectorInterface) {
        return new ImmutableConnectorInterface(connectorInterface.getUuid(), connectorInterface.getInterfaceCode(),
                connectorInterface.getVersion(), connectorInterface.getFeatures());
    }
}
