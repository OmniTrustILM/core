package com.otilm.core.util;

import com.otilm.api.model.client.connector.v2.ConnectorInterface;
import com.otilm.api.model.client.connector.v2.ConnectorVersion;
import com.otilm.api.model.client.connector.v2.FeatureFlag;
import com.otilm.api.model.core.connector.ConnectorStatus;
import com.otilm.core.dao.entity.Connector;
import com.otilm.core.dao.entity.ConnectorInterfaceEntity;
import com.otilm.core.dao.repository.ConnectorInterfaceRepository;
import com.otilm.core.dao.repository.ConnectorRepository;
import java.util.List;
import java.util.UUID;

/**
 * A discovery interface for a v2 run to point at, with the connector that owns it. Both are real rows: the run's
 * interface association is a foreign key, as is the interface's connector, and the run's metadata definitions carry a
 * foreign key to the connector that published them.
 */
public final class DiscoveryInterfaceFixture {

    private DiscoveryInterfaceFixture() {
    }

    public static ConnectorInterfaceEntity v2Interface(ConnectorRepository connectors,
            ConnectorInterfaceRepository interfaces, FeatureFlag... features) {
        Connector connector = new Connector();
        connector.setName("network-discovery-" + UUID.randomUUID());
        // Unique per fixture: url and version are unique together on the connector table.
        connector.setUrl("http://localhost/" + connector.getName());
        connector.setVersion(ConnectorVersion.V2);
        connector.setStatus(ConnectorStatus.CONNECTED);
        connector = connectors.save(connector);

        ConnectorInterfaceEntity discoveryInterface = new ConnectorInterfaceEntity();
        discoveryInterface.setConnectorUuid(connector.getUuid());
        discoveryInterface.setInterfaceCode(ConnectorInterface.DISCOVERY);
        discoveryInterface.setVersion("v2");
        if (features.length > 0) {
            discoveryInterface.setFeatures(List.of(features));
        }
        return interfaces.save(discoveryInterface);
    }
}
