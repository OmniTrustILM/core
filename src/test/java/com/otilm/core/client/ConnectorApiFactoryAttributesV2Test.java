package com.otilm.core.client;

import com.otilm.api.interfaces.client.v2.AttributesSyncApiClient;
import com.otilm.api.model.core.connector.ConnectorStatus;
import com.otilm.api.model.client.connector.v2.ConnectorVersion;
import com.otilm.core.dao.entity.Connector;
import com.otilm.core.dao.repository.ConnectorRepository;
import com.otilm.core.util.BaseSpringBootTest;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;

class ConnectorApiFactoryAttributesV2Test extends BaseSpringBootTest {

    @Autowired
    private ConnectorApiFactory connectorApiFactory;
    @Autowired
    private ConnectorRepository connectorRepository;

    @Test
    void returnsAttributesV2Client() {
        Connector connector = new Connector();
        connector.setName("c");
        connector.setUrl("http://localhost");
        connector.setVersion(ConnectorVersion.V1);
        connector.setStatus(ConnectorStatus.CONNECTED);
        connectorRepository.save(connector);

        // No proxy configured -> REST client returned (never null).
        AttributesSyncApiClient client = connectorApiFactory.getAttributesApiClientV2(connector.mapToDetailDto());
        Assertions.assertNotNull(client);
    }
}
