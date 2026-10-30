package com.otilm.core.integration.dao.entity;

import com.otilm.api.model.client.connector.v2.ConnectorInterface;
import com.otilm.api.model.client.connector.v2.ConnectorVersion;
import com.otilm.api.model.connector.cryptography.enums.TokenInstanceStatus;
import com.otilm.api.model.core.connector.ConnectorStatus;
import com.otilm.core.dao.entity.Connector;
import com.otilm.core.dao.entity.ConnectorInterfaceEntity;
import com.otilm.core.dao.entity.TokenInstanceReference;
import com.otilm.core.dao.repository.ConnectorInterfaceRepository;
import com.otilm.core.dao.repository.ConnectorRepository;
import com.otilm.core.dao.repository.TokenInstanceReferenceRepository;
import com.otilm.core.util.BaseSpringBootTest;
import jakarta.persistence.EntityManager;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.test.annotation.Rollback;
import org.springframework.transaction.annotation.Transactional;

import static org.junit.jupiter.api.Assertions.assertEquals;

@Transactional
@Rollback
class TokenInstanceReferenceConnectorInterfaceITest extends BaseSpringBootTest {

    @Autowired
    private ConnectorRepository connectorRepository;

    @Autowired
    private ConnectorInterfaceRepository connectorInterfaceRepository;

    @Autowired
    private TokenInstanceReferenceRepository tokenInstanceReferenceRepository;

    @Autowired
    private EntityManager entityManager;

    @Test
    void connectorInterface_roundTrips_forTokenInstance() {
        // given
        String supportedVersion = "v2";
        Connector connector = connectorRepository.save(cryptographyConnector());
        ConnectorInterfaceEntity connectorInterface = connectorInterfaceRepository
                .save(cryptographyInterface(connector, supportedVersion));
        TokenInstanceReference tokenInstance = new TokenInstanceReference();
        tokenInstance.setStatus(TokenInstanceStatus.UNKNOWN);
        tokenInstance.setName("token-with-interface");
        tokenInstance.setConnector(connector);
        tokenInstance.setConnectorInterface(connectorInterface);
        tokenInstanceReferenceRepository.save(tokenInstance);
        entityManager.flush();
        entityManager.clear();

        // when
        TokenInstanceReference storedToken = tokenInstanceReferenceRepository
                .findByUuid(tokenInstance.getUuid())
                .orElseThrow();

        // then
        assertEquals(connectorInterface.getUuid(), storedToken.getConnectorInterfaceUuid());
        assertEquals(connectorInterface.getUuid(), storedToken.getConnectorInterface().getUuid());
        assertEquals(supportedVersion, storedToken.getConnectorInterface().getVersion());
    }

    private Connector cryptographyConnector() {
        Connector connector = new Connector();
        connector.setName("cryptography-connector");
        connector.setUrl("http://cryptography-connector.test");
        connector.setVersion(ConnectorVersion.V2);
        connector.setStatus(ConnectorStatus.CONNECTED);
        return connector;
    }

    private ConnectorInterfaceEntity cryptographyInterface(Connector connector, String version) {
        ConnectorInterfaceEntity connectorInterface = new ConnectorInterfaceEntity();
        connectorInterface.setConnectorUuid(connector.getUuid());
        connectorInterface.setInterfaceCode(ConnectorInterface.CRYPTOGRAPHY);
        connectorInterface.setVersion(version);
        return connectorInterface;
    }
}
