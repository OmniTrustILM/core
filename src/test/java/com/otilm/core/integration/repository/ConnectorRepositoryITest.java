package com.otilm.core.integration.repository;

import com.otilm.api.model.client.connector.v2.ConnectorInterface;
import com.otilm.api.model.core.connector.FunctionGroupCode;
import com.otilm.core.Application;
import com.otilm.core.dao.entity.Connector;
import com.otilm.core.dao.repository.Connector2FunctionGroupRepository;
import com.otilm.core.dao.repository.ConnectorInterfaceRepository;
import com.otilm.core.dao.repository.ConnectorRepository;
import com.otilm.core.dao.repository.FunctionGroupRepository;
import com.otilm.core.util.builders.ConnectorBuilder;
import jakarta.persistence.EntityManager;
import java.util.UUID;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.annotation.Rollback;
import org.springframework.transaction.annotation.Transactional;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;

@SpringBootTest(classes = Application.class)
@Transactional
@Rollback
class ConnectorRepositoryITest {

    @Autowired
    private ConnectorRepository connectorRepository;

    @Autowired
    private ConnectorInterfaceRepository connectorInterfaceRepository;

    @Autowired
    private FunctionGroupRepository functionGroupRepository;

    @Autowired
    private Connector2FunctionGroupRepository connector2FunctionGroupRepository;

    @Autowired
    private EntityManager entityManager;

    @Test
    void save_assignsUuid_whenUuidIsMissing() {
        // given
        Connector connectorToSave = ConnectorBuilder.aConnector().withGeneratedUuid().build();

        // when
        Connector savedConnector = connectorRepository.save(connectorToSave);

        // then
        assertNotNull(savedConnector.getUuid());
    }

    @Test
    void findWithInterfacesAndFunctionGroupsByUuid_returnsStoredAssociations() {
        // given
        var expectedInterfaceCount = 1;
        var expectedFunctionGroupCount = 1;
        var expectedInterfaceCode = ConnectorInterface.CRYPTOGRAPHY;
        var expectedFunctionGroupCode = FunctionGroupCode.CRYPTOGRAPHY_PROVIDER;
        Connector persistedConnector = persistConnectorWithAssociations(expectedInterfaceCode,
                expectedFunctionGroupCode);
        UUID persistedConnectorUuid = persistedConnector.getUuid();

        // when
        Connector loadedConnector = connectorRepository
                .findWithInterfacesAndFunctionGroupsByUuid(persistedConnectorUuid)
                .orElseThrow();

        // then
        assertEquals(expectedInterfaceCount, loadedConnector.getInterfaces().size());
        assertEquals(expectedInterfaceCode, loadedConnector.getInterfaces().iterator().next().getInterfaceCode());
        assertEquals(expectedFunctionGroupCount, loadedConnector.getFunctionGroups().size());
        assertEquals(expectedFunctionGroupCode,
                loadedConnector.getFunctionGroups().iterator().next().getFunctionGroup().getCode());
    }

    private Connector persistConnectorWithAssociations(ConnectorInterface interfaceCode,
            FunctionGroupCode functionGroupCode) {
        ConnectorBuilder.Fixture fixture = ConnectorBuilder
                .aConnector()
                .withInterfaceCode(interfaceCode)
                .withFunctionGroupCode(functionGroupCode)
                .buildFixture();
        Connector connector = connectorRepository.save(fixture.connector());
        connectorInterfaceRepository.save(fixture.connectorInterface());
        functionGroupRepository.save(fixture.functionGroup());
        connector2FunctionGroupRepository.save(fixture.relation());
        entityManager.flush();
        entityManager.clear();
        return connector;
    }
}
