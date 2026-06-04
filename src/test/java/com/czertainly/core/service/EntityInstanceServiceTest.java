package com.czertainly.core.service;

import com.czertainly.api.exception.*;
import com.czertainly.api.model.client.certificate.EntityInstanceResponseDto;
import com.czertainly.api.model.client.certificate.SearchRequestDto;
import com.czertainly.api.model.client.connector.v2.ConnectorVersion;
import com.czertainly.api.model.client.entity.EntityInstanceRequestDto;
import com.czertainly.api.model.common.NameAndUuidDto;
import com.czertainly.api.model.core.connector.ConnectorStatus;
import com.czertainly.api.model.core.connector.FunctionGroupCode;
import com.czertainly.api.model.core.entity.EntityInstanceDto;
import com.czertainly.core.dao.entity.*;
import com.czertainly.core.dao.repository.*;
import com.czertainly.core.security.authz.SecuredUUID;
import com.czertainly.core.security.authz.SecurityFilter;
import com.czertainly.core.util.BaseSpringBootTest;
import com.czertainly.core.util.MetaDefinitions;
import com.github.tomakehurst.wiremock.WireMockServer;
import com.github.tomakehurst.wiremock.client.WireMock;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;

import java.util.List;

class EntityInstanceServiceTest extends BaseSpringBootTest {

    private static final String ENTITY_INSTANCE_NAME = "testEntityInstance1";

    @Autowired
    private EntityInstanceService entityInstanceService;
    @Autowired
    private EntityInstanceReferenceRepository entityInstanceReferenceRepository;
    @Autowired
    private ConnectorRepository connectorRepository;
    @Autowired
    private FunctionGroupRepository functionGroupRepository;
    @Autowired
    private Connector2FunctionGroupRepository connector2FunctionGroupRepository;

    private EntityInstanceReference entityInstance;
    private Connector connector;

    private WireMockServer mockServer;

    @BeforeEach
    public void setUp() {
        mockServer = new WireMockServer(0);
        mockServer.start();

        WireMock.configureFor("localhost", mockServer.port());

        connector = new Connector();
        connector.setName("entityInstanceConnector");
        connector.setUrl("http://localhost:"+mockServer.port());
        connector.setVersion(ConnectorVersion.V1);
        connector.setStatus(ConnectorStatus.CONNECTED);
        connector = connectorRepository.save(connector);

        FunctionGroup functionGroup = new FunctionGroup();
        functionGroup.setCode(FunctionGroupCode.ENTITY_PROVIDER);
        functionGroup.setName(FunctionGroupCode.ENTITY_PROVIDER.getCode());
        functionGroupRepository.save(functionGroup);

        Connector2FunctionGroup c2fg = new Connector2FunctionGroup();
        c2fg.setConnector(connector);
        c2fg.setFunctionGroup(functionGroup);
        c2fg.setKinds(MetaDefinitions.serializeArrayString(List.of("TestKind")));
        connector2FunctionGroupRepository.save(c2fg);

        connector.getFunctionGroups().add(c2fg);
        connectorRepository.save(connector);

        entityInstance = new EntityInstanceReference();
        entityInstance.setName(ENTITY_INSTANCE_NAME);
        entityInstance.setConnector(connector);
        entityInstance.setKind("TestKind");
        entityInstance.setEntityInstanceUuid("1l");
        entityInstance = entityInstanceReferenceRepository.save(entityInstance);
    }

    @AfterEach
    public void tearDown() {
        mockServer.stop();
    }

    @Test
    void testListEntityInstances() {
        final EntityInstanceResponseDto entityInstanceResponseDto = entityInstanceService.listEntityInstances(SecurityFilter.create(), new SearchRequestDto());
        final List<EntityInstanceDto> entityInstances = entityInstanceResponseDto.getEntities();
        Assertions.assertNotNull(entityInstances);
        Assertions.assertFalse(entityInstances.isEmpty());
        Assertions.assertEquals(1, entityInstances.size());
        Assertions.assertEquals(entityInstance.getUuid().toString(), entityInstances.get(0).getUuid());
    }

    @Test
    void testGetEntityInstance() throws ConnectorException, NotFoundException {
        mockServer.stubFor(WireMock
                .get(WireMock.urlPathMatching("/v1/entityProvider/entities/[^/]+"))
                .willReturn(WireMock.okJson("{}")));

        EntityInstanceDto dto = entityInstanceService.getEntityInstance(entityInstance.getSecuredUuid());
        Assertions.assertNotNull(dto);
        Assertions.assertEquals(entityInstance.getUuid().toString(), dto.getUuid());
        Assertions.assertNotNull(dto.getConnectorUuid());
        Assertions.assertEquals(entityInstance.getConnectorUuid().toString(), dto.getConnectorUuid());
    }

    @Test
    void testGetEntityInstance_notFound() {
        Assertions.assertThrows(NotFoundException.class, () -> entityInstanceService.getEntityInstance(SecuredUUID.fromString("abfbc322-29e1-11ed-a261-0242ac120002")));
    }

    @Test
    void testAddEntityInstance() throws ConnectorException, AlreadyExistException, AttributeException, NotFoundException {
        mockServer.stubFor(WireMock
                .get(WireMock.urlPathMatching("/v1/entityProvider/[^/]+/attributes"))
                .willReturn(WireMock.okJson("[]")));
        mockServer.stubFor(WireMock
                .post(WireMock.urlPathMatching("/v1/entityProvider/[^/]+/attributes/validate"))
                .willReturn(WireMock.okJson("true")));

        mockServer.stubFor(WireMock
                .post(WireMock.urlPathMatching("/v1/entityProvider/entities"))
                .willReturn(WireMock.okJson("{ \"id\": 2 }")));

        EntityInstanceRequestDto request = new EntityInstanceRequestDto();
        request.setName("testEntityInstance2");
        request.setConnectorUuid(connector.getUuid().toString());
        request.setAttributes(List.of());
        request.setKind("TestKind");

        EntityInstanceDto dto = entityInstanceService.createEntityInstance(request);
        Assertions.assertNotNull(dto);
        Assertions.assertEquals(request.getName(), dto.getName());
        Assertions.assertNotNull(dto.getConnectorUuid());
        Assertions.assertEquals(entityInstance.getConnectorUuid().toString(), dto.getConnectorUuid());
    }

    @Test
    void testAddEntityInstance_notFound() {
        EntityInstanceRequestDto request = new EntityInstanceRequestDto();
        request.setName("Demo");
        // connector uuid not set
        Assertions.assertThrows(ValidationException.class, () -> entityInstanceService.createEntityInstance(request));
    }

    @Test
    void testAddEntityInstance_alreadyExist() {
        EntityInstanceRequestDto request = new EntityInstanceRequestDto();
        request.setName(ENTITY_INSTANCE_NAME); // entityInstance with same name already exist

        Assertions.assertThrows(AlreadyExistException.class, () -> entityInstanceService.createEntityInstance(request));
    }

    @Test
    void testEditEntityInstance_notFound() {
        Assertions.assertThrows(NotFoundException.class, () -> entityInstanceService.editEntityInstance(SecuredUUID.fromString("abfbc322-29e1-11ed-a261-0242ac120002"), null));
    }

    @Test
    void testRemoveEntityInstance() throws ConnectorException, NotFoundException {
        mockServer.stubFor(WireMock
                .delete(WireMock.urlPathMatching("/v1/entityProvider/entities/[^/]+"))
                .willReturn(WireMock.ok()));

        entityInstanceService.deleteEntityInstance(entityInstance.getSecuredUuid());
        Assertions.assertThrows(NotFoundException.class, () -> entityInstanceService.getEntityInstance(entityInstance.getSecuredUuid()));
    }

    @Test
    void testGetLocationAttributes() throws ConnectorException, NotFoundException {
        mockServer.stubFor(WireMock
                .get(WireMock.urlPathMatching("/v1/entityProvider/entities/[^/]+/location/attributes"))
                .willReturn(WireMock.ok()));

        entityInstanceService.listLocationAttributes(entityInstance.getSecuredUuid());
    }

    @Test
    void testGetLocationAttributes_notFound() {
        Assertions.assertThrows(NotFoundException.class, () -> entityInstanceService.listLocationAttributes(SecuredUUID.fromString("abfbc322-29e1-11ed-a261-0242ac120002")));
    }

    @Test
    void testValidateLocationAttributes() throws ConnectorException, NotFoundException {
        mockServer.stubFor(WireMock
                .post(WireMock.urlPathMatching("/v1/entityProvider/entities/[^/]+/location/attributes/validate"))
                .willReturn(WireMock.okJson("true")));

        entityInstanceService.validateLocationAttributes(entityInstance.getSecuredUuid(), List.of());
    }

    @Test
    void testValidateLocationAttributes_notFound() {
        Assertions.assertThrows(NotFoundException.class, () -> entityInstanceService.validateLocationAttributes(SecuredUUID.fromString("abfbc322-29e1-11ed-a261-0242ac120002"), null));
    }

    @Test
    void testRemoveEntityInstance_notFound() {
        Assertions.assertThrows(NotFoundException.class, () -> entityInstanceService.deleteEntityInstance(SecuredUUID.fromString("abfbc322-29e1-11ed-a261-0242ac120002")));
    }

    @Test
    void testGetObjectsForResource() {
        List<NameAndUuidDto> dtos = entityInstanceService.listResourceObjects(SecurityFilter.create(), null, null);
        Assertions.assertEquals(1, dtos.size());
    }

    @Test
    void testGetResourceObject() throws NotFoundException {
        NameAndUuidDto nameAndUuidDto = entityInstanceService.getResourceObjectInternal(entityInstance.getUuid());
        Assertions.assertEquals(entityInstance.getUuid().toString(), nameAndUuidDto.getUuid());
        Assertions.assertEquals(entityInstance.getName(), nameAndUuidDto.getName());

        nameAndUuidDto = entityInstanceService.getResourceObjectExternal(entityInstance.getSecuredUuid());
        Assertions.assertEquals(entityInstance.getUuid().toString(), nameAndUuidDto.getUuid());
        Assertions.assertEquals(entityInstance.getName(), nameAndUuidDto.getName());
    }
}
