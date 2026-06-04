package com.czertainly.core.service;

import com.czertainly.api.exception.AlreadyExistException;
import com.czertainly.api.exception.AttributeException;
import com.czertainly.api.exception.ConnectorException;
import com.czertainly.api.exception.NotFoundException;
import com.czertainly.api.model.client.connector.v2.ConnectorVersion;
import com.czertainly.api.model.common.attribute.common.DataAttribute;
import com.czertainly.api.model.core.connector.ConnectorStatus;
import com.czertainly.api.model.core.connector.FunctionGroupCode;
import com.czertainly.api.model.core.notification.NotificationInstanceDto;
import com.czertainly.api.model.core.notification.NotificationInstanceRequestDto;
import com.czertainly.api.model.core.notification.NotificationInstanceUpdateRequestDto;
import com.czertainly.core.dao.entity.Connector;
import com.czertainly.core.dao.entity.Connector2FunctionGroup;
import com.czertainly.core.dao.entity.FunctionGroup;
import com.czertainly.core.dao.entity.notifications.NotificationInstanceReference;
import com.czertainly.core.dao.repository.Connector2FunctionGroupRepository;
import com.czertainly.core.dao.repository.ConnectorRepository;
import com.czertainly.core.dao.repository.FunctionGroupRepository;
import com.czertainly.core.dao.repository.notifications.NotificationInstanceReferenceRepository;
import com.czertainly.core.util.BaseSpringBootTest;
import com.czertainly.core.util.MetaDefinitions;
import com.github.tomakehurst.wiremock.WireMockServer;
import com.github.tomakehurst.wiremock.client.WireMock;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;

import java.util.List;
import java.util.UUID;

class NotificationInstanceServiceTest extends BaseSpringBootTest {

    @Autowired
    private FunctionGroupRepository functionGroupRepository;

    @Autowired
    private Connector2FunctionGroupRepository connector2FunctionGroupRepository;

    @Autowired
    private ConnectorRepository connectorRepository;

    @Autowired
    private NotificationInstanceReferenceRepository notificationInstanceReferenceRepository;

    @Autowired
    private NotificationInstanceExternalService notificationInstanceService;

    private static final String TEST_CONNECTOR_KIND = "testKind";
    private static final String EXISTING_NIR_NAME = "TestNotificationInstance";
    private static final String EXISTING_NIR_UUID = "eb775202-b81e-460d-a24e-144fe4abe8f0";

    private WireMockServer mockServer;
    private Connector connector;

    @BeforeEach
    void setUp() {
        mockServer = new WireMockServer(0);
        mockServer.start();

        WireMock.configureFor("localhost", mockServer.port());

        mockServer.stubFor(WireMock.get(WireMock.urlPathMatching("/v1/notificationProvider/[^/]+/attributes/mapping")).willReturn(WireMock.okJson("[]")));
        mockServer.stubFor(WireMock.post(WireMock.urlPathMatching("/v1/notificationProvider/[^/]+/attributes/validate")).willReturn(WireMock.ok()));
        mockServer.stubFor(WireMock.get(WireMock.urlPathMatching("/v1/notificationProvider/[^/]+/attributes")).willReturn(WireMock.okJson("[]")));

        connector = new Connector();
        connector.setName("notificationInstanceConnector");
        connector.setUrl("http://localhost:" + mockServer.port());
        connector.setVersion(ConnectorVersion.V1);
        connector.setStatus(ConnectorStatus.CONNECTED);
        connector = connectorRepository.save(connector);

        FunctionGroup functionGroup = new FunctionGroup();
        functionGroup.setCode(FunctionGroupCode.NOTIFICATION_PROVIDER);
        functionGroup.setName(FunctionGroupCode.NOTIFICATION_PROVIDER.getCode());
        functionGroupRepository.save(functionGroup);

        Connector2FunctionGroup c2fg = new Connector2FunctionGroup();
        c2fg.setConnector(connector);
        c2fg.setFunctionGroup(functionGroup);
        c2fg.setKinds(MetaDefinitions.serializeArrayString(List.of(TEST_CONNECTOR_KIND)));
        connector2FunctionGroupRepository.save(c2fg);

        connector.getFunctionGroups().add(c2fg);
        connectorRepository.save(connector);

        NotificationInstanceReference notificationInstance = new NotificationInstanceReference();
        notificationInstance.setName(EXISTING_NIR_NAME);
        notificationInstance.setKind(TEST_CONNECTOR_KIND);
        notificationInstance.setConnectorUuid(connector.getUuid());
        notificationInstance.setNotificationInstanceUuid(UUID.fromString(EXISTING_NIR_UUID));
        notificationInstance.setUuid(UUID.fromString(EXISTING_NIR_UUID));
        notificationInstanceReferenceRepository.save(notificationInstance);
    }

    @Test
    void testCreateNotificationInstance() throws ConnectorException, NotFoundException, AlreadyExistException, AttributeException {
        NotificationInstanceRequestDto requestDto = new NotificationInstanceRequestDto();
        requestDto.setName("test");
        requestDto.setDescription("description");
        requestDto.setConnectorUuid(connector.getUuid().toString());
        requestDto.setKind(TEST_CONNECTOR_KIND);
        requestDto.setAttributes(List.of());
        requestDto.setAttributeMappings(List.of());

        mockServer.stubFor(WireMock.post(
                        WireMock.urlPathMatching("/v1/notificationProvider/notifications"))
                .willReturn(WireMock.okJson("""
                        {
                            "uuid": "%s",
                            "name": "%s",
                            "attributes": []
                        }
                        """.formatted(UUID.randomUUID(), requestDto.getName())
                ))
        );

        NotificationInstanceDto notificationInstanceDto = notificationInstanceService.createNotificationInstance(requestDto);

        // Verify the notification instance was created successfully
        Assertions.assertNotNull(notificationInstanceDto);
    }

    @Test
    void testAlreadyExistNotificationInstance() {
        NotificationInstanceRequestDto requestDto = new NotificationInstanceRequestDto();
        requestDto.setName(EXISTING_NIR_NAME);
        requestDto.setDescription("description");
        requestDto.setConnectorUuid(connector.getUuid().toString());
        requestDto.setKind(TEST_CONNECTOR_KIND);
        requestDto.setAttributes(List.of());
        requestDto.setAttributeMappings(List.of());

        Assertions.assertThrows(AlreadyExistException.class, () -> notificationInstanceService.createNotificationInstance(requestDto));
    }

    @Test
    void testUpdateNotificationInstance() throws ConnectorException, NotFoundException, AttributeException {
        NotificationInstanceUpdateRequestDto requestDto = new NotificationInstanceUpdateRequestDto();
        requestDto.setDescription("new description");
        requestDto.setAttributes(List.of());
        requestDto.setAttributeMappings(List.of());

        mockServer.stubFor(WireMock.put(
                        WireMock.urlPathMatching("/v1/notificationProvider/notifications/%s".formatted(EXISTING_NIR_UUID)))
                .willReturn(WireMock.okJson("""
                        {
                            "uuid": "%s",
                            "name": "%s",
                            "attributes": []
                        }
                        """.formatted(UUID.randomUUID(), EXISTING_NIR_NAME)
                ))
        );

        NotificationInstanceDto notificationInstanceDto = notificationInstanceService.editNotificationInstance(UUID.fromString(EXISTING_NIR_UUID), requestDto);

        // Verify the notification instance was updated successfully
        Assertions.assertNotNull(notificationInstanceDto);
        Assertions.assertEquals(notificationInstanceDto.getDescription(), requestDto.getDescription());
    }

    @Test
    void testUpdateNonExistingNotificationInstance() {
        NotificationInstanceUpdateRequestDto requestDto = new NotificationInstanceUpdateRequestDto();
        requestDto.setDescription("new description");
        requestDto.setAttributes(List.of());
        requestDto.setAttributeMappings(List.of());

        Assertions.assertThrows(NotFoundException.class, () -> notificationInstanceService.editNotificationInstance(UUID.randomUUID(), requestDto));
    }

    @Test
    void testDeleteNotificationInstance() {
        mockServer.stubFor(WireMock.delete(
                        WireMock.urlPathMatching("/v1/notificationProvider/notifications/%s".formatted(EXISTING_NIR_UUID)))
                .willReturn(WireMock.ok())
        );

        Assertions.assertDoesNotThrow(() -> notificationInstanceService.deleteNotificationInstance(UUID.fromString(EXISTING_NIR_UUID)));
    }

    @Test
    void testDeleteNonExistingNotificationInstance() {
        Assertions.assertThrows(NotFoundException.class, () -> notificationInstanceService.deleteNotificationInstance(UUID.randomUUID()));
    }

    @Test
    void testListNotificationInstances() {
        List<NotificationInstanceDto> notificationInstances = notificationInstanceService.listNotificationInstances();

        // Verify the notification instances were retrieved successfully
        Assertions.assertNotNull(notificationInstances);
        Assertions.assertFalse(notificationInstances.isEmpty());
        Assertions.assertEquals(1, notificationInstances.size());
    }

    @Test
    void testGetNotificationInstance() throws ConnectorException, NotFoundException {
        mockServer.stubFor(WireMock.get(
                        WireMock.urlPathMatching("/v1/notificationProvider/notifications/%s".formatted(EXISTING_NIR_UUID)))
                .willReturn(WireMock.okJson("""
                        {
                            "uuid": "%s",
                            "name": "%s",
                            "attributes": []
                        }
                        """.formatted(UUID.fromString(EXISTING_NIR_UUID), EXISTING_NIR_NAME)
                ))
        );

        NotificationInstanceDto notificationInstanceDto = notificationInstanceService.getNotificationInstance(UUID.fromString(EXISTING_NIR_UUID));

        // Verify the notification instance was retrieved successfully
        Assertions.assertNotNull(notificationInstanceDto);
        Assertions.assertEquals(EXISTING_NIR_NAME, notificationInstanceDto.getName());
        Assertions.assertEquals(EXISTING_NIR_UUID, notificationInstanceDto.getUuid());
    }

    @Test
    void testGetNonExistingNotificationInstance() {
        Assertions.assertThrows(NotFoundException.class, () -> notificationInstanceService.getNotificationInstance(UUID.randomUUID()));
    }

    @Test
    void testListMappingAttributes() throws ConnectorException, NotFoundException {
        List<DataAttribute> attributes = notificationInstanceService.listMappingAttributes(connector.getUuid().toString(), TEST_CONNECTOR_KIND);

        // Verify the mapping attributes were retrieved successfully
        Assertions.assertNotNull(attributes);
        Assertions.assertTrue(attributes.isEmpty());
    }

}
