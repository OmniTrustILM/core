package com.czertainly.core.service;

import com.czertainly.api.exception.*;
import com.czertainly.api.model.client.certificate.SearchRequestDto;
import com.czertainly.api.model.client.connector.v2.*;
import com.czertainly.api.model.common.BulkActionMessageDto;
import com.czertainly.api.model.common.NameAndUuidDto;
import com.czertainly.api.model.common.PaginationResponseDto;
import com.czertainly.api.model.core.connector.AuthType;
import com.czertainly.api.model.core.connector.ConnectorStatus;
import com.czertainly.api.model.core.connector.v2.*;
import com.czertainly.core.dao.entity.*;
import com.czertainly.core.dao.repository.*;
import com.czertainly.core.security.authz.SecuredUUID;
import com.czertainly.core.security.authz.SecurityFilter;
import com.czertainly.core.service.v2.ConnectorService;
import com.czertainly.core.util.BaseSpringBootTest;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.github.tomakehurst.wiremock.WireMockServer;
import com.github.tomakehurst.wiremock.client.WireMock;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.test.context.bean.override.mockito.MockitoSpyBean;

import java.util.ArrayList;
import java.util.List;
import java.util.UUID;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.doThrow;

class ConnectorServiceV2Test extends BaseSpringBootTest {

    private static final String CONNECTOR_NAME = "testConnectorV2";

    @Autowired
    private ConnectorService connectorService;

    @Autowired
    private ConnectorRepository connectorRepository;

    @MockitoSpyBean
    private ConnectorRepository connectorRepositorySpy;

    @Autowired
    private ConnectorInterfaceRepository connectorInterfaceRepository;

    @Autowired
    private CredentialRepository credentialRepository;

    @Autowired
    private EntityInstanceReferenceRepository entityInstanceRepository;

    @Autowired
    private TokenInstanceReferenceRepository tokenInstanceRepository;

    @Autowired
    private VaultInstanceRepository vaultInstanceRepository;

    @Autowired
    private AuthorityInstanceReferenceRepository authorityInstanceReferenceRepository;

    @Autowired
    private ObjectMapper objectMapper;

    private Connector connector;
    private WireMockServer mockServer;

    @BeforeEach
    void setUp() {
        mockServer = new WireMockServer(0);
        mockServer.start();
        WireMock.configureFor("localhost", mockServer.port());

        connector = new Connector();
        connector.setName(CONNECTOR_NAME);
        connector.setUrl("http://localhost:" + mockServer.port());
        connector.setVersion(ConnectorVersion.V2);
        connector.setStatus(ConnectorStatus.CONNECTED);
        connector.setAuthType(AuthType.NONE);
        connector = connectorRepository.save(connector);

        // Add connector interface
        ConnectorInterfaceEntity interfaceEntity = new ConnectorInterfaceEntity();
        interfaceEntity.setConnectorUuid(connector.getUuid());
        interfaceEntity.setInterfaceCode(ConnectorInterface.AUTHORITY);
        interfaceEntity.setVersion("v2");
        interfaceEntity.setFeatures(List.of(FeatureFlag.STATELESS));
        connectorInterfaceRepository.save(interfaceEntity);
    }

    @AfterEach
    void tearDown() {
        mockServer.stop();
    }

    @Test
    void testListConnectors() {
        SearchRequestDto request = new SearchRequestDto();
        request.setPageNumber(1);
        request.setItemsPerPage(10);
        request.setFilters(List.of());

        PaginationResponseDto<ConnectorDto> response = connectorService.listConnectors(SecurityFilter.create(), request);
        Assertions.assertNotNull(response);
        Assertions.assertFalse(response.getItems().isEmpty());
        Assertions.assertTrue(response.getItems().stream().anyMatch(c -> c.getName().equals(CONNECTOR_NAME)));
    }

    @Test
    void testGetConnector() throws NotFoundException, ConnectorException {
        ConnectorDetailDto dto = connectorService.getConnector(connector.getSecuredUuid());
        Assertions.assertNotNull(dto);
        Assertions.assertEquals(connector.getUuid().toString(), dto.getUuid());
        Assertions.assertEquals(connector.getName(), dto.getName());
        Assertions.assertEquals(ConnectorVersion.V2, dto.getVersion());
    }

    @Test
    void testGetConnector_notFound() {
        Assertions.assertThrows(NotFoundException.class,
                () -> connectorService.getConnector(SecuredUUID.fromString("abfbc322-29e1-11ed-a261-0242ac120002")));
    }

    @Test
    void testCreateConnector() throws ConnectorException, AlreadyExistException, AttributeException, NotFoundException, JsonProcessingException {
        ConnectorRequestDto request = new ConnectorRequestDto();
        request.setName("newConnectorV2");
        request.setUrl("http://localhost:" + mockServer.port());
        request.setVersion(ConnectorVersion.V2);
        request.setAuthType(AuthType.NONE);
        Assertions.assertThrows(AlreadyExistException.class, () -> connectorService.createConnector(request));

        mockServer.stop();
        mockServer = new WireMockServer(0);
        mockServer.start();
        request.setUrl("http://localhost:" + mockServer.port());

        mockInfoEndpoint();

        ConnectorDetailDto dto = connectorService.createConnector(request);
        Assertions.assertNotNull(dto);
        Assertions.assertEquals(request.getName(), dto.getName());
        Assertions.assertEquals(ConnectorVersion.V2, dto.getVersion());
    }

    @Test
    void testCreateConnector_validationFail() {
        ConnectorRequestDto request = new ConnectorRequestDto();
        Assertions.assertThrows(ValidationException.class, () -> connectorService.createConnector(request));
    }

    @Test
    void testCreateConnector_alreadyExist() {
        ConnectorRequestDto request = new ConnectorRequestDto();
        request.setName(CONNECTOR_NAME);
        request.setUrl("http://localhost:" + mockServer.port());
        request.setVersion(ConnectorVersion.V2);
        request.setAuthType(AuthType.NONE);
        Assertions.assertThrows(AlreadyExistException.class, () -> connectorService.createConnector(request));
    }

    @Test
    void testEditConnector() throws ConnectorException, AttributeException, NotFoundException, JsonProcessingException {
        mockInfoEndpoint();

        ConnectorUpdateRequestDto request = new ConnectorUpdateRequestDto();
        request.setUrl("http://localhost:" + mockServer.port());
        request.setAuthType(AuthType.NONE);

        ConnectorDetailDto dto = connectorService.editConnector(connector.getSecuredUuid(), request);
        Assertions.assertNotNull(dto);
        Assertions.assertEquals(connector.getName(), dto.getName());
    }

    @Test
    void testEditConnector_notFound() {
        Assertions.assertThrows(NotFoundException.class,
                () -> connectorService.editConnector(SecuredUUID.fromString("abfbc322-29e1-11ed-a261-0242ac120002"), new ConnectorUpdateRequestDto()));
    }

    @Test
    void testDeleteConnector() throws NotFoundException {
        connectorService.deleteConnector(connector.getSecuredUuid());
        Assertions.assertThrows(NotFoundException.class, () -> connectorService.getConnector(connector.getSecuredUuid()));
    }

    @Test
    void testDeleteConnector_notFound() {
        Assertions.assertThrows(NotFoundException.class,
                () -> connectorService.deleteConnector(SecuredUUID.fromString("abfbc322-29e1-11ed-a261-0242ac120002")));
    }

    @Test
    void testBulkDeleteConnector() {
        connectorService.bulkDeleteConnector(List.of(connector.getSecuredUuid()));
        Assertions.assertThrows(NotFoundException.class, () -> connectorService.getConnector(connector.getSecuredUuid()));
    }

    @Test
    void testForceDeleteConnector() {
        SecuredUUID connectorUUID = connector.getSecuredUuid();

        // create dependent entities to test force delete
        Credential credential = new Credential();
        credential.setName("test");
        credential.setConnectorUuid(connectorUUID.getValue());
        credential.setConnectorName(CONNECTOR_NAME);
        credential.setKind("TST");
        credentialRepository.save(credential);

        EntityInstanceReference entity = new EntityInstanceReference();
        entity.setName("test");
        entity.setKind("Test");
        entity.setConnectorUuid(connectorUUID.getValue());
        entityInstanceRepository.save(entity);

        TokenInstanceReference token = new TokenInstanceReference();
        token.setName("test");
        token.setKind("TST");
        token.setConnectorUuid(connectorUUID.getValue());
        tokenInstanceRepository.save(token);

        VaultInstance vaultInstance = new VaultInstance();
        vaultInstance.setName("test");
        vaultInstance.setConnectorUuid(connectorUUID.getValue());
        vaultInstance.setConnectorInterface(connectorInterfaceRepository.findAll().getFirst());
        vaultInstanceRepository.save(vaultInstance);

        Assertions.assertThrows(ValidationException.class, () -> connectorService.deleteConnector(connectorUUID));

        List<BulkActionMessageDto> messages = connectorService.forceDeleteConnector(List.of(connector.getSecuredUuid()));
        Assertions.assertNotNull(messages);
        Assertions.assertTrue(messages.isEmpty());
        Assertions.assertThrows(NotFoundException.class, () -> connectorService.getConnector(connector.getSecuredUuid()));
    }

    @Test
    void testReconnectConnector() throws NotFoundException, ConnectorException, JsonProcessingException {
        mockInfoEndpoint();

        ConnectInfo connectInfo = connectorService.reconnect(connector.getSecuredUuid());
        Assertions.assertNotNull(connectInfo);
        Assertions.assertEquals(ConnectorVersion.V2, connectInfo.getVersion());
    }

    @Test
    void testBulkReconnect() throws JsonProcessingException {
        mockInfoEndpoint();

        List<BulkActionMessageDto> messages = connectorService.bulkReconnect(List.of(connector.getSecuredUuid()));
        Assertions.assertNotNull(messages);
        Assertions.assertTrue(messages.isEmpty());
    }

    @Test
    void testBulkReconnect_withError() {
        mockServer.stubFor(WireMock.get("/v2/info")
                .willReturn(WireMock.aResponse().withStatus(500).withBody("Internal Server Error")));

        List<BulkActionMessageDto> messages = connectorService.bulkReconnect(List.of(connector.getSecuredUuid()));
        Assertions.assertNotNull(messages);
        Assertions.assertFalse(messages.isEmpty());
        Assertions.assertEquals(connector.getUuid().toString(), messages.get(0).getUuid());
    }

    @Test
    void testReconnectConnector_notFound() {
        Assertions.assertThrows(NotFoundException.class,
                () -> connectorService.reconnect(SecuredUUID.fromString("abfbc322-29e1-11ed-a261-0242ac120002")));
    }

    @Test
    void testReconnectConnector_communicationError() {
        mockServer.stubFor(WireMock.get("/v2/info")
                .willReturn(WireMock.aResponse().withStatus(500).withBody("Internal Server Error")));

        SecuredUUID connectorUuid = connector.getSecuredUuid();
        Assertions.assertThrows(ConnectorException.class, () -> connectorService.reconnect(connectorUuid));
    }

    @Test
    void testCheckHealth() throws ConnectorException, NotFoundException {
        mockServer.stubFor(WireMock.get("/v2/health")
                .willReturn(WireMock.okJson("{ \"status\": \"UP\" }")));

        HealthInfo health = connectorService.checkHealth(connector.getSecuredUuid());
        Assertions.assertNotNull(health);
        Assertions.assertEquals(HealthStatus.UP, health.getStatus());
    }

    @Test
    void testCheckHealth_notFound() {
        Assertions.assertThrows(NotFoundException.class,
                () -> connectorService.checkHealth(SecuredUUID.fromString("abfbc322-29e1-11ed-a261-0242ac120002")));
    }

    @Test
    void testGetInfo() throws ConnectorException, NotFoundException, JsonProcessingException {
        mockInfoEndpoint();

        ConnectorInfo info = connectorService.getInfo(connector.getSecuredUuid());
        Assertions.assertNotNull(info);
    }

    @Test
    void testApproveConnector() throws NotFoundException {
        Connector waitingConnector = new Connector();
        waitingConnector.setName("waitingConnector");
        waitingConnector.setUrl("http://localhost:" + mockServer.port() + "/waiting");
        waitingConnector.setVersion(ConnectorVersion.V2);
        waitingConnector.setStatus(ConnectorStatus.WAITING_FOR_APPROVAL);
        waitingConnector = connectorRepository.save(waitingConnector);

        connectorService.approve(waitingConnector.getSecuredUuid());

        Connector approvedConnector = connectorRepository.findByUuid(waitingConnector.getUuid()).orElseThrow();
        Assertions.assertEquals(ConnectorStatus.CONNECTED, approvedConnector.getStatus());
    }

    @Test
    void testBulkApprove() {
        Connector waitingConnector = new Connector();
        waitingConnector.setName("waitingConnector");
        waitingConnector.setUrl("http://localhost:" + mockServer.port() + "/waiting_connector");
        waitingConnector.setVersion(ConnectorVersion.V2);
        waitingConnector.setStatus(ConnectorStatus.WAITING_FOR_APPROVAL);
        waitingConnector = connectorRepository.save(waitingConnector);

        List<BulkActionMessageDto> messages = connectorService.bulkApprove(List.of(waitingConnector.getSecuredUuid()));
        Assertions.assertNotNull(messages);
        Assertions.assertTrue(messages.isEmpty());

        Connector approvedConnector = connectorRepository.findByUuid(waitingConnector.getUuid()).orElseThrow();
        Assertions.assertEquals(ConnectorStatus.CONNECTED, approvedConnector.getStatus());
    }

    @Test
    void testApproveConnector_validationFail() {
        // Connector is already CONNECTED, not WAITING_FOR_APPROVAL
        SecuredUUID connectorUuid = connector.getSecuredUuid();
        Assertions.assertThrows(ValidationException.class, () -> connectorService.approve(connectorUuid));
    }

    @Test
    void testApproveConnector_notFound() {
        Assertions.assertThrows(NotFoundException.class,
                () -> connectorService.approve(SecuredUUID.fromString("abfbc322-29e1-11ed-a261-0242ac120002")));
    }

    @Test
    void testConnect() throws JsonProcessingException, ConnectorException {
        mockInfoEndpoint();

        // Mock V1 endpoint to return error (no V1 connector)
        mockServer.stubFor(WireMock.get("/v1")
                .willReturn(WireMock.aResponse().withStatus(404).withBody("Not Found")));

        var request = new com.czertainly.api.model.client.connector.ConnectRequestDto();
        request.setUrl("http://localhost:" + mockServer.port());
        request.setAuthType(AuthType.NONE);

        List<ConnectInfo> connectInfos = connectorService.connect(request);
        Assertions.assertNotNull(connectInfos);
        Assertions.assertFalse(connectInfos.isEmpty());
    }

    @Test
    void testCheckHealth_v1Connector() throws ConnectorException, NotFoundException {
        // Create a V1 connector
        Connector v1Connector = new Connector();
        v1Connector.setName("v1HealthConnector");
        v1Connector.setUrl("http://localhost:" + mockServer.port());
        v1Connector.setVersion(ConnectorVersion.V1);
        v1Connector.setStatus(ConnectorStatus.CONNECTED);
        v1Connector.setAuthType(AuthType.NONE);
        v1Connector = connectorRepository.save(v1Connector);

        mockServer.stubFor(WireMock.get("/v1/health")
                .willReturn(WireMock.okJson("{ \"status\": \"ok\" }")));

        HealthInfo health = connectorService.checkHealth(v1Connector.getSecuredUuid());
        Assertions.assertNotNull(health);
        Assertions.assertEquals(HealthStatus.UP, health.getStatus());
    }

    @Test
    void testListResourceObjects() {
        List<NameAndUuidDto> dtos = connectorService.listResourceObjects(SecurityFilter.create(), null, null);
        Assertions.assertFalse(dtos.isEmpty());
        Assertions.assertTrue(dtos.stream().anyMatch(dto -> dto.getName().equals(CONNECTOR_NAME)));
    }

    private void mockInfoEndpoint() throws JsonProcessingException {
        List<ConnectorInterfaceInfo> connectorInterfaceInfos = createMockInterfaceInfos();

        ConnectorInfo connectorInfo = new ConnectorInfo();
        connectorInfo.setName(CONNECTOR_NAME);
        connectorInfo.setId("czertainly.common.credential.provider");
        connectorInfo.setVersion("1.0.0");

        InfoResponse infoResponse = new InfoResponse();
        infoResponse.setConnector(connectorInfo);
        infoResponse.setInterfaces(connectorInterfaceInfos);
        String jsonBody = objectMapper.writeValueAsString(infoResponse);

        mockServer.stubFor(WireMock.get("/v2/info")
                .willReturn(WireMock.okJson(jsonBody)));
    }

    private List<ConnectorInterfaceInfo> createMockInterfaceInfos() {
        List<ConnectorInterfaceInfo> connectorInterfaceInfos = new ArrayList<>();
        List<ConnectorInterface> interfaces = List.of(
                ConnectorInterface.INFO,
                ConnectorInterface.HEALTH,
                ConnectorInterface.METRICS,
                ConnectorInterface.AUTHORITY
        );

        for (ConnectorInterface connectorInterface : interfaces) {
            ConnectorInterfaceInfo info = new ConnectorInterfaceInfo();
            info.setCode(connectorInterface);
            info.setVersion("v2");
            info.setFeatures(List.of());
            connectorInterfaceInfos.add(info);
        }
        return connectorInterfaceInfos;
    }

    @Test
    void testGetResourceObject() throws NotFoundException {
        NameAndUuidDto dto = connectorService.getResourceObjectInternal(connector.getUuid());
        Assertions.assertNotNull(dto);
        Assertions.assertEquals(connector.getName(), dto.getName());
        Assertions.assertEquals(connector.getUuid().toString(), dto.getUuid());

        NameAndUuidDto nameAndUuidDto = connectorService.getResourceObjectExternal(connector.getSecuredUuid());
        Assertions.assertEquals(connector.getUuid().toString(), nameAndUuidDto.getUuid());
        Assertions.assertEquals(connector.getName(), nameAndUuidDto.getName());
    }

    @Test
    void testBulkDeleteConnector_nonExistentUuid_returnsErrorMessage() throws ValidationException, NotFoundException {
        SecuredUUID nonExistent = SecuredUUID.fromUUID(UUID.fromString("00000000-0000-0000-0000-000000000001"));

        List<BulkActionMessageDto> messages = connectorService.bulkDeleteConnector(List.of(nonExistent));

        Assertions.assertEquals(1, messages.size());
        Assertions.assertEquals("00000000-0000-0000-0000-000000000001", messages.getFirst().getUuid());
        Assertions.assertNotNull(messages.getFirst().getMessage());
    }

    @Test
    void testForceDeleteConnector_nonExistentUuid_returnsErrorMessage() throws ValidationException, NotFoundException {
        SecuredUUID nonExistent = SecuredUUID.fromUUID(UUID.fromString("00000000-0000-0000-0000-000000000001"));

        List<BulkActionMessageDto> messages = connectorService.forceDeleteConnector(List.of(nonExistent));

        Assertions.assertEquals(1, messages.size());
        Assertions.assertEquals("00000000-0000-0000-0000-000000000001", messages.getFirst().getUuid());
        Assertions.assertNotNull(messages.getFirst().getMessage());
        Assertions.assertEquals("", messages.getFirst().getName());
    }

    @Test
    void testBulkApprove_alreadyConnectedConnector_returnsErrorMessage() {
        List<BulkActionMessageDto> messages = connectorService.bulkApprove(List.of(connector.getSecuredUuid()));

        Assertions.assertEquals(1, messages.size());
        Assertions.assertEquals(connector.getUuid().toString(), messages.getFirst().getUuid());
        Assertions.assertNotNull(messages.getFirst().getMessage());
    }

    @Test
    void testBulkDeleteConnector_withAssociatedAuthorityInstance_returnsErrorWithConnectorName() {
        AuthorityInstanceReference authority = new AuthorityInstanceReference();
        authority.setName("dependentAuthority");
        authority.setConnector(connector);
        authority.setKind("ApiKey");
        authority.setAuthorityInstanceUuid("test-instance-uuid");
        authorityInstanceReferenceRepository.save(authority);

        List<BulkActionMessageDto> messages = connectorService.bulkDeleteConnector(
                List.of(connector.getSecuredUuid()));

        Assertions.assertEquals(1, messages.size());
        Assertions.assertEquals(connector.getName(), messages.getFirst().getName());
        Assertions.assertNotNull(messages.getFirst().getMessage());
    }

    @Test
    void testBulkReconnect_nonExistentUuid_returnsErrorMessage() {
        SecuredUUID nonExistent = SecuredUUID.fromUUID(UUID.fromString("00000000-0000-0000-0000-000000000001"));

        List<BulkActionMessageDto> messages = connectorService.bulkReconnect(List.of(nonExistent));

        Assertions.assertEquals(1, messages.size());
        Assertions.assertEquals("00000000-0000-0000-0000-000000000001", messages.getFirst().getUuid());
        Assertions.assertNotNull(messages.getFirst().getMessage());
        Assertions.assertEquals("", messages.getFirst().getName());
    }

    @Test
    void testBulkApprove_nonExistentUuid_returnsErrorMessage() {
        SecuredUUID nonExistent = SecuredUUID.fromUUID(UUID.fromString("00000000-0000-0000-0000-000000000001"));

        List<BulkActionMessageDto> messages = connectorService.bulkApprove(List.of(nonExistent));

        Assertions.assertEquals(1, messages.size());
        Assertions.assertEquals("00000000-0000-0000-0000-000000000001", messages.getFirst().getUuid());
        Assertions.assertNotNull(messages.getFirst().getMessage());
        Assertions.assertEquals("", messages.getFirst().getName());
    }

    @Test
    void testForceDeleteConnector_deleteFailure_returnsErrorWithConnectorName() {
        doThrow(new RuntimeException("DB delete error"))
                .when(connectorRepositorySpy).delete(any());

        List<BulkActionMessageDto> messages = connectorService.forceDeleteConnector(
                List.of(connector.getSecuredUuid()));

        Assertions.assertEquals(1, messages.size());
        Assertions.assertEquals(connector.getUuid().toString(), messages.getFirst().getUuid());
        Assertions.assertEquals(connector.getName(), messages.getFirst().getName());
        Assertions.assertNotNull(messages.getFirst().getMessage());
    }
}
