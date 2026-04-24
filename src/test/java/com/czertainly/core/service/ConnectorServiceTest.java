package com.czertainly.core.service;

import com.czertainly.api.clients.mq.ProxyClient;
import com.czertainly.api.exception.*;
import com.czertainly.api.model.client.connector.*;
import com.czertainly.api.model.client.connector.v2.ConnectorInfo;
import com.czertainly.api.model.client.connector.v2.ConnectorInterface;
import com.czertainly.api.model.client.connector.v2.ConnectorInterfaceInfo;
import com.czertainly.api.model.client.connector.v2.ConnectorVersion;
import com.czertainly.api.model.common.HealthDto;
import com.czertainly.api.model.common.HealthStatus;
import com.czertainly.api.model.common.NameAndUuidDto;
import com.czertainly.api.model.common.attribute.common.BaseAttribute;
import com.czertainly.api.model.core.connector.AuthType;
import com.czertainly.api.model.core.connector.ConnectorDto;
import com.czertainly.api.model.core.connector.ConnectorStatus;
import com.czertainly.api.model.core.connector.FunctionGroupCode;
import com.czertainly.api.model.core.connector.v2.ConnectorDetailDto;
import com.czertainly.api.model.core.proxy.ProxyStatus;
import com.czertainly.core.dao.entity.Connector;
import com.czertainly.core.dao.entity.Connector2FunctionGroup;
import com.czertainly.core.dao.entity.FunctionGroup;
import com.czertainly.core.dao.entity.Proxy;
import com.czertainly.core.dao.repository.Connector2FunctionGroupRepository;
import com.czertainly.core.dao.repository.ConnectorRepository;
import com.czertainly.core.dao.repository.FunctionGroupRepository;
import com.czertainly.core.dao.repository.ProxyRepository;
import com.czertainly.core.security.authz.SecuredUUID;
import com.czertainly.core.security.authz.SecurityFilter;
import com.czertainly.core.util.BaseSpringBootTest;
import com.czertainly.core.util.MetaDefinitions;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.github.tomakehurst.wiremock.WireMockServer;
import com.github.tomakehurst.wiremock.client.WireMock;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.test.context.bean.override.mockito.MockitoBean;

import java.util.*;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.when;

class ConnectorServiceTest extends BaseSpringBootTest {

    private static final String CONNECTOR_NAME = "testConnector1";

    @Autowired
    private ConnectorService connectorService;

    @Autowired
    private com.czertainly.core.service.v2.ConnectorService connectorServiceV2;

    @Autowired
    private ConnectorRepository connectorRepository;
    @Autowired
    private FunctionGroupRepository functionGroupRepository;
    @Autowired
    private Connector2FunctionGroupRepository connector2FunctionGroupRepository;
    @Autowired
    private ProxyRepository proxyRepository;

    @MockitoBean
    private ProxyClient proxyClient;

    @Autowired
    private ObjectMapper objectMapper;

    private Connector connector;
    private Proxy proxy;

    private WireMockServer mockServer;

    @BeforeEach
    void setUp() {
        mockServer = new WireMockServer(0);
        mockServer.start();

        WireMock.configureFor("localhost", mockServer.port());

        connector = new Connector();
        connector.setName(CONNECTOR_NAME);
        connector.setUrl("http://localhost:" + mockServer.port());
        connector.setVersion(ConnectorVersion.V1);
        connector.setStatus(ConnectorStatus.CONNECTED);
        connector = connectorRepository.save(connector);

        FunctionGroup functionGroup = new FunctionGroup();
        functionGroup.setCode(FunctionGroupCode.CREDENTIAL_PROVIDER);
        functionGroup.setName(FunctionGroupCode.CREDENTIAL_PROVIDER.getCode());
        functionGroupRepository.save(functionGroup);

        Connector2FunctionGroup c2fg = new Connector2FunctionGroup();
        c2fg.setConnector(connector);
        c2fg.setFunctionGroup(functionGroup);
        c2fg.setKinds(MetaDefinitions.serializeArrayString(List.of("ApiKey")));
        connector2FunctionGroupRepository.save(c2fg);

        connector.getFunctionGroups().add(c2fg);
        connectorRepository.save(connector);

        proxy = new Proxy();
        proxy.setName("testProxy");
        proxy.setDescription("Test Proxy");
        proxy.setCode("TEST_PROXY");
        proxy.setStatus(ProxyStatus.CONNECTED);
        proxy = proxyRepository.save(proxy);
    }

    @AfterEach
    void tearDown() {
        mockServer.stop();
    }

    @Test
    void testListConnectors() throws NotFoundException {
        List<ConnectorDto> connectors = connectorService.listConnectors(SecurityFilter.create(), Optional.empty(), Optional.empty(), Optional.empty());
        Assertions.assertNotNull(connectors);
        Assertions.assertFalse(connectors.isEmpty());
        Assertions.assertEquals(1, connectors.size());
        Assertions.assertEquals(connector.getUuid().toString(), connectors.get(0).getUuid());
    }

    @Test
    void testListConnectorsByFunctionGroup() throws NotFoundException {
        List<ConnectorDto> connectors = connectorService.listConnectors(
                SecurityFilter.create(),
                Optional.of(FunctionGroupCode.CREDENTIAL_PROVIDER), Optional.empty(), Optional.empty()
        );
        Assertions.assertNotNull(connectors);
        Assertions.assertFalse(connectors.isEmpty());
        Assertions.assertEquals(1, connectors.size());
        Assertions.assertEquals(connector.getUuid().toString(), connectors.get(0).getUuid());
    }

    @Test
    void testListConnectorsByFunctionGroup_notFound() throws NotFoundException {
        List<ConnectorDto> connectors = connectorService.listConnectors(
                SecurityFilter.create(),
                Optional.of(FunctionGroupCode.LEGACY_AUTHORITY_PROVIDER),
                Optional.empty(), Optional.empty()
        );
        Assertions.assertNotNull(connectors);
        Assertions.assertTrue(connectors.isEmpty());
    }

    @Test
    void testListConnectorsByFunctionGroupAndKind() throws NotFoundException {
        List<ConnectorDto> connectors = connectorService.listConnectors(
                SecurityFilter.create(),
                Optional.of(FunctionGroupCode.CREDENTIAL_PROVIDER), Optional.of("ApiKey"),
                Optional.empty()
        );
        Assertions.assertNotNull(connectors);
        Assertions.assertFalse(connectors.isEmpty());
        Assertions.assertEquals(1, connectors.size());
        Assertions.assertEquals(connector.getUuid().toString(), connectors.get(0).getUuid());
    }

    @Test
    void testListConnectorsByFunctionGroupAndKind_notFound() throws NotFoundException {
        Assertions.assertEquals(0,
                connectorService.listConnectors(
                        SecurityFilter.create(),
                        Optional.of(FunctionGroupCode.LEGACY_AUTHORITY_PROVIDER),
                        Optional.of("wrong-kind"), Optional.empty()).size()
        );

    }

    @Test
    void testListConnectorsByFunctionGroupAndKind_noConnectorOfKind() throws NotFoundException {
        List<ConnectorDto> connectors = connectorService.listConnectors(
                SecurityFilter.create(),
                Optional.of(FunctionGroupCode.LEGACY_AUTHORITY_PROVIDER),
                Optional.of("wrong-kind"), Optional.empty()
        );
        Assertions.assertNotNull(connectors);
        Assertions.assertTrue(connectors.isEmpty());
    }

    @Test
    void testGetAllAttributesOfConnector() throws ConnectorException, NotFoundException {
        mockServer.stubFor(WireMock
                .get(WireMock.urlPathMatching("/v1/credentialProvider/[^/]+/attributes"))
                .willReturn(WireMock.okJson("[]")));

        Map<FunctionGroupCode, Map<String, List<BaseAttribute>>> result = connectorService.getAllAttributesOfConnector(connector.getSecuredUuid());
        Assertions.assertNotNull(result);
        Assertions.assertEquals(1, result.size());
        Assertions.assertNotNull(result.get(FunctionGroupCode.CREDENTIAL_PROVIDER));
    }

    @Test
    void testGetAllAttributesOfConnector_notFund() {
        Assertions.assertThrows(NotFoundException.class, () -> connectorService.getAllAttributesOfConnector(SecuredUUID.fromString("abfbc322-29e1-11ed-a261-0242ac120002")));
    }

    @Test
    void testGetConnector() throws ConnectorException, NotFoundException {
        mockServer.stubFor(WireMock
                .get("/v1")
                .willReturn(WireMock.okJson("[]")));

        ConnectorDto dto = connectorService.getConnector(connector.getSecuredUuid());
        Assertions.assertNotNull(dto);
        Assertions.assertEquals(connector.getUuid().toString(), dto.getUuid());
        Assertions.assertEquals(connector.getName(), dto.getName());
    }

    @Test
    void testGetConnector_notFound() {
        Assertions.assertThrows(NotFoundException.class, () -> connectorService.getConnector(SecuredUUID.fromString("abfbc322-29e1-11ed-a261-0242ac120002")));
    }

    @Test
    void testAddConnector() throws ConnectorException, AlreadyExistException, AttributeException, NotFoundException, JsonProcessingException {
        List<ConnectorInterfaceInfo> connectorInterfaceInfos = new ArrayList<>();
        List<ConnectorInterface> connectorInterfaces = List.of(ConnectorInterface.INFO, ConnectorInterface.HEALTH, ConnectorInterface.HEALTH, ConnectorInterface.METRICS, ConnectorInterface.AUTHORITY);
        for (ConnectorInterface connectorInterface : connectorInterfaces) {
            ConnectorInterfaceInfo info = new ConnectorInterfaceInfo();
            info.setCode(connectorInterface);
            info.setVersion("v2");
            info.setFeatures(List.of());
            connectorInterfaceInfos.add(info);
        }

        var infoResponse = new com.czertainly.api.model.client.connector.v2.InfoResponse();
        infoResponse.setConnector(new ConnectorInfo());
        infoResponse.setInterfaces(connectorInterfaceInfos);
        String jsonBody = objectMapper.writeValueAsString(infoResponse);
        mockServer.stubFor(WireMock
                .get("/v2/info")
                .willReturn(WireMock.okJson(jsonBody)));

        var request = new com.czertainly.api.model.core.connector.v2.ConnectorRequestDto();
        request.setName("testConnector2");
        request.setUrl("http://localhost:" + mockServer.port());
        request.setVersion(ConnectorVersion.V2);
        request.setAuthType(AuthType.NONE);

        ConnectorDetailDto dto = connectorServiceV2.createConnector(request);
        Assertions.assertNotNull(dto);
        Assertions.assertEquals(request.getName(), dto.getName());
    }

    @Test
    void testAddConnector_validationFail() {
        ConnectorRequestDto request = new ConnectorRequestDto();
        Assertions.assertThrows(ValidationException.class, () -> connectorService.createConnector(request));
    }

    @Test
    void testAddConnector_duplicateFunctionGroupAndKind() throws JsonProcessingException {
        // Mock V1 endpoint to return function groups with same kind as existing connector
        List<InfoResponse> infoResponses = new ArrayList<>();
        InfoResponse infoResponse = new InfoResponse();
        infoResponse.setFunctionGroupCode(FunctionGroupCode.CREDENTIAL_PROVIDER);
        infoResponse.setKinds(List.of("ApiKey")); // Same kind as setUp connector
        infoResponses.add(infoResponse);

        String jsonBody = objectMapper.writeValueAsString(infoResponses);

        mockServer.stop();
        mockServer = new WireMockServer(0);
        mockServer.start();
        mockServer.stubFor(WireMock
                .get("/v1")
                .willReturn(WireMock.okJson(jsonBody)));

        // Mock V2 info endpoint to return 404 (no V2 support)
        mockServer.stubFor(WireMock
                .get("/v2/info")
                .willReturn(WireMock.aResponse().withStatus(404).withBody("Not Found")));

        ConnectorRequestDto request = new ConnectorRequestDto();
        request.setName("duplicateConnector");
        request.setUrl("http://localhost:" + mockServer.port());
        request.setAuthType(AuthType.NONE);

        // Connector with same function group (CREDENTIAL_PROVIDER) and kind (ApiKey) already exists
        Assertions.assertThrows(ValidationException.class, () -> connectorService.createConnector(request));

        ConnectRequestDto connectRequest = new ConnectRequestDto();
        connectRequest.setUrl(request.getUrl());
        connectRequest.setAuthType(AuthType.NONE);
        connectRequest.setUuid(connector.getUuid().toString());

        // Even though the function group and kind are duplicate, it should not throw exception on connect as the connector is already created and connected successfully
        Assertions.assertDoesNotThrow(() -> connectorService.connect(connectRequest));
    }

    @Test
    void testAddConnector_alreadyExist() {
        ConnectorRequestDto request = new ConnectorRequestDto();
        request.setName(CONNECTOR_NAME);
        Assertions.assertThrows(AlreadyExistException.class, () -> connectorService.createConnector(request));
    }

    @Test
    void testEditConnector() throws ConnectorException, AttributeException, NotFoundException {
        mockServer.stubFor(WireMock
                .get("/v1")
                .willReturn(WireMock.okJson("[]")));

        ConnectorUpdateRequestDto request = new ConnectorUpdateRequestDto();
        request.setUrl("http://localhost:" + mockServer.port());

        ConnectorDto dto = connectorService.editConnector(connector.getSecuredUuid(), request);
        Assertions.assertNotNull(dto);
    }

    @Test
    void testEditConnector_notFound() {
        Assertions.assertThrows(NotFoundException.class, () -> connectorService.editConnector(SecuredUUID.fromString("abfbc322-29e1-11ed-a261-0242ac120002"), new ConnectorUpdateRequestDto()));
    }

    @Test
    void testRemoveConnector() throws NotFoundException {
        connectorService.deleteConnector(connector.getSecuredUuid());
        Assertions.assertThrows(NotFoundException.class, () -> connectorService.getConnector(connector.getSecuredUuid()));
    }

    @Test
    void testRemoveConnector_notFound() {
        Assertions.assertThrows(NotFoundException.class, () -> connectorService.deleteConnector(SecuredUUID.fromString("abfbc322-29e1-11ed-a261-0242ac120002")));
    }

    @Test
    void testBulkRemove() throws NotFoundException {
        connectorService.bulkDeleteConnector(List.of(connector.getSecuredUuid()));
        Assertions.assertThrows(NotFoundException.class, () -> connectorService.getConnector(connector.getSecuredUuid()));
    }

    @Test
    void testConnect() throws ValidationException, ConnectorException, JsonProcessingException {
        List<InfoResponse> infoResponses = new ArrayList<>();
        InfoResponse infoResponse = new InfoResponse();
        infoResponse.setFunctionGroupCode(FunctionGroupCode.CREDENTIAL_PROVIDER);
        infoResponse.setKinds(List.of("Test")); // Same kind as setUp connector
        infoResponses.add(infoResponse);

        String jsonBody = objectMapper.writeValueAsString(infoResponses);

        mockServer.stubFor(WireMock
                .get("/v1")
                .willReturn(WireMock.okJson(jsonBody)));

        // Mock v2 info endpoint to return 404 (no v2 support)
        mockServer.stubFor(WireMock
                .get("/v2/info")
                .willReturn(WireMock.aResponse().withStatus(404).withBody("Not Found")));

        ConnectRequestDto request = new ConnectRequestDto();
        request.setUrl("http://localhost:" + mockServer.port());
        request.setAuthType(AuthType.NONE);

        List<ConnectDto> connectDtos = connectorService.connect(request);
        Assertions.assertNotNull(connectDtos);
        Assertions.assertFalse(connectDtos.isEmpty());
    }

    @Test
    void testReconnect_withV2Connector_throws() {
        Connector v2Connector = new Connector();
        v2Connector.setName("v2Connector");
        v2Connector.setUrl("http://localhost:" + mockServer.port());
        v2Connector.setVersion(ConnectorVersion.V2);
        v2Connector.setStatus(ConnectorStatus.CONNECTED);
        v2Connector = connectorRepository.save(v2Connector);

        SecuredUUID v2ConnectorUuid = v2Connector.getSecuredUuid();
        Assertions.assertThrows(ValidationException.class, () -> connectorService.reconnect(v2ConnectorUuid));
    }

    @Test
    void testApproveConnector() throws ConnectorException, NotFoundException {
        Connector waitingConnector = new Connector();
        waitingConnector.setUrl("http://localhost:" + mockServer.port() + "/waiting_connector");
        waitingConnector.setVersion(ConnectorVersion.V1);
        waitingConnector.setStatus(ConnectorStatus.WAITING_FOR_APPROVAL);
        waitingConnector = connectorRepository.save(waitingConnector);

        connectorService.approve(waitingConnector.getSecuredUuid());

        mockServer.stubFor(WireMock
                .get("/v1")
                .willReturn(WireMock.okJson("[]")));

        Assertions.assertEquals(ConnectorStatus.CONNECTED, connectorService.getConnector(connector.getSecuredUuid()).getStatus());
    }

    @Test
    void testApproveConnector_ValidationFail() {
        Assertions.assertThrows(ValidationException.class, () -> connectorService.approve(connector.getSecuredUuid()));
    }

    @Test
    void testApproveConnector_notFound() {
        Assertions.assertThrows(
                NotFoundException.class,
                () -> connectorService.approve(SecuredUUID.fromString("abfbc322-29e1-11ed-a261-0242ac120002"))
        );
    }

    @Test
    void testCheckHealth() throws ConnectorException, NotFoundException {
        mockServer.stubFor(WireMock
                .get("/v1/health")
                .willReturn(WireMock.okJson("{ \"status\": \"ok\" }")));

        HealthDto health = connectorService.checkHealth(connector.getSecuredUuid());
        Assertions.assertNotNull(health);
        Assertions.assertNotNull(health.getStatus());
        Assertions.assertEquals(HealthStatus.OK, health.getStatus());
    }

    @Test
    void testCheckHealth_notFound() {
        Assertions.assertThrows(
                NotFoundException.class,
                () -> connectorService.checkHealth(SecuredUUID.fromString("abfbc322-29e1-11ed-a261-0242ac120002"))
        );
    }

    @Test
    void testGetAttributes() throws ConnectorException, NotFoundException {
        FunctionGroupCode code = FunctionGroupCode.CREDENTIAL_PROVIDER;
        String kind = "ApiKey";

        mockServer.stubFor(WireMock
                .get(WireMock.urlPathMatching("/v1/" + code.getCode() + "/" + kind + "/attributes"))
                .willReturn(WireMock.okJson("[]")));

        List<BaseAttribute> attributes = connectorService.getAttributes(connector.getSecuredUuid(), code, kind);
        Assertions.assertNotNull(attributes);
    }

    @Test
    void testGetAttributes_validationFail() {
        Assertions.assertThrows(
                ValidationException.class,
                () -> connectorService.getAttributes(
                        connector.getSecuredUuid(),
                        FunctionGroupCode.LEGACY_AUTHORITY_PROVIDER,
                        null
                )
        );
    }

    @Test
    void testGetAttributes_notFound() {
        Assertions.assertThrows(
                NotFoundException.class,
                () -> connectorService.getAttributes(SecuredUUID.fromString("abfbc322-29e1-11ed-a261-0242ac120002"),
                        null,
                        null
                )
        );
    }

    @Test
    void testValidateAttributes() throws ConnectorException, NotFoundException {
        FunctionGroupCode code = FunctionGroupCode.CREDENTIAL_PROVIDER;
        String kind = "ApiKey";

        mockServer.stubFor(WireMock
                .post(WireMock.urlPathMatching("/v1/" + code.getCode() + "/" + kind + "/attributes/validate"))
                .willReturn(WireMock.okJson("true")));

        connectorService.validateAttributes(connector.getSecuredUuid(), code, List.of(), kind);

    }

    @Test
    void testValidateAttributes_validationFail() {
        Assertions.assertThrows(ValidationException.class,
                () -> connectorService.validateAttributes(
                        connector.getSecuredUuid(),
                        FunctionGroupCode.LEGACY_AUTHORITY_PROVIDER,
                        null,
                        null
                )
        );
    }

    @Test
    void testValidateAttributes_validationFailOnConnector() throws ConnectorException, NotFoundException {
        FunctionGroupCode code = FunctionGroupCode.CREDENTIAL_PROVIDER;
        String kind = "ApiKey";

        mockServer.stubFor(WireMock
                .post(WireMock.urlPathMatching("/v1/" + code.getCode() + "/" + kind + "/attributes/validate"))
                .willReturn(WireMock.okJson("false")
                )
        );

        connectorService.validateAttributes(connector.getSecuredUuid(), code, List.of(), kind);
    }

    @Test
    void testValidateAttributes_validationFailOnConnectorException() {
        FunctionGroupCode code = FunctionGroupCode.CREDENTIAL_PROVIDER;
        String kind = "ApiKey";

        mockServer.stubFor(WireMock
                .post(WireMock.urlPathMatching("/v1/" + code.getCode() + "/" + kind + "/attributes/validate"))
                .willReturn(WireMock.aResponse()
                        .withStatus(422)
                        .withHeader("Content-Type", "application/json")
                        .withBody("[ \"Validation failed\" ]")
                )
        );

        SecuredUUID connectorUuid = connector.getSecuredUuid();
        Assertions.assertThrows(ValidationException.class,
                () -> connectorService.validateAttributes(connectorUuid, code, List.of(), kind));
    }

    @Test
    void testValidateAttributes_notFound() {
        Assertions.assertThrows(NotFoundException.class,
                () -> connectorService.validateAttributes(
                        SecuredUUID.fromString("abfbc322-29e1-11ed-a261-0242ac120002"),
                        null,
                        null,
                        null
                )
        );
    }

    @Test
    void testGetObjectsForResource() {
        List<NameAndUuidDto> dtos = connectorService.listResourceObjects(SecurityFilter.create(), null, null);
        Assertions.assertEquals(1, dtos.size());
    }

    // Proxy tests

    @Test
    void testAddConnector_withProxy() throws ConnectorException, AlreadyExistException, AttributeException, NotFoundException {
        // Mock proxy communication - validation now uses MQ client when proxy is set
        when(proxyClient.sendRequest(any(), any(), any(), any(), any()))
                .thenReturn(new InfoResponse[0]);

        ConnectorRequestDto request = new ConnectorRequestDto();
        request.setName("testConnectorWithProxy");
        request.setUrl("http://proxy-connector:1234");
        request.setProxyUuid(proxy.getUuid().toString());

        ConnectorDto dto = connectorService.createConnector(request);
        Assertions.assertNotNull(dto);
        Assertions.assertEquals(request.getName(), dto.getName());
        Assertions.assertNotNull(dto.getProxy());
        Assertions.assertEquals(proxy.getUuid().toString(), dto.getProxy().getUuid());
    }

    @Test
    void testAddConnector_withNonExistentProxy() {
        ConnectorRequestDto request = new ConnectorRequestDto();
        request.setName("testConnectorWithBadProxy");
        request.setUrl("http://proxy-connector:5678");
        request.setProxyUuid("abfbc322-29e1-11ed-a261-0242ac120099");

        Assertions.assertThrows(NotFoundException.class, () -> connectorService.createConnector(request));
    }

    @Test
    void testEditConnector_setProxy() throws ConnectorException, AttributeException, NotFoundException {
        // Mock proxy communication
        when(proxyClient.sendRequest(any(), any(), any(), any(), any()))
                .thenReturn(new InfoResponse[0]);

        ConnectorUpdateRequestDto request = new ConnectorUpdateRequestDto();
        request.setUrl("http://localhost:8080");
        request.setProxyUuid(proxy.getUuid().toString());

        ConnectorDto dto = connectorService.editConnector(connector.getSecuredUuid(), request);
        Assertions.assertNotNull(dto);
        Assertions.assertNotNull(dto.getProxy());
        Assertions.assertEquals(proxy.getUuid().toString(), dto.getProxy().getUuid());
    }

    @Test
    void testEditConnector_withNonExistentProxy() {
        mockServer.stubFor(WireMock
                .get("/v1")
                .willReturn(WireMock.okJson("[]")));

        ConnectorUpdateRequestDto request = new ConnectorUpdateRequestDto();
        request.setUrl("http://localhost:" + mockServer.port());
        request.setProxyUuid("abfbc322-29e1-11ed-a261-0242ac120099");

        Assertions.assertThrows(NotFoundException.class,
                () -> connectorService.editConnector(connector.getSecuredUuid(), request));
    }

    @Test
    void testGetConnector_withProxy() throws ConnectorException, NotFoundException {
        // Mock proxy communication
        when(proxyClient.sendRequest(any(), any(), any(), any(), any()))
            .thenReturn(new InfoResponse[0]);

        // Set proxy on connector
        connector.setProxy(proxy);
        connectorRepository.save(connector);

        ConnectorDto dto = connectorService.getConnector(connector.getSecuredUuid());
        Assertions.assertNotNull(dto);
        Assertions.assertNotNull(dto.getProxy());
        Assertions.assertEquals(proxy.getUuid().toString(), dto.getProxy().getUuid());
        Assertions.assertEquals(proxy.getName(), dto.getProxy().getName());
    }

    @Test
    void testGetResourceObject() throws NotFoundException {
        NameAndUuidDto nameAndUuidDto = connectorService.getResourceObjectInternal(connector.getUuid());
        Assertions.assertEquals(connector.getUuid().toString(), nameAndUuidDto.getUuid());
        Assertions.assertEquals(connector.getName(), nameAndUuidDto.getName());

        nameAndUuidDto = connectorService.getResourceObjectExternal(connector.getSecuredUuid());
        Assertions.assertEquals(connector.getUuid().toString(), nameAndUuidDto.getUuid());
        Assertions.assertEquals(connector.getName(), nameAndUuidDto.getName());
    }
}
