package com.czertainly.core.service;

import com.czertainly.api.clients.ApiClientConnectorInfo;
import com.czertainly.api.clients.ConnectorApiClient;
import com.czertainly.api.model.client.connector.ConnectRequestDto;
import com.czertainly.api.model.client.connector.InfoResponse;
import com.czertainly.api.model.client.connector.v2.ConnectorVersion;
import com.czertainly.api.model.core.connector.FunctionGroupCode;
import com.czertainly.core.attribute.engine.AttributeEngine;
import com.czertainly.core.client.ConnectorApiFactory;
import com.czertainly.core.dao.entity.Endpoint;
import com.czertainly.core.dao.entity.FunctionGroup;
import com.czertainly.core.dao.repository.*;
import com.czertainly.core.service.handler.ConnectorAdapter;
import com.czertainly.core.service.handler.ConnectorV1Adapter;
import com.czertainly.core.service.v2.ConnectorService;
import com.czertainly.core.service.v2.impl.ConnectorServiceImpl;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.Mockito;
import org.springframework.boot.test.context.SpringBootTest;

import java.util.*;

@SpringBootTest
class ConnectorServiceMockTest {

    @Mock
    private ConnectorApiClient connectorApiClient;

    @Mock
    private ConnectorRepository connectorRepository;

    @Mock
    private FunctionGroupRepository functionGroupRepository;

    @Mock
    private Connector2FunctionGroupRepository connector2FunctionGroupRepository;

    @Mock
    private ConnectorApiFactory connectorApiFactory;

    @Mock
    private CredentialRepository credentialRepository;

    @Mock
    private AuthorityInstanceReferenceRepository authorityInstanceReferenceRepository;

    @Mock
    private EntityInstanceReferenceRepository entityInstanceReferenceRepository;

    @Mock
    private TokenInstanceReferenceRepository tokenInstanceReferenceRepository;

    @Mock
    private ComplianceProfileRepository complianceProfileRepository;

    @Mock
    private ComplianceProfileRuleRepository complianceProfileRuleRepository;

    @Mock
    private ConnectorAuthService connectorAuthService;

    @Mock
    private AttributeEngine attributeEngine;

    @Mock
    private VaultInstanceRepository vaultInstanceRepository;

    @Mock
    private ProxyRepository proxyRepository;

    @InjectMocks
    private ConnectorServiceImpl connectorService;

    @InjectMocks
    private ConnectorAdapter connectorAdapter = new ConnectorV1Adapter();

    private Endpoint endpoint1, endpoint2, endpoint3;


    @BeforeEach
    void setUp() {
        endpoint1 = new Endpoint();
        endpoint1.setUuid(UUID.fromString("abfbc322-29e1-11ed-a261-0242ac120002"));
        endpoint1.setName("endpoint1");
        endpoint1.setContext("/e1");
        endpoint1.setMethod("GET");
        endpoint1.setRequired(true);

        endpoint2 = new Endpoint();
        endpoint2.setUuid(UUID.fromString("abfbc322-29e1-11ed-a261-0242ac120003"));
        endpoint2.setName("endpoint2");
        endpoint2.setContext("/e2");
        endpoint2.setMethod("GET");
        endpoint2.setRequired(true);

        endpoint3 = new Endpoint();
        endpoint3.setUuid(UUID.fromString("abfbc322-29e1-11ed-a261-0242ac120004"));
        endpoint3.setName("endpoint3");
        endpoint3.setContext("/e3");
        endpoint3.setMethod("GET");
        endpoint3.setRequired(false);

        FunctionGroup functionGroup = new FunctionGroup();
        functionGroup.setCode(FunctionGroupCode.CREDENTIAL_PROVIDER);
        functionGroup.getEndpoints().add(endpoint1);
        functionGroup.getEndpoints().add(endpoint2);
        functionGroup.getEndpoints().add(endpoint3);

        ((ConnectorV1Adapter) connectorAdapter).setConnectorApiFactory(connectorApiFactory);
        ((ConnectorServiceImpl) connectorService).setConnectorAdapters(Map.of(ConnectorVersion.V1.getCode(), connectorAdapter, ConnectorVersion.V2.getCode(), connectorAdapter));

        Mockito.when(functionGroupRepository.findByCode(Mockito.any())).thenReturn(Optional.empty());
        Mockito.when(functionGroupRepository.findByCode(FunctionGroupCode.CREDENTIAL_PROVIDER)).thenReturn(Optional.of(functionGroup));

        Mockito.when(connectorApiFactory.getConnectorApiClient(Mockito.any(ApiClientConnectorInfo.class))).thenReturn(connectorApiClient);
    }

    @Test
    void testConnect_UnknownFunctionGroup() throws Exception {

        List<InfoResponse> connectorFunctions = new ArrayList<>();
        List<String> types = List.of("default");
        connectorFunctions.add(new InfoResponse(types, FunctionGroupCode.AUTHORITY_PROVIDER, Collections.singletonList(endpoint1.mapToDto())));
        Mockito.when(connectorApiClient.listSupportedFunctions(Mockito.any())).thenReturn(connectorFunctions);

        ConnectRequestDto request = new ConnectRequestDto();
        request.setUrl("http://localhost");

        Assertions.assertNotNull(connectorService.connect(request).getFirst().getErrorMessage());
    }

    @Test
    void testConnect_RequiredEndpointNotSupported() throws Exception {

        List<InfoResponse> connectorFunctions = new ArrayList<>();
        List<String> types = List.of("default");
        connectorFunctions.add(new InfoResponse(types, FunctionGroupCode.CREDENTIAL_PROVIDER, Collections.singletonList(endpoint1.mapToDto())));
        Mockito.when(connectorApiClient.listSupportedFunctions(Mockito.any())).thenReturn(connectorFunctions);

        ConnectRequestDto request = new ConnectRequestDto();
        request.setUrl("http://localhost");

        Assertions.assertNotNull(connectorService.connect(request).getFirst().getErrorMessage());
    }

    @Test
    void testConnect_Successful() throws Exception {

        List<InfoResponse> connectorFunctions = new ArrayList<>();
        List<String> types = List.of("default");
        connectorFunctions.add(new InfoResponse(types, FunctionGroupCode.CREDENTIAL_PROVIDER, Arrays.asList(endpoint1.mapToDto(), endpoint2.mapToDto())));
        Mockito.when(connectorApiClient.listSupportedFunctions(Mockito.any())).thenReturn(connectorFunctions);

        ConnectRequestDto request = new ConnectRequestDto();
        request.setUrl("http://localhost");

        Assertions.assertDoesNotThrow(() -> connectorService.connect(request));
    }
}
