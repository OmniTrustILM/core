package com.otilm.core.integration.service;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.github.tomakehurst.wiremock.WireMockServer;
import com.github.tomakehurst.wiremock.client.WireMock;
import com.otilm.api.clients.ApiClientConnectorInfo;
import com.otilm.api.exception.AlreadyExistException;
import com.otilm.api.exception.AttributeException;
import com.otilm.api.exception.ConnectorCommunicationException;
import com.otilm.api.exception.ConnectorException;
import com.otilm.api.exception.NotFoundException;
import com.otilm.api.exception.NotSupportedException;
import com.otilm.api.exception.ValidationException;
import com.otilm.api.model.client.certificate.SearchRequestDto;
import com.otilm.api.model.client.connector.ConnectRequestDto;
import com.otilm.api.model.client.connector.v2.ConnectorInfo;
import com.otilm.api.model.client.connector.v2.ConnectorInterface;
import com.otilm.api.model.client.connector.v2.ConnectorInterfaceInfo;
import com.otilm.api.model.client.connector.v2.ConnectorVersion;
import com.otilm.api.model.client.connector.v2.FeatureFlag;
import com.otilm.api.model.client.connector.v2.HealthInfo;
import com.otilm.api.model.client.connector.v2.HealthStatus;
import com.otilm.api.model.client.connector.v2.InfoResponse;
import com.otilm.api.model.common.BulkActionMessageDto;
import com.otilm.api.model.common.NameAndUuidDto;
import com.otilm.api.model.common.PaginationResponseDto;
import com.otilm.api.model.connector.cryptography.enums.TokenInstanceStatus;
import com.otilm.api.model.core.auth.Resource;
import com.otilm.api.model.core.connector.AuthType;
import com.otilm.api.model.core.connector.ConnectorStatus;
import com.otilm.api.model.core.connector.FunctionGroupCode;
import com.otilm.api.model.core.connector.v2.ConnectInfo;
import com.otilm.api.model.core.connector.v2.ConnectorDetailDto;
import com.otilm.api.model.core.connector.v2.ConnectorDto;
import com.otilm.api.model.core.connector.v2.ConnectorRequestDto;
import com.otilm.api.model.core.connector.v2.ConnectorUpdateRequestDto;
import com.otilm.api.model.core.discovery.DiscoveryStatus;
import com.otilm.api.model.core.proxy.ProxyStatus;
import com.otilm.core.client.ConnectorApiFactory;
import com.otilm.core.dao.entity.AuthorityInstanceReference;
import com.otilm.core.dao.entity.Connector;
import com.otilm.core.dao.entity.ConnectorInterfaceEntity;
import com.otilm.core.dao.entity.Credential;
import com.otilm.core.dao.entity.Discovery;
import com.otilm.core.dao.entity.EntityInstanceReference;
import com.otilm.core.dao.entity.Proxy;
import com.otilm.core.dao.entity.TokenInstanceReference;
import com.otilm.core.dao.entity.VaultInstance;
import com.otilm.core.dao.repository.AuthorityInstanceReferenceRepository;
import com.otilm.core.dao.repository.ConnectorInterfaceRepository;
import com.otilm.core.dao.repository.ConnectorRepository;
import com.otilm.core.dao.repository.CredentialRepository;
import com.otilm.core.dao.repository.DiscoveryRepository;
import com.otilm.core.dao.repository.EntityInstanceReferenceRepository;
import com.otilm.core.dao.repository.ProxyRepository;
import com.otilm.core.dao.repository.TokenInstanceReferenceRepository;
import com.otilm.core.dao.repository.VaultInstanceRepository;
import com.otilm.core.model.auth.ResourceAction;
import com.otilm.core.model.connector.ImmutableConnectorFullModel;
import com.otilm.core.security.authz.SecuredUUID;
import com.otilm.core.security.authz.SecurityFilter;
import com.otilm.core.service.ConnectorRegistrationExternalService;
import com.otilm.core.service.handler.ConnectorAdapter;
import com.otilm.core.service.v2.ConnectorExternalService;
import com.otilm.core.service.v2.ConnectorInternalService;
import com.otilm.core.service.v2.impl.ConnectorServiceImpl;
import com.otilm.core.service.writer.DiscoveryWriter;
import com.otilm.core.util.BaseSpringBootTest;
import com.otilm.core.util.LoopbackWireMock;
import com.otilm.core.util.seeders.FunctionGroupSeeder;
import jakarta.persistence.EntityManager;
import jakarta.persistence.EntityManagerFactory;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;
import java.time.Duration;
import java.time.OffsetDateTime;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import java.util.concurrent.Callable;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import java.util.function.Consumer;
import java.util.stream.Collectors;
import javax.sql.DataSource;
import org.assertj.core.api.ThrowableAssert.ThrowingCallable;
import org.hibernate.engine.spi.SharedSessionContractImplementor;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.function.Executable;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.EnumSource;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.orm.jpa.EntityManagerHolder;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.concurrent.DelegatingSecurityContextExecutorService;
import org.springframework.test.context.bean.override.mockito.MockitoSpyBean;
import org.springframework.test.util.AopTestUtils;
import org.springframework.transaction.PlatformTransactionManager;
import org.springframework.transaction.TransactionDefinition;
import org.springframework.transaction.TransactionStatus;
import org.springframework.transaction.support.TransactionSynchronizationManager;

import static com.otilm.core.util.builders.ConnectorBuilder.aConnector;
import static com.otilm.core.util.builders.ConnectorRequestDtoBuilder.aV2ConnectorRequest;
import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.awaitility.Awaitility.await;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.doAnswer;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.spy;

class ConnectorServiceV2ITest extends BaseSpringBootTest {

    private static final String CONNECTOR_NAME = "testConnectorV2";

    @Autowired
    private ConnectorExternalService connectorService;

    @Autowired
    private com.otilm.core.service.ConnectorExternalService connectorServiceV1;

    @Autowired
    private ConnectorRegistrationExternalService connectorRegistrationService;

    @Autowired
    private ConnectorApiFactory connectorApiFactory;

    @Autowired
    private FunctionGroupSeeder functionGroupSeeder;

    @Autowired
    private ConnectorInternalService connectorInternalService;

    @Autowired
    private ConnectorRepository connectorRepository;

    @MockitoSpyBean
    private ConnectorRepository connectorRepositorySpy;

    @Autowired
    private ConnectorInterfaceRepository connectorInterfaceRepository;
    @Autowired
    private DiscoveryWriter discoveryWriter;

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
    private DiscoveryRepository discoveryRepository;

    @Autowired
    private ObjectMapper objectMapper;

    @Autowired
    private Map<String, ConnectorAdapter> connectorAdapters;

    @Autowired
    private ProxyRepository proxyRepository;

    @Autowired
    private EntityManagerFactory entityManagerFactory;

    @Autowired
    private DataSource dataSource;

    @Autowired
    private PlatformTransactionManager transactionManager;

    private Connector connector;
    private WireMockServer mockServer;

    @BeforeEach
    void setUp() {
        mockServer = new WireMockServer(LoopbackWireMock.options());
        mockServer.start();
        WireMock.configureFor(LoopbackWireMock.HOST, mockServer.port());

        connector = new Connector();
        connector.setName(CONNECTOR_NAME);
        connector.setUrl(LoopbackWireMock.url(mockServer));
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

        PaginationResponseDto<ConnectorDto> response = connectorService
                .listConnectors(SecurityFilter.create(), request);
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
        Assertions
                .assertThrows(NotFoundException.class, () -> connectorService
                        .getConnector(SecuredUUID.fromString("abfbc322-29e1-11ed-a261-0242ac120002")));
    }

    @Test
    void getConnectorFullModelForApiClient_loadsInterfaces_withoutConnectorAuthorization() throws Exception {
        // given
        denyResourceAccess(Resource.CONNECTOR, ResourceAction.ANY);
        UUID connectorUuid = connector.getUuid();

        // when
        ImmutableConnectorFullModel model = connectorInternalService.getConnectorFullModelForApiClient(connectorUuid);
        Executable externalLookup = () -> connectorService.getConnectorFullModel(connector.getSecuredUuid());

        // then
        assertThat(model.uuid()).isEqualTo(connectorUuid);
        assertThat(model.connectorInterfaces()).singleElement().satisfies(iface -> {
            assertThat(iface.code()).isEqualTo(ConnectorInterface.AUTHORITY);
            assertThat(iface.features()).containsExactly(FeatureFlag.STATELESS);
        });
        assertThrows(AccessDeniedException.class, externalLookup);
    }

    @Test
    void getConnectorFullModelForApiClient_throwsNotFound_forMissingConnector() {
        // given
        UUID missingConnectorUuid = UUID.randomUUID();

        // when
        Executable lookup = () -> connectorInternalService.getConnectorFullModelForApiClient(missingConnectorUuid);

        // then
        NotFoundException failure = assertThrows(NotFoundException.class, lookup);
        assertThat(failure).hasMessageContaining(missingConnectorUuid.toString());
    }

    @Test
    void testCreateConnector() throws ConnectorException, AlreadyExistException, AttributeException, NotFoundException,
            JsonProcessingException {
        ConnectorRequestDto request = new ConnectorRequestDto();
        request.setName("newConnectorV2");
        request.setUrl(LoopbackWireMock.url(mockServer));
        request.setVersion(ConnectorVersion.V2);
        request.setAuthType(AuthType.NONE);
        Assertions.assertThrows(AlreadyExistException.class, () -> connectorService.createConnector(request));

        mockServer.stop();
        mockServer = new WireMockServer(LoopbackWireMock.options());
        mockServer.start();
        request.setUrl(LoopbackWireMock.url(mockServer));

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
        request.setUrl(LoopbackWireMock.url(mockServer));
        request.setVersion(ConnectorVersion.V2);
        request.setAuthType(AuthType.NONE);
        Assertions.assertThrows(AlreadyExistException.class, () -> connectorService.createConnector(request));
    }

    @Test
    void testEditConnector() throws ConnectorException, AttributeException, NotFoundException, JsonProcessingException {
        mockInfoEndpoint();

        ConnectorUpdateRequestDto request = new ConnectorUpdateRequestDto();
        request.setUrl(LoopbackWireMock.url(mockServer));
        request.setAuthType(AuthType.NONE);

        ConnectorDetailDto dto = connectorService.editConnector(connector.getSecuredUuid(), request);
        Assertions.assertNotNull(dto);
        Assertions.assertEquals(connector.getName(), dto.getName());
    }

    @Test
    void testEditConnector_notFound() {
        Assertions
                .assertThrows(NotFoundException.class,
                        () -> connectorService
                                .editConnector(SecuredUUID.fromString("abfbc322-29e1-11ed-a261-0242ac120002"),
                                        new ConnectorUpdateRequestDto()));
    }

    @Test
    void testDeleteConnector() throws NotFoundException {
        connectorService.deleteConnector(connector.getSecuredUuid());
        Assertions
                .assertThrows(NotFoundException.class, () -> connectorService.getConnector(connector.getSecuredUuid()));
    }

    @Test
    void testDeleteConnector_notFound() {
        Assertions
                .assertThrows(NotFoundException.class, () -> connectorService
                        .deleteConnector(SecuredUUID.fromString("abfbc322-29e1-11ed-a261-0242ac120002")));
    }

    /**
     * A discovery run is history and outlives its connector, as v1 runs always have. In production its interface
     * reference is a RESTRICT foreign key, so a plain delete has to release it or the connector's interfaces cannot
     * cascade away and the delete fails.
     */
    @Test
    void deletingAConnectorReleasesTheDiscoveryRunsBoundToItsInterfaces() throws NotFoundException {
        ConnectorInterfaceEntity discoveryInterface = new ConnectorInterfaceEntity();
        discoveryInterface.setConnectorUuid(connector.getUuid());
        discoveryInterface.setInterfaceCode(ConnectorInterface.DISCOVERY);
        discoveryInterface.setVersion("v2");
        discoveryInterface = connectorInterfaceRepository.save(discoveryInterface);
        Discovery run = new Discovery();
        run.setName("finished-run");
        run.setConnectorUuid(connector.getUuid());
        run.setConnectorName(CONNECTOR_NAME);
        run.setStatus(DiscoveryStatus.COMPLETED);
        run.setConnectorStatus(DiscoveryStatus.COMPLETED);
        run.setConnectorInterfaceUuid(discoveryInterface.getUuid());
        run = discoveryRepository.save(run);

        connectorService.deleteConnector(connector.getSecuredUuid());

        Discovery kept = discoveryRepository.findByUuid(run.getUuid()).orElseThrow();
        Assertions.assertNull(kept.getConnectorInterfaceUuid(), "a run may not keep pointing at a deleted interface");
        Assertions.assertEquals(CONNECTOR_NAME, kept.getConnectorName(), "the run stays as history");
        Assertions.assertTrue(connectorInterfaceRepository.findById(discoveryInterface.getUuid()).isEmpty());
    }

    /**
     * A live run is driven by its interface association: releasing it would route the run to the v1 adapter, hide it
     * from the reaper and leave its agenda and the connector-side scan orphaned. So a plain delete refuses, as it does
     * for every other dependent.
     */
    @Test
    void deletingAConnectorIsRefusedWhileADiscoveryRunBoundToItIsLive() {
        Discovery run = liveRunBoundTo(discoveryInterfaceOf(connector));

        SecuredUUID connectorUuid = connector.getSecuredUuid();
        ValidationException refused = assertThrows(ValidationException.class,
                () -> connectorService.deleteConnector(connectorUuid));

        assertThat(refused.getMessage()).contains("discovery run").contains(run.getName());
        Discovery untouched = discoveryRepository.findByUuid(run.getUuid()).orElseThrow();
        assertThat(untouched.getStatus()).isEqualTo(DiscoveryStatus.IN_PROGRESS);
        assertThat(untouched.getConnectorInterfaceUuid()).isNotNull();
        assertThat(connectorRepository.findByUuid(connector.getUuid())).isPresent();
    }

    /** Force delete is for a connector that is gone or broken, so it ends the live runs itself rather than refusing. */
    @Test
    void forceDeletingAConnectorEndsItsLiveDiscoveryRunsBeforeReleasingThem() {
        Discovery run = liveRunBoundTo(discoveryInterfaceOf(connector));

        List<BulkActionMessageDto> messages = connectorService
                .forceDeleteConnector(List.of(connector.getSecuredUuid()));

        assertThat(messages).isEmpty();
        Discovery ended = discoveryRepository.findByUuid(run.getUuid()).orElseThrow();
        assertThat(ended.getStatus()).isEqualTo(DiscoveryStatus.CANCELLED);
        assertThat(ended.getMessage()).contains("was deleted");
        assertThat(ended.getConnectorInterfaceUuid()).isNull();
        assertThat(connectorRepository.findByUuid(connector.getUuid())).isEmpty();
    }

    /**
     * Only what has ended is released. A run created between the live-run check and the release would otherwise lose
     * its association and go on as a v1 run; keeping it bound makes the connector's delete fail on the reference
     * instead.
     */
    @Test
    void releasingInterfacesLeavesALiveRunBound() {
        ConnectorInterfaceEntity discoveryInterface = discoveryInterfaceOf(connector);
        Discovery live = liveRunBoundTo(discoveryInterface);

        int released = discoveryWriter.releaseConnectorInterfaces(List.of(discoveryInterface.getUuid()));

        assertThat(released).isZero();
        assertThat(discoveryRepository.findByUuid(live.getUuid()).orElseThrow().getConnectorInterfaceUuid())
                .isEqualTo(discoveryInterface.getUuid());
    }

    /**
     * The refusal names the runs in the way, up to a point: an operator needs to know there are many, not all of them.
     */
    @Test
    void aRefusalOverManyLiveRunsNamesOnlySoMany() {
        ConnectorInterfaceEntity discoveryInterface = discoveryInterfaceOf(connector);
        for (int i = 0; i < 12; i++) {
            liveRunBoundTo(discoveryInterface);
        }

        ValidationException refused = assertThrows(ValidationException.class,
                () -> connectorService.deleteConnector(connector.getSecuredUuid()));

        assertThat(refused.getMessage()).contains("and 2 more");
    }

    private ConnectorInterfaceEntity discoveryInterfaceOf(Connector owner) {
        ConnectorInterfaceEntity discoveryInterface = new ConnectorInterfaceEntity();
        discoveryInterface.setConnectorUuid(owner.getUuid());
        discoveryInterface.setInterfaceCode(ConnectorInterface.DISCOVERY);
        discoveryInterface.setVersion("v2");
        return connectorInterfaceRepository.save(discoveryInterface);
    }

    private Discovery liveRunBoundTo(ConnectorInterfaceEntity discoveryInterface) {
        Discovery run = new Discovery();
        run.setName("live-run-" + UUID.randomUUID());
        run.setConnectorUuid(connector.getUuid());
        run.setConnectorName(CONNECTOR_NAME);
        run.setStatus(DiscoveryStatus.IN_PROGRESS);
        run.setConnectorStatus(DiscoveryStatus.IN_PROGRESS);
        run.setConnectorInterfaceUuid(discoveryInterface.getUuid());
        return discoveryRepository.save(run);
    }

    @Test
    void testBulkDeleteConnector() {
        connectorService.bulkDeleteConnector(List.of(connector.getSecuredUuid()));
        Assertions
                .assertThrows(NotFoundException.class, () -> connectorService.getConnector(connector.getSecuredUuid()));
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
        token.setStatus(TokenInstanceStatus.UNKNOWN);
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

        List<BulkActionMessageDto> messages = connectorService
                .forceDeleteConnector(List.of(connector.getSecuredUuid()));
        Assertions.assertNotNull(messages);
        Assertions.assertTrue(messages.isEmpty());
        Assertions
                .assertThrows(NotFoundException.class, () -> connectorService.getConnector(connector.getSecuredUuid()));
    }

    @Test
    void testReconnectConnector() throws NotFoundException, ConnectorException, JsonProcessingException {
        mockInfoEndpoint();

        ConnectInfo connectInfo = connectorService.reconnect(connector.getSecuredUuid());
        Assertions.assertNotNull(connectInfo);
        Assertions.assertEquals(ConnectorVersion.V2, connectInfo.getVersion());
    }

    @Test
    void testReconnectConnector_offlineBecomesConnected()
            throws NotFoundException, ConnectorException, JsonProcessingException {
        connector.setStatus(ConnectorStatus.OFFLINE);
        connectorRepository.save(connector);
        mockInfoEndpoint();

        ConnectInfo connectInfo = connectorService.reconnect(connector.getSecuredUuid());
        Assertions.assertNotNull(connectInfo);
        Assertions.assertEquals(ConnectorVersion.V2, connectInfo.getVersion());

        Connector reconnected = connectorRepository.findByUuid(connector.getUuid()).orElseThrow();
        Assertions.assertEquals(ConnectorStatus.CONNECTED, reconnected.getStatus());
    }

    @Test
    void leavesRowUntouched_whenReconnectingConnectedConnector() throws Exception {
        // given
        mockInfoEndpoint();
        OffsetDateTime updatedBeforeReconnect = connectorRepository
                .findByUuid(connector.getUuid())
                .orElseThrow()
                .getUpdated();

        // when
        connectorService.reconnect(connector.getSecuredUuid());

        // then
        Connector reconnected = connectorRepository.findByUuid(connector.getUuid()).orElseThrow();
        assertThat(reconnected.getStatus()).isEqualTo(ConnectorStatus.CONNECTED);
        assertThat(reconnected.getUpdated()).isEqualTo(updatedBeforeReconnect);
    }

    @Test
    void testReconnectConnector_waitingForApprovalRejected() throws JsonProcessingException {
        connector.setStatus(ConnectorStatus.WAITING_FOR_APPROVAL);
        connectorRepository.save(connector);
        mockInfoEndpoint();

        SecuredUUID connectorUuid = connector.getSecuredUuid();
        Assertions.assertThrows(ValidationException.class, () -> connectorService.reconnect(connectorUuid));

        Connector reconnected = connectorRepository.findByUuid(connector.getUuid()).orElseThrow();
        Assertions.assertEquals(ConnectorStatus.WAITING_FOR_APPROVAL, reconnected.getStatus());
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
        mockServer
                .stubFor(WireMock
                        .get("/v2/info")
                        .willReturn(WireMock.aResponse().withStatus(500).withBody("Internal Server Error")));

        List<BulkActionMessageDto> messages = connectorService.bulkReconnect(List.of(connector.getSecuredUuid()));
        Assertions.assertNotNull(messages);
        Assertions.assertFalse(messages.isEmpty());
        Assertions.assertEquals(connector.getUuid().toString(), messages.get(0).getUuid());
    }

    @Test
    void testReconnectConnector_notFound() {
        Assertions
                .assertThrows(NotFoundException.class, () -> connectorService
                        .reconnect(SecuredUUID.fromString("abfbc322-29e1-11ed-a261-0242ac120002")));
    }

    @Test
    void testReconnectConnector_communicationError() {
        mockServer
                .stubFor(WireMock
                        .get("/v2/info")
                        .willReturn(WireMock.aResponse().withStatus(500).withBody("Internal Server Error")));

        SecuredUUID connectorUuid = connector.getSecuredUuid();
        Assertions.assertThrows(ConnectorException.class, () -> connectorService.reconnect(connectorUuid));
    }

    @Test
    void testCheckHealth() throws ConnectorException, NotFoundException {
        mockServer.stubFor(WireMock.get("/v2/health").willReturn(WireMock.okJson("{ \"status\": \"UP\" }")));

        HealthInfo health = connectorService.checkHealth(connector.getSecuredUuid());
        Assertions.assertNotNull(health);
        Assertions.assertEquals(HealthStatus.UP, health.getStatus());
    }

    @Test
    void testCheckHealth_notFound() {
        Assertions
                .assertThrows(NotFoundException.class, () -> connectorService
                        .checkHealth(SecuredUUID.fromString("abfbc322-29e1-11ed-a261-0242ac120002")));
    }

    @Test
    void testGetInfo() throws ConnectorException, NotFoundException, JsonProcessingException {
        mockInfoEndpoint();

        ConnectorInfo info = connectorService.getInfo(connector.getSecuredUuid());
        Assertions.assertNotNull(info);
    }

    @Test
    void testGetInfoV1() {
        connector.setVersion(ConnectorVersion.V1);
        connectorRepository.save(connector);
        SecuredUUID securedUuid = connector.getSecuredUuid();
        Assertions.assertThrows(NotSupportedException.class, () -> connectorService.getInfo(securedUuid));
    }

    @Test
    void testApproveConnector() throws NotFoundException {
        Connector waitingConnector = new Connector();
        waitingConnector.setName("waitingConnector");
        waitingConnector.setUrl(LoopbackWireMock.url(mockServer) + "/waiting");
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
        waitingConnector.setUrl(LoopbackWireMock.url(mockServer) + "/waiting_connector");
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
        Assertions
                .assertThrows(NotFoundException.class,
                        () -> connectorService.approve(SecuredUUID.fromString("abfbc322-29e1-11ed-a261-0242ac120002")));
    }

    @Test
    void testConnect() throws JsonProcessingException, ConnectorException {
        mockInfoEndpoint();

        // Mock V1 endpoint to return error (no V1 connector)
        mockServer.stubFor(WireMock.get("/v1").willReturn(WireMock.aResponse().withStatus(404).withBody("Not Found")));

        var request = new com.otilm.api.model.client.connector.ConnectRequestDto();
        request.setUrl(LoopbackWireMock.url(mockServer));
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
        v1Connector.setUrl(LoopbackWireMock.url(mockServer));
        v1Connector.setVersion(ConnectorVersion.V1);
        v1Connector.setStatus(ConnectorStatus.CONNECTED);
        v1Connector.setAuthType(AuthType.NONE);
        v1Connector = connectorRepository.save(v1Connector);

        mockServer.stubFor(WireMock.get("/v1/health").willReturn(WireMock.okJson("{ \"status\": \"ok\" }")));

        HealthInfo health = connectorService.checkHealth(v1Connector.getSecuredUuid());
        Assertions.assertNotNull(health);
        Assertions.assertEquals(HealthStatus.UP, health.getStatus());
    }

    @Test
    void testListResourceObjects() {
        List<NameAndUuidDto> dtos = connectorInternalService.listResourceObjects(SecurityFilter.create(), null, null);
        Assertions.assertFalse(dtos.isEmpty());
        Assertions.assertTrue(dtos.stream().anyMatch(dto -> dto.getName().equals(CONNECTOR_NAME)));
    }

    private void mockInfoEndpoint() throws JsonProcessingException {
        List<ConnectorInterfaceInfo> connectorInterfaceInfos = createMockInterfaceInfos();

        ConnectorInfo connectorInfo = new ConnectorInfo();
        connectorInfo.setName(CONNECTOR_NAME);
        connectorInfo.setId("common.credential.provider");
        connectorInfo.setVersion("1.0.0");

        InfoResponse infoResponse = new InfoResponse();
        infoResponse.setConnector(connectorInfo);
        infoResponse.setInterfaces(connectorInterfaceInfos);
        String jsonBody = objectMapper.writeValueAsString(infoResponse);

        mockServer.stubFor(WireMock.get(WireMock.urlPathMatching(".*/v2/info")).willReturn(WireMock.okJson(jsonBody)));
    }

    private List<ConnectorInterfaceInfo> createMockInterfaceInfos() {
        List<ConnectorInterfaceInfo> connectorInterfaceInfos = new ArrayList<>();
        List<ConnectorInterface> interfaces = List
                .of(ConnectorInterface.INFO, ConnectorInterface.HEALTH, ConnectorInterface.METRICS,
                        ConnectorInterface.AUTHORITY);

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
        NameAndUuidDto dto = connectorInternalService.getResourceObjectInternal(connector.getUuid());
        Assertions.assertNotNull(dto);
        Assertions.assertEquals(connector.getName(), dto.getName());
        Assertions.assertEquals(connector.getUuid().toString(), dto.getUuid());

        NameAndUuidDto nameAndUuidDto = connectorInternalService.getResourceObjectExternal(connector.getSecuredUuid());
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

        List<BulkActionMessageDto> messages = connectorService.bulkDeleteConnector(List.of(connector.getSecuredUuid()));

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
    void testForceDeleteConnector_deleteFailure_rollsBackWhatItAlreadyDestroyed() {
        Discovery run = liveRunBoundTo(discoveryInterfaceOf(connector));
        Credential credential = new Credential();
        credential.setName("attached-" + UUID.randomUUID());
        credential.setKind("Basic");
        credential.setConnectorUuid(connector.getUuid());
        credential = credentialRepository.saveAndFlush(credential);
        doThrow(new RuntimeException("DB delete error")).when(connectorRepositorySpy).delete(any());

        List<BulkActionMessageDto> messages = connectorService
                .forceDeleteConnector(List.of(connector.getSecuredUuid()));

        assertThat(messages).hasSize(1);
        Discovery stillLive = discoveryRepository.findByUuid(run.getUuid()).orElseThrow();
        assertThat(stillLive.getStatus()).isEqualTo(DiscoveryStatus.IN_PROGRESS);
        assertThat(stillLive.getConnectorInterfaceUuid()).isNotNull();
        assertThat(credentialRepository.findByUuid(credential.getUuid()).orElseThrow().getConnectorUuid())
                .isEqualTo(connector.getUuid());
    }

    @Test
    void testForceDeleteConnector_deleteFailure_returnsErrorWithConnectorName() {
        doThrow(new RuntimeException("DB delete error")).when(connectorRepositorySpy).delete(any());

        List<BulkActionMessageDto> messages = connectorService
                .forceDeleteConnector(List.of(connector.getSecuredUuid()));

        Assertions.assertEquals(1, messages.size());
        Assertions.assertEquals(connector.getUuid().toString(), messages.getFirst().getUuid());
        Assertions.assertEquals(connector.getName(), messages.getFirst().getName());
        Assertions.assertNotNull(messages.getFirst().getMessage());
    }

    // ── ConnectorCalls ────────────────────────────────────────────────────────

    @Nested
    class ConnectorCalls {

        private final List<CallSeen> callsSeen = new CopyOnWriteArrayList<>();
        private final ExecutorService background = new DelegatingSecurityContextExecutorService(
                Executors.newSingleThreadExecutor());
        private DuringCall duringCall = target -> {
        };
        private Consumer<Connector> whileStoring = stored -> {
        };
        private EntityManager requestEntityManager;
        private ConnectorServiceImpl serviceTarget;
        private com.otilm.core.service.impl.ConnectorServiceImpl serviceV1Target;
        private Connector connectorV1;

        @BeforeEach
        void probeConnectorsOfBothVersions() throws JsonProcessingException {
            serviceTarget = AopTestUtils.getUltimateTargetObject(connectorService);
            serviceTarget.setConnectorAdapters(probing(connectorAdapters));
            serviceV1Target = AopTestUtils.getUltimateTargetObject(connectorServiceV1);
            serviceV1Target.setConnectorApiFactory(probing(connectorApiFactory));
            mockInfoEndpoint();
            mockServer.stubFor(WireMock.get("/v2/health").willReturn(WireMock.okJson("{ \"status\": \"UP\" }")));
            mockServer.stubFor(WireMock.get("/v1").willReturn(WireMock.notFound()));
            createConnectorV1();
        }

        @AfterEach
        void stopProbing() {
            serviceTarget.setConnectorAdapters(connectorAdapters);
            serviceV1Target.setConnectorApiFactory(connectorApiFactory);
            background.shutdownNow();
        }

        @ParameterizedTest
        @EnumSource(ConnectorCall.class)
        void holdsNoConnection_whenCallingConnector(ConnectorCall call) throws Exception {
            // given — connectors of both versions that answer every call

            // when
            asRequest(() -> perform(call));

            // then
            assertThat(callsSeen).isNotEmpty().allSatisfy(seen -> {
                assertThat(seen.transactionActive()).as("transaction active during the call").isFalse();
                assertThat(seen.connectionHeld()).as("connection held during the call").isFalse();
            });
        }

        @Test
        void returnsHealth_whenCallerHoldsTransaction() throws Exception {
            // given
            SecuredUUID connectorUuid = connector.getSecuredUuid();

            // when
            HealthInfo health = insideCallersTransaction(() -> connectorService.checkHealth(connectorUuid));

            // then
            assertThat(health.getStatus()).isEqualTo(HealthStatus.UP);
        }

        @Test
        void refusesReconnect_whenRouteEditCommitsWhileItWaits() throws Exception {
            // given
            String originalUrl = connector.getUrl();
            String editedUrl = urlUnder("edited");
            CountDownLatch editHoldsLock = new CountDownLatch(1);
            duringCall = target -> {
                if (target.getUrl().equals(originalUrl)) {
                    awaitEditHoldingLock(editHoldsLock);
                }
            };
            whileStoring = stored -> {
                if (stored.getUrl().equals(editedUrl)) {
                    editHoldsLock.countDown();
                    awaitSessionWaitingOnLock();
                }
            };
            SecuredUUID connectorUuid = connector.getSecuredUuid();
            ConnectorUpdateRequestDto request = editRequest(editedUrl);
            Future<ConnectorDetailDto> edit = background
                    .submit(() -> connectorService.editConnector(connectorUuid, request));

            // when
            ThrowingCallable reconnect = () -> connectorService.reconnect(connectorUuid);

            // then
            assertThatThrownBy(reconnect)
                    .isInstanceOf(ValidationException.class)
                    .hasMessageContaining("Reconnect it again");
            assertThat(edit.get(30, TimeUnit.SECONDS).getUrl()).isEqualTo(editedUrl);
            assertThat(connectorRepository.findByUuid(connector.getUuid()).orElseThrow().getUrl()).isEqualTo(editedUrl);
        }

        @Test
        void keepsRoute_whenConnectorRefusesEdit() {
            // given
            String originalUrl = connector.getUrl();
            duringCall = target -> {
                throw connectionRefused(target);
            };
            SecuredUUID connectorUuid = connector.getSecuredUuid();
            ConnectorUpdateRequestDto request = editRequest(urlUnder("edited"));

            // when
            ThrowingCallable edit = () -> connectorService.editConnector(connectorUuid, request);

            // then
            assertThatThrownBy(edit).isInstanceOf(ConnectorCommunicationException.class);
            assertThat(connectorRepository.findByUuid(connector.getUuid()).orElseThrow().getUrl())
                    .isEqualTo(originalUrl);
        }

        @Test
        void marksConnected_whenEditReachesOfflineConnector() throws Exception {
            // given
            connector.setStatus(ConnectorStatus.OFFLINE);
            connectorRepository.save(connector);
            SecuredUUID connectorUuid = connector.getSecuredUuid();
            ConnectorUpdateRequestDto request = editRequest(urlUnder("edited"));

            // when
            connectorService.editConnector(connectorUuid, request);

            // then
            assertThat(connectorRepository.findByUuid(connector.getUuid()).orElseThrow().getStatus())
                    .isEqualTo(ConnectorStatus.CONNECTED);
        }

        @Test
        void leavesNoConnector_whenProxiedConnectorRefusesCreate() {
            // given
            Proxy proxy = persistProxy();
            duringCall = target -> {
                throw connectionRefused(target);
            };
            ConnectorRequestDto request = aV2ConnectorRequest()
                    .withName("proxiedConnector")
                    .withUrl(urlUnder("proxied"))
                    .build();
            request.setProxyUuid(proxy.getUuid().toString());

            // when
            ThrowingCallable create = () -> connectorService.createConnector(request);

            // then
            assertThatThrownBy(create).isInstanceOf(ConnectorCommunicationException.class);
            assertThat(connectorRepository.findByName(request.getName())).map(Connector::getUuid).isEmpty();
        }

        @Test
        void leavesNoConnector_whenDirectConnectorRefusesCreate() {
            // given
            duringCall = target -> {
                throw connectionRefused(target);
            };
            ConnectorRequestDto request = aV2ConnectorRequest()
                    .withName("directConnector")
                    .withUrl(urlUnder("direct"))
                    .build();

            // when
            ThrowingCallable create = () -> connectorService.createConnector(request);

            // then
            assertThatThrownBy(create).isInstanceOf(ConnectorCommunicationException.class);
            assertThat(connectorRepository.findByName(request.getName())).map(Connector::getUuid).isEmpty();
        }

        @Test
        void refusesReconnect_whenRouteChangesDuringCall() {
            // given
            String editedUrl = urlUnder("edited");
            duringCall = target -> changeUrlBehindTheCaller(editedUrl);
            SecuredUUID connectorUuid = connector.getSecuredUuid();

            // when
            ThrowingCallable reconnect = () -> asRequest(() -> connectorService.reconnect(connectorUuid));

            // then
            assertThatThrownBy(reconnect)
                    .isInstanceOf(ValidationException.class)
                    .hasMessageContaining("Reconnect it again");
            Connector stored = connectorRepository.findWithInterfacesByUuid(connector.getUuid()).orElseThrow();
            assertThat(stored.getUrl()).isEqualTo(editedUrl);
            assertThat(stored.getInterfaces())
                    .extracting(ConnectorInterfaceEntity::getInterfaceCode)
                    .containsExactly(ConnectorInterface.AUTHORITY);
        }

        @Test
        void keepsStatus_whenRouteChangesDuringFailedReconnect() {
            // given
            String editedUrl = urlUnder("edited");
            duringCall = target -> {
                changeUrlBehindTheCaller(editedUrl);
                throw connectionRefused(target);
            };
            SecuredUUID connectorUuid = connector.getSecuredUuid();

            // when
            ThrowingCallable reconnect = () -> asRequest(() -> connectorService.reconnect(connectorUuid));

            // then
            assertThatThrownBy(reconnect).isInstanceOf(ConnectorException.class);
            Connector stored = connectorRepository.findByUuid(connector.getUuid()).orElseThrow();
            assertThat(stored.getStatus()).isEqualTo(ConnectorStatus.CONNECTED);
            assertThat(stored.getUrl()).isEqualTo(editedUrl);
        }

        @Test
        void marksOffline_whenReconnectCannotReachConnector() {
            // given
            duringCall = target -> {
                throw connectionRefused(target);
            };
            SecuredUUID connectorUuid = connector.getSecuredUuid();

            // when
            ThrowingCallable reconnect = () -> connectorService.reconnect(connectorUuid);

            // then
            assertThatThrownBy(reconnect).isInstanceOf(ConnectorException.class);
            assertThat(connectorRepository.findByUuid(connector.getUuid()).orElseThrow().getStatus())
                    .isEqualTo(ConnectorStatus.OFFLINE);
        }

        @Test
        void reconnectsOthers_whenOneConnectorOfBulkCannotBeReached() {
            // given
            Connector unreachable = connectorRepository
                    .save(connectorEntity("unreachableConnector", urlUnder("unreachable"), ConnectorVersion.V2));
            duringCall = target -> {
                if (target.getUrl().equals(unreachable.getUrl())) {
                    throw connectionRefused(target);
                }
            };

            // when
            List<BulkActionMessageDto> messages = connectorService
                    .bulkReconnect(List.of(unreachable.getSecuredUuid(), connector.getSecuredUuid()));

            // then
            assertThat(messages)
                    .singleElement()
                    .extracting(BulkActionMessageDto::getUuid)
                    .isEqualTo(unreachable.getUuid().toString());
            assertThat(connectorRepository.findWithInterfacesByUuid(connector.getUuid()).orElseThrow().getInterfaces())
                    .extracting(ConnectorInterfaceEntity::getInterfaceCode)
                    .containsExactlyInAnyOrder(ConnectorInterface.INFO, ConnectorInterface.HEALTH,
                            ConnectorInterface.METRICS, ConnectorInterface.AUTHORITY);
        }

        // ── Helpers ───────────────────────────────────────────────────────────

        enum ConnectorCall {
            CONNECT,
            CREATE,
            EDIT,
            RECONNECT,
            BULK_RECONNECT,
            CHECK_HEALTH,
            GET_INFO,
            V1_CONNECT,
            V1_CREATE,
            V1_EDIT,
            V1_RECONNECT,
            V1_BULK_RECONNECT,
            V1_CHECK_HEALTH,
            REGISTER,
            REGISTER_V2
        }

        record CallSeen(boolean transactionActive, boolean connectionHeld) {
        }

        @FunctionalInterface
        interface DuringCall {
            void run(ApiClientConnectorInfo target) throws ConnectorException;
        }

        @FunctionalInterface
        interface RequestWork {
            void run() throws Exception;
        }

        private void perform(ConnectorCall call) throws Exception {
            SecuredUUID connectorUuid = connector.getSecuredUuid();
            SecuredUUID connectorV1Uuid = connectorV1.getSecuredUuid();
            switch (call) {
                case CONNECT -> connectorService.connect(connectRequest(LoopbackWireMock.url(mockServer)));
                case CREATE -> connectorService
                        .createConnector(aV2ConnectorRequest()
                                .withName("createdConnector")
                                .withUrl(urlUnder("created"))
                                .build());
                case EDIT -> connectorService.editConnector(connectorUuid, editRequest(urlUnder("edited")));
                case RECONNECT -> connectorService.reconnect(connectorUuid);
                case BULK_RECONNECT -> connectorService.bulkReconnect(List.of(connectorUuid));
                case CHECK_HEALTH -> connectorService.checkHealth(connectorUuid);
                case GET_INFO -> connectorService.getInfo(connectorUuid);
                case V1_CONNECT -> connectorServiceV1.connect(connectRequest(urlUnder("connected-v1")));
                case V1_CREATE ->
                    connectorServiceV1.createConnector(createRequestV1("createdConnectorV1", urlUnder("created-v1")));
                case V1_EDIT -> connectorServiceV1.editConnector(connectorV1Uuid, editRequestV1(urlUnder("edited-v1")));
                case V1_RECONNECT -> connectorServiceV1.reconnect(connectorV1Uuid);
                case V1_BULK_RECONNECT -> connectorServiceV1.reconnect(List.of(connectorV1Uuid));
                case V1_CHECK_HEALTH -> connectorServiceV1.checkHealth(connectorV1Uuid);
                case REGISTER -> connectorRegistrationService
                        .registerConnector(createRequestV1("registeredConnector", urlUnder("registered")));
                case REGISTER_V2 -> connectorRegistrationService
                        .registerConnectorV2(aV2ConnectorRequest()
                                .withName("registeredConnectorV2")
                                .withUrl(urlUnder("registered-v2"))
                                .build());
            }
        }

        private Map<String, ConnectorAdapter> probing(Map<String, ConnectorAdapter> adapters) {
            return adapters
                    .entrySet()
                    .stream()
                    .collect(Collectors.toMap(Map.Entry::getKey, entry -> new ProbingAdapter(entry.getValue())));
        }

        /** Probes the v1 health check. That check calls the connector through the factory's client. */
        private ConnectorApiFactory probing(ConnectorApiFactory factory) {
            ConnectorApiFactory probingFactory = spy(factory);
            doAnswer(invocation -> {
                seeCall(invocation.getArgument(0));
                return invocation.callRealMethod();
            }).when(probingFactory).getHealthApiClient(any());
            return probingFactory;
        }

        private void seeCall(ApiClientConnectorInfo target) throws ConnectorException {
            callsSeen
                    .add(new CallSeen(TransactionSynchronizationManager.isActualTransactionActive(),
                            isConnectionHeld()));
            duringCall.run(target);
        }

        /** Whether the thread holds a connection, through its transaction or a connected EntityManager. */
        private boolean isConnectionHeld() {
            boolean transactionConnectionBound = TransactionSynchronizationManager.hasResource(dataSource);
            boolean boundEntityManagerConnected = TransactionSynchronizationManager
                    .getResourceMap()
                    .values()
                    .stream()
                    .filter(EntityManagerHolder.class::isInstance)
                    .map(holder -> ((EntityManagerHolder) holder).getEntityManager())
                    .anyMatch(ConnectorCalls::isPhysicallyConnected);
            boolean requestEntityManagerConnected = requestEntityManager != null
                    && isPhysicallyConnected(requestEntityManager);
            return transactionConnectionBound || boundEntityManagerConnected || requestEntityManagerConnected;
        }

        private static boolean isPhysicallyConnected(EntityManager entityManager) {
            return entityManager.isOpen() && entityManager
                    .unwrap(SharedSessionContractImplementor.class)
                    .getJdbcCoordinator()
                    .getLogicalConnection()
                    .isPhysicallyConnected();
        }

        /** Runs the work with an EntityManager bound to the thread. Open-in-view binds one to each request. */
        private void asRequest(RequestWork work) throws Exception {
            requestEntityManager = entityManagerFactory.createEntityManager();
            TransactionSynchronizationManager
                    .bindResource(entityManagerFactory, new EntityManagerHolder(requestEntityManager));
            try {
                work.run();
            } finally {
                TransactionSynchronizationManager.unbindResource(entityManagerFactory);
                requestEntityManager.close();
                requestEntityManager = null;
            }
        }

        private <T> T insideCallersTransaction(Callable<T> work) throws Exception {
            TransactionStatus callersTransaction = transactionManager
                    .getTransaction(TransactionDefinition.withDefaults());
            try {
                return work.call();
            } finally {
                transactionManager.rollback(callersTransaction);
            }
        }

        /** Commits the URL on a connection of its own. The caller's persistence context keeps its earlier copy. */
        private void changeUrlBehindTheCaller(String url) {
            try (Connection independent = dataSource.getConnection();
                    PreparedStatement update = independent
                            .prepareStatement("UPDATE " + dbSchema + ".connector SET url = ? WHERE uuid = ?")) {
                update.setString(1, url);
                update.setObject(2, connector.getUuid());
                update.executeUpdate();
                if (!independent.getAutoCommit()) {
                    independent.commit();
                }
            } catch (SQLException e) {
                throw new IllegalStateException(e);
            }
        }

        private static void awaitEditHoldingLock(CountDownLatch editHoldsLock) {
            try {
                if (!editHoldsLock.await(10, TimeUnit.SECONDS)) {
                    throw new IllegalStateException("The edit never took the connector's row lock");
                }
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                throw new IllegalStateException(e);
            }
        }

        private void awaitSessionWaitingOnLock() {
            await()
                    .atMost(Duration.ofSeconds(10))
                    .pollInterval(Duration.ofMillis(50))
                    .until(this::aSessionWaitsOnConnectorLock);
        }

        private boolean aSessionWaitsOnConnectorLock() throws SQLException {
            try (Connection connection = dataSource.getConnection();
                    Statement statement = connection.createStatement();
                    ResultSet rows = statement.executeQuery("""
                            SELECT count(*) FROM pg_stat_activity
                             WHERE wait_event_type = 'Lock' AND query ILIKE '%connector%'
                            """)) {
                rows.next();
                return rows.getLong(1) > 0;
            }
        }

        private void createConnectorV1() throws JsonProcessingException {
            functionGroupSeeder.seed(FunctionGroupCode.CREDENTIAL_PROVIDER, List.of());
            var credentialProvider = new com.otilm.api.model.client.connector.InfoResponse(List.of("Basic"),
                    FunctionGroupCode.CREDENTIAL_PROVIDER, List.of());
            String functionGroups = objectMapper.writeValueAsString(List.of(credentialProvider));
            mockServer
                    .stubFor(WireMock
                            .get(WireMock.urlPathMatching(".+/v1"))
                            .willReturn(WireMock.okJson(functionGroups)));
            mockServer
                    .stubFor(WireMock
                            .get(WireMock.urlPathMatching(".+/v1/health"))
                            .willReturn(WireMock.okJson("{ \"status\": \"ok\" }")));
            connectorV1 = connectorRepository
                    .save(connectorEntity("connectorV1", urlUnder("v1-connector"), ConnectorVersion.V1));
        }

        private Proxy persistProxy() {
            Proxy proxy = new Proxy();
            proxy.setName("testProxy");
            proxy.setCode("TEST_PROXY");
            proxy.setStatus(ProxyStatus.CONNECTED);
            return proxyRepository.save(proxy);
        }

        private String urlUnder(String path) {
            return LoopbackWireMock.url(mockServer) + "/" + path;
        }

        private static ConnectorCommunicationException connectionRefused(ApiClientConnectorInfo target) {
            return new ConnectorCommunicationException("Connection refused", target);
        }

        private static Connector connectorEntity(String name, String url, ConnectorVersion version) {
            Connector created = aConnector()
                    .withGeneratedUuid()
                    .withName(name)
                    .withUrl(url)
                    .withVersion(version)
                    .build();
            created.setAuthType(AuthType.NONE);
            return created;
        }

        private static ConnectRequestDto connectRequest(String url) {
            ConnectRequestDto request = new ConnectRequestDto();
            request.setUrl(url);
            request.setAuthType(AuthType.NONE);
            return request;
        }

        private static com.otilm.api.model.client.connector.ConnectorRequestDto createRequestV1(String name,
                String url) {
            var request = new com.otilm.api.model.client.connector.ConnectorRequestDto();
            request.setName(name);
            request.setUrl(url);
            request.setAuthType(AuthType.NONE);
            return request;
        }

        private static ConnectorUpdateRequestDto editRequest(String url) {
            ConnectorUpdateRequestDto request = new ConnectorUpdateRequestDto();
            request.setUrl(url);
            request.setAuthType(AuthType.NONE);
            return request;
        }

        private static com.otilm.api.model.client.connector.ConnectorUpdateRequestDto editRequestV1(String url) {
            var request = new com.otilm.api.model.client.connector.ConnectorUpdateRequestDto();
            request.setUrl(url);
            request.setAuthType(AuthType.NONE);
            return request;
        }

        /**
         * Records the connection state at each connector call. It runs what the test arranged for the call and for
         * storing its answer.
         */
        private final class ProbingAdapter implements ConnectorAdapter {

            private final ConnectorAdapter delegate;

            private ProbingAdapter(ConnectorAdapter delegate) {
                this.delegate = delegate;
            }

            @Override
            public ConnectorVersion getVersion() {
                return delegate.getVersion();
            }

            @Override
            public ConnectorInfo getInfo(ApiClientConnectorInfo target) throws ConnectorException {
                seeCall(target);
                return delegate.getInfo(target);
            }

            @Override
            public HealthInfo checkHealth(ApiClientConnectorInfo target) throws ConnectorException {
                seeCall(target);
                return delegate.checkHealth(target);
            }

            @Override
            public ConnectInfo checkConnection(ApiClientConnectorInfo target) throws ConnectorException {
                seeCall(target);
                return delegate.checkConnection(target);
            }

            @Override
            public void validateConnection(ConnectInfo connectInfo) {
                delegate.validateConnection(connectInfo);
            }

            @Override
            public void updateConnectorFunctions(Connector updated, ConnectInfo connectInfo)
                    throws ConnectorException, NotFoundException {
                whileStoring.accept(updated);
                delegate.updateConnectorFunctions(updated, connectInfo);
            }
        }
    }
}
