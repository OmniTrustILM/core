package com.otilm.core.integration.service;

import com.github.tomakehurst.wiremock.WireMockServer;
import com.github.tomakehurst.wiremock.client.WireMock;
import com.github.tomakehurst.wiremock.extension.Parameters;
import com.github.tomakehurst.wiremock.extension.ServeEventListener;
import com.github.tomakehurst.wiremock.stubbing.ServeEvent;
import com.otilm.api.exception.AlreadyExistException;
import com.otilm.api.exception.AttributeException;
import com.otilm.api.exception.ConnectorException;
import com.otilm.api.exception.ConnectorProblemException;
import com.otilm.api.exception.NotFoundException;
import com.otilm.api.exception.ValidationException;
import com.otilm.api.model.client.attribute.RequestAttribute;
import com.otilm.api.model.client.attribute.RequestAttributeV2;
import com.otilm.api.model.client.attribute.RequestAttributeV3;
import com.otilm.api.model.client.certificate.DiscoveryResponseDto;
import com.otilm.api.model.client.certificate.SearchRequestDto;
import com.otilm.api.model.client.connector.v2.ConnectorInterface;
import com.otilm.api.model.client.connector.v2.ConnectorVersion;
import com.otilm.api.model.client.connector.v2.FeatureFlag;
import com.otilm.api.model.client.discovery.DiscoveryCertificateResponseDto;
import com.otilm.api.model.client.discovery.DiscoveryDetailDto;
import com.otilm.api.model.client.discovery.DiscoveryDto;
import com.otilm.api.model.client.discovery.DiscoveryListDto;
import com.otilm.api.model.client.discovery.DiscoveryWindowDto;
import com.otilm.api.model.client.discovery.DiscoveryWindowMode;
import com.otilm.api.model.common.NameAndUuidDto;
import com.otilm.api.model.common.PaginationResponseDto;
import com.otilm.api.model.common.attribute.common.AttributeType;
import com.otilm.api.model.common.attribute.common.BaseAttribute;
import com.otilm.api.model.common.attribute.common.MetadataAttribute;
import com.otilm.api.model.common.attribute.common.content.AttributeContentType;
import com.otilm.api.model.common.attribute.common.content.data.CredentialAttributeContentData;
import com.otilm.api.model.common.attribute.common.properties.MetadataAttributeProperties;
import com.otilm.api.model.common.attribute.v2.MetadataAttributeV2;
import com.otilm.api.model.common.attribute.v2.content.CredentialAttributeContentV2;
import com.otilm.api.model.common.attribute.v2.content.StringAttributeContentV2;
import com.otilm.api.model.common.attribute.v3.content.ResourceObjectContent;
import com.otilm.api.model.common.attribute.v3.content.data.ResourceSimpleContentData;
import com.otilm.api.model.connector.discovery.v2.DiscoveryProgressDto;
import com.otilm.api.model.connector.discovery.v2.DiscoverySupportedResourceDto;
import com.otilm.api.model.core.auth.AttributeResource;
import com.otilm.api.model.core.auth.Resource;
import com.otilm.api.model.core.connector.ConnectorStatus;
import com.otilm.api.model.core.connector.FunctionGroupCode;
import com.otilm.api.model.core.discovery.DiscoveryItemDto;
import com.otilm.api.model.core.discovery.DiscoveryMessageDto;
import com.otilm.api.model.core.discovery.DiscoveryMessageSeverity;
import com.otilm.api.model.core.discovery.DiscoveryStatus;
import com.otilm.core.attribute.engine.AttributeEngine;
import com.otilm.core.attribute.engine.records.ObjectAttributeContentInfo;
import com.otilm.core.auth.ContextRefreshListener;
import com.otilm.core.dao.entity.CertificateContent;
import com.otilm.core.dao.entity.Connector;
import com.otilm.core.dao.entity.Connector2FunctionGroup;
import com.otilm.core.dao.entity.ConnectorInterfaceEntity;
import com.otilm.core.dao.entity.Credential;
import com.otilm.core.dao.entity.Discovery;
import com.otilm.core.dao.entity.DiscoveryCertificate;
import com.otilm.core.dao.entity.DiscoveryMessage;
import com.otilm.core.dao.entity.FunctionGroup;
import com.otilm.core.dao.entity.X509CertificateEntity;
import com.otilm.core.dao.repository.CertificateContentRepository;
import com.otilm.core.dao.repository.CertificateRepository;
import com.otilm.core.dao.repository.Connector2FunctionGroupRepository;
import com.otilm.core.dao.repository.ConnectorInterfaceRepository;
import com.otilm.core.dao.repository.ConnectorRepository;
import com.otilm.core.dao.repository.CredentialRepository;
import com.otilm.core.dao.repository.DiscoveryCertificateRepository;
import com.otilm.core.dao.repository.DiscoveryMessageRepository;
import com.otilm.core.dao.repository.DiscoveryRepository;
import com.otilm.core.dao.repository.DiscoveryWorkRepository;
import com.otilm.core.dao.repository.FunctionGroupRepository;
import com.otilm.core.events.data.DiscoveryResult;
import com.otilm.core.events.handlers.CertificateDiscoveredEventHandler;
import com.otilm.core.events.handlers.DiscoveryFinishedEventHandler;
import com.otilm.core.messaging.jms.listeners.EventListener;
import com.otilm.core.messaging.model.EventMessage;
import com.otilm.core.model.auth.ResourceAction;
import com.otilm.core.model.discovery.DiscoveryMessageCode;
import com.otilm.core.model.discovery.DiscoveryWorkType;
import com.otilm.core.security.authz.SecuredUUID;
import com.otilm.core.security.authz.SecurityFilter;
import com.otilm.core.service.DiscoveryExternalService;
import com.otilm.core.service.DiscoveryInternalService;
import com.otilm.core.service.handler.discovery.DiscoveryProviderAdapterFactory;
import com.otilm.core.service.handler.discovery.DiscoveryRunTerminator;
import com.otilm.core.service.writer.discovery.DiscoveryMessageWriter;
import com.otilm.core.service.writer.discovery.DiscoveryWorkWriter;
import com.otilm.core.tasks.ScheduledJobInfo;
import com.otilm.core.util.BaseSpringBootTest;
import com.otilm.core.util.CertificateUtil;
import com.otilm.core.util.DiscoveryCheckpointFixture;
import com.otilm.core.util.LoopbackWireMock;
import com.otilm.core.util.MetaDefinitions;
import com.otilm.core.util.RefusedDefinitionInserts;
import com.otilm.core.util.RefusedDiscoveryDeletes;
import java.time.Duration;
import java.time.OffsetDateTime;
import java.time.ZoneOffset;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import java.util.concurrent.CompletableFuture;
import org.assertj.core.api.ThrowableAssert.ThrowingCallable;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Disabled;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.transaction.support.TransactionSynchronizationManager;

import static com.otilm.core.util.builders.CertificateBuilder.aCertificate;
import static com.otilm.core.util.builders.CertificateContentBuilder.aCertificateContent;
import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class DiscoveryServiceITest extends BaseSpringBootTest {

    private static final String DISCOVERY_NAME = "testDiscovery1";
    private static final String PROVIDER_DISCOVERY_UUID = "4bd64640-be29-4e14-aad8-5c0ffa55c5bd";
    private static final String CERTIFICATE_BASE64 = "MIIDyjCCArKgAwIBAgIUULw4BO/gvFzW2wMYXRhmz1kPPdAwDQYJKoZIhvcNAQELBQAwZDEUMBIGA1UEAwwLdGVzdGNlcnQuY3oxCzAJBgNVBAYTAkNaMRgwFgYDVQQIDA9DZW50cmFsIEJvaGVtaWExDzANBgNVBAcMBlNsYW7DvTEUMBIGA1UECgwLM0tleUNvbXBhbnkwHhcNMjQxMDIxMTAzMDEyWhcNMjUxMDIxMTAzMDEyWjBkMRQwEgYDVQQDDAt0ZXN0Y2VydC5jejELMAkGA1UEBhMCQ1oxGDAWBgNVBAgMD0NlbnRyYWwgQm9oZW1pYTEPMA0GA1UEBwwGU2xhbsO9MRQwEgYDVQQKDAszS2V5Q29tcGFueTCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAJ112/a4p9sZ4F2fABLGtSBrbp71n/0uG+H/3usEQU8/FIW644ly5hNl8+SloPWryCCxOl+saXTKv62h0HnE/HNFMKlps4wwWNMsTploFKiAW9AbaDtzNrMy9f/orMoZldDZt5dLX8UR3qMmdK8nlqiJOyCAxIS70OsEQC8fGuIMNYeW6eidXGHjvpqApWnGTyA4U1bJWsDWcOIh/LL2ae9nwTJjVrHthrM6Wq6PplaPxEKYABp51UAQLMzY+cJElcKmwQxiK+zOHns7/ocosZVqI2QyxSmG60icabyrIT6HQHKVNzZHkltmduyYun9YZ+nl68YOuNmtSNi1TLMlfGECAwEAAaN0MHIwHQYDVR0OBBYEFOWFJRXdCer5Bpj+9JrquuJ7e5eQMB8GA1UdIwQYMBaAFOWFJRXdCer5Bpj+9JrquuJ7e5eQMA4GA1UdDwEB/wQEAwIFoDAgBgNVHSUBAf8EFjAUBggrBgEFBQcDAQYIKwYBBQUHAwIwDQYJKoZIhvcNAQELBQADggEBAA6AWaBFDAWL8oSBCP3q1s2Gq9QhR2QEBZ5tPOMTN5GpIzXxXdm4nHHBK/pSFABUNmrwQMapvq/y6IZ7hNMdC89MTOsHLD0EVPmHHO4xhzMG08XpJdevTrvktjpt0+ju81ratLg34pvJLeLF7ZL5AxwOl6qKX6RgwHpdBUipAYeeVhTVtQ7FLvakKDwYLiN6YFXuM1+CDAK3fsJ6sZki3uRvLYsUi7bguIQCmCQ0/n+T62Driq6mh1FkFB3sgpSFjfEo3bEaaHzF1YZr6otTYPNzcLCStJ5SYNBXKbw7YKAcYavL6yMNTQ2CjmLVnwjjd3O/Sv1kEhZMu86mHeNZK0I=";

    @Autowired
    private DiscoveryExternalService discoveryService;

    @Autowired
    private DiscoveryInternalService discoveryInternalService;

    @Autowired
    private DiscoveryRepository discoveryRepository;
    @Autowired
    private DiscoveryCertificateRepository discoveryCertificateRepository;

    @Autowired
    private DiscoveryWorkRepository workRepository;
    @Autowired
    private DiscoveryWorkWriter workWriter;
    @Autowired
    private CertificateContentRepository certificateContentRepository;
    @Autowired
    private ConnectorRepository connectorRepository;
    @Autowired
    private ConnectorInterfaceRepository connectorInterfaceRepository;
    @Autowired
    private CredentialRepository credentialRepository;
    @Autowired
    private FunctionGroupRepository functionGroupRepository;
    @Autowired
    private Connector2FunctionGroupRepository connector2FunctionGroupRepository;

    @Autowired
    private EventListener eventListener;

    @Autowired
    private DiscoveryMessageWriter messageWriter;
    @Autowired
    private DiscoveryMessageRepository messageRepository;

    @Autowired
    private DiscoveryProviderAdapterFactory adapterFactory;

    @Autowired
    private ContextRefreshListener contextRefreshListener;

    @Autowired
    private DiscoveryRunTerminator terminator;

    @Autowired
    private JdbcTemplate jdbcTemplate;
    @Autowired
    private DiscoveryMessageRepository discoveryMessageRepository;
    @Autowired
    private CertificateRepository certificateRepository;
    @Autowired
    private AttributeEngine attributeEngine;

    private Discovery discovery;
    private Connector connector;

    private WireMockServer mockServer;

    @BeforeEach
    void setUp() {
        mockServer = new WireMockServer(LoopbackWireMock.options());
        mockServer.start();

        WireMock.configureFor(LoopbackWireMock.HOST, mockServer.port());
        stubConnectorEndpoints();

        connector = new Connector();
        connector.setName("discoveryProviderConnector");
        connector.setUrl(LoopbackWireMock.url(mockServer));
        connector.setVersion(ConnectorVersion.V1);
        connector.setStatus(ConnectorStatus.CONNECTED);
        connector = connectorRepository.save(connector);

        FunctionGroup functionGroup = new FunctionGroup();
        functionGroup.setCode(FunctionGroupCode.DISCOVERY_PROVIDER);
        functionGroup.setName(FunctionGroupCode.DISCOVERY_PROVIDER.getCode());
        functionGroupRepository.save(functionGroup);

        Connector2FunctionGroup c2fg = new Connector2FunctionGroup();
        c2fg.setConnector(connector);
        c2fg.setFunctionGroup(functionGroup);
        c2fg.setKinds(MetaDefinitions.serializeArrayString(List.of("IpAndPort")));
        connector2FunctionGroupRepository.save(c2fg);

        connector.getFunctionGroups().add(c2fg);
        connectorRepository.save(connector);

        discovery = new Discovery();
        discovery.setName(DISCOVERY_NAME);
        discovery.setConnectorUuid(connector.getUuid());
        discovery.setConnectorName(connector.getName());
        discovery.setStatus(DiscoveryStatus.IN_PROGRESS);
        discovery.setConnectorStatus(DiscoveryStatus.IN_PROGRESS);
        discovery = discoveryRepository.save(discovery);
    }

    @AfterEach
    void tearDown() {
        RefusedDefinitionInserts.remove(jdbcTemplate);
        RefusedDiscoveryDeletes.remove(jdbcTemplate);
        mockServer.stop();
    }

    @Test
    void testListDiscoveries() {
        final DiscoveryResponseDto discoveryResponseDto = discoveryService
                .listDiscoveries(SecurityFilter.create(), new SearchRequestDto());
        final List<DiscoveryListDto> discoveries = discoveryResponseDto.getDiscoveries();
        Assertions.assertNotNull(discoveries);
        Assertions.assertFalse(discoveries.isEmpty());
        Assertions.assertEquals(1, discoveries.size());
        Assertions.assertEquals(discovery.getUuid().toString(), discoveries.get(0).getUuid());
    }

    @Test
    void testGetDiscovery() throws NotFoundException {
        DiscoveryDetailDto dto = discoveryService.getDiscovery(discovery.getSecuredUuid());
        Assertions.assertNotNull(dto);
        Assertions.assertEquals(discovery.getUuid().toString(), dto.getUuid());
        Assertions.assertEquals(discovery.getConnectorUuid().toString(), dto.getConnectorUuid());
    }

    @Test
    void runMessagesArePagedOldestFirstAndDoNotOverlap() throws NotFoundException {
        for (int i = 1; i <= 5; i++) {
            messageWriter
                    .append(discovery.getUuid(), DiscoveryMessageSeverity.WARNING, DiscoveryMessageCode.INVENTORY_GAP,
                            "problem " + i);
        }

        PaginationResponseDto<DiscoveryMessageDto> first = discoveryService
                .getDiscoveryRunMessages(discovery.getSecuredUuid(), 2, 1);
        PaginationResponseDto<DiscoveryMessageDto> second = discoveryService
                .getDiscoveryRunMessages(discovery.getSecuredUuid(), 2, 2);

        // Oldest first, because the entry that explains a run is usually the one that started it.
        Assertions.assertEquals(List.of("problem 1", "problem 2"), messagesOf(first));
        Assertions.assertEquals(List.of("problem 3", "problem 4"), messagesOf(second));
        Assertions.assertEquals(5, first.getTotalItems());
        Assertions.assertEquals(3, first.getTotalPages());
    }

    @Test
    void theDetailCountsWhatTheListingReturns() throws NotFoundException {
        messageWriter
                .append(discovery.getUuid(), DiscoveryMessageSeverity.WARNING, DiscoveryMessageCode.INVENTORY_GAP,
                        "a gap");
        messageWriter
                .append(discovery.getUuid(), DiscoveryMessageSeverity.INFO,
                        DiscoveryMessageCode.BATCH_PROCESSING_FAILED, "a retried batch");
        // A repeat aggregates, so it must not move the count the detail badges.
        messageWriter
                .append(discovery.getUuid(), DiscoveryMessageSeverity.WARNING, DiscoveryMessageCode.INVENTORY_GAP,
                        "a gap");

        DiscoveryDetailDto detail = discoveryService.getDiscovery(discovery.getSecuredUuid());

        Assertions.assertEquals(2, detail.getRunMessageCount());
        Assertions
                .assertEquals(detail.getRunMessageCount(),
                        discoveryService.getDiscoveryRunMessages(discovery.getSecuredUuid(), 10, 1).getTotalItems());
    }

    @Test
    void theDetailSynthesizesTheV2FieldsForAV1Run() throws NotFoundException {
        DiscoveryDetailDto detail = discoveryService.getDiscovery(discovery.getSecuredUuid());

        // The v1 run stores none of these, and all three are exact rather than defaults: it targets certificates
        // by definition, cannot be stopped at all, and has no connector that reports progress.
        Assertions.assertEquals(List.of(Resource.CERTIFICATE), detail.getResources());
        Assertions.assertEquals(Boolean.FALSE, detail.getStoppable());
        Assertions.assertNull(detail.getProgress());
    }

    @Test
    void theDetailPublishesWhatAV2RunRecorded() throws NotFoundException {
        DiscoveryProgressDto progress = new DiscoveryProgressDto();
        progress.setTargetsProcessed(11L);
        progress.setTargetsTotal(40L);
        // A real interface row, not a bare uuid: the detail resolves the association, and a reference to nothing
        // throws. Production cannot reach that state -- the column is a foreign key -- but the schema these tests
        // build from the entities carries no constraint, so the fixture has to be honest about it.
        ConnectorInterfaceEntity iface = new ConnectorInterfaceEntity();
        iface.setConnectorUuid(connector.getUuid());
        iface.setInterfaceCode(ConnectorInterface.DISCOVERY);
        iface.setVersion("v2");
        discovery.setConnectorInterfaceUuid(connectorInterfaceRepository.save(iface).getUuid());
        discovery.setResources(List.of(Resource.CERTIFICATE, Resource.CRYPTOGRAPHIC_KEY));
        discovery.setStoppable(true);
        discovery.setProgress(progress);
        discovery.setLastAppliedSequence(7L);
        discoveryRepository.save(discovery);

        DiscoveryDetailDto detail = discoveryService.getDiscovery(discovery.getSecuredUuid());

        Assertions.assertEquals(List.of(Resource.CERTIFICATE, Resource.CRYPTOGRAPHIC_KEY), detail.getResources());
        Assertions.assertEquals(Boolean.TRUE, detail.getStoppable());
        Assertions.assertNotNull(detail.getProgress(), "a client polling a live run reads its counters from here");
        Assertions.assertEquals(11L, detail.getProgress().getTargetsProcessed());
        Assertions.assertEquals(40L, detail.getProgress().getTargetsTotal());
        Assertions
                .assertEquals(7L, detail.getItemsDiscovered(),
                        "work and yield are separate: the completion ratio is in targets, the item total is this, "
                                + "and it counts what the items listing can actually return");
    }

    @Test
    void aRunThatCollectedNothingReturnsAnEmptyPageRatherThanNotFound() throws NotFoundException {
        PaginationResponseDto<DiscoveryMessageDto> page = discoveryService
                .getDiscoveryRunMessages(discovery.getSecuredUuid(), 10, 1);

        Assertions.assertTrue(page.getItems().isEmpty());
        Assertions.assertEquals(0, page.getTotalItems());
        Assertions.assertEquals(0, discoveryService.getDiscovery(discovery.getSecuredUuid()).getRunMessageCount());
    }

    @Test
    void runMessagesForAnUnknownRunAreNotFound() {
        // The log is reachable only by uuid, so a run that does not exist must not look like one with no messages.
        Assertions
                .assertThrows(NotFoundException.class,
                        () -> discoveryService
                                .getDiscoveryRunMessages(SecuredUUID.fromString("abfbc322-29e1-11ed-a261-0242ac120002"),
                                        10, 1));
    }

    @Test
    void anOversizedPageRequestIsClampedToTheConfiguredCeiling() throws NotFoundException {
        messageWriter
                .append(discovery.getUuid(), DiscoveryMessageSeverity.WARNING, DiscoveryMessageCode.INVENTORY_GAP,
                        "a gap");

        PaginationResponseDto<DiscoveryMessageDto> page = discoveryService
                .getDiscoveryRunMessages(discovery.getSecuredUuid(), 5000, 1);

        // Clamped to the largest size the frontend's page-size control offers, not to WebAppConfig's Pageable cap:
        // these arrive as raw ints, so that cap never sees them, and clamping below the control would answer a
        // user who picked 1000 with an itemsPerPage that contradicts what they chose.
        Assertions.assertEquals(1000, page.getItemsPerPage());
    }

    @Test
    void aStagedCertificateListsThroughTheItemsEndpointWithItsPayload() throws NotFoundException {
        CertificateContent content = new CertificateContent();
        content.setFingerprint("fp-items");
        content.setContent(CERTIFICATE_BASE64);
        content = certificateContentRepository.saveAndFlush(content);
        DiscoveryCertificate staged = new DiscoveryCertificate();
        staged.setDiscoveryUuid(discovery.getUuid());
        staged.setCertificateContentId(content.getId());
        staged.setNewlyDiscovered(true);
        staged.setProcessed(false);
        discoveryCertificateRepository.saveAndFlush(staged);

        PaginationResponseDto<DiscoveryItemDto> page = discoveryService
                .getDiscoveryItems(discovery.getSecuredUuid(), null, null, 10, 1);

        Assertions.assertEquals(1, page.getTotalItems());
        DiscoveryItemDto item = page.getItems().getFirst();
        // A v1 run's certificates reach the client through the same endpoint as any other resource -- that is what
        // makes it the single retrieval point rather than a v2-only listing.
        Assertions.assertEquals(1L, item.getSequence());
        Assertions.assertEquals("fp-items", item.getUniqueRef());
        Assertions.assertFalse(item.isProcessed());
        Assertions.assertNotNull(item.getPayload(), "the payload is built from the deduplicated content at read time");
        Assertions.assertEquals(Resource.CERTIFICATE, item.getPayload().getResource());
    }

    @Test
    void itemsForAnUnknownRunAreNotFound() {
        Assertions
                .assertThrows(NotFoundException.class, () -> discoveryService
                        .getDiscoveryItems(SecuredUUID.fromUUID(UUID.randomUUID()), null, null, 10, 1));
    }

    private List<String> messagesOf(PaginationResponseDto<DiscoveryMessageDto> page) {
        return page.getItems().stream().map(DiscoveryMessageDto::getMessage).toList();
    }

    @Test
    void testGetDiscovery_notFound() {
        Assertions
                .assertThrows(NotFoundException.class, () -> discoveryService
                        .getDiscovery(SecuredUUID.fromString("abfbc322-29e1-11ed-a261-0242ac120002")));
    }

    @Test
    void createsDiscovery_whenConnectorAndKindAreValid() throws Exception {
        // given
        mockServer
                .stubFor(WireMock
                        .get(WireMock.urlPathMatching("/v1/discoveryProvider/[^/]+/attributes"))
                        .willReturn(WireMock.okJson("[]")));
        mockServer
                .stubFor(WireMock
                        .post(WireMock.urlPathMatching("/v1/discoveryProvider/[^/]+/attributes/validate"))
                        .willReturn(WireMock.okJson("true")));
        DiscoveryDto request = new DiscoveryDto();
        request.setName("testDiscovery2");
        request.setConnectorUuid(connector.getUuid().toString());
        request.setAttributes(List.of());
        request.setKind("ApiKey");

        // when
        DiscoveryDetailDto dto = discoveryService.createDiscovery(request, true, false);

        // then
        assertThat(dto).isNotNull();
        assertThat(dto.getName()).isEqualTo(request.getName());
        assertThat(dto.getConnectorUuid()).isEqualTo(discovery.getConnectorUuid().toString());
    }

    @Test
    void throwsValidation_whenConnectorUuidIsNotSet() {
        // given
        DiscoveryDto request = new DiscoveryDto();
        request.setName("Demo");

        // when
        ThrowingCallable create = () -> discoveryService.createDiscovery(request, true, false);

        // then
        assertThatThrownBy(create).isInstanceOf(ValidationException.class);
    }

    @Test
    void throwsAlreadyExist_whenDiscoveryNameIsTaken() {
        // given
        DiscoveryDto request = new DiscoveryDto();
        request.setName(DISCOVERY_NAME);

        // when
        ThrowingCallable create = () -> discoveryService.createDiscovery(request, true, false);

        // then
        assertThatThrownBy(create).isInstanceOf(AlreadyExistException.class);
    }

    @Test
    @Disabled("Async method is not throwing exception")
    void testDiscoverCertificates_notFound() {
        // connector uui not set
        UUID discoveryUuid = discovery.getUuid();
        Assertions
                .assertThrows(NotFoundException.class,
                        () -> discoveryInternalService.runDiscovery(discoveryUuid, null));
    }

    @Test
    @Disabled("Async method is not throwing exception")
    void testDiscoverCertificates_validationFailed() {
        mockServer
                .stubFor(WireMock
                        .post(WireMock.urlPathMatching("/v1/discoveryProvider/[^/]+/attributes/validate"))
                        .willReturn(WireMock.okJson("false")));

        UUID discoveryUuid = discovery.getUuid();
        Assertions
                .assertThrows(ValidationException.class,
                        () -> discoveryInternalService.runDiscovery(discoveryUuid, null));
    }

    @Test
    void testRemoveDiscovery() throws NotFoundException {
        discoveryService.deleteDiscovery(discovery.getSecuredUuid());
        Assertions
                .assertThrows(NotFoundException.class, () -> discoveryService.getDiscovery(discovery.getSecuredUuid()));
    }

    @Test
    void testRemoveDiscovery_notFound() {
        Assertions
                .assertThrows(NotFoundException.class, () -> discoveryService
                        .deleteDiscovery(SecuredUUID.fromString("abfbc322-29e1-11ed-a261-0242ac120002")));
    }

    @Test
    void testBulkRemove() throws NotFoundException {
        discoveryService.bulkRemoveDiscovery(List.of(discovery.getSecuredUuid()));
        Assertions
                .assertThrows(NotFoundException.class, () -> discoveryService.getDiscovery(discovery.getSecuredUuid()));
    }

    @Test
    void commitsTheLocalDelete_beforeTheConnectorDeletesItsCopy() throws Exception {
        // given
        givenConnectorCopy();
        CompletableFuture<Integer> runRowsVisibleToTheConnectorCall = countRunRowsWhenTheConnectorDeletesItsCopy();

        // when
        discoveryService.deleteDiscovery(discovery.getSecuredUuid());

        // then
        assertThat(runRowsVisibleToTheConnectorCall).succeedsWithin(Duration.ofSeconds(5)).isEqualTo(0);
    }

    @Test
    void keepsTheConnectorCopy_whenTheLocalDeleteFails() {
        // given
        givenConnectorCopy();
        stubConnectorCopyDeletion(HttpStatus.NO_CONTENT);
        RefusedDiscoveryDeletes.install(jdbcTemplate, discovery.getUuid());

        // when
        ThrowingCallable delete = () -> discoveryService.deleteDiscovery(discovery.getSecuredUuid());

        // then
        assertThatThrownBy(delete).hasStackTraceContaining(RefusedDiscoveryDeletes.REASON);
        WireMock.verify(0, WireMock.deleteRequestedFor(WireMock.urlPathEqualTo(connectorCopyPath())));
    }

    @Test
    void deletesTheRun_whenTheConnectorFailsToDeleteItsCopy() throws Exception {
        // given
        givenConnectorCopy();
        stubConnectorCopyDeletion(HttpStatus.INTERNAL_SERVER_ERROR);

        // when
        discoveryService.deleteDiscovery(discovery.getSecuredUuid());

        // then
        WireMock.verify(1, WireMock.deleteRequestedFor(WireMock.urlPathEqualTo(connectorCopyPath())));
        assertThat(discoveryRepository.findByUuid(discovery.getUuid())).isEmpty();
    }

    @Test
    void deletesTheOtherRunsOfABulkDelete_whenOneFailsToDelete() throws Exception {
        // given
        Discovery refusedByTheDatabase = saveEndedV1Run("refused-by-the-database");
        Discovery afterTheFailure = saveEndedV1Run("after-the-failure");
        RefusedDiscoveryDeletes.install(jdbcTemplate, refusedByTheDatabase.getUuid());

        // when
        discoveryService
                .bulkRemoveDiscovery(List
                        .of(discovery.getSecuredUuid(), refusedByTheDatabase.getSecuredUuid(),
                                afterTheFailure.getSecuredUuid()));

        // then
        assertThat(discoveryRepository.findByUuid(discovery.getUuid())).isEmpty();
        assertThat(discoveryRepository.findByUuid(afterTheFailure.getUuid())).isEmpty();
        assertThat(discoveryRepository.findByUuid(refusedByTheDatabase.getUuid())).isPresent();
    }

    @Test
    void keepsTheInventoryCertificateAndItsContent_whenDeletingARunThatFoundIt() throws Exception {
        // given
        X509CertificateEntity inventoryCertificate = saveInventoryCertificate();
        stageResult(discovery, inventoryCertificate.getCertificateContentId());

        // when
        discoveryService.deleteDiscovery(discovery.getSecuredUuid());

        // then
        assertThat(certificateRepository.findByUuid(inventoryCertificate.getUuid())).isPresent();
        assertThat(certificateContentRepository.findById(inventoryCertificate.getCertificateContentId())).isPresent();
    }

    @Test
    void deletesTheContent_whenOnlyTheDeletedRunReferencedIt() throws Exception {
        // given
        CertificateContent foundOnlyByThisRun = saveContent("fp-found-only-by-this-run");
        stageResult(discovery, foundOnlyByThisRun.getId());

        // when
        discoveryService.deleteDiscovery(discovery.getSecuredUuid());

        // then
        assertThat(certificateContentRepository.findById(foundOnlyByThisRun.getId())).isEmpty();
    }

    @Test
    void keepsTheResultsOfOtherRuns_whenDeletingARun() throws Exception {
        // given
        Discovery otherRun = saveEndedV1Run("other-run");
        CertificateContent content = saveContent("fp-other-run");
        DiscoveryCertificate otherRunsResult = stageResult(otherRun, content.getId());

        // when
        discoveryService.deleteDiscovery(discovery.getSecuredUuid());

        // then
        assertThat(discoveryCertificateRepository.findByUuid(otherRunsResult.getUuid())).isPresent();
    }

    @Test
    void keepsTheContent_whenAnotherRunStillReferencesIt() throws Exception {
        // given
        Discovery otherRun = saveEndedV1Run("other-run");
        CertificateContent foundByBothRuns = saveContent("fp-found-by-both-runs");
        stageResult(discovery, foundByBothRuns.getId());
        stageResult(otherRun, foundByBothRuns.getId());

        // when
        discoveryService.deleteDiscovery(discovery.getSecuredUuid());

        // then
        assertThat(certificateContentRepository.findById(foundByBothRuns.getId())).isPresent();
    }

    @Test
    void failsRun_whenConnectorOfTheDiscoveryNoLongerExists() throws Exception {
        // given
        UUID discoveryUuid = createRunnableDiscovery();
        Discovery created = discoveryRepository.findByUuid(discoveryUuid).orElseThrow();
        created.setConnectorUuid(UUID.randomUUID());
        discoveryRepository.save(created);

        // when
        discoveryInternalService.runDiscovery(discoveryUuid, null);

        // then
        Discovery persisted = discoveryRepository.findByUuid(discoveryUuid).orElseThrow();
        assertThat(persisted.getStatus()).isEqualTo(DiscoveryStatus.FAILED);
        assertThat(discoveryCertificateRepository.countByDiscovery(persisted)).isZero();
    }

    @Test
    void failsRun_whenConnectorEndpointsAreNoLongerStubbed() throws Exception {
        // given
        UUID discoveryUuid = createRunnableDiscovery();
        mockServer.resetMappings();

        // when
        discoveryInternalService.runDiscovery(discoveryUuid, null);

        // then
        Discovery persisted = discoveryRepository.findByUuid(discoveryUuid).orElseThrow();
        assertThat(persisted.getStatus()).isEqualTo(DiscoveryStatus.FAILED);
        assertThat(discoveryCertificateRepository.countByDiscovery(persisted)).isZero();
    }

    @Test
    void aV1ConnectorsResourcesAreSynthesizedWithoutCallingIt() throws Exception {
        List<DiscoverySupportedResourceDto> resources = discoveryService
                .listDiscoveryResources(SecuredUUID.fromUUID(connector.getUuid()));

        // A v1 connector discovers certificates and nothing else, so the answer is known without asking -- and a
        // v1 connector has no endpoint to ask.
        Assertions.assertEquals(1, resources.size());
        Assertions.assertEquals(Resource.CERTIFICATE, resources.getFirst().getResource());
        WireMock.verify(0, WireMock.getRequestedFor(WireMock.urlPathEqualTo("/v2/discoveryProvider/resources")));
    }

    @Test
    void aV2ConnectorsResourcesAreRelayedLive() throws Exception {
        giveConnectorAV2DiscoveryInterface();
        stubSupportedResources("""
                [{"resource":"certificates"},{"resource":"keys"}]""");

        List<DiscoverySupportedResourceDto> resources = discoveryService
                .listDiscoveryResources(SecuredUUID.fromUUID(connector.getUuid()));

        Assertions
                .assertEquals(List.of(Resource.CERTIFICATE, Resource.CRYPTOGRAPHIC_KEY),
                        resources.stream().map(DiscoverySupportedResourceDto::getResource).toList());
    }

    @Test
    void attributesAreRefusedForAConnectorWithoutTheV2Interface() {
        // v1 publishes no discovery attribute schema, so there is nothing to relay -- refused rather than empty,
        // which a client would render as "no configuration needed".
        SecuredUUID connectorUuid = SecuredUUID.fromUUID(connector.getUuid());
        Assertions
                .assertThrows(ValidationException.class, () -> discoveryService.getDiscoveryAttributes(connectorUuid));
    }

    @Test
    void attributesAreRefusedForAResourceTheContractCannotDiscover() {
        giveConnectorAV2DiscoveryInterface();

        // Refused here rather than at the client, whose IllegalArgumentException would surface as a 500.
        SecuredUUID connectorUuid = SecuredUUID.fromUUID(connector.getUuid());
        Assertions
                .assertThrows(ValidationException.class,
                        () -> discoveryService.getDiscoveryResourceAttributes(connectorUuid, Resource.RA_PROFILE));
    }

    @Test
    void attributesAreRefusedForAResourceThisConnectorDoesNotDiscover() {
        giveConnectorAV2DiscoveryInterface();
        stubSupportedResources("""
                [{"resource":"certificates"}]""");

        // Discoverable in general, but not by this connector -- only its own live answer settles that.
        SecuredUUID connectorUuid = SecuredUUID.fromUUID(connector.getUuid());
        Assertions
                .assertThrows(ValidationException.class, () -> discoveryService
                        .getDiscoveryResourceAttributes(connectorUuid, Resource.CRYPTOGRAPHIC_KEY));
        WireMock.verify(0, WireMock.getRequestedFor(WireMock.urlPathEqualTo("/v2/discoveryProvider/keys/attributes")));
    }

    @Test
    void relaysTheAttributes_whenTheConnectorDiscoversTheResource() throws Exception {
        // given
        giveConnectorAV2DiscoveryInterface();
        stubSupportedResources("""
                [{"resource":"certificates"},{"resource":"keys"}]""");
        WireMock
                .stubFor(WireMock
                        .get(WireMock.urlPathEqualTo("/v2/discoveryProvider/keys/attributes"))
                        .willReturn(WireMock.okJson("""
                                [{"uuid":"7f7f0000-0000-4000-8000-000000000001","name":"keyStore",
                                  "type":"data","version":3,"contentType":"string",
                                  "properties":{"label":"Key store","visible":true,"required":false}}]""")));

        // when
        List<BaseAttribute> attributes = discoveryService
                .getDiscoveryResourceAttributes(SecuredUUID.fromUUID(connector.getUuid()), Resource.CRYPTOGRAPHIC_KEY);

        // then
        assertThat(attributes).singleElement().extracting(BaseAttribute::getName).isEqualTo("keyStore");
    }

    /** The listing stores what it relays, so the form's callbacks find it. */
    @Test
    void refusesTheListing_whenTheConnectorDeclaresADefinitionCoreCannotStore() {
        // given
        giveConnectorAV2DiscoveryInterface();
        var definitionWithoutProperties = """
                [{"uuid":"7f7f0000-0000-4000-8000-000000000001","name":"keyStore",
                  "type":"data","version":3,"contentType":"string"}]""";
        stubRunAttributes(definitionWithoutProperties);
        SecuredUUID connectorUuid = SecuredUUID.fromUUID(connector.getUuid());

        // when
        ThrowingCallable list = () -> discoveryService.getDiscoveryAttributes(connectorUuid);

        // then
        assertThatThrownBy(list).isInstanceOf(ValidationException.class).hasMessageContaining("keyStore");
    }

    private void stubSupportedResources(String json) {
        WireMock
                .stubFor(WireMock
                        .get(WireMock.urlPathEqualTo("/v2/discoveryProvider/resources"))
                        .willReturn(WireMock.okJson(json)));
    }

    private void giveConnectorAV2DiscoveryInterface() {
        ConnectorInterfaceEntity iface = new ConnectorInterfaceEntity();
        iface.setConnectorUuid(connector.getUuid());
        iface.setInterfaceCode(ConnectorInterface.DISCOVERY);
        iface.setVersion("v2");
        connectorInterfaceRepository.save(iface);
    }

    @Test
    void runDiscoveryWithUnsupportedInterfaceVersionFailsTheRunAndReturnsItsDetail() {
        ConnectorInterfaceEntity iface = new ConnectorInterfaceEntity();
        iface.setConnectorUuid(connector.getUuid());
        iface.setInterfaceCode(ConnectorInterface.DISCOVERY);
        iface.setVersion("v9");
        iface = connectorInterfaceRepository.save(iface);

        discovery.setConnectorInterfaceUuid(iface.getUuid());
        discoveryRepository.save(discovery);

        DiscoveryDetailDto detail = discoveryInternalService.runDiscovery(discovery.getUuid(), null);

        Assertions.assertEquals(DiscoveryStatus.FAILED, detail.getStatus());
        Discovery persisted = discoveryRepository.findByUuid(discovery.getUuid()).orElseThrow();
        Assertions.assertEquals(DiscoveryStatus.FAILED, persisted.getStatus());
        Assertions.assertEquals(DiscoveryStatus.FAILED, persisted.getConnectorStatus());
        Assertions
                .assertEquals("The discovery's connector interface version is not supported.", persisted.getMessage());
        Assertions.assertNotNull(persisted.getEndTime());
    }

    @Test
    void aV2RunWhoseConnectorRefusesTheResourceNeverOpens() {
        givenV2Run(List.of(Resource.CRYPTOGRAPHIC_KEY));
        stubSupportedResources("""
                [{"resource":"certificates"}]""");

        DiscoveryDetailDto detail = discoveryInternalService.runDiscovery(discovery.getUuid(), null);

        // Refused before initiate, so the connector is never asked to open a run it cannot perform.
        Assertions.assertEquals(DiscoveryStatus.FAILED, detail.getStatus());
        WireMock
                .verify(0, WireMock
                        .postRequestedFor(WireMock.urlPathEqualTo("/v2/discoveryProvider/discoveries/initiate")));
        Discovery persisted = discoveryRepository.findByUuid(discovery.getUuid()).orElseThrow();
        Assertions.assertNotNull(persisted.getEndTime());
        Assertions
                .assertTrue(persisted.getMessage().contains(Resource.CRYPTOGRAPHIC_KEY.getLabel()),
                        "the message names the refused resource in the label a reader recognises");
    }

    @Test
    void aStartedV2RunRecordsItsHandleAndGetsBothAgendaRows() {
        givenV2Run(List.of(Resource.CERTIFICATE));
        stubSupportedResources("""
                [{"resource":"certificates"}]""");
        // The content item carries its own contentType: without it the deserializer builds a v2 content
        // item, which does not fit a v3 attribute.
        stubInitiate("""
                {"checkpoint":[{"uuid":"7f7f0000-0000-4000-8000-000000000009","name":"connectorRunId","type":"meta",
                          "version":3,"contentType":"string","content":[{"contentType":"string","data":"run-42"}]}],
                 "stoppable":true}""");

        DiscoveryDetailDto detail = discoveryInternalService.runDiscovery(discovery.getUuid(), null);

        Assertions.assertEquals(DiscoveryStatus.IN_PROGRESS, detail.getStatus());
        Discovery persisted = discoveryRepository.findByUuid(discovery.getUuid()).orElseThrow();
        Assertions
                .assertNotNull(persisted.getCheckpoint(),
                        "without the handle the connector cannot resolve the run again");
        Assertions.assertEquals("connectorRunId", persisted.getCheckpoint().getFirst().getName());
        // Clamped: the connector claimed stoppable, but its interface does not advertise discoveryStopResume, and a
        // connector may only narrow that flag.
        Assertions.assertEquals(Boolean.FALSE, persisted.getStoppable());
        // Both rows from the outset: STATUS reports terminality, DRAIN pulls results. One without the other leaves
        // the run undriveable in one direction.
        Assertions.assertTrue(workRepository.existsByDiscoveryUuid(discovery.getUuid()));
    }

    @Test
    void anOversizedRunHandleFailsTheRunRatherThanBeingStored() {
        givenV2Run(List.of(Resource.CERTIFICATE));
        stubSupportedResources("""
                [{"resource":"certificates"}]""");
        stubInitiate("""
                {"checkpoint":[{"uuid":"7f7f0000-0000-4000-8000-000000000009","name":"connectorRunId","type":"meta",
                          "version":3,"contentType":"string","content":[{"contentType":"string","data":"%s"}]}]}"""
                .formatted("x".repeat(70_000)));

        DiscoveryDetailDto detail = discoveryInternalService.runDiscovery(discovery.getUuid(), null);

        // Failed at the only point the run can still be reported; DiscoveryProviderV2Adapter#MAX_META_BYTES says why.
        Assertions.assertEquals(DiscoveryStatus.FAILED, detail.getStatus());
        Discovery persisted = discoveryRepository.findByUuid(discovery.getUuid()).orElseThrow();
        Assertions.assertNull(persisted.getCheckpoint());
        Assertions.assertTrue(persisted.getMessage().contains("checkpoint size exceeded"));
    }

    @Test
    void aResumeAnsweredWithAnUnreplayableHandleEndsTheRunRatherThanLeavingItStopped() throws Exception {
        givenV2Run(List.of(Resource.CERTIFICATE));
        Discovery run = discoveryRepository.findByUuid(discovery.getUuid()).orElseThrow();
        run.setStatus(DiscoveryStatus.STOPPED);
        run.setStoppable(true);
        discoveryRepository.saveAndFlush(run);
        giveInterfaceStopResumeFlag();
        stubOversizedHandle("/v2/discoveryProvider/discoveries/resume");

        adapterFactory.forDiscovery(run).resume(run);

        Discovery persisted = discoveryRepository.findByUuid(discovery.getUuid()).orElseThrow();
        // Rolled back instead, Core would sit STOPPED while the connector runs, with nothing to reconcile it.
        Assertions.assertEquals(DiscoveryStatus.FAILED, persisted.getStatus());
        Assertions.assertTrue(persisted.getMessage().contains("too large to replay"), persisted.getMessage());
        Assertions.assertNull(persisted.getCheckpoint());
    }

    @Test
    void aStopAnsweredWithAnUnreplayableHandleEndsTheRunRatherThanLeavingItInProgress() throws Exception {
        givenV2Run(List.of(Resource.CERTIFICATE));
        Discovery run = discoveryRepository.findByUuid(discovery.getUuid()).orElseThrow();
        run.setStoppable(true);
        discoveryRepository.saveAndFlush(run);
        giveInterfaceStopResumeFlag();
        stubOversizedHandle("/v2/discoveryProvider/discoveries/stop");

        adapterFactory.forDiscovery(run).stop(run);

        Discovery persisted = discoveryRepository.findByUuid(discovery.getUuid()).orElseThrow();
        // The connector is already paused; reverting to IN_PROGRESS would describe a scan nobody is running.
        Assertions.assertEquals(DiscoveryStatus.FAILED, persisted.getStatus());
        Assertions.assertNull(persisted.getCheckpoint());
    }

    @Test
    void aResumeTheConnectorCannotHonourEndsTheRunAndKeepsWhatItStaged() throws Exception {
        givenV2Run(List.of(Resource.CERTIFICATE));
        Discovery run = discoveryRepository.findByUuid(discovery.getUuid()).orElseThrow();
        run.setStatus(DiscoveryStatus.STOPPED);
        run.setStoppable(true);
        discoveryRepository.saveAndFlush(run);
        giveInterfaceStopResumeFlag();
        stubResumeStatus(410);

        adapterFactory.forDiscovery(run).resume(run);

        Discovery persisted = discoveryRepository.findByUuid(discovery.getUuid()).orElseThrow();
        Assertions.assertEquals(DiscoveryStatus.FAILED, persisted.getStatus());
        Assertions.assertEquals("checkpoint lost", persisted.getMessage());
        // The handle is dropped: it addresses a run the connector can no longer resume, so replaying it would
        // only produce the same 410 on every later call.
        Assertions.assertNull(persisted.getCheckpoint());
    }

    @Test
    void aRunTheConnectorAlreadyForgotCancelsSuccessfully() throws Exception {
        givenV2Run(List.of(Resource.CERTIFICATE));
        Discovery run = discoveryRepository.findByUuid(discovery.getUuid()).orElseThrow();
        WireMock
                .stubFor(WireMock
                        .post(WireMock.urlPathEqualTo("/v2/discoveryProvider/discoveries/cancel"))
                        .willReturn(WireMock.aResponse().withStatus(404)));

        adapterFactory.forDiscovery(run).cancel(run);

        Discovery persisted = discoveryRepository.findByUuid(discovery.getUuid()).orElseThrow();
        Assertions.assertEquals(DiscoveryStatus.CANCELLED, persisted.getStatus());
        Assertions.assertNull(persisted.getCheckpoint());
        // Committed with the terminal transition: written separately, a status tick in between could write this back.
        Assertions
                .assertEquals(DiscoveryStatus.CANCELLED, persisted.getConnectorStatus(),
                        "a cancelled run must not go on reporting its connector as still scanning");
    }

    @Test
    void throwsNotFound_leavingNoRunBehind_whenTriggerToAssociateDoesNotExist() {
        // given
        giveConnectorAV2DiscoveryInterface();
        stubSupportedResources("""
                [{"resource":"certificates"}]""");
        DiscoveryDto request = v2Request(List.of(Resource.CERTIFICATE));
        // Associating a trigger that does not exist fails after the run row and its attributes are written, and
        // fails with a checked exception -- which Spring does not roll back on by default.
        request.setTriggers(List.of(UUID.randomUUID()));

        // when
        ThrowingCallable create = () -> discoveryService.createDiscovery(request, true, false);

        // then
        assertThatThrownBy(create).isInstanceOf(NotFoundException.class);
        assertThat(discoveryRepository.findByName(request.getName()))
                .as("a half-created run is left IN_PROGRESS with part of its configuration missing, reachable "
                        + "only to be deleted")
                .isEmpty();
    }

    @Test
    void stoppingARunDropsItsDrainRowAndKeepsItsStatusRow() throws Exception {
        givenV2Run(List.of(Resource.CERTIFICATE));
        Discovery run = discoveryRepository.findByUuid(discovery.getUuid()).orElseThrow();
        run.setStoppable(true);
        discoveryRepository.saveAndFlush(run);
        giveInterfaceStopResumeFlag();
        workWriter.schedule(run.getUuid(), DiscoveryWorkType.STATUS, OffsetDateTime.now(ZoneOffset.UTC));
        workWriter.schedule(run.getUuid(), DiscoveryWorkType.DRAIN, OffsetDateTime.now(ZoneOffset.UTC));
        stubLifecycle("/v2/discoveryProvider/discoveries/stop");

        adapterFactory.forDiscovery(run).stop(run);

        Assertions.assertEquals(DiscoveryStatus.STOPPED, reloadStatus());
        Assertions.assertTrue(hasWork(DiscoveryWorkType.STATUS), "a stopped run is still watched at its connector");
        Assertions
                .assertFalse(hasWork(DiscoveryWorkType.DRAIN),
                        "an idle drain against a paused run asks for results that cannot arrive");
    }

    /** The agenda write is an upsert, so nothing has to remember the row was dropped. */
    @Test
    void resumingARunRestoresTheDrainRowItWasStoppedWithout() throws Exception {
        givenV2Run(List.of(Resource.CERTIFICATE));
        Discovery run = discoveryRepository.findByUuid(discovery.getUuid()).orElseThrow();
        run.setStatus(DiscoveryStatus.STOPPED);
        run.setStoppable(true);
        discoveryRepository.saveAndFlush(run);
        giveInterfaceStopResumeFlag();
        stubLifecycle("/v2/discoveryProvider/discoveries/resume");

        adapterFactory.forDiscovery(run).resume(run);

        Assertions.assertTrue(hasWork(DiscoveryWorkType.DRAIN), "a resumed run must collect what it left behind");
    }

    /**
     * The replayed handle comes from the response that last carried one, so an omitted checkpoint is not a cleared one.
     */
    @Test
    void aStopResponseWithoutACheckpointKeepsTheStoredOne() throws Exception {
        givenV2Run(List.of(Resource.CERTIFICATE));
        Discovery run = discoveryRepository.findByUuid(discovery.getUuid()).orElseThrow();
        run.setStoppable(true);
        run.setCheckpoint(DiscoveryCheckpointFixture.checkpoint("connectorRunId", "run-42"));
        discoveryRepository.saveAndFlush(run);
        giveInterfaceStopResumeFlag();
        stubLifecycle("/v2/discoveryProvider/discoveries/stop");

        adapterFactory.forDiscovery(run).stop(run);

        Discovery persisted = discoveryRepository.findByUuid(discovery.getUuid()).orElseThrow();
        Assertions.assertNotNull(persisted.getCheckpoint(), "the handle the connector minted must survive the stop");
        Assertions.assertEquals("connectorRunId", persisted.getCheckpoint().getFirst().getName());
    }

    @Test
    void aResumeResponseWithoutACheckpointKeepsTheStoredOne() throws Exception {
        givenV2Run(List.of(Resource.CERTIFICATE));
        Discovery run = discoveryRepository.findByUuid(discovery.getUuid()).orElseThrow();
        run.setStatus(DiscoveryStatus.STOPPED);
        run.setStoppable(true);
        run.setCheckpoint(DiscoveryCheckpointFixture.checkpoint("connectorRunId", "run-42"));
        discoveryRepository.saveAndFlush(run);
        giveInterfaceStopResumeFlag();
        stubLifecycle("/v2/discoveryProvider/discoveries/resume");

        adapterFactory.forDiscovery(run).resume(run);

        Discovery persisted = discoveryRepository.findByUuid(discovery.getUuid()).orElseThrow();
        Assertions
                .assertNotNull(persisted.getCheckpoint(),
                        "the handle the run was stopped with must survive the resume");
        Assertions.assertEquals("connectorRunId", persisted.getCheckpoint().getFirst().getName());
    }

    @Test
    void stopIsRefusedForARunTheConnectorNeverDeclaredStoppable() {
        givenV2Run(List.of(Resource.CERTIFICATE));
        Discovery run = discoveryRepository.findByUuid(discovery.getUuid()).orElseThrow();
        giveInterfaceStopResumeFlag();

        // The interface advertises the capability, but this run was not declared stoppable at initiate.
        var v2 = adapterFactory.forDiscovery(run);
        Assertions.assertThrows(ValidationException.class, () -> v2.stop(run));
    }

    @Test
    void aV1RunAnswers422RatherThan500ForEveryLifecycleOperation() {
        // The v1 adapter refuses with UnsupportedOperationException, which has no handler and would otherwise
        // reach the client as a 500. From a caller's side this means the same as an illegal transition.
        SecuredUUID uuid = discovery.getSecuredUuid();
        Assertions.assertThrows(ValidationException.class, () -> discoveryService.stopDiscovery(uuid));
        Assertions.assertThrows(ValidationException.class, () -> discoveryService.resumeDiscovery(uuid));
        Assertions.assertThrows(ValidationException.class, () -> discoveryService.cancelDiscovery(uuid));
    }

    @Test
    void theSyncedActionCatalogueCarriesTheLifecycleActions() {
        // The catalogue is scanned from @ExternalAuthorization, so an endpoint gated on an action the auth service
        // has never been told about would authorize against a permission nobody can grant.
        List<String> discoveryActions = contextRefreshListener
                .getResources()
                .stream()
                // Fully qualified: the auth catalogue has its own Resource enum, distinct from the wire one
                // this test already imports.
                .filter(resource -> resource.getName() == com.otilm.core.model.auth.Resource.DISCOVERY)
                .findFirst()
                .orElseThrow()
                .getActions();

        Assertions
                .assertTrue(discoveryActions.containsAll(List.of("stop", "resume", "cancel")),
                        "expected stop/resume/cancel among " + discoveryActions);
    }

    @Test
    void aTerminatedV2RunAnnouncesItselfOnTheSameEventAV1RunRaises() {
        givenV2Run(List.of(Resource.CERTIFICATE));
        Discovery run = discoveryRepository.findByUuid(discovery.getUuid()).orElseThrow();

        terminator.end(run.getUuid(), DiscoveryStatus.FAILED, "connector gave up");

        // Without the event, a v2 run reaches none of what an ending drives: platform triggers, the user
        // notification, and the scheduled job's completion. The handler consumes it and leaves the status alone.
        Discovery persisted = discoveryRepository.findByUuid(discovery.getUuid()).orElseThrow();
        Assertions.assertEquals(DiscoveryStatus.FAILED, persisted.getStatus());
        Assertions.assertEquals("connector gave up", persisted.getMessage());
    }

    @Test
    void aScheduledV2RunRemembersItsJobSoTheSchedulerCanBeToldLater() {
        givenV2Run(List.of(Resource.CERTIFICATE));
        stubSupportedResources("""
                [{"resource":"certificates"}]""");
        stubInitiate("""
                {"checkpoint":[],"stoppable":false}""");
        ScheduledJobInfo job = new ScheduledJobInfo("nightly", UUID.randomUUID(), UUID.randomUUID());

        discoveryInternalService.runDiscovery(discovery.getUuid(), job);

        Discovery persisted = discoveryRepository.findByUuid(discovery.getUuid()).orElseThrow();
        Assertions.assertEquals(job.jobHistoryUuid(), persisted.getScheduledJobHistoryUuid());
    }

    @Test
    void recordsInterfaceAssociationAndResources_whenCreatingAgainstV2Connector() throws Exception {
        // given
        giveConnectorAV2DiscoveryInterface();
        stubSupportedResources("""
                [{"resource":"certificates"},{"resource":"keys"}]""");

        // when
        DiscoveryDetailDto created = discoveryService
                .createDiscovery(v2Request(List.of(Resource.CRYPTOGRAPHIC_KEY)), true, false);

        // then
        // Without the association the run is a v1 run whatever the connector implements, so every later operation
        // routes to the wrong adapter.
        Discovery persisted = discoveryRepository.findByUuid(UUID.fromString(created.getUuid())).orElseThrow();
        assertThat(persisted.getConnectorInterfaceUuid()).isNotNull();
        assertThat(persisted.getResources()).containsExactly(Resource.CRYPTOGRAPHIC_KEY);
    }

    @Test
    void throwsValidation_whenV2RunNamesNoResources() {
        // given
        giveConnectorAV2DiscoveryInterface();
        // A v2 connector discovers several kinds and cannot guess which was meant.
        DiscoveryDto request = v2Request(null);

        // when
        ThrowingCallable create = () -> discoveryService.createDiscovery(request, true, false);

        // then
        assertThatThrownBy(create).isInstanceOf(ValidationException.class);
    }

    /**
     * v1 creation is gated on the connector through {@code mergeAndValidateAttributes}; the v2 path calls the connector
     * itself, so it must ask the same question first, or discovery-create permission alone reaches a restricted
     * connector.
     */
    @Test
    void throwsAccessDenied_whenCallerLacksAccessToTheV2Connector() {
        // given
        giveConnectorAV2DiscoveryInterface();
        stubSupportedResources("""
                [{"resource":"certificates"}]""");
        denyResourceAccess(Resource.CONNECTOR, ResourceAction.ANY);
        DiscoveryDto request = v2Request(List.of(Resource.CERTIFICATE));

        // when
        ThrowingCallable create = () -> discoveryService.createDiscovery(request, true, false);

        // then
        assertThatThrownBy(create).isInstanceOf(AccessDeniedException.class);
        mockServer.verify(0, WireMock.anyRequestedFor(WireMock.urlPathMatching("/v2/discoveryProvider/.*")));
    }

    /**
     * A run's references are dereferenced later, by a tick under the system identity, so create is the only moment the
     * caller is on the thread to be asked whether they may read what they filed. Authority creation asks the same way.
     */
    @Test
    void throwsAccessDenied_whenCredentialReferenceIsOneTheCallerMayNotRead() {
        // given
        giveConnectorAV2DiscoveryInterface();
        stubSupportedResources("""
                [{"resource":"certificates"}]""");
        stubRunAttributes(CREDENTIAL_DEFINITION);
        denyResourceAccess(Resource.CREDENTIAL, ResourceAction.DETAIL);
        DiscoveryDto request = v2Request(List.of(Resource.CERTIFICATE));
        request.setAttributes(List.of(credentialReference(aCredential())));

        // when
        ThrowingCallable create = () -> discoveryService.createDiscovery(request, true, false);

        // then
        assertThatThrownBy(create).isInstanceOf(AccessDeniedException.class);
        assertThat(discoveryRepository.findByName(request.getName()))
                .as("refused before anything was persisted")
                .isEmpty();
    }

    @Test
    void throwsAccessDenied_whenPerResourceCredentialReferenceIsOneTheCallerMayNotRead() {
        // given
        giveConnectorAV2DiscoveryInterface();
        stubSupportedResources("""
                [{"resource":"certificates"}]""");
        WireMock
                .stubFor(WireMock
                        .get(WireMock.urlPathEqualTo("/v2/discoveryProvider/certificates/attributes"))
                        .willReturn(WireMock.okJson(CREDENTIAL_DEFINITION)));
        denyResourceAccess(Resource.CREDENTIAL, ResourceAction.DETAIL);
        DiscoveryDto request = v2Request(List.of(Resource.CERTIFICATE));
        request.setResourceAttributes(Map.of(Resource.CERTIFICATE, List.of(credentialReference(aCredential()))));

        // when
        ThrowingCallable create = () -> discoveryService.createDiscovery(request, true, false);

        // then
        assertThatThrownBy(create).isInstanceOf(AccessDeniedException.class);
        assertThat(discoveryRepository.findByName(request.getName())).isEmpty();
    }

    @Test
    void createsRun_whenCredentialReferenceIsOneTheCallerMayRead() throws Exception {
        // given
        giveConnectorAV2DiscoveryInterface();
        stubSupportedResources("""
                [{"resource":"certificates"}]""");
        stubRunAttributes(CREDENTIAL_DEFINITION);
        DiscoveryDto request = v2Request(List.of(Resource.CERTIFICATE));
        request.setAttributes(List.of(credentialReference(aCredential())));

        // when
        DiscoveryDetailDto created = discoveryService.createDiscovery(request, true, false);

        // then
        assertThat(created.getUuid()).isNotNull();
    }

    @Test
    void createsRun_whenResourceReferenceIsUsedWithoutCredentialPermission() throws Exception {
        // given
        giveConnectorAV2DiscoveryInterface();
        stubSupportedResources("""
                [{"resource":"certificates"}]""");
        stubRunAttributes(RESOURCE_DEFINITION);
        // The resource loader gates per object, inside, so this run needs no credential permission at all.
        denyResourceAccess(Resource.CREDENTIAL, ResourceAction.DETAIL);
        DiscoveryDto request = v2Request(List.of(Resource.CERTIFICATE));
        request.setAttributes(List.of(resourceReference(aCredential())));

        // when
        DiscoveryDetailDto created = discoveryService.createDiscovery(request, true, false);

        // then
        assertThat(created.getUuid()).isNotNull();
    }

    /**
     * A client that leaves out {@code "version": "v3"} gets an attribute Jackson reads as a v2 one, which a v3
     * definition cannot take. That is the caller's to correct, so it is refused as such rather than failing inside.
     */
    @Test
    void throwsValidation_whenAttributeIsSentAsEarlierVersionThanItsDefinition() {
        // given
        giveConnectorAV2DiscoveryInterface();
        stubSupportedResources("""
                [{"resource":"certificates"}]""");
        stubRunAttributes(HOSTS_DEFINITION);
        DiscoveryDto request = v2Request(List.of(Resource.CERTIFICATE));
        request
                .setAttributes(List
                        .of(new RequestAttributeV2(HOSTS_UUID, "data_hosts", AttributeContentType.STRING,
                                List.of(new StringAttributeContentV2("10.0.0.1")))));

        // when
        ThrowingCallable create = () -> discoveryService.createDiscovery(request, true, false);

        // then
        assertThatThrownBy(create)
                .isInstanceOf(ValidationException.class)
                .hasMessageContaining("data_hosts")
                .hasMessageContaining("v3");
        assertThat(discoveryRepository.findByName(request.getName())).isEmpty();
    }

    /**
     * The connector is the only party that can judge a target list, and it does so at initiate. Started on the creating
     * caller's thread, its refusal reaches that caller, and the run it refused is not kept.
     */
    @Test
    void throwsConnectorProblem_leavingNoRunBehind_whenConnectorRefusesTheRunAtInitiate() throws Exception {
        // given
        giveConnectorAV2DiscoveryInterface();
        stubSupportedResources("""
                [{"resource":"certificates"}]""");
        stubRunAttributes("[]");
        WireMock
                .stubFor(WireMock
                        .post(WireMock.urlPathEqualTo("/v2/discoveryProvider/discoveries/initiate"))
                        .willReturn(WireMock
                                .aResponse()
                                .withStatus(422)
                                .withHeader("Content-Type", "application/problem+json")
                                .withBody("""
                                        {"type":"https://docs.otilm.com/problems/common/VALIDATION_FAILED",
                                         "title":"Validation failed","status":422,
                                         "detail":"data_hosts entry \\"10.0.0.999\\" is not valid",
                                         "errorCode":"VALIDATION_FAILED","retryable":false}""")));
        UUID created = UUID
                .fromString(discoveryService
                        .createDiscovery(v2Request(List.of(Resource.CERTIFICATE)), true, false)
                        .getUuid());

        // when
        ThrowingCallable start = () -> discoveryService.startDiscovery(created);

        // then
        assertThatThrownBy(start)
                .isInstanceOfSatisfying(ConnectorProblemException.class,
                        refused -> assertThat(refused.getHttpStatus()).isEqualTo(HttpStatus.UNPROCESSABLE_CONTENT))
                .hasMessageContaining("10.0.0.999");
        assertThat(discoveryRepository.findByUuid(created)).as("the refused run is not kept").isEmpty();
    }

    private static final UUID HOSTS_UUID = UUID.fromString("7f7f0000-0000-4000-8000-000000000004");

    private static final String HOSTS_DEFINITION = """
            [{"uuid":"7f7f0000-0000-4000-8000-000000000004","name":"data_hosts",
              "type":"data","version":3,"contentType":"string",
              "properties":{"label":"Hosts","visible":true,"required":true,
                            "list":true,"multiSelect":true,"extensibleList":true}}]""";

    private static final String RESOURCE_DEFINITION = """
            [{"uuid":"7f7f0000-0000-4000-8000-000000000003","name":"vault",
              "type":"data","version":3,"contentType":"resource",
              "properties":{"label":"Vault","visible":true,"required":false,"resource":"credentials"},
              "attributeCallback":{"callbackContext":"/v2/discoveryProvider/vaults","callbackMethod":"GET",
                                   "mappings":[]}}]""";

    /** What a caller files for a resource reference: the object's identity. */
    private static RequestAttribute resourceReference(Credential credential) {
        ResourceSimpleContentData identity = new ResourceSimpleContentData(AttributeResource.CREDENTIAL);
        identity.setUuid(credential.getUuid().toString());
        identity.setName(credential.getName());
        return new RequestAttributeV3(UUID.fromString("7f7f0000-0000-4000-8000-000000000003"), "vault",
                AttributeContentType.RESOURCE, List.of(new ResourceObjectContent(credential.getName(), identity)));
    }

    private static final String CREDENTIAL_DEFINITION = """
            [{"uuid":"7f7f0000-0000-4000-8000-000000000002","name":"credential",
              "type":"data","version":2,"contentType":"credential",
              "properties":{"label":"Credential","visible":true,"required":false}}]""";

    private void stubRunAttributes(String json) {
        WireMock
                .stubFor(WireMock
                        .get(WireMock.urlPathEqualTo("/v2/discoveryProvider/attributes"))
                        .willReturn(WireMock.okJson(json)));
    }

    private Credential aCredential() {
        Credential credential = new Credential();
        credential.setName("vault-" + UUID.randomUUID());
        credential.setKind("Basic");
        credential.setConnectorUuid(connector.getUuid());
        return credentialRepository.save(credential);
    }

    /** What a caller files: the credential's identity, nothing of its content. */
    private static RequestAttribute credentialReference(Credential credential) {
        CredentialAttributeContentData identity = new CredentialAttributeContentData();
        identity.setUuid(credential.getUuid().toString());
        identity.setName(credential.getName());
        return new RequestAttributeV2(UUID.fromString("7f7f0000-0000-4000-8000-000000000002"), "credential",
                AttributeContentType.CREDENTIAL,
                List.of(new CredentialAttributeContentV2(credential.getName(), identity)));
    }

    @Test
    void throwsValidation_whenResourceIsOneThePlatformCannotReportOn() {
        // given
        giveConnectorAV2DiscoveryInterface();
        // A connector is free to claim anything here. Its claim decides what it can scan, not what this platform can
        // carry an item for -- that is fixed by the payload subtypes the v2 contract registers.
        stubSupportedResources("""
                [{"resource":"certificates"},{"resource":"vaults"}]""");
        DiscoveryDto request = v2Request(List.of(Resource.VAULT));

        // when
        ThrowingCallable create = () -> discoveryService.createDiscovery(request, true, false);

        // then
        // Refused at create, where a caller is present. Accepted, it would open a run that fails at ingest instead.
        assertThatThrownBy(create).isInstanceOf(ValidationException.class).hasMessageContaining("cannot report");
    }

    @Test
    void throwsValidation_whenV1ConnectorIsGivenPerResourceAttributes() {
        // given
        // Honouring them would send Core to a v2 endpoint this connector does not implement; dropping them would
        // accept a run configured differently from the one that was asked for.
        DiscoveryDto request = v2Request(null);
        request.setResourceAttributes(Map.of(Resource.CERTIFICATE, List.of()));

        // when
        ThrowingCallable create = () -> discoveryService.createDiscovery(request, true, false);

        // then
        // The message, not just the type: unvalidated, the request reaches a v2 client call against a v1 connector,
        // which also fails -- but for a reason the caller cannot act on.
        assertThatThrownBy(create)
                .isInstanceOf(ValidationException.class)
                .hasMessageContaining("per-resource attributes");
    }

    @Test
    void throwsValidation_whenPerResourceAttributesNameAResourceTheRunDoesNotTarget() {
        // given
        giveConnectorAV2DiscoveryInterface();
        stubSupportedResources("""
                [{"resource":"certificates"},{"resource":"keys"}]""");
        DiscoveryDto request = v2Request(List.of(Resource.CERTIFICATE));
        request.setResourceAttributes(Map.of(Resource.CRYPTOGRAPHIC_KEY, List.of()));

        // when
        ThrowingCallable create = () -> discoveryService.createDiscovery(request, true, false);

        // then
        // The connector discovers keys, so the key is legal in itself -- it is this run that does not target them,
        // and filing attributes against it would store content nothing ever reads back.
        assertThatThrownBy(create).isInstanceOf(ValidationException.class).hasMessageContaining("does not target");
    }

    @Test
    void throwsValidation_whenV1ConnectorIsGivenResources() {
        // given
        // Accepting the field would let a caller believe they had selected something a v1 connector cannot honour.
        DiscoveryDto request = v2Request(List.of(Resource.CERTIFICATE));

        // when
        ThrowingCallable create = () -> discoveryService.createDiscovery(request, true, false);

        // then
        assertThatThrownBy(create).isInstanceOf(ValidationException.class);
    }

    @Test
    void throwsValidation_whenConnectorDoesNotDiscoverTheRequestedResource() {
        // given
        giveConnectorAV2DiscoveryInterface();
        stubSupportedResources("""
                [{"resource":"certificates"}]""");
        // Caught now, at one connector call, rather than by a run that opens and immediately fails.
        DiscoveryDto request = v2Request(List.of(Resource.CRYPTOGRAPHIC_KEY));

        // when
        ThrowingCallable create = () -> discoveryService.createDiscovery(request, true, false);

        // then
        assertThatThrownBy(create).isInstanceOf(ValidationException.class);
    }

    @Test
    void throwsValidation_whenConnectorExposesOnlyAFutureInterfaceVersion() {
        // given
        ConnectorInterfaceEntity future = new ConnectorInterfaceEntity();
        future.setConnectorUuid(connector.getUuid());
        future.setInterfaceCode(ConnectorInterface.DISCOVERY);
        future.setVersion("v9");
        connectorInterfaceRepository.saveAndFlush(future);
        // The association is recorded whatever the version, so the adapter factory is the one thing that decides
        // which generation drives a run. Keying create on "v2" instead would leave a v9-only connector looking
        // like a legacy connector and silently drive it through the v1 adapter.
        DiscoveryDto request = v2Request(List.of(Resource.CERTIFICATE));

        // when
        ThrowingCallable create = () -> discoveryService.createDiscovery(request, true, false);

        // then
        assertThatThrownBy(create).isInstanceOf(ValidationException.class);
    }

    @Test
    void usesNamedInterface_whenConnectorExposesSeveral() throws Exception {
        // given
        giveConnectorAV2DiscoveryInterface();
        ConnectorInterfaceEntity chosen = connectorInterfaceRepository
                .findByConnectorUuidAndInterfaceCodeAndVersion(connector.getUuid(), ConnectorInterface.DISCOVERY, "v2")
                .orElseThrow();
        ConnectorInterfaceEntity other = new ConnectorInterfaceEntity();
        other.setConnectorUuid(connector.getUuid());
        other.setInterfaceCode(ConnectorInterface.DISCOVERY);
        other.setVersion("v3");
        connectorInterfaceRepository.saveAndFlush(other);
        stubSupportedResources("""
                [{"resource":"certificates"}]""");
        DiscoveryDto request = v2Request(List.of(Resource.CERTIFICATE));
        request.setInterfaceUuid(chosen.getUuid());

        // when
        DiscoveryDetailDto created = discoveryService.createDiscovery(request, true, false);

        // then
        // Named explicitly, so the ambiguity that would otherwise be refused is resolved by the caller -- and the
        // detail says which interface drives the run rather than leaving a client to infer the generation.
        assertThat(created.getConnectorInterface().getUuid()).isEqualTo(chosen.getUuid());
        assertThat(created.getConnectorInterface().getVersion()).isEqualTo("v2");
    }

    @Test
    void throwsValidation_whenNamedInterfaceIsNotExposedByTheConnector() {
        // given
        giveConnectorAV2DiscoveryInterface();
        DiscoveryDto request = v2Request(List.of(Resource.CERTIFICATE));
        request.setInterfaceUuid(UUID.randomUUID());

        // when
        ThrowingCallable create = () -> discoveryService.createDiscovery(request, true, false);

        // then
        assertThatThrownBy(create).isInstanceOf(ValidationException.class);
    }

    @Test
    void throwsValidation_whenConnectorExposesSeveralInterfacesAndNoneIsNamed() {
        // given
        giveConnectorAV2DiscoveryInterface();
        ConnectorInterfaceEntity future = new ConnectorInterfaceEntity();
        future.setConnectorUuid(connector.getUuid());
        future.setInterfaceCode(ConnectorInterface.DISCOVERY);
        future.setVersion("v3");
        connectorInterfaceRepository.saveAndFlush(future);
        // Picking one silently would decide how the run is driven for its whole life, on no input from the caller.
        DiscoveryDto request = v2Request(List.of(Resource.CERTIFICATE));

        // when
        ThrowingCallable create = () -> discoveryService.createDiscovery(request, true, false);

        // then
        assertThatThrownBy(create)
                .as("the refusal says how to resolve it")
                .isInstanceOf(ValidationException.class)
                .hasMessageContaining("interfaceUuid");
    }

    @Test
    void rejectsWindow_whenInterfaceLacksIncrementalFlag() {
        // given
        giveConnectorAV2DiscoveryInterface();
        stubSupportedResources("""
                [{"resource":"certificates"}]""");
        DiscoveryDto request = v2Request(List.of(Resource.CERTIFICATE));
        request.setWindow(createWindow(DiscoveryWindowMode.LOOKBACK, Duration.ofDays(1)));

        // when
        ThrowingCallable create = () -> discoveryService.createDiscovery(request, true, false);

        // then
        assertThatThrownBy(create)
                .isInstanceOf(ValidationException.class)
                .hasMessageContaining("advertises discoveryIncremental");
        mockServer.verify(0, WireMock.anyRequestedFor(WireMock.urlPathMatching("/v2/discoveryProvider/.*")));
    }

    @Test
    void rejectsWindow_whenDiscoveryIsV1() {
        // given — the connector of this test declares no discovery interface, so the run is a v1 run
        DiscoveryDto request = new DiscoveryDto();
        request.setName("created-" + UUID.randomUUID());
        request.setConnectorUuid(connector.getUuid().toString());
        request.setKind("IpAndPort");
        request.setAttributes(List.of());
        request.setWindow(createWindow(DiscoveryWindowMode.LOOKBACK, Duration.ofDays(1)));

        // when
        ThrowingCallable create = () -> discoveryService.createDiscovery(request, true, false);

        // then
        assertThatThrownBy(create)
                .isInstanceOf(ValidationException.class)
                .hasMessageContaining("advertises discoveryIncremental");
    }

    @Test
    void rejectsSinceLastSuccessfulRun_whenNotScheduled() {
        // given
        giveConnectorAnIncrementalV2DiscoveryInterface();
        stubSupportedResources("""
                [{"resource":"certificates"}]""");
        DiscoveryDto request = v2Request(List.of(Resource.CERTIFICATE));
        request.setWindow(createWindow(DiscoveryWindowMode.SINCE_LAST_SUCCESSFUL_RUN, null));

        // when
        ThrowingCallable create = () -> discoveryService.createDiscovery(request, true, false);

        // then
        assertThatThrownBy(create)
                .isInstanceOf(ValidationException.class)
                .hasMessageContaining("sinceLastSuccessfulRun is available only for a scheduled discovery");
    }

    @Test
    void acceptsSinceLastSuccessfulRun_whenScheduled() throws Exception {
        // given
        giveConnectorAnIncrementalV2DiscoveryInterface();
        stubSupportedResources("""
                [{"resource":"certificates"}]""");
        DiscoveryDto request = v2Request(List.of(Resource.CERTIFICATE));
        request.setWindow(createWindow(DiscoveryWindowMode.SINCE_LAST_SUCCESSFUL_RUN, null));

        // when
        DiscoveryDetailDto created = discoveryService.createDiscovery(request, true, true);

        // then
        Discovery stored = discoveryRepository.findByUuid(UUID.fromString(created.getUuid())).orElseThrow();
        assertThat(stored.getWindowMode()).isEqualTo(DiscoveryWindowMode.SINCE_LAST_SUCCESSFUL_RUN);
        assertThat(stored.getWindowLookback()).isNull();
    }

    @Test
    void storesLookbackWindow_whenInterfaceAdvertisesIncrementalFlag() throws Exception {
        // given
        giveConnectorAnIncrementalV2DiscoveryInterface();
        stubSupportedResources("""
                [{"resource":"certificates"}]""");
        DiscoveryDto request = v2Request(List.of(Resource.CERTIFICATE));
        request.setWindow(createWindow(DiscoveryWindowMode.LOOKBACK, Duration.ofHours(6)));

        // when
        DiscoveryDetailDto created = discoveryService.createDiscovery(request, true, false);

        // then
        Discovery stored = discoveryRepository.findByUuid(UUID.fromString(created.getUuid())).orElseThrow();
        assertThat(stored.getWindowMode()).isEqualTo(DiscoveryWindowMode.LOOKBACK);
        assertThat(stored.getWindowLookback()).isEqualTo(Duration.ofHours(6));
    }

    @Test
    void acceptsFullWindow_whenInterfaceLacksIncrementalFlag() throws Exception {
        // given
        giveConnectorAV2DiscoveryInterface();
        stubSupportedResources("""
                [{"resource":"certificates"}]""");
        DiscoveryDto request = v2Request(List.of(Resource.CERTIFICATE));
        request.setWindow(createWindow(DiscoveryWindowMode.FULL, null));

        // when
        DiscoveryDetailDto created = discoveryService.createDiscovery(request, true, false);

        // then
        assertThat(created.getUuid()).isNotNull();
    }

    private DiscoveryDto v2Request(List<Resource> resources) {
        DiscoveryDto request = new DiscoveryDto();
        request.setName("created-" + UUID.randomUUID());
        request.setConnectorUuid(connector.getUuid().toString());
        request.setKind("IpAndPort");
        request.setAttributes(List.of());
        request.setResources(resources);
        return request;
    }

    @Test
    void aLiveV2RunCannotBeDeletedOutFromUnderItsAgenda() {
        givenV2Run(List.of(Resource.CERTIFICATE));

        // Deleting it would cascade away the agenda rows that drive it, so nothing would ever end the run.
        SecuredUUID liveRun = discovery.getSecuredUuid();
        ValidationException refused = Assertions
                .assertThrows(ValidationException.class, () -> discoveryService.deleteDiscovery(liveRun));
        Assertions.assertTrue(refused.getMessage().contains("cancel"), refused.getMessage());
    }

    @Test
    void aProcessingV2RunIsRefusedDeletionWithoutBeingSentToCancel() {
        givenV2Run(List.of(Resource.CERTIFICATE));
        Discovery run = discoveryRepository.findByUuid(discovery.getUuid()).orElseThrow();
        run.setStatus(DiscoveryStatus.PROCESSING);
        discoveryRepository.saveAndFlush(run);

        SecuredUUID processing = discovery.getSecuredUuid();
        ValidationException refused = Assertions
                .assertThrows(ValidationException.class, () -> discoveryService.deleteDiscovery(processing));
        Assertions
                .assertFalse(refused.getMessage().contains("cancel"),
                        "cancel is refused for a processing run, so the refusal must not send the caller there: "
                                + refused.getMessage());
        Assertions
                .assertTrue(refused.getMessage().contains("wait"),
                        "the only way out of processing is waiting, which the refusal must say: "
                                + refused.getMessage());
    }

    @Test
    void aLiveV2RunInABulkDeleteDoesNotStopTheRestBeingDeleted() throws Exception {
        givenV2Run(List.of(Resource.CERTIFICATE));
        Discovery live = discoveryRepository.findByUuid(discovery.getUuid()).orElseThrow();
        Discovery finished = new Discovery();
        finished.setName("already-finished");
        finished.setStatus(DiscoveryStatus.COMPLETED);
        finished.setConnectorStatus(DiscoveryStatus.COMPLETED);
        finished.setConnectorInterface(live.getConnectorInterface());
        discoveryRepository.saveAndFlush(finished);

        discoveryService
                .bulkRemoveDiscovery(
                        List.of(SecuredUUID.fromUUID(live.getUuid()), SecuredUUID.fromUUID(finished.getUuid())));

        Assertions
                .assertTrue(discoveryRepository.findByUuid(finished.getUuid()).isEmpty(),
                        "a run that refuses deletion must not keep the rest of the batch alive");
        Assertions
                .assertTrue(discoveryRepository.findByUuid(live.getUuid()).isPresent(),
                        "the live run itself is still refused");
    }

    @Test
    void aTerminatedV2RunDeletesNormally() throws Exception {
        givenV2Run(List.of(Resource.CERTIFICATE));
        Discovery run = discoveryRepository.findByUuid(discovery.getUuid()).orElseThrow();
        run.setStatus(DiscoveryStatus.COMPLETED);
        discoveryRepository.saveAndFlush(run);

        discoveryService.deleteDiscovery(discovery.getSecuredUuid());

        Assertions.assertTrue(discoveryRepository.findByUuid(discovery.getUuid()).isEmpty());
    }

    @Test
    void readsRunAttributesFromTheV2Schema_whenCreatingAV2Run() throws Exception {
        // given
        giveConnectorAV2DiscoveryInterface();
        stubSupportedResources("""
                [{"resource":"certificates"}]""");

        // when
        discoveryService.createDiscovery(v2Request(List.of(Resource.CERTIFICATE)), true, false);

        // then
        // The v1 kind-scoped endpoint is what mergeAndValidateAttributes reads, and a v2-only connector does not
        // implement it; the run-level schema comes from the v2 relay instead.
        WireMock.verify(1, WireMock.getRequestedFor(WireMock.urlPathEqualTo("/v2/discoveryProvider/attributes")));
        WireMock
                .verify(0,
                        WireMock.getRequestedFor(WireMock.urlPathMatching("/v1/discoveryProvider/[^/]+/attributes")));
    }

    @Test
    void throwsValidation_whenRequestOmitsARequiredResourceAttribute() {
        // given
        giveConnectorAV2DiscoveryInterface();
        stubSupportedResources("""
                [{"resource":"certificates"}]""");
        WireMock
                .stubFor(WireMock
                        .get(WireMock.urlPathEqualTo("/v2/discoveryProvider/certificates/attributes"))
                        .willReturn(WireMock.okJson("""
                                [{"uuid":"7f7f0000-0000-4000-8000-000000000009","name":"scanDepth",
                                  "type":"data","version":3,"contentType":"integer",
                                  "properties":{"label":"Scan depth","required":true}}]""")));
        DiscoveryDto request = v2Request(List.of(Resource.CERTIFICATE));

        // when
        ThrowingCallable create = () -> discoveryService.createDiscovery(request, true, false);

        // then
        assertThatThrownBy(create)
                .as("a run targeting a resource whose schema requires an attribute must not be created without it")
                .isInstanceOf(ValidationException.class);
        assertThat(discoveryRepository.findByName(request.getName()))
                .as("the refusal happens before anything is written")
                .isEmpty();
    }

    @Test
    void aLifecycleOperationOnAnUnknownRunIsNotFound() {
        SecuredUUID missing = SecuredUUID.fromUUID(UUID.randomUUID());
        Assertions.assertThrows(NotFoundException.class, () -> discoveryService.cancelDiscovery(missing));
    }

    @Test
    void cancellingAV2RunEndsItAndTellsTheConnector() throws Exception {
        givenV2Run(List.of(Resource.CERTIFICATE));
        WireMock
                .stubFor(WireMock
                        .post(WireMock.urlPathEqualTo("/v2/discoveryProvider/discoveries/cancel"))
                        .willReturn(WireMock.aResponse().withStatus(204)));

        discoveryService.cancelDiscovery(discovery.getSecuredUuid());

        Discovery persisted = discoveryRepository.findByUuid(discovery.getUuid()).orElseThrow();
        Assertions.assertEquals(DiscoveryStatus.CANCELLED, persisted.getStatus());
        WireMock
                .verify(1,
                        WireMock.postRequestedFor(WireMock.urlPathEqualTo("/v2/discoveryProvider/discoveries/cancel")));
        Assertions
                .assertEquals(List.of(DiscoveryMessageSeverity.INFO),
                        messageRepository
                                .findByDiscoveryUuidOrderByIdAsc(discovery.getUuid())
                                .stream()
                                .map(DiscoveryMessage::getSeverity)
                                .toList(),
                        "a cancel the user asked for is the run doing what it was told, not an error");
    }

    private void giveInterfaceStopResumeFlag() {
        ConnectorInterfaceEntity iface = connectorInterfaceRepository
                .findById(discoveryRepository.findByUuid(discovery.getUuid()).orElseThrow().getConnectorInterfaceUuid())
                .orElseThrow();
        iface.setFeatures(List.of(FeatureFlag.DISCOVERY_STOP_RESUME));
        connectorInterfaceRepository.saveAndFlush(iface);
    }

    private DiscoveryStatus reloadStatus() {
        return discoveryRepository.findByUuid(discovery.getUuid()).orElseThrow().getStatus();
    }

    private boolean hasWork(DiscoveryWorkType workType) {
        return workRepository
                .findAll()
                .stream()
                .anyMatch(
                        work -> work.getDiscoveryUuid().equals(discovery.getUuid()) && work.getWorkType() == workType);
    }

    /** A lifecycle call the connector answers cleanly, with no run handle to replay. */
    private void stubLifecycle(String path) {
        WireMock
                .stubFor(WireMock
                        .post(WireMock.urlPathEqualTo(path))
                        .willReturn(WireMock
                                .aResponse()
                                .withStatus(200)
                                .withHeader("Content-Type", "application/json")
                                .withBody("{}")));
    }

    private void stubOversizedHandle(String path) {
        WireMock
                .stubFor(WireMock
                        .post(WireMock.urlPathEqualTo(path))
                        .willReturn(WireMock
                                .aResponse()
                                .withStatus(200)
                                .withHeader("Content-Type", "application/json")
                                .withBody("""
                                        {"checkpoint":[{"uuid":"7f7f0000-0000-4000-8000-00000000000a",
                                                  "name":"connectorRunId","type":"meta","version":3,
                                                  "contentType":"string",
                                                  "content":[{"contentType":"string","data":"%s"}]}]}"""
                                        .formatted("x".repeat(70_000)))));
    }

    private void stubResumeStatus(int status) {
        WireMock
                .stubFor(WireMock
                        .post(WireMock.urlPathEqualTo("/v2/discoveryProvider/discoveries/resume"))
                        .willReturn(WireMock
                                .aResponse()
                                .withStatus(status)
                                .withHeader("Content-Type", "application/problem+json")
                                .withBody("""
                                        {"status":%d,"errorCode":"CHECKPOINT_LOST","detail":"gone"}"""
                                        .formatted(status))));
    }

    private void givenV2Run(List<Resource> resources) {
        ConnectorInterfaceEntity iface = new ConnectorInterfaceEntity();
        iface.setConnectorUuid(connector.getUuid());
        iface.setInterfaceCode(ConnectorInterface.DISCOVERY);
        iface.setVersion("v2");
        iface = connectorInterfaceRepository.save(iface);
        discovery.setConnectorInterfaceUuid(iface.getUuid());
        discovery.setResources(resources);
        discoveryRepository.save(discovery);
    }

    private void stubInitiate(String json) {
        WireMock
                .stubFor(WireMock
                        .post(WireMock.urlPathEqualTo("/v2/discoveryProvider/discoveries/initiate"))
                        .willReturn(WireMock.okJson(json)));
    }

    @Test
    void runDiscoveryFailsWhenProviderReportsFailureWithoutCertificates()
            throws AlreadyExistException, ConnectorException, AttributeException, NotFoundException {
        UUID discoveryUuid = createRunnableDiscovery();
        stubDiscoveryStart("""
                {"uuid": "%s", "name": "integration-provider", "status": "failed",
                 "totalCertificatesDiscovered": 0, "certificateData": [], "meta": [%s]}
                """.formatted(PROVIDER_DISCOVERY_UUID, RUN_META_JSON));

        discoveryInternalService.runDiscovery(discoveryUuid, null);

        Discovery persisted = discoveryRepository.findByUuid(discoveryUuid).orElseThrow();
        Assertions.assertEquals(DiscoveryStatus.FAILED, persisted.getStatus());
        Assertions
                .assertTrue(persisted.getMessage().contains("failed on connector side without any certificates found"),
                        persisted.getMessage());
    }

    @Test
    void runDiscoveryFailsWhenProviderResponseLacksItsReference()
            throws AlreadyExistException, ConnectorException, AttributeException, NotFoundException {
        UUID discoveryUuid = createRunnableDiscovery();
        stubDiscoveryStart("""
                {"uuid": null, "name": "integration-provider", "status": "completed",
                 "totalCertificatesDiscovered": 1, "certificateData": [], "meta": []}
                """);

        discoveryInternalService.runDiscovery(discoveryUuid, null);

        Discovery persisted = discoveryRepository.findByUuid(discoveryUuid).orElseThrow();
        Assertions.assertEquals(DiscoveryStatus.FAILED, persisted.getStatus());
        Assertions
                .assertTrue(persisted.getMessage().contains("does not have associated discovery object at provider"),
                        persisted.getMessage());
    }

    @Test
    void runDiscoveryTreatsARepeatedCertificateAsDuplicate()
            throws AlreadyExistException, ConnectorException, AttributeException, NotFoundException {
        UUID discoveryUuid = createRunnableDiscovery();
        // Two certificates promised, every page serves the same one: page 2 repeats page 1's content.
        stubDiscoveryStart(startResponse(2));
        stubDiscoveryData(dataResponse(2));

        discoveryInternalService.runDiscovery(discoveryUuid, null);

        Discovery persisted = discoveryRepository.findByUuid(discoveryUuid).orElseThrow();
        Assertions.assertEquals(DiscoveryStatus.PROCESSING, persisted.getStatus());
        Assertions.assertEquals(1, discoveryCertificateRepository.countByDiscovery(persisted));
    }

    @Test
    void runDiscoveryWarnsWhenAPageComesBackEmpty()
            throws AlreadyExistException, ConnectorException, AttributeException, NotFoundException {
        UUID discoveryUuid = createRunnableDiscovery();
        stubDiscoveryStart(startResponse(2));
        stubDiscoveryData(dataResponse(2));
        WireMock
                .stubFor(WireMock
                        .post(WireMock.urlPathMatching("/v1/discoveryProvider/discover/" + PROVIDER_DISCOVERY_UUID))
                        .withRequestBody(WireMock.matchingJsonPath("$.pageNumber", WireMock.equalTo("2")))
                        .willReturn(WireMock.okJson("""
                                {"uuid": "%s", "name": "integration-provider", "status": "completed",
                                 "totalCertificatesDiscovered": 2, "certificateData": [], "meta": []}
                                """.formatted(PROVIDER_DISCOVERY_UUID))));

        discoveryInternalService.runDiscovery(discoveryUuid, null);

        Discovery persisted = discoveryRepository.findByUuid(discoveryUuid).orElseThrow();
        Assertions.assertEquals(DiscoveryStatus.PROCESSING, persisted.getStatus());
        Assertions.assertTrue(persisted.getMessage().contains("Retrieved only"), persisted.getMessage());
        Assertions.assertEquals(1, discoveryCertificateRepository.countByDiscovery(persisted));
    }

    @Test
    void countsCertificatesAsItems_whenV1RunTargetsThem() throws Exception {
        // given
        UUID discoveryUuid = createRunnableDiscovery();

        // when
        discoveryInternalService.runDiscovery(discoveryUuid, null);

        // then
        Discovery persisted = discoveryRepository.findByUuid(discoveryUuid).orElseThrow();
        assertThat(persisted.getResources()).containsExactly(Resource.CERTIFICATE);
        assertThat(persisted.getTotalCertificatesDiscovered()).isEqualTo(1);
        assertThat(persisted.getTotalItemsDiscovered()).isEqualTo(1);
    }

    @Test
    void completesDuplicateRunWithoutNewCertificates_whenEarlierRunDiscoveredTheSameCertificate() throws Exception {
        // given
        UUID originalUuid = createRunnableDiscovery();
        discoveryInternalService.runDiscovery(originalUuid, null);
        Discovery original = discoveryRepository.findByUuid(originalUuid).orElseThrow();
        assertThat(original.getStatus()).isEqualTo(DiscoveryStatus.PROCESSING);
        assertThat(discoveryCertificateRepository.countByDiscovery(original)).isEqualTo(1);
        EventMessage eventMessage = CertificateDiscoveredEventHandler
                .constructEventMessage(original.getUuid(), null, null);
        eventListener.processMessage(eventMessage);
        eventMessage = DiscoveryFinishedEventHandler
                .constructEventMessage(original.getUuid(), null, eventMessage.getScheduledJobInfo(),
                        new DiscoveryResult(DiscoveryStatus.PROCESSING, null));
        eventListener.processMessage(eventMessage);
        DiscoveryCertificateResponseDto originalCertificates = discoveryService
                .getDiscoveryCertificates(SecuredUUID.fromUUID(originalUuid), null, 10, 1);
        assertThat(originalCertificates.getCertificates()).hasSize(1);
        assertThat(discoveryCertificateRepository.countByDiscoveryAndNewlyDiscovered(original, true)).isEqualTo(1);
        original = discoveryRepository.findByUuid(originalUuid).orElseThrow();
        assertThat(original.getStatus()).isEqualTo(DiscoveryStatus.COMPLETED);
        UUID duplicateUuid = createRunnableDiscovery();

        // when
        discoveryInternalService.runDiscovery(duplicateUuid, null);

        // then
        Discovery duplicate = discoveryRepository.findByUuid(duplicateUuid).orElseThrow();
        assertThat(duplicate.getStatus()).isEqualTo(DiscoveryStatus.COMPLETED);
        assertThat(discoveryCertificateRepository.countByDiscovery(duplicate)).isEqualTo(1);
        DiscoveryCertificateResponseDto duplicateCertificates = discoveryService
                .getDiscoveryCertificates(SecuredUUID.fromUUID(duplicateUuid), null, 10, 1);
        assertThat(duplicateCertificates.getCertificates()).hasSize(1);
        assertThat(discoveryCertificateRepository.countByDiscoveryAndNewlyDiscovered(duplicate, true)).isZero();
    }

    @Test
    void completesRunWithoutCertificates_whenProviderReportsCompletedWithNone() throws Exception {
        // given
        stubDiscoveryStart(emptyProviderResponse("completed"));
        stubDiscoveryData(emptyProviderResponse("inProgress"));
        UUID discoveryUuid = createRunnableDiscovery();

        // when
        discoveryInternalService.runDiscovery(discoveryUuid, null);

        // then
        Discovery persisted = discoveryRepository.findByUuid(discoveryUuid).orElseThrow();
        assertThat(persisted.getStatus()).isEqualTo(DiscoveryStatus.COMPLETED);
        assertThat(discoveryCertificateRepository.countByDiscovery(persisted)).isZero();
    }

    @Test
    void failsRun_whenProviderStaysInProgressPastTheTimeLimit() throws Exception {
        // given
        stubDiscoveryStart(emptyProviderResponse("inProgress"));
        stubDiscoveryData(emptyProviderResponse("inProgress"));
        UUID discoveryUuid = createRunnableDiscovery();
        Discovery stale = discoveryRepository.findByUuid(discoveryUuid).orElseThrow();
        stale.setStartTime(OffsetDateTime.now().minusDays(7));
        discoveryRepository.save(stale);

        // when
        discoveryInternalService.runDiscovery(discoveryUuid, null);

        // then
        Discovery persisted = discoveryRepository.findByUuid(discoveryUuid).orElseThrow();
        assertThat(persisted.getStatus()).isEqualTo(DiscoveryStatus.FAILED);
        assertThat(discoveryCertificateRepository.countByDiscovery(persisted)).isZero();
    }

    @Test
    void testGetResourceObject() throws NotFoundException {
        NameAndUuidDto nameAndUuidDto = discoveryInternalService.getResourceObjectInternal(discovery.getUuid());
        Assertions.assertEquals(discovery.getUuid().toString(), nameAndUuidDto.getUuid());
        Assertions.assertEquals(discovery.getName(), nameAndUuidDto.getName());

        nameAndUuidDto = discoveryInternalService.getResourceObjectExternal(discovery.getSecuredUuid());
        Assertions.assertEquals(discovery.getUuid().toString(), nameAndUuidDto.getUuid());
        Assertions.assertEquals(discovery.getName(), nameAndUuidDto.getName());
    }

    private static final String RUN_META_JSON = """
            {
                "version": 2,
                "uuid": "872ca286-601f-11ed-9b6a-0242ac120002",
                "name": "totalUrls",
                "description": "Total number of URLs for the discovery",
                "content": [{"reference": "5", "data": 5}],
                "type": "meta",
                "contentType": "integer",
                "properties": {"label": "Total URLs", "visible": true, "group": null, "global": false, "overwrite": false}
            }
            """;

    private UUID createRunnableDiscovery()
            throws AlreadyExistException, ConnectorException, AttributeException, NotFoundException {
        DiscoveryDto dto = new DiscoveryDto();
        dto.setName("RunDiscoveryIT-" + UUID.randomUUID());
        dto.setKind("IpAndPort");
        dto.setConnectorUuid(connector.getUuid().toString());
        dto.setAttributes(List.of());
        return UUID.fromString(discoveryService.createDiscovery(dto, true, false).getUuid());
    }

    /** Registered after {@code setUp}'s defaults, so it wins for the start endpoint. */
    private void stubDiscoveryStart(String responseJson) {
        WireMock
                .stubFor(WireMock
                        .post(WireMock.urlPathMatching("/v1/discoveryProvider/discover"))
                        .willReturn(WireMock.okJson(responseJson)));
    }

    /** Registered after {@code setUp}'s defaults, so it wins for the data endpoint. */
    private void stubDiscoveryData(String responseJson) {
        WireMock
                .stubFor(WireMock
                        .post(WireMock.urlPathMatching("/v1/discoveryProvider/discover/" + PROVIDER_DISCOVERY_UUID))
                        .willReturn(WireMock.okJson(responseJson)));
    }

    private String startResponse(int totalCertificates) {
        return """
                {"uuid": "%s", "name": "integration-provider", "status": "completed",
                 "totalCertificatesDiscovered": %d, "certificateData": [], "meta": []}
                """.formatted(PROVIDER_DISCOVERY_UUID, totalCertificates);
    }

    /** A single-certificate page reporting {@code totalCertificates} in total, page-number agnostic. */
    private String dataResponse(int totalCertificates) {
        return """
                {"uuid": "%s", "name": "integration-provider", "status": "completed",
                 "totalCertificatesDiscovered": %d,
                 "certificateData": [{
                     "uuid": "0279d416-02ed-4415-a8cd-85af3f083222",
                     "base64Content": "%s",
                     "meta": []
                 }],
                 "meta": []}
                """.formatted(PROVIDER_DISCOVERY_UUID, totalCertificates, CERTIFICATE_BASE64);
    }

    private void stubConnectorEndpoints() {
        // A v2 connector publishes its run-level schema here, not on the v1 kind-scoped endpoints; create reads it
        // to validate what the caller submitted.
        WireMock
                .stubFor(WireMock
                        .get(WireMock.urlPathEqualTo("/v2/discoveryProvider/attributes"))
                        .willReturn(WireMock.okJson("[]")));
        WireMock
                .stubFor(WireMock
                        .get(WireMock.urlPathMatching("/v1/discoveryProvider/[^/]+/attributes"))
                        .willReturn(WireMock.okJson("[]")));
        // Create reads a per-resource schema for every resource a run targets, so every v2 create reaches this.
        WireMock
                .stubFor(WireMock
                        .get(WireMock.urlPathMatching("/v2/discoveryProvider/[^/]+/attributes"))
                        .willReturn(WireMock.okJson("[]")));
        WireMock
                .stubFor(WireMock
                        .post(WireMock.urlPathMatching("/v1/discoveryProvider/[^/]+/attributes/validate"))
                        .willReturn(WireMock.okJson("true")));

        String discoveryStartResponse = """
                {
                    "uuid": "%s",
                    "name": "integration-provider",
                    "status": "completed",
                    "totalCertificatesDiscovered": 1,
                    "certificateData": [],
                    "meta": []
                }
                """.formatted(PROVIDER_DISCOVERY_UUID);

        String discoveryDataResponse = """
                {
                     "uuid": "%s",
                     "name": "integration-provider",
                     "status": "completed",
                     "totalCertificatesDiscovered": 1,
                     "certificateData": [
                         {
                             "uuid": "0279d416-02ed-4415-a8cd-85af3f083222",
                             "base64Content": "%s",
                             "meta": [
                                 {
                                     "version": 2,
                                     "uuid": "000043aa-6022-11ed-9b6a-0242ac120002",
                                     "name": "discoverySource",
                                     "description": "Source from where the certificate is discovered",
                                     "content": [
                                         {
                                             "reference": "https://cnb.cz:443",
                                             "data": "https://cnb.cz:443"
                                         }
                                     ],
                                     "type": "meta",
                                     "contentType": "string",
                                     "properties": {
                                         "label": "Discovery Source",
                                         "visible": true,
                                         "group": null,
                                         "global": true,
                                         "overwrite": false
                                     }
                                 }
                             ]
                         }
                     ],
                     "meta": [
                         {
                             "version": 2,
                             "uuid": "872ca286-601f-11ed-9b6a-0242ac120002",
                             "name": "totalUrls",
                             "description": "Total number of URLs for the discovery",
                             "content": [
                                 {
                                     "reference": "5",
                                     "data": 5
                                 }
                             ],
                             "type": "meta",
                             "contentType": "integer",
                             "properties": {
                                 "label": "Total URLs",
                                 "visible": true,
                                 "group": null,
                                 "global": false,
                                 "overwrite": false
                             }
                         }
                     ]
                }
                """.formatted(PROVIDER_DISCOVERY_UUID, CERTIFICATE_BASE64);

        WireMock
                .stubFor(WireMock
                        .post(WireMock.urlPathMatching("/v1/discoveryProvider/discover"))
                        .willReturn(WireMock.okJson(discoveryStartResponse)));
        WireMock
                .stubFor(WireMock
                        .post(WireMock.urlPathMatching("/v1/discoveryProvider/discover/" + PROVIDER_DISCOVERY_UUID))
                        .willReturn(WireMock.okJson(discoveryDataResponse)));
    }

    private static final String REFUSED_META_JSON = """
            {"version": 2, "uuid": "00000000-0000-0000-0000-0000000000f1", "name": "%s",
             "content": [{"reference": "1", "data": 1}], "type": "meta", "contentType": "integer",
             "properties": {"label": "Refused", "visible": true, "group": null, "global": false, "overwrite": false}}
            """.formatted(RefusedDefinitionInserts.REFUSED_NAME);

    @Test
    void aRunWhoseMetadataCannotBeStoredCompletesWithAWarning() throws Exception {
        RefusedDefinitionInserts.install(jdbcTemplate);
        UUID discoveryUuid = createRunnableDiscovery();
        stubDiscoveryStart(startResponseWithMeta(0, REFUSED_META_JSON));

        discoveryInternalService.runDiscovery(discoveryUuid, null);

        Discovery persisted = discoveryRepository.findByUuid(discoveryUuid).orElseThrow();
        Assertions.assertEquals(DiscoveryStatus.COMPLETED, persisted.getStatus());
        Assertions
                .assertEquals("Discovery completed. No certificates discovered at provider."
                        + " Discovery metadata could not be stored.", persisted.getMessage());
        Assertions
                .assertEquals(List.of(DiscoveryMessageCode.RUN_METADATA_NOT_RECORDED.code()),
                        runMessageCodes(discoveryUuid));
    }

    @Test
    void aRunThatFindsOnlyKnownCertificatesCompletesWithTheMetadataWarning() throws Exception {
        RefusedDefinitionInserts.install(jdbcTemplate);
        knownCertificate();
        UUID discoveryUuid = createRunnableDiscovery();
        stubDiscoveryStart(startResponseWithMeta(1, REFUSED_META_JSON));
        stubDiscoveryData(dataResponse(1));

        discoveryInternalService.runDiscovery(discoveryUuid, null);

        Discovery persisted = discoveryRepository.findByUuid(discoveryUuid).orElseThrow();
        Assertions.assertEquals(DiscoveryStatus.COMPLETED, persisted.getStatus());
        Assertions
                .assertEquals("Discovery completed successfully. Discovery metadata could not be stored.",
                        persisted.getMessage());
        Assertions
                .assertEquals(List.of(DiscoveryMessageCode.RUN_METADATA_NOT_RECORDED.code()),
                        runMessageCodes(discoveryUuid));
    }

    @Test
    void aRunWithNewCertificatesCarriesTheMetadataWarningIntoProcessing() throws Exception {
        RefusedDefinitionInserts.install(jdbcTemplate);
        UUID discoveryUuid = createRunnableDiscovery();
        stubDiscoveryStart(startResponseWithMeta(1, REFUSED_META_JSON));
        stubDiscoveryData(dataResponse(1));

        discoveryInternalService.runDiscovery(discoveryUuid, null);

        Discovery persisted = discoveryRepository.findByUuid(discoveryUuid).orElseThrow();
        Assertions.assertEquals(DiscoveryStatus.PROCESSING, persisted.getStatus());
        // Processing keeps this message on a clean run: the final one appends it after "Discovery completed
        // successfully."
        Assertions
                .assertEquals(
                        "Discovered certificates downloaded from provider. Discovery metadata could not be stored.",
                        persisted.getMessage());
        Assertions
                .assertEquals(List.of(DiscoveryMessageCode.RUN_METADATA_NOT_RECORDED.code()),
                        runMessageCodes(discoveryUuid));
    }

    @Test
    void aRunWhoseMetadataIsStoredCompletesWithoutAWarning() throws Exception {
        UUID discoveryUuid = createRunnableDiscovery();
        stubDiscoveryStart(startResponseWithMeta(0, RUN_META_JSON));

        discoveryInternalService.runDiscovery(discoveryUuid, null);

        Discovery persisted = discoveryRepository.findByUuid(discoveryUuid).orElseThrow();
        Assertions.assertEquals(DiscoveryStatus.COMPLETED, persisted.getStatus());
        Assertions.assertEquals("Discovery completed. No certificates discovered at provider", persisted.getMessage());
        Assertions.assertEquals(List.of(), runMessageCodes(discoveryUuid));
        Assertions.assertEquals(List.of("totalUrls"), storedRunMetadataNames(discoveryUuid));
    }

    @Test
    void metadataTheEngineRefusesPartWayStoresNoneOfTheRunsMetadata() throws Exception {
        // Registered as a string; the run below reports it as an integer, which the engine refuses with a checked
        // exception after it has stored the first statement.
        attributeEngine
                .updateMetadataAttributeDefinition(
                        stringMetadata("ffffffff-ffff-ffff-ffff-fffffffffff1", "laterRefused"), connector.getUuid());
        UUID discoveryUuid = createRunnableDiscovery();
        stubDiscoveryStart(
                startResponseWithMeta(0, integerRunMeta("00000000-0000-0000-0000-0000000000a1", "aStoredFirst") + ", "
                        + integerRunMeta("ffffffff-ffff-ffff-ffff-fffffffffff1", "laterRefused")));

        discoveryInternalService.runDiscovery(discoveryUuid, null);

        Discovery persisted = discoveryRepository.findByUuid(discoveryUuid).orElseThrow();
        Assertions.assertEquals(DiscoveryStatus.COMPLETED, persisted.getStatus());
        Assertions
                .assertTrue(persisted.getMessage().endsWith("Discovery metadata could not be stored."),
                        persisted.getMessage());
        Assertions.assertEquals(List.of(), storedRunMetadataNames(discoveryUuid));
        Assertions
                .assertEquals(List.of(DiscoveryMessageCode.RUN_METADATA_NOT_RECORDED.code()),
                        runMessageCodes(discoveryUuid));
    }

    @Test
    void aRunCoreCannotFinishEndsFailedRatherThanInProgress() throws Exception {
        RefusedDefinitionInserts.install(jdbcTemplate);
        UUID discoveryUuid = createRunnableDiscovery();
        stubDiscoveryStart(startResponse(1));
        stubDiscoveryData(dataResponseWithCertificateMeta(1, REFUSED_META_JSON));

        Assertions.assertDoesNotThrow(() -> discoveryInternalService.runDiscovery(discoveryUuid, null));

        Discovery persisted = discoveryRepository.findByUuid(discoveryUuid).orElseThrow();
        Assertions.assertEquals(DiscoveryStatus.FAILED, persisted.getStatus());
        Assertions.assertEquals("Discovery failed in Core.", persisted.getMessage());
        Assertions.assertNotNull(persisted.getEndTime());
        // Every boundary rolled back on the way out: nothing is left bound to the thread.
        Assertions.assertFalse(TransactionSynchronizationManager.isActualTransactionActive());
        Assertions.assertTrue(TransactionSynchronizationManager.getResourceMap().isEmpty());
    }

    /**
     * A runtime failure that crosses a transactional service marks the load rollback-only; the run must still end
     * FAILED with Core's fixed text, not the commit's {@code UnexpectedRollbackException}. A validation failure gets
     * the fixed text too, since a connector can raise one.
     */
    @Test
    void failsRunWithFixedText_whenLoadingTheContextThrowsARuntimeException() throws Exception {
        // given
        WireMock
                .stubFor(WireMock
                        .get(WireMock.urlPathMatching("/v1/discoveryProvider/[^/]+/attributes"))
                        .willReturn(WireMock.okJson(CREDENTIAL_DEFINITION)));
        CredentialAttributeContentData identity = new CredentialAttributeContentData();
        identity.setUuid("not-a-uuid");
        identity.setName("broken-reference");
        DiscoveryDto dto = new DiscoveryDto();
        dto.setName("RunDiscoveryIT-" + UUID.randomUUID());
        dto.setKind("IpAndPort");
        dto.setConnectorUuid(connector.getUuid().toString());
        dto
                .setAttributes(List
                        .of(new RequestAttributeV2(UUID.fromString("7f7f0000-0000-4000-8000-000000000002"),
                                "credential", AttributeContentType.CREDENTIAL,
                                List.of(new CredentialAttributeContentV2("broken-reference", identity)))));
        UUID discoveryUuid = UUID.fromString(discoveryService.createDiscovery(dto, true, false).getUuid());

        // when
        discoveryInternalService.runDiscovery(discoveryUuid, null);

        // then
        Discovery persisted = discoveryRepository.findByUuid(discoveryUuid).orElseThrow();
        assertThat(persisted.getStatus()).isEqualTo(DiscoveryStatus.FAILED);
        assertThat(persisted.getConnectorStatus()).isEqualTo(DiscoveryStatus.FAILED);
        assertThat(persisted.getMessage()).isEqualTo("Discovery could not be prepared in Core.");
        assertThat(persisted.getEndTime()).isNotNull();
    }

    private String dataResponseWithCertificateMeta(int totalCertificates, String metaJson) {
        return """
                {"uuid": "%s", "name": "integration-provider", "status": "completed",
                 "totalCertificatesDiscovered": %d,
                 "certificateData": [{
                     "uuid": "0279d416-02ed-4415-a8cd-85af3f083222",
                     "base64Content": "%s",
                     "meta": [%s]
                 }],
                 "meta": []}
                """.formatted(PROVIDER_DISCOVERY_UUID, totalCertificates, CERTIFICATE_BASE64, metaJson);
    }

    private String startResponseWithMeta(int totalCertificates, String metaJson) {
        return """
                {"uuid": "%s", "name": "integration-provider", "status": "completed",
                 "totalCertificatesDiscovered": %d, "certificateData": [], "meta": [%s]}
                """.formatted(PROVIDER_DISCOVERY_UUID, totalCertificates, metaJson);
    }

    private static String integerRunMeta(String uuid, String name) {
        return """
                {"version": 2, "uuid": "%s", "name": "%s", "content": [{"reference": "1", "data": 1}],
                 "type": "meta", "contentType": "integer",
                 "properties": {"label": "%s", "visible": true, "group": null, "global": false, "overwrite": false}}
                """.formatted(uuid, name, name);
    }

    private static MetadataAttributeV2 stringMetadata(String uuid, String name) {
        MetadataAttributeV2 metadata = new MetadataAttributeV2();
        metadata.setUuid(uuid);
        metadata.setName(name);
        metadata.setType(AttributeType.META);
        metadata.setContentType(AttributeContentType.STRING);
        MetadataAttributeProperties properties = new MetadataAttributeProperties();
        properties.setLabel(name);
        metadata.setProperties(properties);
        return metadata;
    }

    private void knownCertificate() throws Exception {
        X509CertificateEntity known = aCertificate().build();
        known
                .setFingerprint(CertificateUtil
                        .getThumbprint(CertificateUtil.parseCertificate(CERTIFICATE_BASE64).getEncoded()));
        certificateRepository.save(known);
    }

    private List<String> runMessageCodes(UUID discoveryUuid) {
        return discoveryMessageRepository
                .findAll()
                .stream()
                .filter(message -> message.getDiscoveryUuid().equals(discoveryUuid))
                .map(DiscoveryMessage::getCode)
                .toList();
    }

    private List<String> storedRunMetadataNames(UUID discoveryUuid) {
        return attributeEngine
                .getMetadataAttributesDefinitionContent(ObjectAttributeContentInfo
                        .builder(Resource.DISCOVERY, discoveryUuid)
                        .connector(connector.getUuid())
                        .build())
                .stream()
                .map(MetadataAttribute::getName)
                .toList();
    }

    private void giveConnectorAnIncrementalV2DiscoveryInterface() {
        ConnectorInterfaceEntity iface = new ConnectorInterfaceEntity();
        iface.setConnectorUuid(connector.getUuid());
        iface.setInterfaceCode(ConnectorInterface.DISCOVERY);
        iface.setVersion("v2");
        iface.setFeatures(List.of(FeatureFlag.DISCOVERY_INCREMENTAL));
        connectorInterfaceRepository.save(iface);
    }

    private static DiscoveryWindowDto createWindow(DiscoveryWindowMode mode, Duration lookback) {
        DiscoveryWindowDto window = new DiscoveryWindowDto();
        window.setMode(mode);
        window.setLookback(lookback);
        return window;
    }

    private static String emptyProviderResponse(String status) {
        return """
                {"uuid": "%s", "name": "integration-provider", "status": "%s",
                 "totalCertificatesDiscovered": 0, "certificateData": [], "meta": []}
                """.formatted(PROVIDER_DISCOVERY_UUID, status);
    }

    private void givenConnectorCopy() {
        discovery.setStatus(DiscoveryStatus.COMPLETED);
        discovery.setConnectorStatus(DiscoveryStatus.COMPLETED);
        discovery.setDiscoveryConnectorReference(PROVIDER_DISCOVERY_UUID);
        discovery = discoveryRepository.saveAndFlush(discovery);
    }

    private static String connectorCopyPath() {
        return "/v1/discoveryProvider/discover/" + PROVIDER_DISCOVERY_UUID;
    }

    private void stubConnectorCopyDeletion(HttpStatus status) {
        mockServer
                .stubFor(WireMock
                        .delete(WireMock.urlPathEqualTo(connectorCopyPath()))
                        .willReturn(WireMock.status(status.value())));
    }

    /**
     * Restarts the connector with a listener that counts the run's rows from a connection of its own while the
     * connector is deleting its copy, which sees the local delete only once it has committed.
     */
    private CompletableFuture<Integer> countRunRowsWhenTheConnectorDeletesItsCopy() {
        CompletableFuture<Integer> runRows = new CompletableFuture<>();
        UUID runUuid = discovery.getUuid();
        ServeEventListener listener = new ServeEventListener() {
            @Override
            public void beforeResponseSent(ServeEvent serveEvent, Parameters parameters) {
                if (!serveEvent.getRequest().getUrl().equals(connectorCopyPath())) {
                    return;
                }
                try {
                    runRows
                            .complete(jdbcTemplate
                                    .queryForObject("SELECT count(*) FROM discovery WHERE uuid = ?", Integer.class,
                                            runUuid));
                } catch (Exception e) {
                    runRows.completeExceptionally(e);
                }
            }

            @Override
            public String getName() {
                return "count-run-rows-when-the-connector-deletes-its-copy";
            }
        };
        mockServer.stop();
        mockServer = new WireMockServer(LoopbackWireMock.options().extensions(listener));
        mockServer.start();
        WireMock.configureFor(LoopbackWireMock.HOST, mockServer.port());
        connector.setUrl(LoopbackWireMock.url(mockServer));
        connector = connectorRepository.saveAndFlush(connector);
        stubConnectorCopyDeletion(HttpStatus.NO_CONTENT);
        return runRows;
    }

    private Discovery saveEndedV1Run(String name) {
        Discovery run = new Discovery();
        run.setName(name);
        run.setConnectorUuid(connector.getUuid());
        run.setConnectorName(connector.getName());
        run.setStatus(DiscoveryStatus.COMPLETED);
        run.setConnectorStatus(DiscoveryStatus.COMPLETED);
        return discoveryRepository.saveAndFlush(run);
    }

    private CertificateContent saveContent(String fingerprint) {
        CertificateContent content = aCertificateContent()
                .withFingerprint(fingerprint)
                .withContent(CERTIFICATE_BASE64)
                .build();
        return certificateContentRepository.saveAndFlush(content);
    }

    private X509CertificateEntity saveInventoryCertificate() {
        CertificateContent content = saveContent("fp-inventory");
        X509CertificateEntity inventoryCertificate = aCertificate()
                .withFingerprint("fp-inventory")
                .withCertificateContent(content)
                .withCertificateContentId(content.getId())
                .build();
        return certificateRepository.saveAndFlush(inventoryCertificate);
    }

    private DiscoveryCertificate stageResult(Discovery run, Long certificateContentId) {
        DiscoveryCertificate result = new DiscoveryCertificate();
        result.setDiscoveryUuid(run.getUuid());
        result.setCertificateContentId(certificateContentId);
        result.setNewlyDiscovered(true);
        result.setProcessed(true);
        return discoveryCertificateRepository.saveAndFlush(result);
    }
}
