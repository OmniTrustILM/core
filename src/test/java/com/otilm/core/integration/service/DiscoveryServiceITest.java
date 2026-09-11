package com.otilm.core.integration.service;

import com.github.tomakehurst.wiremock.WireMockServer;
import com.github.tomakehurst.wiremock.client.WireMock;
import com.otilm.api.exception.AlreadyExistException;
import com.otilm.api.exception.AttributeException;
import com.otilm.api.exception.ConnectorException;
import com.otilm.api.exception.NotFoundException;
import com.otilm.api.exception.ValidationException;
import com.otilm.api.model.client.certificate.DiscoveryResponseDto;
import com.otilm.api.model.client.certificate.SearchRequestDto;
import com.otilm.api.model.client.connector.v2.ConnectorInterface;
import com.otilm.api.model.client.connector.v2.ConnectorVersion;
import com.otilm.api.model.client.connector.v2.FeatureFlag;
import com.otilm.api.model.client.discovery.DiscoveryCertificateResponseDto;
import com.otilm.api.model.client.discovery.DiscoveryDetailDto;
import com.otilm.api.model.client.discovery.DiscoveryDto;
import com.otilm.api.model.client.discovery.DiscoveryListDto;
import com.otilm.api.model.common.NameAndUuidDto;
import com.otilm.api.model.common.PaginationResponseDto;
import com.otilm.api.model.common.attribute.common.BaseAttribute;
import com.otilm.api.model.connector.discovery.v2.DiscoveryProgressDto;
import com.otilm.api.model.connector.discovery.v2.DiscoverySupportedResourceDto;
import com.otilm.api.model.core.auth.Resource;
import com.otilm.api.model.core.connector.ConnectorStatus;
import com.otilm.api.model.core.connector.FunctionGroupCode;
import com.otilm.api.model.core.discovery.DiscoveryItemDto;
import com.otilm.api.model.core.discovery.DiscoveryMessageDto;
import com.otilm.api.model.core.discovery.DiscoveryMessageSeverity;
import com.otilm.api.model.core.discovery.DiscoveryStatus;
import com.otilm.core.auth.ContextRefreshListener;
import com.otilm.core.dao.entity.CertificateContent;
import com.otilm.core.dao.entity.Connector;
import com.otilm.core.dao.entity.Connector2FunctionGroup;
import com.otilm.core.dao.entity.ConnectorInterfaceEntity;
import com.otilm.core.dao.entity.Discovery;
import com.otilm.core.dao.entity.DiscoveryCertificate;
import com.otilm.core.dao.entity.FunctionGroup;
import com.otilm.core.dao.repository.CertificateContentRepository;
import com.otilm.core.dao.repository.Connector2FunctionGroupRepository;
import com.otilm.core.dao.repository.ConnectorInterfaceRepository;
import com.otilm.core.dao.repository.ConnectorRepository;
import com.otilm.core.dao.repository.DiscoveryCertificateRepository;
import com.otilm.core.dao.repository.DiscoveryRepository;
import com.otilm.core.dao.repository.DiscoveryWorkRepository;
import com.otilm.core.dao.repository.FunctionGroupRepository;
import com.otilm.core.events.data.DiscoveryResult;
import com.otilm.core.events.handlers.CertificateDiscoveredEventHandler;
import com.otilm.core.events.handlers.DiscoveryFinishedEventHandler;
import com.otilm.core.messaging.jms.listeners.EventListener;
import com.otilm.core.messaging.model.EventMessage;
import com.otilm.core.model.discovery.DiscoveryMessageCode;
import com.otilm.core.security.authz.SecuredUUID;
import com.otilm.core.security.authz.SecurityFilter;
import com.otilm.core.service.DiscoveryExternalService;
import com.otilm.core.service.DiscoveryInternalService;
import com.otilm.core.service.handler.discovery.DiscoveryProviderAdapterFactory;
import com.otilm.core.service.handler.discovery.DiscoveryRunTerminator;
import com.otilm.core.service.writer.discovery.DiscoveryMessageWriter;
import com.otilm.core.tasks.ScheduledJobInfo;
import com.otilm.core.util.BaseSpringBootTest;
import com.otilm.core.util.MetaDefinitions;
import java.time.OffsetDateTime;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Disabled;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;

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
    private CertificateContentRepository certificateContentRepository;
    @Autowired
    private ConnectorRepository connectorRepository;
    @Autowired
    private ConnectorInterfaceRepository connectorInterfaceRepository;
    @Autowired
    private FunctionGroupRepository functionGroupRepository;
    @Autowired
    private Connector2FunctionGroupRepository connector2FunctionGroupRepository;

    @Autowired
    private EventListener eventListener;

    @Autowired
    private DiscoveryMessageWriter messageWriter;

    @Autowired
    private DiscoveryProviderAdapterFactory adapterFactory;

    @Autowired
    private ContextRefreshListener contextRefreshListener;

    @Autowired
    private DiscoveryRunTerminator terminator;

    private Discovery discovery;
    private Connector connector;

    private WireMockServer mockServer;

    @BeforeEach
    void setUp() {
        mockServer = new WireMockServer(0);
        mockServer.start();

        WireMock.configureFor("localhost", mockServer.port());
        stubConnectorEndpoints();

        connector = new Connector();
        connector.setName("discoveryProviderConnector");
        connector.setUrl("http://localhost:" + mockServer.port());
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
    void testAddDiscovery() throws ConnectorException, AlreadyExistException, AttributeException, NotFoundException {
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

        DiscoveryDetailDto dto = discoveryService.createDiscovery(request, true);
        Assertions.assertNotNull(dto);
        Assertions.assertEquals(request.getName(), dto.getName());
        Assertions.assertEquals(discovery.getConnectorUuid().toString(), dto.getConnectorUuid());
    }

    @Test
    void testAddDiscovery_notFound() {
        DiscoveryDto request = new DiscoveryDto();
        request.setName("Demo");
        // connector uui not set
        Assertions.assertThrows(ValidationException.class, () -> discoveryService.createDiscovery(request, true));
    }

    @Test
    void testAddDiscovery_alreadyExist() {
        DiscoveryDto request = new DiscoveryDto();
        request.setName(DISCOVERY_NAME); // discovery with same name exist

        Assertions.assertThrows(AlreadyExistException.class, () -> discoveryService.createDiscovery(request, true));
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
    void runDiscoveryWithoutConnector()
            throws AlreadyExistException, ConnectorException, AttributeException, NotFoundException {
        DiscoveryDto dto = new DiscoveryDto();
        dto.setName("RunDiscoveryIT-" + UUID.randomUUID());
        dto.setKind("IpAndPort");
        dto.setConnectorUuid(connector.getUuid().toString());
        dto.setAttributes(List.of());

        UUID discoveryUuid = UUID.fromString(discoveryService.createDiscovery(dto, true).getUuid());

        Discovery persisted = discoveryRepository.findByUuid(discoveryUuid).orElseThrow();
        persisted.setConnectorUuid(UUID.randomUUID());
        discoveryRepository.save(persisted);

        discoveryInternalService.runDiscovery(discoveryUuid, null);
        persisted = discoveryRepository.findByUuid(discoveryUuid).orElseThrow();

        Assertions.assertEquals(DiscoveryStatus.FAILED, persisted.getStatus());
        Assertions.assertEquals(0, discoveryCertificateRepository.countByDiscovery(persisted));
    }

    @Test
    void runDiscoveryWithoutConnectorStubEndpoints()
            throws AlreadyExistException, ConnectorException, AttributeException, NotFoundException {
        DiscoveryDto dto = new DiscoveryDto();
        dto.setName("RunDiscoveryIT-" + UUID.randomUUID());
        dto.setKind("IpAndPort");
        dto.setConnectorUuid(connector.getUuid().toString());
        dto.setAttributes(List.of());

        UUID discoveryUuid = UUID.fromString(discoveryService.createDiscovery(dto, true).getUuid());

        mockServer.resetMappings();

        discoveryInternalService.runDiscovery(discoveryUuid, null);
        Discovery persisted = discoveryRepository.findByUuid(discoveryUuid).orElseThrow();

        Assertions.assertEquals(DiscoveryStatus.FAILED, persisted.getStatus());
        Assertions.assertEquals(0, discoveryCertificateRepository.countByDiscovery(persisted));
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
        Assertions
                .assertThrows(ValidationException.class,
                        () -> discoveryService.getDiscoveryAttributes(SecuredUUID.fromUUID(connector.getUuid())));
    }

    @Test
    void attributesAreRefusedForAResourceTheContractCannotDiscover() {
        giveConnectorAV2DiscoveryInterface();

        // Refused here rather than at the client, whose IllegalArgumentException would surface as a 500.
        Assertions
                .assertThrows(ValidationException.class,
                        () -> discoveryService
                                .getDiscoveryResourceAttributes(SecuredUUID.fromUUID(connector.getUuid()),
                                        Resource.RA_PROFILE));
    }

    @Test
    void attributesAreRefusedForAResourceThisConnectorDoesNotDiscover() {
        giveConnectorAV2DiscoveryInterface();
        stubSupportedResources("""
                [{"resource":"certificates"}]""");

        // Discoverable in general, but not by this connector -- only its own live answer settles that.
        Assertions
                .assertThrows(ValidationException.class,
                        () -> discoveryService
                                .getDiscoveryResourceAttributes(SecuredUUID.fromUUID(connector.getUuid()),
                                        Resource.CRYPTOGRAPHIC_KEY));
        WireMock.verify(0, WireMock.getRequestedFor(WireMock.urlPathEqualTo("/v2/discoveryProvider/keys/attributes")));
    }

    @Test
    void attributesAreRelayedForAResourceThisConnectorDiscovers() throws Exception {
        giveConnectorAV2DiscoveryInterface();
        stubSupportedResources("""
                [{"resource":"certificates"},{"resource":"keys"}]""");
        WireMock
                .stubFor(WireMock
                        .get(WireMock.urlPathEqualTo("/v2/discoveryProvider/keys/attributes"))
                        .willReturn(WireMock.okJson("""
                                [{"uuid":"7f7f0000-0000-4000-8000-000000000001","name":"keyStore",
                                  "type":"data","version":3,"contentType":"string"}]""")));

        List<BaseAttribute> attributes = discoveryService
                .getDiscoveryResourceAttributes(SecuredUUID.fromUUID(connector.getUuid()), Resource.CRYPTOGRAPHIC_KEY);

        Assertions.assertEquals(1, attributes.size());
        Assertions.assertEquals("keyStore", attributes.getFirst().getName());
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
                {"meta":[{"uuid":"7f7f0000-0000-4000-8000-000000000009","name":"connectorRunId","type":"meta",
                          "version":3,"contentType":"string","content":[{"contentType":"string","data":"run-42"}]}],
                 "stoppable":true}""");

        DiscoveryDetailDto detail = discoveryInternalService.runDiscovery(discovery.getUuid(), null);

        Assertions.assertEquals(DiscoveryStatus.IN_PROGRESS, detail.getStatus());
        Discovery persisted = discoveryRepository.findByUuid(discovery.getUuid()).orElseThrow();
        Assertions
                .assertNotNull(persisted.getRunMeta(), "without the handle the connector cannot resolve the run again");
        Assertions.assertEquals("connectorRunId", persisted.getRunMeta().getFirst().getName());
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
                {"meta":[{"uuid":"7f7f0000-0000-4000-8000-000000000009","name":"connectorRunId","type":"meta",
                          "version":3,"contentType":"string","content":[{"contentType":"string","data":"%s"}]}]}"""
                .formatted("x".repeat(70_000)));

        DiscoveryDetailDto detail = discoveryInternalService.runDiscovery(discovery.getUuid(), null);

        // The handle is replayed on every later call, so one that exceeds the cap would make every tick send a
        // request the transport cannot carry -- better to fail the run at the only point it can still be reported.
        Assertions.assertEquals(DiscoveryStatus.FAILED, detail.getStatus());
        Discovery persisted = discoveryRepository.findByUuid(discovery.getUuid()).orElseThrow();
        Assertions.assertNull(persisted.getRunMeta());
        Assertions.assertTrue(persisted.getMessage().contains("meta size exceeded"));
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
        Assertions.assertNull(persisted.getRunMeta());
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
        Assertions.assertNull(persisted.getRunMeta());
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
        Assertions.assertNull(persisted.getRunMeta());
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

        // 404 says the connector no longer tracks the run -- which is exactly what cancel asked for, so it counts
        // as success rather than leaving the run un-cancelled.
        Discovery persisted = discoveryRepository.findByUuid(discovery.getUuid()).orElseThrow();
        Assertions.assertEquals(DiscoveryStatus.CANCELLED, persisted.getStatus());
        Assertions.assertNull(persisted.getRunMeta());
        // Both statuses, committed together with the terminal transition. Written in a transaction of its own, the
        // run would be non-terminal between the two commits and a status tick could write this back.
        Assertions
                .assertEquals(DiscoveryStatus.CANCELLED, persisted.getConnectorStatus(),
                        "a cancelled run must not go on reporting its connector as still scanning");
    }

    @Test
    void aCreateThatFailsPartWayThroughLeavesNoRunBehind() {
        giveConnectorAV2DiscoveryInterface();
        stubSupportedResources("""
                [{"resource":"certificates"}]""");
        DiscoveryDto request = v2Request(List.of(Resource.CERTIFICATE));
        // Associating a trigger that does not exist fails after the run row and its attributes are written, and
        // fails with a checked exception -- which Spring does not roll back on by default.
        request.setTriggers(List.of(UUID.randomUUID()));

        Assertions.assertThrows(NotFoundException.class, () -> discoveryService.createDiscovery(request, true));

        Assertions
                .assertTrue(discoveryRepository.findByName(request.getName()).isEmpty(),
                        "a half-created run is left IN_PROGRESS with part of its configuration missing, reachable "
                                + "only to be deleted");
    }

    @Test
    void stopIsRefusedForARunTheConnectorNeverDeclaredStoppable() {
        givenV2Run(List.of(Resource.CERTIFICATE));
        Discovery run = discoveryRepository.findByUuid(discovery.getUuid()).orElseThrow();
        giveInterfaceStopResumeFlag();

        // The interface advertises the capability, but this run was not declared stoppable at initiate.
        Assertions.assertThrows(ValidationException.class, () -> adapterFactory.forDiscovery(run).stop(run));
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
                {"meta":[],"stoppable":false}""");
        ScheduledJobInfo job = new ScheduledJobInfo("nightly", UUID.randomUUID(), UUID.randomUUID());

        discoveryInternalService.runDiscovery(discovery.getUuid(), job);

        // The run ends much later in a tick worker that never saw this, so it has to be on the row or the job
        // hangs open forever.
        Discovery persisted = discoveryRepository.findByUuid(discovery.getUuid()).orElseThrow();
        // Only the execution: the history row already points at the job, so a second copy here would be one more
        // thing to keep in step.
        Assertions.assertEquals(job.jobHistoryUuid(), persisted.getScheduledJobHistoryUuid());
    }

    @Test
    void creatingAgainstAV2ConnectorRecordsTheAssociationThatRoutesTheRun() throws Exception {
        giveConnectorAV2DiscoveryInterface();
        stubSupportedResources("""
                [{"resource":"certificates"},{"resource":"keys"}]""");

        DiscoveryDetailDto created = discoveryService
                .createDiscovery(v2Request(List.of(Resource.CRYPTOGRAPHIC_KEY)), true);

        // Without the association the run is a v1 run whatever the connector implements, so every later operation
        // routes to the wrong adapter.
        Discovery persisted = discoveryRepository.findByUuid(UUID.fromString(created.getUuid())).orElseThrow();
        Assertions.assertNotNull(persisted.getConnectorInterfaceUuid());
        Assertions.assertEquals(List.of(Resource.CRYPTOGRAPHIC_KEY), persisted.getResources());
    }

    @Test
    void creatingAgainstAV2ConnectorRequiresTheResourcesToTarget() {
        giveConnectorAV2DiscoveryInterface();

        // A v2 connector discovers several kinds and cannot guess which was meant.
        DiscoveryDto request = v2Request(null);
        Assertions.assertThrows(ValidationException.class, () -> discoveryService.createDiscovery(request, true));
    }

    @Test
    void creatingRefusesAResourceThePlatformCannotReportOnEvenIfTheConnectorOffersIt() {
        giveConnectorAV2DiscoveryInterface();
        // A connector is free to claim anything here. Its claim decides what it can scan, not what this platform can
        // carry an item for -- that is fixed by the payload subtypes the v2 contract registers.
        stubSupportedResources("""
                [{"resource":"certificates"},{"resource":"vaults"}]""");
        DiscoveryDto request = v2Request(List.of(Resource.VAULT));

        ValidationException refused = Assertions
                .assertThrows(ValidationException.class, () -> discoveryService.createDiscovery(request, true));

        // Refused at create, where a caller is present. Accepted, it would open a run that fails at ingest instead.
        Assertions.assertTrue(refused.getMessage().contains("cannot report"), refused.getMessage());
    }

    @Test
    void creatingAgainstAV1ConnectorRefusesPerResourceAttributes() {
        // Honouring them would send Core to a v2 endpoint this connector does not implement; dropping them would
        // accept a run configured differently from the one that was asked for.
        DiscoveryDto request = v2Request(null);
        request.setResourceAttributes(Map.of(Resource.CERTIFICATE, List.of()));

        ValidationException refused = Assertions
                .assertThrows(ValidationException.class, () -> discoveryService.createDiscovery(request, true));
        // The message, not just the type: unvalidated, the request reaches a v2 client call against a v1 connector,
        // which also fails -- but for a reason the caller cannot act on.
        Assertions.assertTrue(refused.getMessage().contains("per-resource attributes"), refused.getMessage());
    }

    @Test
    void creatingRefusesPerResourceAttributesForAResourceTheRunDoesNotTarget() {
        giveConnectorAV2DiscoveryInterface();
        stubSupportedResources("""
                [{"resource":"certificates"},{"resource":"keys"}]""");
        DiscoveryDto request = v2Request(List.of(Resource.CERTIFICATE));
        request.setResourceAttributes(Map.of(Resource.CRYPTOGRAPHIC_KEY, List.of()));

        // The connector discovers keys, so the key is legal in itself -- it is this run that does not target them,
        // and filing attributes against it would store content nothing ever reads back.
        ValidationException refused = Assertions
                .assertThrows(ValidationException.class, () -> discoveryService.createDiscovery(request, true));
        Assertions.assertTrue(refused.getMessage().contains("does not target"), refused.getMessage());
    }

    @Test
    void creatingAgainstAV1ConnectorRefusesResources() {
        // Accepting the field would let a caller believe they had selected something a v1 connector cannot honour.
        DiscoveryDto request = v2Request(List.of(Resource.CERTIFICATE));
        Assertions.assertThrows(ValidationException.class, () -> discoveryService.createDiscovery(request, true));
    }

    @Test
    void creatingRefusesAResourceTheConnectorDoesNotDiscover() {
        giveConnectorAV2DiscoveryInterface();
        stubSupportedResources("""
                [{"resource":"certificates"}]""");

        // Caught now, at one connector call, rather than by a run that opens and immediately fails.
        DiscoveryDto request = v2Request(List.of(Resource.CRYPTOGRAPHIC_KEY));
        Assertions.assertThrows(ValidationException.class, () -> discoveryService.createDiscovery(request, true));
    }

    @Test
    void creatingAgainstAFutureInterfaceVersionRefusesRatherThanRunningItAsV1() {
        ConnectorInterfaceEntity future = new ConnectorInterfaceEntity();
        future.setConnectorUuid(connector.getUuid());
        future.setInterfaceCode(ConnectorInterface.DISCOVERY);
        future.setVersion("v9");
        connectorInterfaceRepository.saveAndFlush(future);

        // The association is recorded whatever the version, so the adapter factory is the one thing that decides
        // which generation drives a run. Keying create on "v2" instead would leave a v9-only connector looking
        // like a legacy connector and silently drive it through the v1 adapter.
        DiscoveryDto request = v2Request(List.of(Resource.CERTIFICATE));
        Assertions.assertThrows(ValidationException.class, () -> discoveryService.createDiscovery(request, true));
    }

    @Test
    void namingTheInterfaceSelectsItWhenAConnectorExposesSeveral() throws Exception {
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
        DiscoveryDetailDto created = discoveryService.createDiscovery(request, true);

        // Named explicitly, so the ambiguity that would otherwise be refused is resolved by the caller -- and the
        // detail says which interface drives the run rather than leaving a client to infer the generation.
        Assertions.assertEquals(chosen.getUuid(), created.getConnectorInterface().getUuid());
        Assertions.assertEquals("v2", created.getConnectorInterface().getVersion());
    }

    @Test
    void namingAnInterfaceTheConnectorDoesNotExposeIsRefused() {
        giveConnectorAV2DiscoveryInterface();

        DiscoveryDto request = v2Request(List.of(Resource.CERTIFICATE));
        request.setInterfaceUuid(UUID.randomUUID());
        Assertions.assertThrows(ValidationException.class, () -> discoveryService.createDiscovery(request, true));
    }

    @Test
    void aConnectorExposingSeveralDiscoveryInterfacesIsRefusedRatherThanGuessed() {
        giveConnectorAV2DiscoveryInterface();
        ConnectorInterfaceEntity future = new ConnectorInterfaceEntity();
        future.setConnectorUuid(connector.getUuid());
        future.setInterfaceCode(ConnectorInterface.DISCOVERY);
        future.setVersion("v3");
        connectorInterfaceRepository.saveAndFlush(future);

        // Picking one silently would decide how the run is driven for its whole life, on no input from the caller.
        DiscoveryDto request = v2Request(List.of(Resource.CERTIFICATE));
        ValidationException refused = Assertions
                .assertThrows(ValidationException.class, () -> discoveryService.createDiscovery(request, true));
        Assertions
                .assertTrue(refused.getMessage().contains("interfaceUuid"),
                        "the refusal says how to resolve it: " + refused.getMessage());
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

        // Deleting it would cascade away the agenda rows that drive it, so nothing would ever end the run: no
        // terminal transition, no event, a connector still scanning, and a scheduled job open forever.
        ValidationException refused = Assertions
                .assertThrows(ValidationException.class,
                        () -> discoveryService.deleteDiscovery(discovery.getSecuredUuid()));
        Assertions.assertTrue(refused.getMessage().contains("cancel"), refused.getMessage());
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
    void aV2RunsAttributesAreValidatedAgainstTheV2Schema() throws Exception {
        giveConnectorAV2DiscoveryInterface();
        stubSupportedResources("""
                [{"resource":"certificates"}]""");

        discoveryService.createDiscovery(v2Request(List.of(Resource.CERTIFICATE)), true);

        // The v1 kind-scoped endpoint is what mergeAndValidateAttributes reads, and a v2-only connector does not
        // implement it; the run-level schema comes from the v2 relay instead.
        WireMock.verify(1, WireMock.getRequestedFor(WireMock.urlPathEqualTo("/v2/discoveryProvider/attributes")));
        WireMock
                .verify(0,
                        WireMock.getRequestedFor(WireMock.urlPathMatching("/v1/discoveryProvider/[^/]+/attributes")));
    }

    /**
     * A per-resource schema is a contract like the run-level one, and a request that ignores it is refused rather than
     * stored.
     */
    @Test
    void aRequiredResourceAttributeTheRequestOmits_refusesTheRun() {
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

        Assertions
                .assertThrows(ValidationException.class, () -> discoveryService.createDiscovery(request, true),
                        "a run targeting a resource whose schema requires an attribute must not be created without it");
        Assertions
                .assertTrue(discoveryRepository.findByName(request.getName()).isEmpty(),
                        "the refusal happens before anything is written");
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
    }

    private void giveInterfaceStopResumeFlag() {
        ConnectorInterfaceEntity iface = connectorInterfaceRepository
                .findById(discoveryRepository.findByUuid(discovery.getUuid()).orElseThrow().getConnectorInterfaceUuid())
                .orElseThrow();
        iface.setFeatures(List.of(FeatureFlag.DISCOVERY_STOP_RESUME));
        connectorInterfaceRepository.saveAndFlush(iface);
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
                                        {"meta":[{"uuid":"7f7f0000-0000-4000-8000-00000000000a",
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
    void runDiscoveryTest() throws AlreadyExistException, ConnectorException, AttributeException, NotFoundException {
        DiscoveryDto dto = new DiscoveryDto();
        dto.setName("RunDiscoveryIT-" + UUID.randomUUID());
        dto.setKind("IpAndPort");
        dto.setConnectorUuid(connector.getUuid().toString());
        dto.setAttributes(List.of());

        UUID discoveryUuid = UUID.fromString(discoveryService.createDiscovery(dto, true).getUuid());

        discoveryInternalService.runDiscovery(discoveryUuid, null);

        Discovery persisted = discoveryRepository.findByUuid(discoveryUuid).orElseThrow();
        Assertions.assertEquals(DiscoveryStatus.PROCESSING, persisted.getStatus());
        Assertions.assertEquals(1, discoveryCertificateRepository.countByDiscovery(persisted));

        EventMessage eventMessage = CertificateDiscoveredEventHandler
                .constructEventMessage(persisted.getUuid(), null, null);
        eventListener.processMessage(eventMessage);
        eventMessage = DiscoveryFinishedEventHandler
                .constructEventMessage(persisted.getUuid(), null, eventMessage.getScheduledJobInfo(),
                        new DiscoveryResult(DiscoveryStatus.PROCESSING, null));
        eventListener.processMessage(eventMessage);

        DiscoveryCertificateResponseDto certificates = discoveryService
                .getDiscoveryCertificates(SecuredUUID.fromUUID(discoveryUuid), null, 10, 1);
        Assertions.assertEquals(1, certificates.getCertificates().size());
        Assertions.assertEquals(1, discoveryCertificateRepository.countByDiscoveryAndNewlyDiscovered(persisted, true));

        persisted = discoveryRepository.findByUuid(discoveryUuid).orElseThrow();
        Assertions.assertEquals(DiscoveryStatus.COMPLETED, persisted.getStatus());

        dto.setName("RunDiscoveryDuplicated-" + UUID.randomUUID());
        discoveryUuid = UUID.fromString(discoveryService.createDiscovery(dto, true).getUuid());
        discoveryInternalService.runDiscovery(discoveryUuid, null);

        persisted = discoveryRepository.findByUuid(discoveryUuid).orElseThrow();
        Assertions.assertEquals(DiscoveryStatus.COMPLETED, persisted.getStatus());
        Assertions.assertEquals(1, discoveryCertificateRepository.countByDiscovery(persisted));

        certificates = discoveryService.getDiscoveryCertificates(SecuredUUID.fromUUID(discoveryUuid), null, 10, 1);
        Assertions.assertEquals(1, certificates.getCertificates().size());
        Assertions.assertEquals(0, discoveryCertificateRepository.countByDiscoveryAndNewlyDiscovered(persisted, true));

        String discoveryStartResponse = """
                {
                    "uuid": "%s",
                    "name": "integration-provider",
                    "status": "completed",
                    "totalCertificatesDiscovered": 0,
                    "certificateData": [],
                    "meta": []
                }
                """.formatted(PROVIDER_DISCOVERY_UUID);

        WireMock
                .stubFor(WireMock
                        .post(WireMock.urlPathMatching("/v1/discoveryProvider/discover"))
                        .willReturn(WireMock.okJson(discoveryStartResponse)));

        String discoveryDataResponse = """
                {
                     "uuid": "%s",
                     "name": "integration-provider",
                     "status": "inProgress",
                     "totalCertificatesDiscovered": 0,
                     "certificateData": [],
                     "meta": []
                }
                """.formatted(PROVIDER_DISCOVERY_UUID);

        WireMock
                .stubFor(WireMock
                        .post(WireMock.urlPathMatching("/v1/discoveryProvider/discover/" + PROVIDER_DISCOVERY_UUID))
                        .willReturn(WireMock.okJson(discoveryDataResponse)));

        dto.setName("RunDiscoveryLongRunning-" + UUID.randomUUID());
        discoveryUuid = UUID.fromString(discoveryService.createDiscovery(dto, true).getUuid());

        discoveryInternalService.runDiscovery(discoveryUuid, null);

        persisted = discoveryRepository.findByUuid(discoveryUuid).orElseThrow();
        Assertions.assertEquals(DiscoveryStatus.COMPLETED, persisted.getStatus());
        Assertions.assertEquals(0, discoveryCertificateRepository.countByDiscovery(persisted));

        discoveryStartResponse = """
                {
                    "uuid": "%s",
                    "name": "integration-provider",
                    "status": "inProgress",
                    "totalCertificatesDiscovered": 0,
                    "certificateData": [],
                    "meta": []
                }
                """.formatted(PROVIDER_DISCOVERY_UUID);

        WireMock
                .stubFor(WireMock
                        .post(WireMock.urlPathMatching("/v1/discoveryProvider/discover"))
                        .willReturn(WireMock.okJson(discoveryStartResponse)));

        dto.setName("RunDiscoveryLongRunning2-" + UUID.randomUUID());
        discoveryUuid = UUID.fromString(discoveryService.createDiscovery(dto, true).getUuid());

        persisted = discoveryRepository.findByUuid(discoveryUuid).orElseThrow();
        persisted.setStartTime(OffsetDateTime.now().minusDays(7));
        discoveryRepository.save(persisted);

        discoveryInternalService.runDiscovery(discoveryUuid, null);

        persisted = discoveryRepository.findByUuid(discoveryUuid).orElseThrow();
        Assertions.assertEquals(DiscoveryStatus.FAILED, persisted.getStatus());
        Assertions.assertEquals(0, discoveryCertificateRepository.countByDiscovery(persisted));
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
        return UUID.fromString(discoveryService.createDiscovery(dto, true).getUuid());
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
}
