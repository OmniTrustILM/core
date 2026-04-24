package com.czertainly.core.service;

import com.czertainly.api.exception.*;
import com.czertainly.api.model.client.certificate.DiscoveryResponseDto;
import com.czertainly.api.model.client.certificate.SearchRequestDto;
import com.czertainly.api.model.client.connector.v2.ConnectorVersion;
import com.czertainly.api.model.client.discovery.DiscoveryCertificateResponseDto;
import com.czertainly.api.model.client.discovery.DiscoveryDto;
import com.czertainly.api.model.client.discovery.DiscoveryHistoryDetailDto;
import com.czertainly.api.model.client.discovery.DiscoveryHistoryDto;
import com.czertainly.api.model.common.NameAndUuidDto;
import com.czertainly.api.model.core.connector.ConnectorStatus;
import com.czertainly.api.model.core.connector.FunctionGroupCode;
import com.czertainly.api.model.core.discovery.DiscoveryStatus;
import com.czertainly.core.dao.entity.Connector;
import com.czertainly.core.dao.entity.Connector2FunctionGroup;
import com.czertainly.core.dao.entity.DiscoveryHistory;
import com.czertainly.core.dao.entity.FunctionGroup;
import com.czertainly.core.dao.repository.*;
import com.czertainly.core.events.data.DiscoveryResult;
import com.czertainly.core.events.handlers.CertificateDiscoveredEventHandler;
import com.czertainly.core.events.handlers.DiscoveryFinishedEventHandler;
import com.czertainly.core.messaging.jms.listeners.EventListener;
import com.czertainly.core.messaging.model.EventMessage;
import com.czertainly.core.security.authz.SecuredUUID;
import com.czertainly.core.security.authz.SecurityFilter;
import com.czertainly.core.util.BaseSpringBootTest;
import com.czertainly.core.util.MetaDefinitions;
import com.github.tomakehurst.wiremock.WireMockServer;
import com.github.tomakehurst.wiremock.client.WireMock;
import org.junit.jupiter.api.*;
import org.springframework.beans.factory.annotation.Autowired;

import java.time.Instant;
import java.util.Date;
import java.util.List;
import java.util.UUID;

class DiscoveryServiceTest extends BaseSpringBootTest {

    private static final String DISCOVERY_NAME = "testDiscovery1";
    private static final String PROVIDER_DISCOVERY_UUID = "4bd64640-be29-4e14-aad8-5c0ffa55c5bd";
    private static final String CERTIFICATE_BASE64 = "MIIDyjCCArKgAwIBAgIUULw4BO/gvFzW2wMYXRhmz1kPPdAwDQYJKoZIhvcNAQELBQAwZDEUMBIGA1UEAwwLdGVzdGNlcnQuY3oxCzAJBgNVBAYTAkNaMRgwFgYDVQQIDA9DZW50cmFsIEJvaGVtaWExDzANBgNVBAcMBlNsYW7DvTEUMBIGA1UECgwLM0tleUNvbXBhbnkwHhcNMjQxMDIxMTAzMDEyWhcNMjUxMDIxMTAzMDEyWjBkMRQwEgYDVQQDDAt0ZXN0Y2VydC5jejELMAkGA1UEBhMCQ1oxGDAWBgNVBAgMD0NlbnRyYWwgQm9oZW1pYTEPMA0GA1UEBwwGU2xhbsO9MRQwEgYDVQQKDAszS2V5Q29tcGFueTCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAJ112/a4p9sZ4F2fABLGtSBrbp71n/0uG+H/3usEQU8/FIW644ly5hNl8+SloPWryCCxOl+saXTKv62h0HnE/HNFMKlps4wwWNMsTploFKiAW9AbaDtzNrMy9f/orMoZldDZt5dLX8UR3qMmdK8nlqiJOyCAxIS70OsEQC8fGuIMNYeW6eidXGHjvpqApWnGTyA4U1bJWsDWcOIh/LL2ae9nwTJjVrHthrM6Wq6PplaPxEKYABp51UAQLMzY+cJElcKmwQxiK+zOHns7/ocosZVqI2QyxSmG60icabyrIT6HQHKVNzZHkltmduyYun9YZ+nl68YOuNmtSNi1TLMlfGECAwEAAaN0MHIwHQYDVR0OBBYEFOWFJRXdCer5Bpj+9JrquuJ7e5eQMB8GA1UdIwQYMBaAFOWFJRXdCer5Bpj+9JrquuJ7e5eQMA4GA1UdDwEB/wQEAwIFoDAgBgNVHSUBAf8EFjAUBggrBgEFBQcDAQYIKwYBBQUHAwIwDQYJKoZIhvcNAQELBQADggEBAA6AWaBFDAWL8oSBCP3q1s2Gq9QhR2QEBZ5tPOMTN5GpIzXxXdm4nHHBK/pSFABUNmrwQMapvq/y6IZ7hNMdC89MTOsHLD0EVPmHHO4xhzMG08XpJdevTrvktjpt0+ju81ratLg34pvJLeLF7ZL5AxwOl6qKX6RgwHpdBUipAYeeVhTVtQ7FLvakKDwYLiN6YFXuM1+CDAK3fsJ6sZki3uRvLYsUi7bguIQCmCQ0/n+T62Driq6mh1FkFB3sgpSFjfEo3bEaaHzF1YZr6otTYPNzcLCStJ5SYNBXKbw7YKAcYavL6yMNTQ2CjmLVnwjjd3O/Sv1kEhZMu86mHeNZK0I=";


    @Autowired
    private DiscoveryService discoveryService;

    @Autowired
    private DiscoveryRepository discoveryRepository;
    @Autowired
    private DiscoveryCertificateRepository discoveryCertificateRepository;

    @Autowired
    private ConnectorRepository connectorRepository;
    @Autowired
    private FunctionGroupRepository functionGroupRepository;
    @Autowired
    private Connector2FunctionGroupRepository connector2FunctionGroupRepository;

    @Autowired
    private EventListener eventListener;

    private DiscoveryHistory discovery;
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

        discovery = new DiscoveryHistory();
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
        final DiscoveryResponseDto discoveryHistoryDTO = discoveryService.listDiscoveries(SecurityFilter.create(), new SearchRequestDto());
        final List<DiscoveryHistoryDto> discoveries = discoveryHistoryDTO.getDiscoveries();
        Assertions.assertNotNull(discoveries);
        Assertions.assertFalse(discoveries.isEmpty());
        Assertions.assertEquals(1, discoveries.size());
        Assertions.assertEquals(discovery.getUuid().toString(), discoveries.get(0).getUuid());
    }

    @Test
    void testGetDiscovery() throws NotFoundException {
        DiscoveryHistoryDetailDto dto = discoveryService.getDiscovery(discovery.getSecuredUuid());
        Assertions.assertNotNull(dto);
        Assertions.assertEquals(discovery.getUuid().toString(), dto.getUuid());
        Assertions.assertEquals(discovery.getConnectorUuid().toString(), dto.getConnectorUuid());
    }

    @Test
    void testGetDiscovery_notFound() {
        Assertions.assertThrows(NotFoundException.class, () -> discoveryService.getDiscovery(SecuredUUID.fromString("abfbc322-29e1-11ed-a261-0242ac120002")));
    }

    @Test
    void testAddDiscovery() throws ConnectorException, AlreadyExistException, AttributeException, NotFoundException {
        mockServer.stubFor(WireMock
                .get(WireMock.urlPathMatching("/v1/discoveryProvider/[^/]+/attributes"))
                .willReturn(WireMock.okJson("[]")));
        mockServer.stubFor(WireMock
                .post(WireMock.urlPathMatching("/v1/discoveryProvider/[^/]+/attributes/validate"))
                .willReturn(WireMock.okJson("true")));

        DiscoveryDto request = new DiscoveryDto();
        request.setName("testDiscovery2");
        request.setConnectorUuid(connector.getUuid().toString());
        request.setAttributes(List.of());
        request.setKind("ApiKey");

        DiscoveryHistoryDetailDto dto = discoveryService.createDiscovery(request, true);
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
        Assertions.assertThrows(NotFoundException.class, () -> discoveryService.runDiscovery(discovery.getUuid(), null));
    }

    @Test
    @Disabled("Async method is not throwing exception")
    void testDiscoverCertificates_validationFailed() {
        mockServer.stubFor(WireMock
                .post(WireMock.urlPathMatching("/v1/discoveryProvider/[^/]+/attributes/validate"))
                .willReturn(WireMock.okJson("false")));

        Assertions.assertThrows(ValidationException.class, () -> discoveryService.runDiscovery(discovery.getUuid(), null));
    }

    @Test
    void testRemoveDiscovery() throws NotFoundException {
        discoveryService.deleteDiscovery(discovery.getSecuredUuid());
        Assertions.assertThrows(NotFoundException.class, () -> discoveryService.getDiscovery(discovery.getSecuredUuid()));
    }

    @Test
    void testRemoveDiscovery_notFound() {
        Assertions.assertThrows(NotFoundException.class, () -> discoveryService.deleteDiscovery(SecuredUUID.fromString("abfbc322-29e1-11ed-a261-0242ac120002")));
    }

    @Test
    void testBulkRemove() throws NotFoundException {
        discoveryService.bulkRemoveDiscovery(List.of(discovery.getSecuredUuid()));
        Assertions.assertThrows(NotFoundException.class, () -> discoveryService.getDiscovery(discovery.getSecuredUuid()));
    }

    @Test
    void runDiscoveryWithoutConnector() throws AlreadyExistException, ConnectorException, AttributeException, NotFoundException {
        DiscoveryDto dto = new DiscoveryDto();
        dto.setName("RunDiscoveryIT-" + UUID.randomUUID());
        dto.setKind("IpAndPort");
        dto.setConnectorUuid(connector.getUuid().toString());
        dto.setAttributes(List.of());

        UUID discoveryUuid = UUID.fromString(discoveryService.createDiscovery(dto, true).getUuid());

        DiscoveryHistory persisted = discoveryRepository.findByUuid(discoveryUuid).orElseThrow();
        persisted.setConnectorUuid(UUID.randomUUID());
        discoveryRepository.save(persisted);

        discoveryService.runDiscovery(discoveryUuid, null);
        persisted = discoveryRepository.findByUuid(discoveryUuid).orElseThrow();

        Assertions.assertEquals(DiscoveryStatus.FAILED, persisted.getStatus());
        Assertions.assertEquals(0, discoveryCertificateRepository.countByDiscovery(persisted));
    }

    @Test
    void runDiscoveryWithoutConnectorStubEndpoints() throws AlreadyExistException, ConnectorException, AttributeException, NotFoundException {
        DiscoveryDto dto = new DiscoveryDto();
        dto.setName("RunDiscoveryIT-" + UUID.randomUUID());
        dto.setKind("IpAndPort");
        dto.setConnectorUuid(connector.getUuid().toString());
        dto.setAttributes(List.of());

        UUID discoveryUuid = UUID.fromString(discoveryService.createDiscovery(dto, true).getUuid());

        mockServer.resetMappings();

        discoveryService.runDiscovery(discoveryUuid, null);
        DiscoveryHistory persisted = discoveryRepository.findByUuid(discoveryUuid).orElseThrow();

        Assertions.assertEquals(DiscoveryStatus.FAILED, persisted.getStatus());
        Assertions.assertEquals(0, discoveryCertificateRepository.countByDiscovery(persisted));
    }

    @Test
    void runDiscoveryTest() throws AlreadyExistException, ConnectorException, AttributeException, NotFoundException {
        DiscoveryDto dto = new DiscoveryDto();
        dto.setName("RunDiscoveryIT-" + UUID.randomUUID());
        dto.setKind("IpAndPort");
        dto.setConnectorUuid(connector.getUuid().toString());
        dto.setAttributes(List.of());

        UUID discoveryUuid = UUID.fromString(discoveryService.createDiscovery(dto, true).getUuid());

        discoveryService.runDiscovery(discoveryUuid, null);

        DiscoveryHistory persisted = discoveryRepository.findByUuid(discoveryUuid).orElseThrow();
        Assertions.assertEquals(DiscoveryStatus.PROCESSING, persisted.getStatus());
        Assertions.assertEquals(1, discoveryCertificateRepository.countByDiscovery(persisted));

        EventMessage eventMessage = CertificateDiscoveredEventHandler.constructEventMessage(persisted.getUuid(), null, null);
        eventListener.processMessage(eventMessage);
        eventMessage = DiscoveryFinishedEventHandler.constructEventMessage(persisted.getUuid(), null, eventMessage.getScheduledJobInfo(), new DiscoveryResult(DiscoveryStatus.PROCESSING, null));
        eventListener.processMessage(eventMessage);

        DiscoveryCertificateResponseDto certificates = discoveryService.getDiscoveryCertificates(SecuredUUID.fromUUID(discoveryUuid), null, 10, 1);
        Assertions.assertEquals(1, certificates.getCertificates().size());
        Assertions.assertEquals(1, discoveryCertificateRepository.countByDiscoveryAndNewlyDiscovered(persisted, true));

        persisted = discoveryRepository.findByUuid(discoveryUuid).orElseThrow();
        Assertions.assertEquals(DiscoveryStatus.COMPLETED, persisted.getStatus());

        dto.setName("RunDiscoveryDuplicated-" + UUID.randomUUID());
        discoveryUuid = UUID.fromString(discoveryService.createDiscovery(dto, true).getUuid());
        discoveryService.runDiscovery(discoveryUuid, null);

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

        WireMock.stubFor(WireMock.post(WireMock.urlPathMatching("/v1/discoveryProvider/discover"))
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

        WireMock.stubFor(WireMock.post(WireMock.urlPathMatching("/v1/discoveryProvider/discover/" + PROVIDER_DISCOVERY_UUID))
                .willReturn(WireMock.okJson(discoveryDataResponse)));

        dto.setName("RunDiscoveryLongRunning-" + UUID.randomUUID());
        discoveryUuid = UUID.fromString(discoveryService.createDiscovery(dto, true).getUuid());

        discoveryService.runDiscovery(discoveryUuid, null);

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

        WireMock.stubFor(WireMock.post(WireMock.urlPathMatching("/v1/discoveryProvider/discover"))
                .willReturn(WireMock.okJson(discoveryStartResponse)));

        dto.setName("RunDiscoveryLongRunning2-" + UUID.randomUUID());
        discoveryUuid = UUID.fromString(discoveryService.createDiscovery(dto, true).getUuid());

        persisted = discoveryRepository.findByUuid(discoveryUuid).orElseThrow();
        persisted.setStartTime(Date.from(Instant.now().minus(7, java.time.temporal.ChronoUnit.DAYS)));
        discoveryRepository.save(persisted);

        discoveryService.runDiscovery(discoveryUuid, null);

        persisted = discoveryRepository.findByUuid(discoveryUuid).orElseThrow();
        Assertions.assertEquals(DiscoveryStatus.FAILED, persisted.getStatus());
        Assertions.assertEquals(0, discoveryCertificateRepository.countByDiscovery(persisted));
    }

    @Test
    void testGetResourceObject() throws NotFoundException {
        NameAndUuidDto nameAndUuidDto = discoveryService.getResourceObjectInternal(discovery.getUuid());
        Assertions.assertEquals(discovery.getUuid().toString(), nameAndUuidDto.getUuid());
        Assertions.assertEquals(discovery.getName(), nameAndUuidDto.getName());

        nameAndUuidDto = discoveryService.getResourceObjectExternal(discovery.getSecuredUuid());
        Assertions.assertEquals(discovery.getUuid().toString(), nameAndUuidDto.getUuid());
        Assertions.assertEquals(discovery.getName(), nameAndUuidDto.getName());
    }

    private void stubConnectorEndpoints() {
        WireMock.stubFor(WireMock.get(WireMock.urlPathMatching("/v1/discoveryProvider/[^/]+/attributes"))
                .willReturn(WireMock.okJson("[]")));
        WireMock.stubFor(WireMock.post(WireMock.urlPathMatching("/v1/discoveryProvider/[^/]+/attributes/validate"))
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

        WireMock.stubFor(WireMock.post(WireMock.urlPathMatching("/v1/discoveryProvider/discover"))
                .willReturn(WireMock.okJson(discoveryStartResponse)));
        WireMock.stubFor(WireMock.post(WireMock.urlPathMatching("/v1/discoveryProvider/discover/" + PROVIDER_DISCOVERY_UUID))
                .willReturn(WireMock.okJson(discoveryDataResponse)));
    }
}
