package com.czertainly.core.service;

import com.czertainly.api.exception.*;
import com.czertainly.api.model.client.attribute.RequestAttribute;
import com.czertainly.api.model.client.attribute.RequestAttributeV2;
import com.czertainly.api.model.client.certificate.LocationsResponseDto;
import com.czertainly.api.model.client.certificate.SearchRequestDto;
import com.czertainly.api.model.client.connector.v2.ConnectorVersion;
import com.czertainly.api.model.client.location.AddLocationRequestDto;
import com.czertainly.api.model.client.location.EditLocationRequestDto;
import com.czertainly.api.model.client.location.IssueToLocationRequestDto;
import com.czertainly.api.model.client.location.PushToLocationRequestDto;
import com.czertainly.api.model.common.NameAndUuidDto;
import com.czertainly.api.model.common.attribute.common.AttributeType;
import com.czertainly.api.model.common.attribute.v2.DataAttributeV2;
import com.czertainly.api.model.common.attribute.common.content.AttributeContentType;
import com.czertainly.api.model.common.attribute.v2.content.StringAttributeContentV2;
import com.czertainly.api.model.common.attribute.common.properties.DataAttributeProperties;
import com.czertainly.api.model.common.attribute.v3.DataAttributeV3;
import com.czertainly.api.model.common.attribute.v3.content.StringAttributeContentV3;
import com.czertainly.api.model.core.auth.Resource;
import com.czertainly.api.model.core.certificate.CertificateState;
import com.czertainly.api.model.core.certificate.CertificateValidationStatus;
import com.czertainly.api.model.core.connector.ConnectorStatus;
import com.czertainly.api.model.core.location.LocationDto;
import com.czertainly.api.model.core.v2.ClientCertificateDataResponseDto;
import com.czertainly.core.attribute.engine.AttributeEngine;
import com.czertainly.core.attribute.engine.records.ObjectAttributeContentInfo;
import com.czertainly.core.dao.entity.*;
import com.czertainly.core.dao.repository.*;
import com.czertainly.core.security.authz.SecuredParentUUID;
import com.czertainly.core.security.authz.SecuredUUID;
import com.czertainly.core.security.authz.SecurityFilter;
import com.czertainly.core.service.v2.ClientOperationService;
import com.czertainly.core.util.BaseSpringBootTest;
import com.github.tomakehurst.wiremock.WireMockServer;
import com.github.tomakehurst.wiremock.client.WireMock;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import org.mockito.Mockito;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.test.context.bean.override.mockito.MockitoBean;

import java.io.IOException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.*;

import static org.mockito.ArgumentMatchers.any;

class LocationServiceTest extends BaseSpringBootTest {

    private static final String LOCATION_NAME = "testLocation1";
    private static final String LOCATION_NAME_NOMULTIENTRIES = "testLocation-noMultiEntries";
    private static final String LOCATION_NAME_NOKEYMANAGEMENT = "testLocation-noKeyManagement";

    @Autowired
    private LocationService locationService;
    @Autowired
    private LocationRepository locationRepository;
    @Autowired
    private CertificateRepository certificateRepository;
    @Autowired
    private CertificateContentRepository certificateContentRepository;
    @Autowired
    private EntityInstanceReferenceRepository entityInstanceReferenceRepository;
    @Autowired
    private ConnectorRepository connectorRepository;
    @Autowired
    private RaProfileRepository raProfileRepository;
    @Autowired
    private AuthorityInstanceReferenceRepository authorityInstanceReferenceRepository;
    @Autowired
    private CertificateLocationRepository certificateLocationRepository;
    @MockitoBean
    private ClientOperationService clientOperationService;

    private DataAttributeV2 testAttribute;
    private DataAttributeV2 testAttribute2;
    private Location location;
    private Location locationNoMultiEntries;
    private Location locationNoKeyManagement;
    private EntityInstanceReference entityInstanceReference;
    private Certificate certificate;
    private Certificate certificateWithoutLocation;
    private WireMockServer mockServer;
    private AttributeEngine attributeEngine;

    @Autowired
    void setAttributeEngine(AttributeEngine attributeEngine) {
        this.attributeEngine = attributeEngine;
    }

    @BeforeEach
    void setUp() throws NotFoundException, AttributeException {
        mockServer = new WireMockServer(0);
        mockServer.start();

        WireMock.configureFor("localhost", mockServer.port());

        CertificateContent certificateContent = new CertificateContent();
        certificateContent = certificateContentRepository.save(certificateContent);

        certificate = new Certificate();
        certificate.setCertificateContent(certificateContent);
        certificate.setSerialNumber("cc4ab59d436a88dae957");
        certificate = certificateRepository.save(certificate);

        certificateWithoutLocation = new Certificate();
        certificateWithoutLocation.setState(CertificateState.ISSUED);
        certificateWithoutLocation.setValidationStatus(CertificateValidationStatus.VALID);
        certificateWithoutLocation.setCertificateContentId(certificateContent.getId());
        certificateWithoutLocation.setSerialNumber("aa4ab59d436a88dae957");
        certificateWithoutLocation = certificateRepository.save(certificateWithoutLocation);

        Connector connector = new Connector();
        connector.setUrl("http://localhost:" + mockServer.port());
        connector.setVersion(ConnectorVersion.V1);
        connector.setStatus(ConnectorStatus.CONNECTED);
        connector = connectorRepository.save(connector);

        entityInstanceReference = new EntityInstanceReference();
        entityInstanceReference.setEntityInstanceUuid("ad8d8995-f12e-407e-a8d2-9a2fb91772bb");
        entityInstanceReference.setConnector(connector);
        entityInstanceReference = entityInstanceReferenceRepository.save(entityInstanceReference);

        prepareDataAttributesDefinitions();

        location = createLocation();
        locationNoMultiEntries = createLocationNoMultiEntries();
        locationNoKeyManagement = createLocationNoKeyManagement();

        // Use distinct instances of CertificateLocation
        CertificateLocation certificateLocation1 = new CertificateLocation();
        certificateLocation1.setWithKey(true);
        certificateLocation1.setCertificate(certificate);
        certificateLocation1.setLocation(location);

        CertificateLocation certificateLocation2 = new CertificateLocation();
        certificateLocation2.setWithKey(true);
        certificateLocation2.setCertificate(certificate);
        certificateLocation2.setLocation(locationNoMultiEntries);

        CertificateLocation certificateLocation3 = new CertificateLocation();
        certificateLocation3.setWithKey(true);
        certificateLocation3.setCertificate(certificate);
        certificateLocation3.setLocation(locationNoKeyManagement);

        location.getCertificates().add(certificateLocation1);
        locationNoMultiEntries.getCertificates().add(certificateLocation2);
        locationNoKeyManagement.getCertificates().add(certificateLocation3);

        location = locationRepository.save(location);
        locationNoMultiEntries = locationRepository.save(locationNoMultiEntries);
        locationNoKeyManagement = locationRepository.save(locationNoKeyManagement);
    }


    private void prepareDataAttributesDefinitions() throws AttributeException {
        testAttribute = new DataAttributeV2();
        testAttribute.setUuid("5e9146a6-da8a-403f-99cb-d5d64d93ce1c");
        testAttribute.setName("attribute");

        DataAttributeProperties properties = new DataAttributeProperties();
        properties.setLabel("Attribute");
        testAttribute.setDescription("description");
        testAttribute.setContentType(AttributeContentType.STRING);
        testAttribute.setType(AttributeType.DATA);
        properties.setRequired(true);
        properties.setReadOnly(false);
        properties.setVisible(true);
        testAttribute.setProperties(properties);

        testAttribute2 = new DataAttributeV2();
        testAttribute2.setUuid("c9819613-725e-4f01-89fb-cb896a26e555");
        testAttribute2.setName("sample");

        DataAttributeProperties sampleProps = new DataAttributeProperties();
        sampleProps.setLabel("Sample Attribute");
        testAttribute2.setDescription("Desc");
        testAttribute2.setContentType(AttributeContentType.STRING);
        testAttribute2.setType(AttributeType.DATA);
        sampleProps.setRequired(true);
        sampleProps.setReadOnly(false);
        sampleProps.setVisible(true);
        testAttribute2.setProperties(sampleProps);

        attributeEngine.updateDataAttributeDefinitions(entityInstanceReference.getConnectorUuid(), null, List.of(testAttribute, testAttribute2));
    }

    private Location createLocation() throws AttributeException, NotFoundException {
        Location newLocation = new Location();
        newLocation.setUuid(UUID.randomUUID());
        newLocation.setName(LOCATION_NAME);
        newLocation.setEntityInstanceReference(entityInstanceReference);
        newLocation.setEnabled(true);
        newLocation.setSupportKeyManagement(true);
        newLocation.setSupportMultipleEntries(true);

        List<RequestAttribute> requestAttributes = new ArrayList<>();
        requestAttributes.add(new RequestAttributeV2(UUID.fromString(testAttribute.getUuid()), testAttribute.getName(), AttributeContentType.STRING, List.of(new StringAttributeContentV2("newLocation"))));
        attributeEngine.updateObjectDataAttributesContent(ObjectAttributeContentInfo.builder(Resource.LOCATION, newLocation.getUuid()).connector(entityInstanceReference.getConnectorUuid()).build(), requestAttributes);
        return newLocation;
    }

    private Location createLocationNoMultiEntries() throws AttributeException, NotFoundException {
        Location newLocation = new Location();
        newLocation.setUuid(UUID.randomUUID());
        newLocation.setName(LOCATION_NAME_NOMULTIENTRIES);
        newLocation.setEntityInstanceReferenceUuid(entityInstanceReference.getUuid());
        newLocation.setEnabled(true);
        newLocation.setSupportKeyManagement(true);
        newLocation.setSupportMultipleEntries(false);

        List<RequestAttribute> requestAttributes = new ArrayList<>();
        requestAttributes.add(new RequestAttributeV2(UUID.fromString(testAttribute.getUuid()), testAttribute.getName(), AttributeContentType.STRING, List.of(new StringAttributeContentV2("location_multi"))));
        attributeEngine.updateObjectDataAttributesContent(ObjectAttributeContentInfo.builder(Resource.LOCATION, newLocation.getUuid()).connector(entityInstanceReference.getConnectorUuid()).build(), requestAttributes);

        return newLocation;
    }

    private Location createLocationNoKeyManagement() throws AttributeException, NotFoundException {
        Location newLocation = new Location();
        newLocation.setUuid(UUID.randomUUID());
        newLocation.setName(LOCATION_NAME_NOKEYMANAGEMENT);
        newLocation.setEntityInstanceReference(entityInstanceReference);
        newLocation.setEnabled(true);
        newLocation.setSupportKeyManagement(false);
        newLocation.setSupportMultipleEntries(true);

        List<RequestAttribute> requestAttributes = new ArrayList<>();
        requestAttributes.add(new RequestAttributeV2(UUID.fromString(testAttribute.getUuid()), testAttribute.getName(), AttributeContentType.STRING, List.of(new StringAttributeContentV2("location_no_key"))));
        attributeEngine.updateObjectDataAttributesContent(ObjectAttributeContentInfo.builder(Resource.LOCATION, newLocation.getUuid()).connector(entityInstanceReference.getConnectorUuid()).build(), requestAttributes);

        return newLocation;
    }

    @AfterEach
    void tearDown() {
        mockServer.stop();
    }

    @Test
    void testListLocations() {
        LocationsResponseDto locationsResponseDto = locationService.listLocations(SecurityFilter.create(), new SearchRequestDto());
        List<LocationDto> locations = locationsResponseDto.getLocations();
        Assertions.assertNotNull(locations);
        Assertions.assertFalse(locations.isEmpty());
        Assertions.assertEquals(3, locations.size());
    }

    @Test
    void testGetLocationByUuid() throws NotFoundException {
        LocationDto dto = locationService.getLocation(SecuredParentUUID.fromUUID(location.getEntityInstanceReferenceUuid()), location.getSecuredUuid());
        Assertions.assertNotNull(dto);
        Assertions.assertEquals(location.getUuid().toString(), dto.getUuid());
    }

    @Test
    void testGetLocationByUuid_notFound() {
        Assertions.assertThrows(NotFoundException.class, () -> locationService.getLocation(SecuredParentUUID.fromUUID(location.getEntityInstanceReferenceUuid()), SecuredUUID.fromString("abfbc322-29e1-11ed-a261-0242ac120002")));
    }

    @Test
    void testAddLocation() throws ConnectorException, AlreadyExistException, LocationException, AttributeException, NotFoundException {
        mockServer.stubFor(WireMock
                .get(WireMock.urlPathMatching("/v1/entityProvider/entities/[^/]+/location/attributes"))
                .willReturn(WireMock.okJson("[]")));
        mockServer.stubFor(WireMock
                .post(WireMock.urlPathMatching("/v1/entityProvider/entities/[^/]+/location/attributes/validate"))
                .willReturn(WireMock.okJson("true")));
        mockServer.stubFor(WireMock
                .post(WireMock.urlPathMatching("/v1/entityProvider/entities/[^/]+/locations"))
                .willReturn(WireMock.okJson("""
                        {
                          "certificates": [],
                          "multipleEntries": true,
                          "supportKeyManagement": true
                        }""")));

        AddLocationRequestDto request = new AddLocationRequestDto();
        request.setName("testLocation2");
        RequestAttributeV2 requestAttribute = new RequestAttributeV2();
        requestAttribute.setUuid(UUID.fromString(testAttribute2.getUuid()));
        requestAttribute.setName(testAttribute2.getName());
        requestAttribute.setContent(List.of(new StringAttributeContentV2("test")));
        request.setAttributes(List.of(requestAttribute));

        LocationDto dto = locationService.addLocation(SecuredParentUUID.fromUUID(entityInstanceReference.getUuid()), request);
        Assertions.assertNotNull(dto);
        Assertions.assertEquals(request.getName(), dto.getName());
    }

    @Test
    void testAddLocation_DuplicateEntity() {
        AddLocationRequestDto request = new AddLocationRequestDto();
        request.setName(LOCATION_NAME);
        RequestAttributeV2 attribute = new RequestAttributeV2();
        attribute.setName("attribute");
        attribute.setContent(List.of(new StringAttributeContentV2("location")));
        request.setAttributes(List.of(attribute));

        Assertions.assertThrows(AlreadyExistException.class, () -> locationService.addLocation(SecuredParentUUID.fromUUID(entityInstanceReference.getUuid()), request));
    }

    @Test
    void testAddLocation_validationFail() {
        AddLocationRequestDto request = new AddLocationRequestDto();
        Assertions.assertThrows(ValidationException.class, () -> locationService.addLocation(entityInstanceReference.getSecuredParentUuid(), request));
    }

    @Test
    void testAddLocation_alreadyExist() {
        AddLocationRequestDto request = new AddLocationRequestDto();
        request.setName(LOCATION_NAME); // location with the name that already exists

        Assertions.assertThrows(AlreadyExistException.class, () -> locationService.addLocation(entityInstanceReference.getSecuredParentUuid(), request));
    }

    @Test
    void testEditLocation() throws ConnectorException, LocationException, AttributeException, NotFoundException {
        mockServer.stubFor(WireMock
                .get(WireMock.urlPathMatching("/v1/entityProvider/entities/[^/]+/location/attributes"))
                .willReturn(WireMock.okJson("[]")));
        mockServer.stubFor(WireMock
                .post(WireMock.urlPathMatching("/v1/entityProvider/entities/[^/]+/location/attributes/validate"))
                .willReturn(WireMock.okJson("true")));
        mockServer.stubFor(WireMock
                .post(WireMock.urlPathMatching("/v1/entityProvider/entities/[^/]+/locations"))
                .willReturn(WireMock.okJson("""
                        {
                          "certificates": [],
                          "multipleEntries": true,
                          "supportKeyManagement": true
                        }""")));

        EditLocationRequestDto request = new EditLocationRequestDto();
        request.setDescription("some description");
        request.setAttributes(List.of());

        LocationDto dto = locationService.editLocation(entityInstanceReference.getSecuredParentUuid(), location.getSecuredUuid(), request);
        Assertions.assertNotNull(dto);
        Assertions.assertEquals(request.getDescription(), dto.getDescription());
    }

    @Test
    void testEditLocation_notFound() {
        EditLocationRequestDto request = new EditLocationRequestDto();

        Assertions.assertThrows(NotFoundException.class, () -> locationService.editLocation(entityInstanceReference.getSecuredParentUuid(), SecuredUUID.fromString("abfbc322-29e1-11ed-a261-0242ac120002"), request));
    }

    @Test
    void testRemoveLocation_notFound() {
        Assertions.assertThrows(NotFoundException.class, () -> locationService.deleteLocation(entityInstanceReference.getSecuredParentUuid(), SecuredUUID.fromString("abfbc322-29e1-11ed-a261-0242ac120002")));
    }

    @Test
    void testEnableLocation() throws NotFoundException {
        locationService.enableLocation(SecuredParentUUID.fromUUID(location.getEntityInstanceReferenceUuid()), location.getSecuredUuid());
        Assertions.assertEquals(true, location.getEnabled());
    }

    @Test
    void testEnableLocation_notFound() {
        Assertions.assertThrows(NotFoundException.class, () -> locationService.enableLocation(entityInstanceReference.getSecuredParentUuid(), SecuredUUID.fromString("abfbc322-29e1-11ed-a261-0242ac120002")));
    }

    @Test
    void testDisableLocation() throws NotFoundException {
        locationService.disableLocation(SecuredParentUUID.fromUUID(location.getEntityInstanceReferenceUuid()), location.getSecuredUuid());
        Assertions.assertFalse(locationService.getLocation(SecuredParentUUID.fromUUID(location.getEntityInstanceReferenceUuid()), location.getSecuredUuid()).isEnabled());
    }

    @Test
    void testDisableLocation_notFound() {
        Assertions.assertThrows(NotFoundException.class, () -> locationService.disableLocation(entityInstanceReference.getSecuredParentUuid(), SecuredUUID.fromString("abfbc322-29e1-11ed-a261-0242ac120002")));
    }

    // TODO: testing the location push, remove, issue, sync
    @Test
    void testPushCertificateToLocation_MultiNotSupported() {
        PushToLocationRequestDto request = new PushToLocationRequestDto();
        request.setAttributes(List.of());

        Assertions.assertThrows(LocationException.class, () -> locationService.pushCertificateToLocation(
                entityInstanceReference.getSecuredParentUuid(),
                locationNoMultiEntries.getSecuredUuid(),
                certificateWithoutLocation.getUuid().toString(), request)
        );
    }

    @Test
    void testIssueCertificateToLocation_KeyManagementNotSupported() {
        IssueToLocationRequestDto request = new IssueToLocationRequestDto();
        request.setCsrAttributes(List.of());
        request.setIssueAttributes(List.of());
        request.setRaProfileUuid("test");

        Assertions.assertThrows(LocationException.class, () -> locationService.issueCertificateToLocation(SecuredParentUUID.fromUUID(locationNoKeyManagement.getEntityInstanceReferenceUuid()),
                locationNoKeyManagement.getSecuredUuid(),
                request.getRaProfileUuid(), request)
        );
    }

    @Test
    void testIssueCertificateToLocation_MultiNotSupported() {
        IssueToLocationRequestDto request = new IssueToLocationRequestDto();
        request.setCsrAttributes(List.of());
        request.setIssueAttributes(List.of());
        request.setRaProfileUuid("test");

        Assertions.assertThrows(LocationException.class, () -> locationService.issueCertificateToLocation(
                SecuredParentUUID.fromUUID(locationNoMultiEntries.getEntityInstanceReferenceUuid()),
                locationNoMultiEntries.getSecuredUuid(),
                request.getRaProfileUuid(), request)
        );
    }

    @Test
    void testSyncLocationWithDuplicateCertificates() throws ConnectorException, LocationException, AttributeException, NotFoundException {
        // Provider returns the same certificate twice under different aliases
        String certBase64 = "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";

        mockServer.stubFor(WireMock
                .get(WireMock.urlPathMatching("/v1/entityProvider/entities/[^/]+/location/attributes"))
                .willReturn(WireMock.okJson("[]")));
        mockServer.stubFor(WireMock
                .post(WireMock.urlPathMatching("/v1/entityProvider/entities/[^/]+/location/attributes/validate"))
                .willReturn(WireMock.okJson("true")));
        mockServer.stubFor(WireMock
                .post(WireMock.urlPathMatching("/v1/entityProvider/entities/[^/]+/locations"))
                .willReturn(WireMock.okJson("""
                        {
                          "certificates": [
                            {"certificateData": "%s", "withKey": true, "certificateType": "X.509"},
                            {"certificateData": "%s", "withKey": false, "certificateType": "X.509"}
                          ],
                          "multipleEntries": true,
                          "supportKeyManagement": true
                        }""".formatted(certBase64, certBase64))));

        EditLocationRequestDto request = new EditLocationRequestDto();
        request.setDescription("sync with duplicates");
        request.setAttributes(List.of());

        LocationDto dto = locationService.editLocation(entityInstanceReference.getSecuredParentUuid(), location.getSecuredUuid(), request);

        // Only one CertificateLocation per unique certificate should exist
        Assertions.assertEquals(1, dto.getCertificates().size());

        // Verify no duplicate rows in DB
        List<CertificateLocation> dbRows = certificateLocationRepository.findByCertificateUuidIn(
                dto.getCertificates().stream()
                        .map(c -> UUID.fromString(c.getCertificateUuid()))
                        .toList());
        long rowsForThisLocation = dbRows.stream()
                .filter(cl -> cl.getLocation().getUuid().equals(location.getUuid()))
                .count();
        Assertions.assertEquals(1, rowsForThisLocation);
    }

    @Test
    void testPushCertificateAlreadyInLocation() throws NotFoundException, LocationException, AttributeException {
        // certificate is already in location from setUp
        Assertions.assertFalse(location.getCertificates().isEmpty());
        UUID existingCertUuid = certificate.getUuid();

        // Count rows before push
        long rowsBefore = certificateLocationRepository.findByCertificateUuidIn(List.of(existingCertUuid)).stream()
                .filter(cl -> cl.getLocation().getUuid().equals(location.getUuid()))
                .count();

        CertificateContent pushContent = new CertificateContent();
        certificateContentRepository.save(pushContent);
        certificate.setCertificateContent(pushContent);
        certificate.setState(CertificateState.ISSUED);
        certificateRepository.save(certificate);

        mockServer.stubFor(WireMock.post(WireMock.urlPathMatching("/v1/entityProvider/entities/[^/]+/locations/push")).willReturn(WireMock.okJson("{\"withKey\": true}")));
        mockServer.stubFor(WireMock.get(WireMock.urlPathMatching("/v1/entityProvider/entities/[^/]+/locations/push/attributes")).willReturn(WireMock.okJson("[]")));
        mockServer.stubFor(WireMock.get(WireMock.urlPathMatching("/v1/entityProvider/entities/[^/]+/locations/csr/attributes")).willReturn(WireMock.okJson("[]")));

        PushToLocationRequestDto pushRequest = new PushToLocationRequestDto();
        pushRequest.setAttributes(new ArrayList<>());

        LocationDto dto = locationService.pushCertificateToLocation(
                entityInstanceReference.getSecuredParentUuid(),
                location.getSecuredUuid(),
                existingCertUuid.toString(),
                pushRequest);

        // Certificate should still appear exactly once
        long certCount = dto.getCertificates().stream()
                .filter(c -> c.getCertificateUuid().equals(existingCertUuid.toString()))
                .count();
        Assertions.assertEquals(1, certCount);

        // Verify no duplicate rows created in DB
        long rowsAfter = certificateLocationRepository.findByCertificateUuidIn(List.of(existingCertUuid)).stream()
                .filter(cl -> cl.getLocation().getUuid().equals(location.getUuid()))
                .count();
        Assertions.assertEquals(rowsBefore, rowsAfter);
    }

    @Test
    void testSyncAfterPushReplacesContent() throws ConnectorException, LocationException, AttributeException, NotFoundException {
        // Push a new certificate to the location
        String certBase64 = "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";

        Certificate pushedCert = new Certificate();
        CertificateContent pushedContent = new CertificateContent();
        certificateContentRepository.save(pushedContent);
        pushedCert.setCertificateContent(pushedContent);
        pushedCert.setState(CertificateState.ISSUED);
        certificateRepository.save(pushedCert);

        mockServer.stubFor(WireMock.post(WireMock.urlPathMatching("/v1/entityProvider/entities/[^/]+/locations/push")).willReturn(WireMock.okJson("{\"withKey\": false}")));
        mockServer.stubFor(WireMock.get(WireMock.urlPathMatching("/v1/entityProvider/entities/[^/]+/locations/push/attributes")).willReturn(WireMock.okJson("[]")));
        mockServer.stubFor(WireMock.get(WireMock.urlPathMatching("/v1/entityProvider/entities/[^/]+/locations/csr/attributes")).willReturn(WireMock.okJson("[]")));

        PushToLocationRequestDto pushRequest = new PushToLocationRequestDto();
        pushRequest.setAttributes(new ArrayList<>());
        locationService.pushCertificateToLocation(
                entityInstanceReference.getSecuredParentUuid(),
                location.getSecuredUuid(),
                pushedCert.getUuid().toString(),
                pushRequest);

        // Location now has 2 certificates: the original from setUp + the pushed one
        long rowsBefore = certificateLocationRepository.findByCertificateUuidIn(
                List.of(certificate.getUuid(), pushedCert.getUuid())).stream()
                .filter(cl -> cl.getLocation().getUuid().equals(location.getUuid()))
                .count();
        Assertions.assertEquals(2, rowsBefore);

        // Sync — provider returns only the new certificate (the original is gone from keystore)
        mockServer.stubFor(WireMock
                .get(WireMock.urlPathMatching("/v1/entityProvider/entities/[^/]+/location/attributes"))
                .willReturn(WireMock.okJson("[]")));
        mockServer.stubFor(WireMock
                .post(WireMock.urlPathMatching("/v1/entityProvider/entities/[^/]+/location/attributes/validate"))
                .willReturn(WireMock.okJson("true")));
        mockServer.stubFor(WireMock
                .post(WireMock.urlPathMatching("/v1/entityProvider/entities/[^/]+/locations"))
                .willReturn(WireMock.okJson("""
                        {
                          "certificates": [
                            {"certificateData": "%s", "withKey": true, "certificateType": "X.509"}
                          ],
                          "multipleEntries": true,
                          "supportKeyManagement": true
                        }""".formatted(certBase64))));

        EditLocationRequestDto request = new EditLocationRequestDto();
        request.setDescription("sync after push");
        request.setAttributes(List.of());

        LocationDto dto = locationService.editLocation(entityInstanceReference.getSecuredParentUuid(), location.getSecuredUuid(), request);

        // Sync replaces all content — only the provider's certificate remains
        Assertions.assertEquals(1, dto.getCertificates().size());

        // The original and pushed certificates are no longer in this location
        long originalCertRows = certificateLocationRepository.findByCertificateUuidIn(List.of(certificate.getUuid())).stream()
                .filter(cl -> cl.getLocation().getUuid().equals(location.getUuid()))
                .count();
        Assertions.assertEquals(0, originalCertRows, "Original certificate should be removed after sync");

        long pushedCertRows = certificateLocationRepository.findByCertificateUuidIn(List.of(pushedCert.getUuid())).stream()
                .filter(cl -> cl.getLocation().getUuid().equals(location.getUuid()))
                .count();
        Assertions.assertEquals(0, pushedCertRows, "Pushed certificate should be removed after sync");
    }

    @Test
    void testGetObjectsForResource() {
        List<NameAndUuidDto> dtos = locationService.listResourceObjects(SecurityFilter.create(), null, null);
        Assertions.assertEquals(3, dtos.size());
    }

    @Test
    void testIssueToLocation() throws ConnectorException, java.security.cert.CertificateException, NoSuchAlgorithmException, CertificateOperationException, IOException, InvalidKeyException, CertificateRequestException, LocationException, NotFoundException {
        RaProfile raProfile = getRaProfile();

        ClientCertificateDataResponseDto responseDto = new ClientCertificateDataResponseDto();

        responseDto.setUuid(certificate.getUuid().toString());
        Mockito.when(clientOperationService.issueCertificate(any(), any(), any(), any())).thenReturn(responseDto);
        mockServer.stubFor(WireMock.get(WireMock.urlPathMatching("/v1/entityProvider/entities/[^/]+/locations/push/attributes")).willReturn(WireMock.okJson("[]")));
        mockServer.stubFor(WireMock.get(WireMock.urlPathMatching("/v1/entityProvider/entities/[^/]+/locations/csr/attributes")).willReturn(WireMock.okJson("[]")));
        mockServer.stubFor(WireMock.post(WireMock.urlPathMatching("/v1/entityProvider/entities/[^/]+/locations/csr")).willReturn(WireMock.okJson("{}")));
        LocationDto locationDto = locationService.issueCertificateToLocation(entityInstanceReference.getSecuredParentUuid(), location.getSecuredUuid(), String.valueOf(raProfile.getUuid()), new IssueToLocationRequestDto());

        Assertions.assertNotNull(locationDto.getCertificates().stream()
                .filter(cl ->  cl.getCertificateUuid().equals(certificate.getUuid().toString()))
                .findFirst().orElse(null));

        Certificate newlyIssuedCertificate = new Certificate();
        certificateRepository.save(newlyIssuedCertificate);
        responseDto.setUuid(newlyIssuedCertificate.getUuid().toString());
        LocationDto locationDto1 = locationService.issueCertificateToLocation(entityInstanceReference.getSecuredParentUuid(), location.getSecuredUuid(), String.valueOf(raProfile.getUuid()), new IssueToLocationRequestDto());
        Assertions.assertNotNull(locationDto1.getCertificates().stream()
                .filter(cl -> cl.getCertificateUuid().equals(newlyIssuedCertificate.getUuid().toString()))
                .findFirst().orElse(null));
    }

    @Test
    void testPushCertificateToLocation() throws NotFoundException, LocationException, AttributeException {
        Certificate certificateToPush = new Certificate();
        CertificateContent certificateContent = new CertificateContent();
        certificateContentRepository.save(certificateContent);
        certificateToPush.setCertificateContent(certificateContent);
        certificateToPush.setState(CertificateState.ISSUED);
        certificateToPush.setArchived(true);
        certificateRepository.save(certificateToPush);
        PushToLocationRequestDto pushRequest = new PushToLocationRequestDto();
        pushRequest.setAttributes(new ArrayList<>());
        mockServer.stubFor(WireMock.post(WireMock.urlPathMatching("/v1/entityProvider/entities/[^/]+/locations/push")).willReturn(WireMock.okJson("{\"withKey\": false}")));
        mockServer.stubFor(WireMock.get(WireMock.urlPathMatching("/v1/entityProvider/entities/[^/]+/locations/push/attributes")).willReturn(WireMock.okJson("[]")));
        mockServer.stubFor(WireMock.get(WireMock.urlPathMatching("/v1/entityProvider/entities/[^/]+/locations/csr/attributes")).willReturn(WireMock.okJson("[]")));
        SecuredParentUUID entityUuid = entityInstanceReference.getSecuredParentUuid();
        SecuredUUID locationUuid = location.getSecuredUuid();
        String certificateUuid = certificateToPush.getUuid().toString();
        Assertions.assertThrows(ValidationException.class, () -> locationService.pushCertificateToLocation(entityUuid, locationUuid, certificateUuid, pushRequest));

        certificateToPush.setArchived(false);
        certificateRepository.save(certificateToPush);
        LocationDto locationDto = locationService.pushCertificateToLocation(entityUuid, locationUuid, certificateUuid, pushRequest);
        Assertions.assertNotNull(locationDto.getCertificates().stream()
                .filter(cl -> cl.getCertificateUuid().equals(certificateUuid))
                .findFirst().orElse(null));
    }

    @Test
    void renewCertificateInLocation() throws ConnectorException, LocationException, CertificateOperationException, java.security.cert.CertificateException, IOException, NoSuchAlgorithmException, InvalidKeyException, CertificateRequestException, NotFoundException {
        CertificateLocation certificateLocation = location.getCertificates().stream().findFirst().get();
        DataAttributeV2 pushAttribute = new DataAttributeV2();
        pushAttribute.setUuid(UUID.randomUUID().toString());
        pushAttribute.setContent(List.of(new StringAttributeContentV2("data", "ref")));
        DataAttributeV3 csrAttribute = new DataAttributeV3();
        csrAttribute.setUuid(UUID.randomUUID().toString());
        csrAttribute.setContent(List.of(new StringAttributeContentV3("data", "ref")));
        certificateLocation.setPushAttributes(List.of(pushAttribute));
        certificateLocation.setCsrAttributes(List.of(csrAttribute));
        locationRepository.save(location);

        certificate.setRaProfile(getRaProfile());
        Certificate renewedCertificate = new Certificate();
        certificateRepository.save(renewedCertificate);
        certificateRepository.save(certificate);

        ClientCertificateDataResponseDto responseDto = new ClientCertificateDataResponseDto();
        responseDto.setUuid(renewedCertificate.getUuid().toString());
        Mockito.when(clientOperationService.renewCertificate(any(), any(), any(), any())).thenReturn(responseDto);

        mockServer.stubFor(WireMock.post(WireMock.urlPathMatching("/v1/entityProvider/entities/[^/]+/locations/csr")).willReturn(WireMock.okJson("{}")));
        mockServer.stubFor(WireMock.get(WireMock.urlPathMatching("/v1/entityProvider/entities/[^/]+/locations/push/attributes")).willReturn(WireMock.okJson("[]")));
        mockServer.stubFor(WireMock.get(WireMock.urlPathMatching("/v1/entityProvider/entities/[^/]+/locations/csr/attributes")).willReturn(WireMock.okJson("[]")));

        certificate.setArchived(true);
        certificateRepository.save(certificate);
        Assertions.assertThrows(LocationException.class, () -> locationService.renewCertificateInLocation(entityInstanceReference.getSecuredParentUuid(), location.getSecuredUuid(), certificate.getUuid().toString()));
        certificate.setArchived(false);
        certificateRepository.save(certificate);
        LocationDto locationDto = locationService.renewCertificateInLocation(entityInstanceReference.getSecuredParentUuid(), location.getSecuredUuid(), certificate.getUuid().toString());
        Assertions.assertNotNull(locationDto.getCertificates().stream()
                .filter(cl ->  cl.getCertificateUuid().equals(renewedCertificate.getUuid().toString()))
                .findFirst().orElse(null));
    }

    @Test
    void testRemoveCertificatesFromLocationsOnDelete() {
        SecuredUUID certificateUuid = certificate.getSecuredUuid();

        List<CertificateLocation> associations = certificateLocationRepository.findByCertificateUuidIn(List.of(certificate.getUuid()));
        Assertions.assertEquals(3, associations.size());

        mockServer.stubFor(WireMock.post(WireMock.urlPathMatching("/v1/entityProvider/entities/[^/]+/locations/remove")).willReturn(WireMock.okJson("{}")));

        locationService.removeCertificatesFromLocationsOnDelete(List.of(certificateUuid));

        mockServer.verify(WireMock.moreThanOrExactly(1), WireMock.postRequestedFor(WireMock.urlPathMatching("/v1/entityProvider/entities/[^/]+/locations/remove")));

        associations = certificateLocationRepository.findByCertificateUuidIn(List.of(certificate.getUuid()));
        Assertions.assertEquals(0, associations.size());
    }

    @Test
    void testGetResourceObject() throws NotFoundException {
        NameAndUuidDto nameAndUuidDto = locationService.getResourceObjectInternal(location.getUuid());
        Assertions.assertEquals(location.getUuid().toString(), nameAndUuidDto.getUuid());
        Assertions.assertEquals(location.getName(), nameAndUuidDto.getName());

        nameAndUuidDto = locationService.getResourceObjectExternal(location.getSecuredUuid());
        Assertions.assertEquals(location.getUuid().toString(), nameAndUuidDto.getUuid());
        Assertions.assertEquals(location.getName(), nameAndUuidDto.getName());
    }

    private RaProfile getRaProfile() {
        RaProfile raProfile = new RaProfile();
        raProfile.setEnabled(true);
        AuthorityInstanceReference authorityInstanceReference = new AuthorityInstanceReference();
        authorityInstanceReference.setStatus("connected");
        Connector connector = new Connector();
        connector.setVersion(ConnectorVersion.V1);
        connector.setStatus(ConnectorStatus.CONNECTED);
        connectorRepository.save(connector);
        authorityInstanceReference.setConnector(connector);
        authorityInstanceReferenceRepository.save(authorityInstanceReference);
        raProfile.setAuthorityInstanceReference(authorityInstanceReference);
        raProfileRepository.save(raProfile);
        return raProfile;
    }

}
