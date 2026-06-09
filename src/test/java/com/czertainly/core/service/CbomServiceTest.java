package com.czertainly.core.service;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.time.OffsetDateTime;
import java.util.ArrayList;
import java.util.Date;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;

import com.czertainly.api.model.common.NameAndUuidDto;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.Mockito;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import org.springframework.test.context.bean.override.mockito.MockitoSpyBean;


import com.czertainly.api.exception.AlreadyExistException;
import com.czertainly.api.exception.CbomRepositoryException;
import com.czertainly.api.exception.NotFoundException;
import com.czertainly.api.exception.ValidationException;
import com.czertainly.api.model.client.certificate.SearchRequestDto;
import com.czertainly.api.model.common.BulkActionMessageDto;
import com.czertainly.api.model.common.PaginationResponseDto;
import com.czertainly.api.model.core.auth.Resource;
import com.czertainly.api.model.core.cbom.CbomDetailDto;
import com.czertainly.api.model.core.cbom.CbomDto;
import com.czertainly.api.model.core.cbom.CbomUploadRequestDto;
import com.czertainly.api.model.core.search.SearchFieldDataByGroupDto;
import com.czertainly.api.model.core.search.SearchFieldDataDto;
import com.czertainly.api.model.core.settings.PlatformSettingsDto;
import com.czertainly.api.model.core.settings.SettingsSection;
import com.czertainly.api.model.core.settings.UtilsSettingsDto;
import com.czertainly.api.model.scheduler.SchedulerJobExecutionStatus;
import com.czertainly.core.attribute.engine.AttributeEngine;
import com.czertainly.core.dao.entity.Cbom;
import com.czertainly.core.dao.entity.ScheduledJob;
import com.czertainly.core.dao.entity.ScheduledJobHistory;
import com.czertainly.core.dao.repository.CbomRepository;
import com.czertainly.core.dao.repository.ScheduledJobHistoryRepository;
import com.czertainly.core.dao.repository.ScheduledJobsRepository;
import com.czertainly.core.enums.FilterField;
import com.czertainly.core.model.cbom.BomEntryDto;
import com.czertainly.core.model.cbom.BomVersionDto;
import com.czertainly.core.model.cbom.CryptoAssetCountDto;
import com.czertainly.core.model.cbom.CryptoAssetsDto;
import com.czertainly.core.model.cbom.CryptoStatsDto;
import com.czertainly.core.security.authz.SecuredUUID;
import com.czertainly.core.security.authz.SecurityFilter;
import com.czertainly.core.settings.SettingsCache;
import com.czertainly.core.tasks.CbomSyncTask;
import com.czertainly.core.util.BaseSpringBootTest;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.github.tomakehurst.wiremock.WireMockServer;
import com.github.tomakehurst.wiremock.client.WireMock;
import com.google.gson.Gson;

class CbomServiceTest extends BaseSpringBootTest {

    private static final String CONTENT_TYPE = "application/vnd.cyclonedx+json";

    private static final String BOM_ENTRY_JSON = """
{
  "serialNumber": "urn:uuid:3e671687-395b-41f5-a30f-a58921a69b79",
  "version": 42,
  "cryptoStats": {
    "cryptoAssets": {
      "algorithms": {
        "total": 5
      },
      "certificates": {
        "total": 3
      },
      "protocols": {
        "total": 2
      },
      "relatedCryptoMaterials": {
        "total": 4
      },
      "total": 14
    }
  }
}
    """;

    @Autowired
    private CbomService cbomService;

    @Autowired
    private CbomRepository cbomRepository;

    @Autowired
    private ScheduledJobHistoryRepository scheduledJobHistoryRepository;

    @Autowired
    private ScheduledJobsRepository scheduledJobsRepository;

    @MockitoBean
    private AttributeEngine attributeEngine;

    @MockitoSpyBean
    private CbomRepository cbomRepositorySpy;

    private WireMockServer mockServer;

    @Autowired
    private SettingsCache settingsCache;

    @Autowired
    private ObjectMapper objectMapper;

    private PlatformSettingsDto originalSettings;

    @BeforeEach
    void setUp() {
        originalSettings = SettingsCache.getSettings(SettingsSection.PLATFORM);

        cbomRepository.deleteAll();
        scheduledJobHistoryRepository.deleteAll();
        scheduledJobsRepository.deleteAll();

        mockServer = new WireMockServer(0);
        mockServer.start();

        WireMock.configureFor("localhost", mockServer.port());

        PlatformSettingsDto platformSettings = new PlatformSettingsDto();
        platformSettings.setUtils(new UtilsSettingsDto());
        platformSettings.getUtils().setCbomRepositoryUrl("http://localhost:" + mockServer.port());
        settingsCache.cacheSettings(SettingsSection.PLATFORM, platformSettings);
    }

    @AfterEach
    void tearDown() {
        mockServer.stop();
        settingsCache.cacheSettings(SettingsSection.PLATFORM, originalSettings);
        Mockito.reset(cbomRepositorySpy);
    }

    @Test
    void testListCboms() {
        // Given
        Cbom cbom = new Cbom();
        cbom.setSerialNumber("testing");
        cbom.setTimestamp(OffsetDateTime.now());
        cbom.setVersion(1);
        cbom.setSpecVersion("1.6");
        cbomRepository.save(cbom);

        // When
        SecurityFilter filter = new SecurityFilter();
        SearchRequestDto search = new SearchRequestDto();
        PaginationResponseDto<CbomDto> response = cbomService.listCboms(filter, search);

        // Then
        assertNotNull(response);
        assertEquals(1, response.getItems().size());
        assertEquals("testing", response.getItems().get(0).getSerialNumber());
    }

    @Test
    void testGetCbomDetail_Success() throws Exception {
        // Given
        SecuredUUID uuid = SecuredUUID.fromString("807d4ff9-8bcf-4dd4-9239-3a8f2a177710");
        String serialNumber = "urn:uuid:3e671687-395b-41f5-a30f-a58921a69b79";
        int version = 1;

        // Create and save Cbom entity
        Cbom cbom = new Cbom();
        cbom.setUuid(uuid.getValue());
        cbom.setSerialNumber(serialNumber);
        cbom.setVersion(version);
        cbom.setSpecVersion("1.6");
        cbom.setTimestamp(OffsetDateTime.now());
        cbomRepository.save(cbom);

        String responseBody = """
        {
        "$schema": "https://cyclonedx.org/schema/bom-1.6.schema.json",
        "bomFormat": "CycloneDX",
        "specVersion": "1.6",
        "serialNumber": "urn:uuid:3e671687-395b-41f5-a30f-a58921a69b79",
        "version": 1,
        "metadata": {},
        "components": []
        }
        """;

        mockServer.stubFor(WireMock.get(WireMock.urlPathMatching("/api/v1/bom/.*"))
            .withQueryParam("version", WireMock.equalTo(Integer.toString(version)))
            .willReturn(WireMock.aResponse()
                .withStatus(200)
                .withHeader("Content-Type", "application/json")
                .withBody(responseBody)));

        // When
        CbomDetailDto result = cbomService.getCbomDetail(uuid);

        // Then
        assertNotNull(result);
        assertEquals(serialNumber, result.getSerialNumber());
        assertEquals(version, result.getVersion());
        assertNotNull(result.getContent());
        assertEquals("CycloneDX", result.getContent().get("bomFormat"));

        // Verify WireMock was called
        mockServer.verify(WireMock.getRequestedFor(
            WireMock.urlPathMatching("/api/v1/bom/.*"))
            .withQueryParam("version", WireMock.equalTo(Integer.toString(version))));
    }

    @Test
    void testGetCbomDetail_NotFoundInCbomRepository() {
        // Given
        SecuredUUID uuid = SecuredUUID.fromString("807d4ff9-8bcf-4dd4-9239-3a8f2a177710");
        String serialNumber = "urn:uuid:3e671687-395b-41f5-a30f-a58921a69b79";
        int version = 1;

        // Create and save Cbom entity
        Cbom cbom = new Cbom();
        cbom.setUuid(uuid.getValue());
        cbom.setSerialNumber(serialNumber);
        cbom.setVersion(version);
        cbom.setSpecVersion("1.6");
        cbom.setTimestamp(OffsetDateTime.now());
        cbomRepository.save(cbom);

        // Mock WireMock to return 404 for the requested BOM
        mockServer.stubFor(WireMock.get(WireMock.urlPathEqualTo("/api/v1/bom/" + serialNumber))
            .willReturn(WireMock.aResponse()
                .withStatus(404)
                .withHeader("Content-Type", "application/problem+json")
                .withBody("{\"status\": 404, \"title\": \"Not Found\"}")));

        // When/Then
        assertThrows(NotFoundException.class, () -> cbomService.getCbomDetail(uuid));
    }

    @Test
    void testGetCbomDetail_CbomRepositoryError() {
        // Given
        SecuredUUID uuid = SecuredUUID.fromString("807d4ff9-8bcf-4dd4-9239-3a8f2a177710");
        String serialNumber = "urn:uuid:3e671687-395b-41f5-a30f-a58921a69b79";
        int version = 1;

        // Create and save Cbom entity
        Cbom cbom = new Cbom();
        cbom.setUuid(uuid.getValue());
        cbom.setSerialNumber(serialNumber);
        cbom.setVersion(version);
        cbom.setSpecVersion("1.6");
        cbom.setTimestamp(OffsetDateTime.now());
        cbomRepository.save(cbom);

        // Mock WireMock to return 500 error for the CBOM repository endpoint
        mockServer.stubFor(WireMock.get(WireMock.urlPathMatching("/api/v1/bom/.*"))
            .withQueryParam("version", WireMock.equalTo(Integer.toString(version)))
            .willReturn(WireMock.aResponse()
                .withStatus(500)
                .withHeader("Content-Type", "application/problem+json")
                .withBody("""
                    {
                        "type": "about:blank",
                        "title": "Internal Server Error",
                        "status": 500,
                        "detail": "Server error occurred"
                    }
                    """)));

        // When/Then - Use assertThrows with Throwable cast
        Exception exception = assertThrows(Exception.class, () -> cbomService.getCbomDetail(uuid));
        assertTrue(exception instanceof CbomRepositoryException,
        "Expected CbomRepositoryException but got: " + exception.getClass().getName());
        CbomRepositoryException cbomException = (CbomRepositoryException) exception;
        assertNotNull(cbomException.getProblemDetail());
        assertEquals(500, cbomException.getProblemDetail().getStatus());
    }

    @Test
    void testCreateCbom_Success() throws Exception {
        // Given
        String serialNumber = "urn:uuid:3e671687-395b-41f5-a30f-a58921a69b79";
        int version = 1;

        LinkedHashMap<String, Object> content = new LinkedHashMap<>();
        content.put("serialNumber", serialNumber);
        content.put("version", version);
        content.put("specVersion", "1.6");

        CbomUploadRequestDto request = new CbomUploadRequestDto();
        request.setContent(content);

        // Mock WireMock to return successful response
        mockServer.stubFor(WireMock.post(WireMock.urlPathEqualTo("/api/v1/bom"))
            .willReturn(WireMock.aResponse()
                .withStatus(201)
                .withHeader("Content-Type", "application/json")
                .withBody("""
                    {
                    "serialNumber": "urn:uuid:3e671687-395b-41f5-a30f-a58921a69b79",
                    "version": 1,
                    "cryptoStats": {
                    "cryptoAssets": {
                    "algorithms": {
                    "total": 5
                    },
                    "certificates": {
                    "total": 3
                    },
                    "protocols": {
                    "total": 2
                    },
                    "relatedCryptoMaterials": {
                    "total": 4
                    },
                    "total": 14
                    }
                    }
                    }
                    """)));

        // When
        CbomDto result = cbomService.createCbom(request);

        // Then
        assertNotNull(result);
        assertEquals(serialNumber, result.getSerialNumber());
        assertEquals(version, result.getVersion());
        assertEquals("1.6", result.getSpecVersion());
        assertEquals(5, result.getAlgorithms());
        assertEquals(3, result.getCertificates());
        assertEquals(2, result.getProtocols());
        assertEquals(4, result.getCryptoMaterial());
        assertEquals(14, result.getTotalAssets());

        // Verify entity was saved to database
        List<Cbom> savedCboms = cbomRepository.findAll();
        assertEquals(1, savedCboms.size());
        assertEquals(serialNumber, savedCboms.getFirst().getSerialNumber());
        assertNull(savedCboms.getFirst().getSource());

        // Assert
        mockServer.verify(WireMock.postRequestedFor(
            WireMock.urlEqualTo("/api/v1/bom")));
    }

    @Test
    void testGetCbomVersions() throws NotFoundException {
        // Given
        String serialNumber = "urn:uuid:test-123";

        Cbom cbom1 = new Cbom();
        cbom1.setSerialNumber(serialNumber);
        cbom1.setVersion(1);
        cbom1.setSpecVersion("1.6");
        cbom1.setTimestamp(OffsetDateTime.now());
        cbom1 = cbomRepository.save(cbom1);

        Cbom cbom2 = new Cbom();
        cbom2.setSerialNumber(serialNumber);
        cbom2.setVersion(2);
        cbom2.setTimestamp(OffsetDateTime.now());
        cbom2.setSpecVersion("1.6");
        cbom2 = cbomRepository.save(cbom2);

        Cbom cbom3 = new Cbom();
        cbom3.setSerialNumber(serialNumber);
        cbom3.setVersion(3);
        cbom3.setTimestamp(OffsetDateTime.now());
        cbom3.setSpecVersion("1.6");
        cbom3 = cbomRepository.save(cbom3);

        List<UUID> uuids = List.of(cbom1, cbom2, cbom3)
            .stream()
            .map(Cbom::getUuid)
            .toList();

        for (UUID uuid: uuids) {
            // When
            List<CbomDto> versions = cbomService.getCbomVersions(SecuredUUID.fromUUID(uuid));

            // Then
            assertNotNull(versions);
            assertEquals(3, versions.size());
            assertEquals(serialNumber, versions.get(0).getSerialNumber());
            assertEquals(serialNumber, versions.get(1).getSerialNumber());
            assertEquals(serialNumber, versions.get(2).getSerialNumber());
        }
    }

    @Test
    void testGetCbomVersions_EmptyList() throws NotFoundException {
        // Given
        SecuredUUID uuid = SecuredUUID.fromString("100a1949-cdf9-49bb-a580-d34aa2f39225");

        // When
        List<CbomDto> versions = cbomService.getCbomVersions(uuid);

        // Then
        assertNotNull(versions);
        assertEquals(0, versions.size());
    }

    @Test
    void testGetCbomVersions_SingleVersion() throws NotFoundException {
        // Given
        String serialNumber = "urn:uuid:single-version";

        Cbom cbom = new Cbom();
        cbom.setSerialNumber(serialNumber);
        cbom.setVersion(1);
        cbom.setSpecVersion("1.6");
        cbom.setTimestamp(OffsetDateTime.now());
        cbom = cbomRepository.save(cbom);

        // When
        List<CbomDto> versions = cbomService.getCbomVersions(cbom.getSecuredUuid());

        // Then
        assertNotNull(versions);
        assertEquals(1, versions.size());
        assertEquals(serialNumber, versions.getFirst().getSerialNumber());
        assertEquals(1, versions.getFirst().getVersion());
    }

    @Test
    void testGetCbomVersions_MultipleSerialNumbers() throws NotFoundException {
        // Given
        String serialNumber1 = "urn:uuid:test-456";
        String serialNumber2 = "urn:uuid:test-789";

        Cbom cbom1 = new Cbom();
        cbom1.setSerialNumber(serialNumber1);
        cbom1.setVersion(1);
        cbom1.setSpecVersion("1.6");
        cbom1.setTimestamp(OffsetDateTime.now());
        cbomRepository.save(cbom1);

        Cbom cbom2 = new Cbom();
        cbom2.setSerialNumber(serialNumber2);
        cbom2.setVersion(1);
        cbom2.setSpecVersion("1.6");
        cbom2.setTimestamp(OffsetDateTime.now());
        cbomRepository.save(cbom2);

        // When
        List<CbomDto> versions = cbomService.getCbomVersions(cbom1.getSecuredUuid());

        // Then
        assertNotNull(versions);
        assertEquals(1, versions.size());
        assertEquals(serialNumber1, versions.get(0).getSerialNumber());
    }

    @Test
    void testUploadCbom_MissingContent() {
        // Given - null content
        CbomUploadRequestDto request = new CbomUploadRequestDto();

        // When / Then
        assertThrows(ValidationException.class, () ->
            cbomService.createCbom(request)
        );
    }

    @Test
    void testUploadCbom_MissingSerialNumber() throws AlreadyExistException, CbomRepositoryException {
        // Given
        LinkedHashMap<String, Object> content = new LinkedHashMap<>();
        // Missing serialNumber
        content.put("bomFormat", "CycloneDX");
        content.put("specVersion", "1.5");
        content.put("version", 1);

        CbomUploadRequestDto request = new CbomUploadRequestDto();
        request.setContent(content);

        mockServer.stubFor(WireMock.post(WireMock.urlPathEqualTo("/api/v1/bom"))
            .willReturn(WireMock.aResponse()
                .withStatus(201)
                .withHeader("Content-Type", "application/json")
                .withBody(BOM_ENTRY_JSON)));

        // When
        CbomDto result = cbomService.createCbom(request);

        assertNotNull(result);
        assertEquals("urn:uuid:3e671687-395b-41f5-a30f-a58921a69b79", result.getSerialNumber());
    }

    @Test
    void testUploadCbom_MissingVersion() throws AlreadyExistException, CbomRepositoryException {
        // Given
        String serialNumber = "urn:uuid:3e671687-395b-41f5-a30f-a58921a69b79";
        LinkedHashMap<String, Object> content = new LinkedHashMap<>();
        content.put("serialNumber", serialNumber);
        content.put("bomFormat", "CycloneDX");
        content.put("specVersion", "1.5");
        // Missing version

        CbomUploadRequestDto request = new CbomUploadRequestDto();
        request.setContent(content);

        mockServer.stubFor(WireMock.post(WireMock.urlPathEqualTo("/api/v1/bom"))
            .willReturn(WireMock.aResponse()
                .withStatus(201)
                .withHeader("Content-Type", "application/json")
                .withBody(BOM_ENTRY_JSON)));

        // When
        CbomDto result = cbomService.createCbom(request);

        // Then
        assertNotNull(result);
        assertEquals(42, result.getVersion());
    }

    @Test
    void testUploadCbom_MissingSpecVersion() {
        // Given
        LinkedHashMap<String, Object> content = new LinkedHashMap<>();
        content.put("serialNumber", "urn:uuid:test-123");
        content.put("bomFormat", "CycloneDX");
        // Missing specVersion
        content.put("version", "1");

        CbomUploadRequestDto request = new CbomUploadRequestDto();
        request.setContent(content);

        // When / Then
        assertThrows(ValidationException.class, () ->
            cbomService.createCbom(request)
        );
    }

    @Test
    void testUploadCbom_MissingMetadata() throws AlreadyExistException, CbomRepositoryException {
        // Given
        LinkedHashMap<String, Object> content = new LinkedHashMap<>();
        content.put("serialNumber", "urn:uuid:test-123");
        content.put("bomFormat", "CycloneDX");
        content.put("specVersion", "1.5");
        content.put("version", "1");
        // Missing metadata

        CbomUploadRequestDto request = new CbomUploadRequestDto();
        request.setContent(content);

        mockServer.stubFor(WireMock.post(WireMock.urlPathEqualTo("/api/v1/bom"))
            .willReturn(WireMock.aResponse()
                .withStatus(201)
                .withHeader("Content-Type", "application/json")
                .withBody(BOM_ENTRY_JSON)));

        // When
        CbomDto result = cbomService.createCbom(request);

        // Then
        assertNotNull(result);
    }

    @Test
    void testUploadCbom_MetadataNotObject() throws AlreadyExistException, CbomRepositoryException {
        // Given
        LinkedHashMap<String, Object> content = new LinkedHashMap<>();
        content.put("serialNumber", "urn:uuid:test-123");
        content.put("bomFormat", "CycloneDX");
        content.put("specVersion", "1.5");
        content.put("version", "1");
        content.put("metadata", "not an object"); // String instead of Map

        CbomUploadRequestDto request = new CbomUploadRequestDto();
        request.setContent(content);

        mockServer.stubFor(WireMock.post(WireMock.urlPathEqualTo("/api/v1/bom"))
            .willReturn(WireMock.aResponse()
                .withStatus(201)
                .withHeader("Content-Type", "application/json")
                .withBody(BOM_ENTRY_JSON)));

        // When
        CbomDto result = cbomService.createCbom(request);

        // Then
        assertNotNull(result);
    }

    @Test
    void testUploadCbom_MissingTimestamp() throws AlreadyExistException, CbomRepositoryException {
        // Given
        LinkedHashMap<String, Object> content = new LinkedHashMap<>();
        content.put("serialNumber", "urn:uuid:test-123");
        content.put("bomFormat", "CycloneDX");
        content.put("specVersion", "1.5");
        content.put("version", "1");

        Map<String, Object> metadata = new HashMap<>();
        // Missing timestamp
        content.put("metadata", metadata);

        CbomUploadRequestDto request = new CbomUploadRequestDto();
        request.setContent(content);

        mockServer.stubFor(WireMock.post(WireMock.urlPathEqualTo("/api/v1/bom"))
            .willReturn(WireMock.aResponse()
                .withStatus(201)
                .withHeader("Content-Type", "application/json")
                .withBody(BOM_ENTRY_JSON)));

        // When
        CbomDto result = cbomService.createCbom(request);

        // Then
        assertNotNull(result);
    }

    @Test
    void testUploadCbom_InvalidTimestampFormat() throws AlreadyExistException, CbomRepositoryException {
        // Given
        LinkedHashMap<String, Object> content = new LinkedHashMap<>();
        content.put("serialNumber", "urn:uuid:test-123");
        content.put("bomFormat", "CycloneDX");
        content.put("specVersion", "1.5");
        content.put("version", "1");

        Map<String, Object> metadata = new HashMap<>();
        metadata.put("timestamp", "not-a-valid-timestamp");
        content.put("metadata", metadata);

        CbomUploadRequestDto request = new CbomUploadRequestDto();
        request.setContent(content);

        mockServer.stubFor(WireMock.post(WireMock.urlPathEqualTo("/api/v1/bom"))
            .willReturn(WireMock.aResponse()
                .withStatus(201)
                .withHeader("Content-Type", "application/json")
                .withBody(BOM_ENTRY_JSON)));

        // When
        CbomDto result = cbomService.createCbom(request);

        // Then
        assertNotNull(result);
    }

    @Test
    void testUploadCbom_TimestampNotAString() throws AlreadyExistException, CbomRepositoryException {
        // Given
        LinkedHashMap<String, Object> content = new LinkedHashMap<>();
        content.put("serialNumber", "urn:uuid:test-123");
        content.put("bomFormat", "CycloneDX");
        content.put("specVersion", "1.5");
        content.put("version", "1");

        Map<String, Object> metadata = new HashMap<>();
        metadata.put("timestamp", 42);
        content.put("metadata", metadata);

        CbomUploadRequestDto request = new CbomUploadRequestDto();
        request.setContent(content);

        mockServer.stubFor(WireMock.post(WireMock.urlPathEqualTo("/api/v1/bom"))
            .willReturn(WireMock.aResponse()
                .withStatus(201)
                .withHeader("Content-Type", "application/json")
                .withBody(BOM_ENTRY_JSON)));

        // When
        CbomDto result = cbomService.createCbom(request);

        // Then
        assertNotNull(result);
    }

    @Test
    void testCreateCbom_AlreadyExists_409Response() throws AlreadyExistException, CbomRepositoryException, JsonProcessingException {
        // Given
        String serialNumber = "urn:uuid:test-123";
        Integer version = 1;

        LinkedHashMap<String, Object> content = new LinkedHashMap<>();
        content.put("serialNumber", serialNumber);
        content.put("bomFormat", "CycloneDX");
        content.put("specVersion", "1.6");
        content.put("version", version);

        CbomUploadRequestDto request = new CbomUploadRequestDto();
        request.setContent(content);

        mockConflictResponse();

        BomVersionDto versionDto = new BomVersionDto();
        versionDto.setTimestamp(OffsetDateTime.now().toString());
        versionDto.setVersion(String.valueOf(version));
        BomEntryDto e = entry(serialNumber, String.valueOf(version), OffsetDateTime.now());
        versionDto.setCryptoStats(e.getCryptoStats());
        // Mock WireMock to return versions list
        mockServer.stubFor(WireMock.get(WireMock.urlMatching("/api/v1/bom/.*/versions"))
            .willReturn(WireMock.aResponse()
                .withStatus(200)
                .withHeader("Content-Type", "application/json")
                .withBody(objectMapper.writeValueAsString(List.of(versionDto)))));

        // When / Then
        cbomService.createCbom(request);

        // Verify entity was saved to database
        List<Cbom> savedCboms = cbomRepository.findAll();
        assertEquals(1, savedCboms.size());

        mockServer.verify(WireMock.postRequestedFor(WireMock.urlEqualTo("/api/v1/bom")));
    }

    @Test
    void testCreateCbom_RepositoryServerError_500() {
        // Given
        String serialNumber = "urn:uuid:server-error";
        Integer version = 1;

        LinkedHashMap<String, Object> content = new LinkedHashMap<>();
        content.put("serialNumber", serialNumber);
        content.put("bomFormat", "CycloneDX");
        content.put("specVersion", "1.5");
        content.put("version", version);

        CbomUploadRequestDto request = new CbomUploadRequestDto();
        request.setContent(content);

        // Mock WireMock to return 500 Server Error
        mockServer.stubFor(WireMock.post(WireMock.urlPathEqualTo("/api/v1/bom"))
            .willReturn(WireMock.aResponse()
                .withStatus(500)
                .withHeader("Content-Type", "application/problem+json")
                .withBody("""
                    {
                    "type": "about:blank",
                    "title": "Internal Server Error",
                    "status": 500,
                    "detail": "Server error occurred"
                    }
                    """)));

        // When / Then
        assertThrows(CbomRepositoryException.class, () ->
            cbomService.createCbom(request)
        );

        // Verify entity was NOT saved to database
        List<Cbom> savedCboms = cbomRepository.findAll();
        assertEquals(0, savedCboms.size());

        mockServer.verify(WireMock.postRequestedFor(WireMock.urlEqualTo("/api/v1/bom")));
    }

    @Test
    void testCreateCbom_BadRequest_400() {
        // Given
        String serialNumber = "urn:uuid:bad-request";
        Integer version = 1;

        LinkedHashMap<String, Object> content = new LinkedHashMap<>();
        content.put("serialNumber", serialNumber);
        content.put("specVersion", "1.5");
        content.put("version", version);

        CbomUploadRequestDto request = new CbomUploadRequestDto();
        request.setContent(content);

        // Mock WireMock to return 400 Bad Request
        mockServer.stubFor(WireMock.post(WireMock.urlPathEqualTo("/api/v1/bom"))
            .willReturn(WireMock.aResponse()
                .withStatus(400)
                .withHeader("Content-Type", "application/problem+json")
                .withBody("""
                    {
                    "type": "about:blank",
                    "title": "Bad Request",
                    "status": 400,
                    "detail": "Unsupported spec version 1.5"
                    }
                    """)));

        // When / Then
        assertThrows(CbomRepositoryException.class, () ->
            cbomService.createCbom(request)
        );

        mockServer.verify(WireMock.postRequestedFor(WireMock.urlEqualTo("/api/v1/bom")));
    }

    @Test
    void testCreateCbom_MultipleCreations() throws Exception {
        // Given
        CbomUploadRequestDto request1 = new CbomUploadRequestDto();

        request1.setContent(new LinkedHashMap<>(Map.of(
            "serialNumber", "urn:uuid:first",
            "version", 1,
            "specVersion", "1.6"
        )));

        CbomUploadRequestDto request2 = new CbomUploadRequestDto();
        request2.setContent(new LinkedHashMap<>(Map.of(
            "serialNumber", "urn:uuid:second",
            "version", 1,
            "specVersion", "1.6"
        )));

        mockServer.stubFor(WireMock.post(WireMock.urlPathEqualTo("/api/v1/bom"))
            .inScenario("multipleCreations")
            .whenScenarioStateIs(com.github.tomakehurst.wiremock.stubbing.Scenario.STARTED)
            .willReturn(WireMock.aResponse()
                .withStatus(201)
                .withHeader("Content-Type", "application/json")
                .withBody(bomEntryJson()))
            .willSetStateTo("second"));

        mockServer.stubFor(WireMock.post(WireMock.urlPathEqualTo("/api/v1/bom"))
            .inScenario("multipleCreations")
            .whenScenarioStateIs("second")
            .willReturn(WireMock.aResponse()
                .withStatus(201)
                .withHeader("Content-Type", "application/json")
                .withBody(bomEntryJson())));

        // When
        CbomDto result1 = cbomService.createCbom(request1);
        CbomDto result2 = cbomService.createCbom(request2);

        // Then
        assertNotNull(result1);
        assertNotNull(result2);

        List<Cbom> savedCboms = cbomRepository.findAll();
        assertEquals(2, savedCboms.size());

        mockServer.verify(2, WireMock.postRequestedFor(WireMock.urlEqualTo("/api/v1/bom")));
    }

    @Test
    void testDeleteCbom_Success() throws NotFoundException {
        Cbom cbom = new Cbom();
        cbom.setSerialNumber("urn:uuid:delete-test");
        cbom.setVersion(1);
        cbom.setSpecVersion("1.6");
        cbom.setTimestamp(OffsetDateTime.now());
        cbom = cbomRepository.save(cbom);
        UUID uuid = cbom.getUuid();

        // Verify it exists
        assertEquals(1, cbomRepository.findAll().size());

        // When
        cbomService.deleteCbom(uuid);

        // Then
        assertEquals(0, cbomRepository.findAll().size());
        assertFalse(cbomRepository.findById(uuid).isPresent());
    }

    @Test
    void testDeleteCbom_NotFound() {
        UUID nonExistentUuid = UUID.randomUUID();
        assertThrows(NotFoundException.class, () -> cbomService.deleteCbom(nonExistentUuid));
    }

    @Test
    void testBulkDeleteCbom_Success() {
        // Given
        Cbom cbom1 = new Cbom();
        cbom1.setSerialNumber("urn:uuid:bulk-delete-1");
        cbom1.setVersion(1);
        cbom1.setSpecVersion("1.6");
        cbom1.setTimestamp(OffsetDateTime.now());
        cbom1 = cbomRepository.save(cbom1);

        Cbom cbom2 = new Cbom();
        cbom2.setSerialNumber("urn:uuid:bulk-delete-2");
        cbom2.setVersion(1);
        cbom2.setSpecVersion("1.6");
        cbom2.setTimestamp(OffsetDateTime.now());
        cbom2 = cbomRepository.save(cbom2);

        Cbom cbom3 = new Cbom();
        cbom3.setSerialNumber("urn:uuid:bulk-delete-3");
        cbom3.setVersion(1);
        cbom3.setSpecVersion("1.6");
        cbom3.setTimestamp(OffsetDateTime.now());
        cbom3 = cbomRepository.save(cbom3);

        List<UUID> uuids = List.of(cbom1.getUuid(), cbom2.getUuid(), cbom3.getUuid());

        // Verify they exist
        assertEquals(3, cbomRepository.findAll().size());

        // When
        List<BulkActionMessageDto> messages = cbomService.bulkDeleteCbom(uuids);

        // Then
        assertEquals(0, messages.size());
        assertEquals(0, cbomRepository.findAll().size());
    }

    @Test
    void testBulkDeleteCbom_PartialSuccess() {
        // Given
        Cbom cbom1 = new Cbom();
        cbom1.setSerialNumber("urn:uuid:bulk-partial-1");
        cbom1.setVersion(1);
        cbom1.setSpecVersion("1.6");
        cbom1.setTimestamp(OffsetDateTime.now());
        cbom1 = cbomRepository.save(cbom1);

        UUID nonExistentUuid = UUID.randomUUID();
        List<UUID> uuids = List.of(cbom1.getUuid(), nonExistentUuid);

        // Verify initial state
        assertEquals(1, cbomRepository.findAll().size());

        // When
        List<BulkActionMessageDto> messages = cbomService.bulkDeleteCbom(uuids);

        // Then
        assertEquals(1, messages.size());
        assertEquals(nonExistentUuid.toString(), messages.getFirst().getUuid());
        assertTrue(messages.getFirst().getMessage().contains("not found"));
        assertEquals(0, cbomRepository.findAll().size());
    }

    @Test
    void testBulkDeleteCbom_AllNotFound() {
        // Given
        UUID nonExistent1 = UUID.randomUUID();
        UUID nonExistent2 = UUID.randomUUID();
        List<UUID> uuids = List.of(nonExistent1, nonExistent2);

        // When
        List<BulkActionMessageDto> messages = cbomService.bulkDeleteCbom(uuids);

        // Then
        assertEquals(2, messages.size());
        assertTrue(messages.stream().allMatch(m -> m.getMessage().contains("not found")));
    }

    @Test
    void testBulkDeleteCbom_NullEmptyList() {
        List<BulkActionMessageDto> messages = cbomService.bulkDeleteCbom(null);
        assertEquals(0, messages.size());

        List<UUID> uuids = List.of();
        messages = cbomService.bulkDeleteCbom(uuids);
        assertEquals(0, messages.size());
    }

    @Test
    void testGetSearchableFieldInformationByGroup() {
        // given
        List<SearchFieldDataByGroupDto> attributeFields = new ArrayList<>();
        Mockito.when(attributeEngine.getResourceSearchableFields(Resource.CBOM, false))
                .thenReturn(attributeFields);

        // when
        List<SearchFieldDataByGroupDto> result = cbomService.getSearchableFieldInformationByGroup();

        // then
        assertNotNull(result);
        assertFalse(result.isEmpty());

        // Verify attributeEngine was called
        Mockito.verify(attributeEngine).getResourceSearchableFields(Resource.CBOM, false);

        // Get the last group (which should be the property group we added)
        SearchFieldDataByGroupDto propertyGroup = result.get(result.size() - 1);

        assertNotNull(propertyGroup);
        assertEquals(9, propertyGroup.getSearchFieldData().size());

        // Verify all expected fields are present
        List<String> fieldNames = propertyGroup.getSearchFieldData().stream()
                .map(SearchFieldDataDto::getFieldIdentifier)
                .toList();

        assertTrue(fieldNames.contains(FilterField.CBOM_SERIAL_NUMBER.name()));
        assertTrue(fieldNames.contains(FilterField.CBOM_VERSION.name()));
        assertTrue(fieldNames.contains(FilterField.CBOM_TIMESTAMP.name()));
        assertTrue(fieldNames.contains(FilterField.CBOM_SOURCE.name()));
        assertTrue(fieldNames.contains(FilterField.CBOM_ALGORITHMS_COUNT.name()));
        assertTrue(fieldNames.contains(FilterField.CBOM_CERTIFICATES_COUNT.name()));
        assertTrue(fieldNames.contains(FilterField.CBOM_PROTOCOLS_COUNT.name()));
        assertTrue(fieldNames.contains(FilterField.CBOM_CRYPTO_MATERIAL_COUNT.name()));
        assertTrue(fieldNames.contains(FilterField.CBOM_TOTAL_ASSETS_COUNT.name()));
    }

    @Test
    void sync_shouldSyncAllEntries_whenNoLastSyncExists() throws Exception {
        // Given
        OffsetDateTime now = OffsetDateTime.now();
        BomEntryDto entry1 = entry("serial-1", "1", now.minusHours(3));
        BomEntryDto entry2 = entry("serial-2", "2", now.minusHours(2));
        BomEntryDto entry3 = entry("serial-3", "3", now.minusHours(1));

        mockSearchResponse(List.of(entry1, entry2, entry3));

        OffsetDateTime timestamp = OffsetDateTime.parse("2024-01-15T10:30:00Z");
        mockEntrySpecVersionSource(entry1, "1.6", "name-1", timestamp);
        mockEntrySpecVersionSource(entry2, "1.7", "name-2", timestamp);
        mockEntrySpecVersionSource(entry3, "1.7", "name-3", timestamp);

        // When
        cbomService.sync();

        // Then
        List<Cbom> savedCboms = cbomRepository.findAll();
        assertEquals(3, savedCboms.size());

        List<String> serialNumbers = savedCboms.stream()
                .map(Cbom::getSerialNumber)
                .sorted()
                .toList();

        assertTrue(serialNumbers.containsAll(List.of("serial-1", "serial-2", "serial-3")));

        List<OffsetDateTime> timestamps = savedCboms.stream()
                .map(Cbom::getTimestamp)
                .toList();

        assertTrue(timestamps.stream().allMatch(timestamp::equals));
    }

    @Test
    void sync_shouldSyncAllEntries_whenNoLastSyncIsNull() throws Exception {
        // Given

        ScheduledJob scheduledJob = new ScheduledJob();
        scheduledJob.setJobName(CbomSyncTask.NAME);
        scheduledJob.setJobClassName(CbomSyncTask.class.getName());
        scheduledJob.setEnabled(true);

        OffsetDateTime now = OffsetDateTime.now();
        BomEntryDto entry1 = entry("serial-1", "1", now.minusHours(3));
        BomEntryDto entry2 = entry("serial-2", "2", now.minusHours(2));
        BomEntryDto entry3 = entry("serial-3", "3", now.minusHours(1));

        mockSearchResponse(List.of(entry1, entry2, entry3));

        mockEntrySpecVersionSource(entry1, "1.6", "name-1", null);
        mockEntrySpecVersionSource(entry2, "1.7", "name-2", null);
        mockEntrySpecVersionSource(entry3, "1.7", "name-3", null);

        // When
        cbomService.sync();

        // Then
        List<Cbom> savedCboms = cbomRepository.findAll();
        assertEquals(3, savedCboms.size());

        List<String> serialNumbers = savedCboms.stream()
                .map(Cbom::getSerialNumber)
                .sorted()
                .toList();

        assertTrue(serialNumbers.containsAll(List.of("serial-1", "serial-2", "serial-3")));

        long nullTimestamps = savedCboms.stream()
                .map(Cbom::getTimestamp)
                .count();
        assertEquals(3, nullTimestamps);
    }

    @Test
    void syncAuthorized_shouldSyncAllEntries_whenNoLastSyncExists() throws Exception {
        // Given
        OffsetDateTime now = OffsetDateTime.now();
        BomEntryDto entry1 = entry("serial-1", "1", now.minusHours(3));
        BomEntryDto entry2 = entry("serial-2", "2", now.minusHours(2));
        BomEntryDto entry3 = entry("serial-3", "3", now.minusHours(1));

        mockSearchResponse(List.of(entry1, entry2, entry3));

        mockEntrySpecVersionSource(entry1, "1.6", "name-1");
        mockEntrySpecVersionSource(entry2, "1.7", "name-2");
        mockEntrySpecVersionSource(entry3, "1.7", "name-3");

        // When
        cbomService.syncAuthorized();

        // Then
        List<Cbom> savedCboms = cbomRepository.findAll();
        assertEquals(3, savedCboms.size());

        List<String> serialNumbers = savedCboms.stream()
                .map(Cbom::getSerialNumber)
                .sorted()
                .toList();

        assertTrue(serialNumbers.containsAll(List.of("serial-1", "serial-2", "serial-3")));

        // Resync again
        cbomService.syncAuthorized();

        // Then should be still 3 entries (no duplicates)
        savedCboms = cbomRepository.findAll();
        assertEquals(3, savedCboms.size());
    }

    @Test
    void sync_shouldUseTimestampFromLastSuccess() throws Exception {
        // Given: A successful job from 1 hour ago
        Date oneHourAgo = new Date(System.currentTimeMillis() - 3600 * 1000);
        ScheduledJob scheduledJob = new ScheduledJob();
        scheduledJob.setJobName(CbomSyncTask.NAME);
        scheduledJob.setJobClassName(CbomSyncTask.class.getName());
        scheduledJob.setEnabled(true);
        scheduledJob = scheduledJobsRepository.save(scheduledJob);

        ScheduledJobHistory history = new ScheduledJobHistory();
        history.setScheduledJobUuid(scheduledJob.getUuid());
        history.setJobExecution(oneHourAgo);
        history.setJobEndTime(oneHourAgo);
        history.setSchedulerExecutionStatus(SchedulerJobExecutionStatus.SUCCESS);
        scheduledJobHistoryRepository.save(history);

        long safetyOverlapSeconds = 60L;
        long baseTimestamp = oneHourAgo.getTime() / 1000;
        long expectedAfter = Math.max(0L, baseTimestamp - safetyOverlapSeconds);

        mockServer.stubFor(WireMock.get(WireMock.urlPathEqualTo("/api/v1/bom"))
            .withQueryParam("after", WireMock.equalTo(String.valueOf(expectedAfter)))
            .willReturn(WireMock.aResponse()
                .withStatus(200)
                .withHeader("Content-Type", "application/json")
                .withBody("[]")));

        // When
        cbomService.sync();

        // Then: WireMock verification ensures the 'after' param matched the DB timestamp
        mockServer.verify(WireMock.getRequestedFor(WireMock.urlPathEqualTo("/api/v1/bom"))
            .withQueryParam("after", WireMock.equalTo(String.valueOf(expectedAfter))));
    }

    @Test
    void sync_ThrowsCbomRepositoryExceptionOn500Error() {
        // Given: cbom-repository does not work
        mockServer.stubFor(WireMock.get(WireMock.urlPathEqualTo("/api/v1/bom"))
            .willReturn(WireMock.aResponse()
                .withStatus(500)
                .withHeader("Content-Type", "application/problem+json")
                .withBody("""
                    {
                    "type": "about:blank",
                    "title": "Internal Server Error",
                    "status": 500,
                    "detail": "Server error occurred"
                    }
                    """)));

        // Then sync should throw an exception
        assertThrows(CbomRepositoryException.class, () -> {
            cbomService.sync();
        });

        mockServer.verify(WireMock.getRequestedFor(WireMock.urlPathEqualTo("/api/v1/bom"))
            .withQueryParam("after", WireMock.equalTo("0")));
    }

    @Test
    void sync_NumberFormatExceptionIgnored() throws Exception {
        // Given
        OffsetDateTime now = OffsetDateTime.now();
        BomEntryDto entry1 = entry("serial-1", "1", now.minusHours(3));
        entry1.setVersion("bogus");
        List<BomEntryDto> response = List.of(entry1);

        mockSearchResponse(response);

        // When
        cbomService.sync();

        // Then no boms were stored
        List<Cbom> savedCboms = cbomRepository.findAll();
        assertEquals(0, savedCboms.size());
        // ... and no get detail REST API has been called
        mockServer.verify(0, WireMock.getRequestedFor(WireMock.urlPathEqualTo("/api/v1/bom/serial-1")));
    }

    @Test
    void sync_NotFoundExceptionIgnored() throws Exception {
        // Given
        OffsetDateTime now = OffsetDateTime.now();
        BomEntryDto entry1 = entry("serial-1", "1", now.minusHours(3));
        BomEntryDto entry2 = entry("serial-2", "2", now.minusHours(3));
        mockSearchResponse(List.of(entry1, entry2));

        // ... serial-1 exists and serial-2 gets not found
        mockEntrySpecVersionSource(entry1, "1.6", "name-1");
        mockServer.stubFor(WireMock.get(WireMock.urlPathMatching("/api/v1/bom/serial-2"))
            .withQueryParam("version", WireMock.equalTo("2"))
            .willReturn(WireMock.aResponse()
                .withStatus(404)
                .withHeader("Content-Type", "application/problem+json")
                .withBody("""
                    {
                        "type": "about:blank",
                        "title": "Not Found",
                        "status": 404,
                        "detail": "Requested CBOM not found"
                    }
                    """)));

        // When
        cbomService.sync();

        // Then no boms were stored
        List<Cbom> savedCboms = cbomRepository.findAll();
        assertEquals(1, savedCboms.size());
        List<String> serialNumbers = savedCboms.stream()
                .map(Cbom::getSerialNumber)
                .sorted()
                .toList();

        assertTrue(serialNumbers.containsAll(List.of("serial-1")));
    }

    @Test
    void testGetResourceObject() throws NotFoundException {
        Cbom cbom = new Cbom();
        cbom.setSerialNumber("testing");
        cbom.setTimestamp(OffsetDateTime.now());
        cbom.setVersion(1);
        cbom.setSpecVersion("1.6");
        cbomRepository.save(cbom);

        NameAndUuidDto nameAndUuidDto = cbomService.getResourceObjectInternal(cbom.getUuid());
        Assertions.assertEquals(cbom.getUuid().toString(), nameAndUuidDto.getUuid());
        Assertions.assertEquals(cbom.getSerialNumber(), nameAndUuidDto.getName());

        nameAndUuidDto = cbomService.getResourceObjectExternal(cbom.getSecuredUuid());
        Assertions.assertEquals(cbom.getUuid().toString(), nameAndUuidDto.getUuid());
        Assertions.assertEquals(cbom.getSerialNumber(), nameAndUuidDto.getName());

    }

    @Test
    void testCreateCbom_AlreadyExists_VersionNotFoundInList() throws JsonProcessingException {
        // Given
        String serialNumber = "urn:uuid:test-version-missing";
        Integer version = 5;

        LinkedHashMap<String, Object> content = new LinkedHashMap<>();
        content.put("serialNumber", serialNumber);
        content.put("bomFormat", "CycloneDX");
        content.put("specVersion", "1.6");
        content.put("version", version);

        CbomUploadRequestDto request = new CbomUploadRequestDto();
        request.setContent(content);

        mockConflictResponse();

        // Mock versions endpoint to return list WITHOUT the version we're looking for
        BomVersionDto versionDto1 = new BomVersionDto();
        versionDto1.setTimestamp(OffsetDateTime.now().toString());
        versionDto1.setVersion("1");
        versionDto1.setCryptoStats(new CryptoStatsDto());

        BomVersionDto versionDto2 = new BomVersionDto();
        versionDto2.setTimestamp(OffsetDateTime.now().toString());
        versionDto2.setVersion("3");
        versionDto2.setCryptoStats(new CryptoStatsDto());

        // Version 5 is NOT in this list - should trigger the exception
        mockServer.stubFor(WireMock.get(WireMock.urlMatching("/api/v1/bom/.*/versions"))
            .willReturn(WireMock.aResponse()
                .withStatus(200)
                .withHeader("Content-Type", "application/json")
                .withBody(objectMapper.writeValueAsString(List.of(versionDto1, versionDto2)))));

        // When / Then
        CbomRepositoryException exception = assertThrows(CbomRepositoryException.class, 
        () -> cbomService.createCbom(request));

        assertNotNull(exception.getProblemDetail());
        assertEquals(500, exception.getProblemDetail().getStatus());
        assertEquals("CBOM serialNumber and version is reported as existing but was not found in the repository. Please try to upload it again to synchronize state.", exception.getProblemDetail().getDetail());

        mockServer.verify(WireMock.postRequestedFor(WireMock.urlEqualTo("/api/v1/bom")));
        mockServer.verify(WireMock.getRequestedFor(WireMock.urlMatching("/api/v1/bom/.*/versions")));
    }

    @Test
    void testCreateCbom_AlreadyExistsInLocalDb() throws Exception {
        // Given - entry already committed to local DB
        String serialNumber = "urn:uuid:already-local";
        int version = 1;

        Cbom existing = new Cbom();
        existing.setSerialNumber(serialNumber);
        existing.setVersion(version);
        existing.setSpecVersion("1.6");
        existing.setTimestamp(OffsetDateTime.now());
        cbomRepository.save(existing);

        LinkedHashMap<String, Object> content = new LinkedHashMap<>();
        content.put("serialNumber", serialNumber);
        content.put("version", version);
        content.put("specVersion", "1.6");

        CbomUploadRequestDto request = new CbomUploadRequestDto();
        request.setContent(content);

        // Repository accepts the upload (201) with the same serialNumber/version
        mockServer.stubFor(WireMock.post(WireMock.urlPathEqualTo("/api/v1/bom"))
            .willReturn(WireMock.aResponse()
                .withStatus(201)
                .withHeader("Content-Type", "application/json")
                .withBody("""
                    {
                      "serialNumber": "urn:uuid:already-local",
                      "version": 1,
                      "cryptoStats": {
                        "cryptoAssets": {
                          "algorithms": { "total": 1 },
                          "certificates": { "total": 1 },
                          "protocols": { "total": 1 },
                          "relatedCryptoMaterials": { "total": 1 },
                          "total": 4
                        }
                      }
                    }
                    """)));

        // When / Then - local DB pre-check fires (line 252)
        assertThrows(AlreadyExistException.class, () -> cbomService.createCbom(request));
        assertEquals(1, cbomRepository.findAll().size());
    }

    @Test
    void sync_shouldCountDuplicate_whenRaceConditionInCreateCbomEntry() throws Exception {
        // Race condition: validateSyncedCbomEntry (first check) sees no entry,
        // but createCbomEntry (second check, new transaction) finds it already exists.
        String serialNumber = "serial-race";
        int version = 1;

        BomEntryDto entry = entry(serialNumber, String.valueOf(version), OffsetDateTime.now());
        mockSearchResponse(List.of(entry));
        mockEntrySpecVersionSource(entry, "1.6", "source");

        Mockito.doReturn(false)  // validateSyncedCbomEntry: passes
               .doReturn(true)   // createCbomEntry: already exists
               .when(cbomRepositorySpy).existsBySerialNumberAndVersion(serialNumber, version);

        // When
        String result = cbomService.sync();

        // Then: counted as duplicate, nothing stored
        assertTrue(result.contains("skipped duplicates 1"));
        assertTrue(result.contains("stored 0 new entries"));
    }

    @Test
    void sync_shouldHandleDataIntegrityViolation_asAlreadyExist() throws Exception {
        // Race condition fallback: both existence checks pass (false),
        // but save() fails with a unique constraint violation.
        String serialNumber = "serial-integrity";
        int version = 1;

        BomEntryDto entry = entry(serialNumber, String.valueOf(version), OffsetDateTime.now());
        mockSearchResponse(List.of(entry));
        mockEntrySpecVersionSource(entry, "1.6", "source");

        Mockito.doReturn(false)
               .when(cbomRepositorySpy).existsBySerialNumberAndVersion(serialNumber, version);
        Mockito.doThrow(new org.springframework.dao.DataIntegrityViolationException("duplicate key"))
               .when(cbomRepositorySpy).save(Mockito.any(Cbom.class));

        // When
        String result = cbomService.sync();

        // Then: DataIntegrityViolationException propagates out of the transaction and is counted as duplicate
        assertTrue(result.contains("skipped duplicates 1"));
        assertTrue(result.contains("stored 0 new entries"));
    }

    private String bomEntryJson() {
        return BOM_ENTRY_JSON.replace("urn:uuid:3e671687-395b-41f5-a30f-a58921a69b79", "urn:uuid:" + UUID.randomUUID());
    }

    private BomEntryDto entry(String serialNumber, String version, OffsetDateTime timestamp) {
        CryptoAssetCountDto count = new CryptoAssetCountDto();
        count.setTotal(1);

        CryptoAssetsDto cryptoAssets = new CryptoAssetsDto();
        cryptoAssets.setAlgorithms(count);
        cryptoAssets.setCertificates(count);
        cryptoAssets.setProtocols(count);
        cryptoAssets.setRelatedCryptoMaterials(count);
        cryptoAssets.setTotal(4);

        CryptoStatsDto cryptoStats = new CryptoStatsDto();
        cryptoStats.setCryptoAssets(cryptoAssets);

        BomEntryDto entry = new BomEntryDto();
        entry.setSerialNumber(serialNumber);
        entry.setVersion(version);
        entry.setTimestamp(timestamp);
        entry.setCryptoStats(cryptoStats);

        return entry;
    }

    private void mockEntrySpecVersionSource(BomEntryDto entry, String specVersion, String source) {
        mockEntrySpecVersionSource(entry, specVersion, source, null);
    }

    private void mockEntrySpecVersionSource(BomEntryDto entry, String specVersion, String source, OffsetDateTime timestamp) {
        Map<String, Object> metadata = new HashMap<>();
        if (timestamp != null) {
            metadata.put("timestamp", timestamp.toString());
        }
        metadata.put("component", Map.of("name", source));

        Map<String, Object> response = Map.of(
            "specVersion", specVersion,
            "metadata", metadata
        );

        mockServer.stubFor(WireMock.get(WireMock.urlPathEqualTo("/api/v1/bom/" + entry.getSerialNumber()))
            .withQueryParam("version", WireMock.equalTo(entry.getVersion()))
            .willReturn(WireMock.aResponse()
                .withStatus(200)
                .withHeader("Content-Type", CONTENT_TYPE)
                .withBody(new Gson().toJson(response))));
    }

    private void mockSearchResponse(List<BomEntryDto>  response) throws JsonProcessingException {
        String jsonBody = objectMapper.writeValueAsString(response);

        mockServer.stubFor(WireMock.get(WireMock.urlPathEqualTo("/api/v1/bom"))
            .withQueryParam("after", WireMock.matching("\\d+"))
            .willReturn(WireMock.aResponse()
                .withStatus(200)
                .withHeader("Content-Type", "application/json")
                .withBody(jsonBody)));
    }

    private void mockConflictResponse() {
        // Mock WireMock to return 409 Conflict
        mockServer.stubFor(WireMock.post(WireMock.urlPathEqualTo("/api/v1/bom"))
            .willReturn(WireMock.aResponse()
                .withStatus(409)
                .withHeader("Content-Type", "application/problem+json")
                .withBody("""
                    {
                    "type": "about:blank",
                    "title": "Conflict",
                    "status": 409,
                    "detail": "CBOM with this serial number and version already exists"
                    }
                    """)));
    }

    @Test
    void testBulkDeleteCbom_deleteFailure_returnsErrorMessage() {
        Cbom cbom = new Cbom();
        cbom.setSerialNumber("urn:uuid:spy-test-1");
        cbom.setVersion(1);
        cbom.setSpecVersion("1.6");
        cbom.setTimestamp(OffsetDateTime.now());
        cbom = cbomRepository.save(cbom);
        final UUID savedUuid = cbom.getUuid();

        Mockito.doThrow(new RuntimeException("DB delete error"))
                .when(cbomRepositorySpy).deleteById(savedUuid);

        List<BulkActionMessageDto> messages = cbomService.bulkDeleteCbom(List.of(savedUuid));

        Assertions.assertEquals(1, messages.size());
        Assertions.assertEquals(savedUuid.toString(), messages.getFirst().getUuid());
        Assertions.assertNotNull(messages.getFirst().getMessage());
    }
}
