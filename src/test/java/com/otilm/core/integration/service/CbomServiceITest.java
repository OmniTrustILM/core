package com.otilm.core.integration.service;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.github.tomakehurst.wiremock.WireMockServer;
import com.github.tomakehurst.wiremock.client.WireMock;
import com.google.gson.Gson;
import com.otilm.api.exception.AlreadyExistException;
import com.otilm.api.exception.CbomRepositoryException;
import com.otilm.api.exception.NotFoundException;
import com.otilm.api.exception.ValidationException;
import com.otilm.api.model.client.certificate.SearchRequestDto;
import com.otilm.api.model.common.BulkActionMessageDto;
import com.otilm.api.model.common.NameAndUuidDto;
import com.otilm.api.model.common.PaginationResponseDto;
import com.otilm.api.model.core.auth.Resource;
import com.otilm.api.model.core.cbom.CbomAssetSyncState;
import com.otilm.api.model.core.cbom.CbomDetailDto;
import com.otilm.api.model.core.cbom.CbomDto;
import com.otilm.api.model.core.cbom.CbomUploadRequestDto;
import com.otilm.api.model.core.cryptoasset.CryptographicAssetType;
import com.otilm.api.model.core.search.SearchFieldDataByGroupDto;
import com.otilm.api.model.core.search.SearchFieldDataDto;
import com.otilm.api.model.core.settings.PlatformSettingsDto;
import com.otilm.api.model.core.settings.SettingsSection;
import com.otilm.api.model.core.settings.UtilsSettingsDto;
import com.otilm.api.model.scheduler.SchedulerJobExecutionStatus;
import com.otilm.core.attribute.engine.AttributeEngine;
import com.otilm.core.cbom.asset.AssetRowKeys;
import com.otilm.core.cbom.asset.CryptoAssetIdentityFields;
import com.otilm.core.cbom.ingest.CbomAssetDetachService;
import com.otilm.core.dao.entity.Cbom;
import com.otilm.core.dao.entity.ScheduledJob;
import com.otilm.core.dao.entity.ScheduledJobHistory;
import com.otilm.core.dao.repository.CbomRepository;
import com.otilm.core.dao.repository.ScheduledJobHistoryRepository;
import com.otilm.core.dao.repository.ScheduledJobsRepository;
import com.otilm.core.dao.repository.cbom.CbomSyncSkipRepository;
import com.otilm.core.dao.repository.cbom.CbomTombstoneRepository;
import com.otilm.core.dao.repository.cbom.CryptoAssetRepository;
import com.otilm.core.dao.repository.cbom.CryptoAssetSourceRepository;
import com.otilm.core.enums.FilterField;
import com.otilm.core.model.cbom.BomEntryDto;
import com.otilm.core.model.cbom.BomVersionDto;
import com.otilm.core.model.cbom.CryptoAssetCountDto;
import com.otilm.core.model.cbom.CryptoAssetsDto;
import com.otilm.core.model.cbom.CryptoStatsDto;
import com.otilm.core.security.authz.SecuredUUID;
import com.otilm.core.security.authz.SecurityFilter;
import com.otilm.core.service.CbomExternalService;
import com.otilm.core.service.CbomInternalService;
import com.otilm.core.service.writer.cbom.CbomAssetSyncStateWriter;
import com.otilm.core.service.writer.cbom.CryptoAssetSourceWriter;
import com.otilm.core.service.writer.cbom.CryptoAssetWriter;
import com.otilm.core.settings.SettingsCache;
import com.otilm.core.tasks.CbomSyncTask;
import com.otilm.core.util.BaseSpringBootTest;
import java.sql.SQLException;
import java.time.OffsetDateTime;
import java.time.temporal.ChronoUnit;
import java.util.ArrayList;
import java.util.Date;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import org.hibernate.exception.ConstraintViolationException;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.dao.DataIntegrityViolationException;
import org.springframework.data.domain.Limit;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import org.springframework.test.context.bean.override.mockito.MockitoSpyBean;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.any;
import static org.mockito.Mockito.doReturn;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.reset;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

class CbomServiceITest extends BaseSpringBootTest {

    private static final String CONTENT_TYPE = "application/vnd.cyclonedx+json";

    /** Two components the extractor keys as distinct algorithm assets. */
    private static final String TWO_ALGORITHM_COMPONENTS = """
            [{"type":"cryptographic-asset","name":"AES-256",
              "cryptoProperties":{"assetType":"algorithm","algorithmProperties":{}}},
             {"type":"cryptographic-asset","name":"RSA-2048",
              "cryptoProperties":{"assetType":"algorithm","algorithmProperties":{}}}]
            """;

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
    private CbomExternalService cbomService;

    @Autowired
    private CbomInternalService cbomInternalService;

    @Autowired
    private CbomRepository cbomRepository;

    @Autowired
    private CbomSyncSkipRepository skipRepository;

    @Autowired
    private CbomTombstoneRepository tombstoneRepository;

    @Autowired
    private CryptoAssetRepository cryptoAssetRepository;

    @Autowired
    private CryptoAssetSourceRepository cryptoAssetSourceRepository;

    @Autowired
    private CbomAssetSyncStateWriter syncStateWriter;

    @Autowired
    private ScheduledJobHistoryRepository scheduledJobHistoryRepository;

    @Autowired
    private ScheduledJobsRepository scheduledJobsRepository;

    @MockitoBean
    private AttributeEngine attributeEngine;

    @Autowired
    private CryptoAssetWriter cryptoAssetWriter;

    @Autowired
    private CryptoAssetSourceWriter cryptoAssetSourceWriter;

    @MockitoSpyBean
    private CbomRepository cbomRepositorySpy;

    @MockitoSpyBean
    private CbomAssetDetachService detachServiceSpy;

    @MockitoSpyBean
    private CbomTombstoneRepository tombstoneRepositorySpy;

    @MockitoSpyBean
    private CbomAssetSyncStateWriter syncStateWriterSpy;

    private WireMockServer mockServer;

    @Autowired
    private SettingsCache settingsCache;

    @Autowired
    private ObjectMapper objectMapper;

    private PlatformSettingsDto originalSettings;

    @BeforeEach
    void setUp() {
        originalSettings = SettingsCache.getSettings(SettingsSection.PLATFORM);

        // crypto_asset_source_to_cbom_key is RESTRICT, so a CBOM with sources cannot be deleted until they are gone.
        cryptoAssetSourceRepository.deleteAll();
        cryptoAssetRepository.deleteAll();
        cbomRepository.deleteAll();
        tombstoneRepository.deleteAll();
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
        reset(cbomRepositorySpy);
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
    void listServesTheAssetSyncStateFields() {
        // Given
        Cbom cbom = new Cbom();
        cbom.setSerialNumber("urn:uuid:sync-state-list");
        cbom.setTimestamp(OffsetDateTime.now());
        cbom.setVersion(1);
        cbom.setSpecVersion("1.6");
        cbom = cbomRepository.save(cbom);

        // Truncated to microseconds: the DB column stores microsecond precision, so a nanosecond-precision
        // `now()` would round on the way back out and break the round-trip equality below.
        OffsetDateTime syncedAt = OffsetDateTime.now().minusMinutes(5).truncatedTo(ChronoUnit.MICROS);

        SecurityFilter filter = new SecurityFilter();
        SearchRequestDto search = new SearchRequestDto();

        // When / Then - freshly-seeded row reads as PENDING with no synced timestamp
        PaginationResponseDto<CbomDto> beforeSync = cbomService.listCboms(filter, search);
        assertEquals(CbomAssetSyncState.PENDING, beforeSync.getItems().getFirst().getAssetSyncState());
        assertNull(beforeSync.getItems().getFirst().getAssetSyncedAt());

        // When
        syncStateWriter.markSynced(cbom.getUuid(), syncedAt);

        // Then
        PaginationResponseDto<CbomDto> afterSync = cbomService.listCboms(filter, search);
        assertEquals(CbomAssetSyncState.SYNCED, afterSync.getItems().getFirst().getAssetSyncState());
        assertEquals(syncedAt.toInstant(), afterSync.getItems().getFirst().getAssetSyncedAt().toInstant());
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

        mockServer
                .stubFor(WireMock
                        .get(WireMock.urlPathMatching("/api/v1/bom/.*"))
                        .withQueryParam("version", WireMock.equalTo(Integer.toString(version)))
                        .willReturn(WireMock
                                .aResponse()
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
        mockServer
                .verify(WireMock
                        .getRequestedFor(WireMock.urlPathMatching("/api/v1/bom/.*"))
                        .withQueryParam("version", WireMock.equalTo(Integer.toString(version))));
    }

    @Test
    void detailServesTheAssetSyncStateFields() throws Exception {
        // Given
        SecuredUUID uuid = SecuredUUID.fromString("807d4ff9-8bcf-4dd4-9239-3a8f2a177710");
        String serialNumber = "urn:uuid:3e671687-395b-41f5-a30f-a58921a69b79";
        int version = 1;

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

        mockServer
                .stubFor(WireMock
                        .get(WireMock.urlPathMatching("/api/v1/bom/.*"))
                        .withQueryParam("version", WireMock.equalTo(Integer.toString(version)))
                        .willReturn(WireMock
                                .aResponse()
                                .withStatus(200)
                                .withHeader("Content-Type", "application/json")
                                .withBody(responseBody)));

        // Truncated to microseconds: the DB column stores microsecond precision, so a nanosecond-precision
        // `now()` would round on the way back out and break the round-trip equality below.
        OffsetDateTime syncedAt = OffsetDateTime.now().minusMinutes(5).truncatedTo(ChronoUnit.MICROS);

        // When / Then - freshly-seeded row reads as PENDING with no synced timestamp
        CbomDetailDto beforeSync = cbomService.getCbomDetail(uuid);
        assertEquals(CbomAssetSyncState.PENDING, beforeSync.getAssetSyncState());
        assertNull(beforeSync.getAssetSyncedAt());

        // When
        syncStateWriter.markSynced(uuid.getValue(), syncedAt);

        // Then
        CbomDetailDto afterSync = cbomService.getCbomDetail(uuid);
        assertEquals(CbomAssetSyncState.SYNCED, afterSync.getAssetSyncState());
        assertEquals(syncedAt.toInstant(), afterSync.getAssetSyncedAt().toInstant());
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
        mockServer
                .stubFor(WireMock
                        .get(WireMock.urlPathEqualTo("/api/v1/bom/" + serialNumber))
                        .willReturn(WireMock
                                .aResponse()
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
        mockServer
                .stubFor(WireMock
                        .get(WireMock.urlPathMatching("/api/v1/bom/.*"))
                        .withQueryParam("version", WireMock.equalTo(Integer.toString(version)))
                        .willReturn(WireMock
                                .aResponse()
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
        mockServer
                .stubFor(WireMock
                        .post(WireMock.urlPathEqualTo("/api/v1/bom"))
                        .willReturn(WireMock
                                .aResponse()
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
        mockServer.verify(WireMock.postRequestedFor(WireMock.urlEqualTo("/api/v1/bom")));
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

        List<UUID> uuids = List.of(cbom1, cbom2, cbom3).stream().map(Cbom::getUuid).toList();

        for (UUID uuid : uuids) {
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
        assertThrows(ValidationException.class, () -> cbomService.createCbom(request));
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

        mockServer
                .stubFor(WireMock
                        .post(WireMock.urlPathEqualTo("/api/v1/bom"))
                        .willReturn(WireMock
                                .aResponse()
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

        mockServer
                .stubFor(WireMock
                        .post(WireMock.urlPathEqualTo("/api/v1/bom"))
                        .willReturn(WireMock
                                .aResponse()
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
        assertThrows(ValidationException.class, () -> cbomService.createCbom(request));
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

        mockServer
                .stubFor(WireMock
                        .post(WireMock.urlPathEqualTo("/api/v1/bom"))
                        .willReturn(WireMock
                                .aResponse()
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

        mockServer
                .stubFor(WireMock
                        .post(WireMock.urlPathEqualTo("/api/v1/bom"))
                        .willReturn(WireMock
                                .aResponse()
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

        mockServer
                .stubFor(WireMock
                        .post(WireMock.urlPathEqualTo("/api/v1/bom"))
                        .willReturn(WireMock
                                .aResponse()
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

        mockServer
                .stubFor(WireMock
                        .post(WireMock.urlPathEqualTo("/api/v1/bom"))
                        .willReturn(WireMock
                                .aResponse()
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

        mockServer
                .stubFor(WireMock
                        .post(WireMock.urlPathEqualTo("/api/v1/bom"))
                        .willReturn(WireMock
                                .aResponse()
                                .withStatus(201)
                                .withHeader("Content-Type", "application/json")
                                .withBody(BOM_ENTRY_JSON)));

        // When
        CbomDto result = cbomService.createCbom(request);

        // Then
        assertNotNull(result);
    }

    @Test
    void testCreateCbom_AlreadyExists_409Response()
            throws AlreadyExistException, CbomRepositoryException, JsonProcessingException {
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
        mockServer
                .stubFor(WireMock
                        .get(WireMock.urlMatching("/api/v1/bom/.*/versions"))
                        .willReturn(WireMock
                                .aResponse()
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
        mockServer
                .stubFor(WireMock
                        .post(WireMock.urlPathEqualTo("/api/v1/bom"))
                        .willReturn(WireMock
                                .aResponse()
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
        assertThrows(CbomRepositoryException.class, () -> cbomService.createCbom(request));

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
        mockServer
                .stubFor(WireMock
                        .post(WireMock.urlPathEqualTo("/api/v1/bom"))
                        .willReturn(WireMock
                                .aResponse()
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
        assertThrows(CbomRepositoryException.class, () -> cbomService.createCbom(request));

        mockServer.verify(WireMock.postRequestedFor(WireMock.urlEqualTo("/api/v1/bom")));
    }

    @Test
    void testCreateCbom_MultipleCreations() throws Exception {
        // Given
        CbomUploadRequestDto request1 = new CbomUploadRequestDto();

        request1
                .setContent(new LinkedHashMap<>(
                        Map.of("serialNumber", "urn:uuid:first", "version", 1, "specVersion", "1.6")));

        CbomUploadRequestDto request2 = new CbomUploadRequestDto();
        request2
                .setContent(new LinkedHashMap<>(
                        Map.of("serialNumber", "urn:uuid:second", "version", 1, "specVersion", "1.6")));

        mockServer
                .stubFor(WireMock
                        .post(WireMock.urlPathEqualTo("/api/v1/bom"))
                        .inScenario("multipleCreations")
                        .whenScenarioStateIs(com.github.tomakehurst.wiremock.stubbing.Scenario.STARTED)
                        .willReturn(WireMock
                                .aResponse()
                                .withStatus(201)
                                .withHeader("Content-Type", "application/json")
                                .withBody(bomEntryJson()))
                        .willSetStateTo("second"));

        mockServer
                .stubFor(WireMock
                        .post(WireMock.urlPathEqualTo("/api/v1/bom"))
                        .inScenario("multipleCreations")
                        .whenScenarioStateIs("second")
                        .willReturn(WireMock
                                .aResponse()
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
        when(attributeEngine.getResourceSearchableFields(Resource.CBOM, false)).thenReturn(attributeFields);

        // when
        List<SearchFieldDataByGroupDto> result = cbomService.getSearchableFieldInformationByGroup();

        // then
        assertNotNull(result);
        assertFalse(result.isEmpty());

        // Verify attributeEngine was called
        verify(attributeEngine).getResourceSearchableFields(Resource.CBOM, false);

        // Get the last group (which should be the property group we added)
        SearchFieldDataByGroupDto propertyGroup = result.get(result.size() - 1);

        assertNotNull(propertyGroup);
        assertEquals(11, propertyGroup.getSearchFieldData().size());

        // Verify all expected fields are present
        List<String> fieldNames = propertyGroup
                .getSearchFieldData()
                .stream()
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
        assertTrue(fieldNames.contains(FilterField.CBOM_ASSET_SYNC_STATE.name()));
        assertTrue(fieldNames.contains(FilterField.CBOM_ASSETS_SYNCED_AT.name()));
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
        cbomInternalService.sync();

        // Then
        List<Cbom> savedCboms = cbomRepository.findAll();
        assertEquals(3, savedCboms.size());

        List<String> serialNumbers = savedCboms.stream().map(Cbom::getSerialNumber).sorted().toList();

        assertTrue(serialNumbers.containsAll(List.of("serial-1", "serial-2", "serial-3")));

        List<OffsetDateTime> timestamps = savedCboms.stream().map(Cbom::getTimestamp).toList();

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
        cbomInternalService.sync();

        // Then
        List<Cbom> savedCboms = cbomRepository.findAll();
        assertEquals(3, savedCboms.size());

        List<String> serialNumbers = savedCboms.stream().map(Cbom::getSerialNumber).sorted().toList();

        assertTrue(serialNumbers.containsAll(List.of("serial-1", "serial-2", "serial-3")));

        long nullTimestamps = savedCboms.stream().map(Cbom::getTimestamp).count();
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

        List<String> serialNumbers = savedCboms.stream().map(Cbom::getSerialNumber).sorted().toList();

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

        mockServer
                .stubFor(WireMock
                        .get(WireMock.urlPathEqualTo("/api/v1/bom"))
                        .withQueryParam("after", WireMock.equalTo(String.valueOf(expectedAfter)))
                        .willReturn(WireMock
                                .aResponse()
                                .withStatus(200)
                                .withHeader("Content-Type", "application/json")
                                .withBody("[]")));

        // When
        cbomInternalService.sync();

        // Then: WireMock verification ensures the 'after' param matched the DB timestamp
        mockServer
                .verify(WireMock
                        .getRequestedFor(WireMock.urlPathEqualTo("/api/v1/bom"))
                        .withQueryParam("after", WireMock.equalTo(String.valueOf(expectedAfter))));
    }

    @Test
    void sync_ThrowsCbomRepositoryExceptionOn500Error() {
        // Given: cbom-repository does not work
        mockServer
                .stubFor(WireMock
                        .get(WireMock.urlPathEqualTo("/api/v1/bom"))
                        .willReturn(WireMock
                                .aResponse()
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
            cbomInternalService.sync();
        });

        mockServer
                .verify(WireMock
                        .getRequestedFor(WireMock.urlPathEqualTo("/api/v1/bom"))
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
        String result = cbomInternalService.sync();

        // Then no boms were stored
        List<Cbom> savedCboms = cbomRepository.findAll();
        assertEquals(0, savedCboms.size());
        // ... and no get detail REST API has been called
        mockServer.verify(0, WireMock.getRequestedFor(WireMock.urlPathEqualTo("/api/v1/bom/serial-1")));
        // an entry without a usable identity cannot be retried, so nothing is recorded for it
        assertEquals(0, skipRepository.count());
        assertTrue(result.contains("1 invalid entries"));
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
        mockServer
                .stubFor(WireMock
                        .get(WireMock.urlPathMatching("/api/v1/bom/serial-2"))
                        .withQueryParam("version", WireMock.equalTo("2"))
                        .willReturn(WireMock
                                .aResponse()
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
        cbomInternalService.sync();

        // Then no boms were stored
        List<Cbom> savedCboms = cbomRepository.findAll();
        assertEquals(1, savedCboms.size());
        List<String> serialNumbers = savedCboms.stream().map(Cbom::getSerialNumber).sorted().toList();

        assertTrue(serialNumbers.containsAll(List.of("serial-1")));
        // the 404 entry is not lost: it is recorded for the bounded retry
        assertEquals(1, skipRepository.count());
        assertEquals("serial-2", skipRepository.findAll().getFirst().getSerialNumber());
        assertEquals("document not found in the repository (HTTP 404)",
                skipRepository.findAll().getFirst().getReason());
    }

    @Test
    void testGetResourceObject() throws NotFoundException {
        Cbom cbom = new Cbom();
        cbom.setSerialNumber("testing");
        cbom.setTimestamp(OffsetDateTime.now());
        cbom.setVersion(1);
        cbom.setSpecVersion("1.6");
        cbomRepository.save(cbom);

        NameAndUuidDto nameAndUuidDto = cbomInternalService.getResourceObjectInternal(cbom.getUuid());
        Assertions.assertEquals(cbom.getUuid().toString(), nameAndUuidDto.getUuid());
        Assertions.assertEquals(cbom.getSerialNumber(), nameAndUuidDto.getName());

        nameAndUuidDto = cbomInternalService.getResourceObjectExternal(cbom.getSecuredUuid());
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
        mockServer
                .stubFor(WireMock
                        .get(WireMock.urlMatching("/api/v1/bom/.*/versions"))
                        .willReturn(WireMock
                                .aResponse()
                                .withStatus(200)
                                .withHeader("Content-Type", "application/json")
                                .withBody(objectMapper.writeValueAsString(List.of(versionDto1, versionDto2)))));

        // When / Then
        CbomRepositoryException exception = assertThrows(CbomRepositoryException.class,
                () -> cbomService.createCbom(request));

        assertNotNull(exception.getProblemDetail());
        assertEquals(500, exception.getProblemDetail().getStatus());
        assertEquals(
                "CBOM serialNumber and version is reported as existing but was not found in the repository. Please try to upload it again to synchronize state.",
                exception.getProblemDetail().getDetail());

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
        mockServer
                .stubFor(WireMock
                        .post(WireMock.urlPathEqualTo("/api/v1/bom"))
                        .willReturn(WireMock
                                .aResponse()
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

        doReturn(false) // validateSyncedCbomEntry: passes
                .doReturn(true) // createCbomEntry: already exists
                .when(cbomRepositorySpy)
                .existsBySerialNumberAndVersion(serialNumber, version);

        // When
        String result = cbomInternalService.sync();

        // Then: counted as duplicate, nothing stored
        assertTrue(result.contains("skipped duplicates 1"));
        assertTrue(result.contains("stored 0 new entries"));
    }

    /**
     * The repository goes on offering a document an operator deleted here -- deletion in Core is not deletion there --
     * so without the tombstone every run would store it again, and the next ingest would rebuild the inventory behind
     * it.
     */
    @Test
    void sync_doesNotStoreAgainWhatAnOperatorDeleted() throws Exception {
        String serialNumber = "serial-tombstoned";
        Cbom deleted = new Cbom();
        deleted.setSerialNumber(serialNumber);
        deleted.setVersion(1);
        deleted.setSpecVersion("1.6");
        cbomService.deleteCbom(cbomRepository.save(deleted).getUuid());

        BomEntryDto entry = entry(serialNumber, "1", OffsetDateTime.now());
        mockSearchResponse(List.of(entry));
        mockEntrySpecVersionSource(entry, "1.6", "source");

        String result = cbomInternalService.sync();

        assertTrue(result.contains("stored 0 new entries"));
        assertTrue(result.contains("1 entries an operator had deleted were not stored again"));
        assertTrue(cbomRepository.findAll().isEmpty());
    }

    /**
     * A skip recorded for an identity an operator has since deleted is resolved by the feed pass itself. It cannot be
     * left to the retry pass: the feed pass puts the identity in the run's attempted set before it tests the tombstone,
     * and the retry pass returns for anything already attempted -- so its own tombstone branch is never reached. The
     * repository goes on offering a deleted document every run, so the skip would sit RETRYING for ever.
     */
    @Test
    void sync_resolvesTheSkipOfAnEntryAnOperatorHasSinceDeleted() throws Exception {
        String serialNumber = "serial-skip-then-deleted";
        BomEntryDto entry = entry(serialNumber, "1", OffsetDateTime.now());
        mockSearchResponse(List.of(entry));
        mockServer
                .stubFor(WireMock
                        .get(WireMock.urlPathMatching("/api/v1/bom/" + serialNumber))
                        .withQueryParam("version", WireMock.equalTo("1"))
                        .willReturn(WireMock
                                .aResponse()
                                .withStatus(404)
                                .withHeader("Content-Type", "application/problem+json")
                                .withBody(
                                        """
                                                                                        {"type":"about:blank","title":"Not Found","status":404,\
                                                "detail":"Requested CBOM not found"}
                                                                                        """)));

        cbomInternalService.sync();
        assertEquals(1, skipRepository.count(), "the unreadable document is recorded for the bounded retry");

        Cbom deleted = new Cbom();
        deleted.setSerialNumber(serialNumber);
        deleted.setVersion(1);
        deleted.setSpecVersion("1.6");
        cbomService.deleteCbom(cbomRepository.save(deleted).getUuid());

        String result = cbomInternalService.sync();

        assertTrue(result.contains("1 entries an operator had deleted were not stored again"));
        assertEquals(0, skipRepository.count(), "nothing is owed for an entry an operator deleted");
    }

    /**
     * The tombstone pre-check happens before the document is read, and that read is an HTTP call. An operator deleting
     * the document while it is in flight would otherwise have it stored straight back under a uuid of its own -- the
     * delete cannot remove a row that did not exist when it ran, and nothing else notices. So the tombstone is tested
     * again inside the transaction that inserts.
     */
    @Test
    void sync_doesNotStoreADocumentDeletedWhileItsDocumentWasBeingRead() throws Exception {
        String serialNumber = "serial-deleted-mid-read";
        BomEntryDto entry = entry(serialNumber, "1", OffsetDateTime.now());
        mockSearchResponse(List.of(entry));
        mockEntrySpecVersionSource(entry, "1.6", "source");

        // false for the pre-check ahead of the read, true for the test inside the insert transaction: the operator's
        // delete commits while the document is in flight.
        doReturn(false, true).when(tombstoneRepositorySpy).existsBySerialNumberAndVersion(serialNumber, 1);

        String result = cbomInternalService.sync();

        assertTrue(result.contains("stored 0 new entries"));
        assertTrue(result.contains("1 entries an operator had deleted were not stored again"));
        assertTrue(cbomRepository.findAll().isEmpty());
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

        doReturn(false).when(cbomRepositorySpy).existsBySerialNumberAndVersion(serialNumber, version);
        doThrow(constraintViolation("cbom_serial_version_unique")).when(cbomRepositorySpy).save(any(Cbom.class));

        // When
        String result = cbomInternalService.sync();

        // Then: DataIntegrityViolationException propagates out of the transaction and is counted as duplicate
        assertTrue(result.contains("skipped duplicates 1"));
        assertTrue(result.contains("stored 0 new entries"));
    }

    @Test
    void sync_shouldRecordASkipWhenTheDatabaseRefusesTheRowForAnotherConstraint() throws Exception {
        // Only the dedup key's unique constraint means "someone else stored it first". Any other invariant of the
        // `cbom` row -- a check constraint, a column the feed left null -- is this entry's own problem, and counting
        // it as a duplicate would drop the entry without a trace.
        String serialNumber = "serial-other-constraint";
        int version = 1;

        BomEntryDto entry = entry(serialNumber, String.valueOf(version), OffsetDateTime.now());
        mockSearchResponse(List.of(entry));
        mockEntrySpecVersionSource(entry, "1.6", "source");

        doReturn(false).when(cbomRepositorySpy).existsBySerialNumberAndVersion(serialNumber, version);
        doThrow(constraintViolation("ck_cbom_asset_sync_state")).when(cbomRepositorySpy).save(any(Cbom.class));

        String result = cbomInternalService.sync();

        assertTrue(result.contains("1 entries could not be stored and were recorded for retry"), result);
        assertTrue(result.contains("stored 0 new entries"), result);
        assertEquals(1, skipRepository.count());
        assertEquals("storing the CBOM row failed: the database refused it (see the Core log)",
                skipRepository.findAll().getFirst().getReason());
    }

    /** A refusal shaped the way the JPA stack delivers one: the constraint name lives in the Hibernate cause. */
    private static DataIntegrityViolationException constraintViolation(String constraintName) {
        return new DataIntegrityViolationException("duplicate key", new ConstraintViolationException("duplicate key",
                new SQLException("duplicate key value", "23505"), constraintName));
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
        entry.setCreatedAt(timestamp);
        entry.setCryptoStats(cryptoStats);

        return entry;
    }

    private void mockEntrySpecVersionSource(BomEntryDto entry, String specVersion, String source) {
        mockEntrySpecVersionSource(entry, specVersion, source, null);
    }

    private void mockEntrySpecVersionSource(BomEntryDto entry, String specVersion, String source,
            OffsetDateTime timestamp) {
        Map<String, Object> metadata = new HashMap<>();
        if (timestamp != null) {
            metadata.put("timestamp", timestamp.toString());
        }
        metadata.put("component", Map.of("name", source));

        Map<String, Object> response = Map.of("specVersion", specVersion, "metadata", metadata);

        mockServer
                .stubFor(WireMock
                        .get(WireMock.urlPathEqualTo("/api/v1/bom/" + entry.getSerialNumber()))
                        .withQueryParam("version", WireMock.equalTo(entry.getVersion()))
                        .willReturn(WireMock
                                .aResponse()
                                .withStatus(200)
                                .withHeader("Content-Type", CONTENT_TYPE)
                                .withBody(new Gson().toJson(response))));
    }

    private void mockSearchResponse(List<BomEntryDto> response) throws JsonProcessingException {
        String jsonBody = objectMapper.writeValueAsString(response);

        mockServer
                .stubFor(WireMock
                        .get(WireMock.urlPathEqualTo("/api/v1/bom"))
                        .withQueryParam("after", WireMock.matching("\\d+"))
                        .willReturn(WireMock
                                .aResponse()
                                .withStatus(200)
                                .withHeader("Content-Type", "application/json")
                                .withBody(jsonBody)));
    }

    private void mockConflictResponse() {
        // Mock WireMock to return 409 Conflict
        mockServer
                .stubFor(WireMock
                        .post(WireMock.urlPathEqualTo("/api/v1/bom"))
                        .willReturn(WireMock
                                .aResponse()
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

    /**
     * A withdrawal that threw before committing anything withdrew nothing, so the row still says what it said.
     * Recording "a deletion withdrew this CBOM's cryptographic assets" for it would flip a genuinely SYNCED row to
     * FAILED under a sentence untrue of it, and cost a re-ingest of a document nothing is wrong with.
     *
     * <p>
     * The distinction is "withdrew nothing" and not "threw" -- see
     * {@link #aWithdrawalThatEmptiedPartOfTheInventoryBeforeFailingLeavesTheRowOwingARebuild}.
     */
    @Test
    void testBulkDeleteCbom_withdrawalFailure_leavesTheRowsStateAlone() {
        Cbom cbom = new Cbom();
        cbom.setSerialNumber("urn:uuid:withdrawal-failure");
        cbom.setVersion(1);
        cbom.setSpecVersion("1.6");
        cbom.setAssetSyncState(CbomAssetSyncState.SYNCED);
        final UUID savedUuid = cbomRepository.save(cbom).getUuid();

        doThrow(new RuntimeException("advisory lock error")).when(detachServiceSpy).withdrawWaiting(savedUuid);

        List<BulkActionMessageDto> messages = cbomService.bulkDeleteCbom(List.of(savedUuid));

        Assertions.assertEquals(1, messages.size());
        Cbom untouched = cbomRepository.findById(savedUuid).orElseThrow();
        Assertions.assertEquals(CbomAssetSyncState.SYNCED, untouched.getAssetSyncState());
        Assertions.assertNull(untouched.getAssetSyncError());
    }

    /**
     * The backlog pass selects its work list with a plain read, so every node selects the same rows. The claim is what
     * stops the second one from spending the same HTTP document read. It is a compare-and-swap on what the work list
     * saw rather than a state allowlist, because an allowlist admitting IN_PROGRESS would let the loser through.
     */
    @Test
    void theIngestWorkListIsClaimedOncePerRow() {
        Cbom cbom = new Cbom();
        cbom.setSerialNumber("urn:uuid:claimed-once");
        cbom.setVersion(1);
        cbom.setSpecVersion("1.6");
        final Cbom saved = cbomRepository.save(cbom);

        Assertions
                .assertEquals(1, syncStateWriter
                        .claimForIngest(saved.getUuid(), CbomAssetSyncState.PENDING, saved.getAssetSyncAttemptedAt()));
        Assertions
                .assertEquals(0, syncStateWriter
                        .claimForIngest(saved.getUuid(), CbomAssetSyncState.PENDING, saved.getAssetSyncAttemptedAt()),
                        "the second node reads the row as the work list left it and must not claim it");
        Assertions
                .assertEquals(CbomAssetSyncState.IN_PROGRESS,
                        cbomRepository.findById(saved.getUuid()).orElseThrow().getAssetSyncState());
    }

    @Test
    void testBulkDeleteCbom_deleteFailure_returnsErrorMessage() {
        Cbom cbom = new Cbom();
        cbom.setSerialNumber("urn:uuid:spy-test-1");
        cbom.setVersion(1);
        cbom.setSpecVersion("1.6");
        cbom.setTimestamp(OffsetDateTime.now());
        // SYNCED, because that is the state the record exists to overrule. A row still owing its first ingest has
        // nothing to withdraw, and is left where it is -- pinned by
        // aDeleteFailureLeavesARowThatOwesItsFirstIngestAlone.
        cbom.setAssetSyncState(CbomAssetSyncState.SYNCED);
        cbom = cbomRepository.save(cbom);
        final UUID savedUuid = cbom.getUuid();

        doThrow(new RuntimeException("DB delete error")).when(cbomRepositorySpy).delete(any(Cbom.class));

        List<BulkActionMessageDto> messages = cbomService.bulkDeleteCbom(List.of(savedUuid));

        Assertions.assertEquals(1, messages.size());
        Assertions.assertEquals(savedUuid.toString(), messages.getFirst().getUuid());
        Assertions.assertNotNull(messages.getFirst().getMessage());
        // The withdrawal ran before the header delete, so the row must owe an ingest rather than claim one.
        Assertions
                .assertEquals(CbomAssetSyncState.FAILED,
                        cbomRepository.findById(savedUuid).orElseThrow().getAssetSyncState());
    }

    /**
     * The one delete failure the row is not marked failed for. The withdrawal releases the asset-sync lock at every
     * batch commit, so an ingest of the same document can re-attach sources before the header delete runs: the
     * inventory's RESTRICT foreign key then refuses, and the row is genuinely sourced again. Marking it FAILED would
     * force a re-ingest of a document nothing is wrong with, under a sentence -- the inventory was withdrawn -- that is
     * no longer true of it.
     */
    @Test
    void aDeleteTheInventoryRefusesLeavesTheRowSynced() {
        Cbom cbom = new Cbom();
        cbom.setSerialNumber("urn:uuid:re-attached-mid-delete");
        cbom.setVersion(1);
        cbom.setSpecVersion("1.6");
        cbom.setAssetSyncState(CbomAssetSyncState.SYNCED);
        final UUID savedUuid = cbomRepository.save(cbom).getUuid();

        doThrow(constraintViolation("crypto_asset_source_to_cbom_key")).when(cbomRepositorySpy).delete(any(Cbom.class));

        ValidationException refused = Assertions
                .assertThrows(ValidationException.class, () -> cbomService.deleteCbom(savedUuid));
        assertTrue(refused.getMessage().contains("still referenced by the cryptographic asset inventory"),
                "the operator is told what refused it, in text this platform shaped");

        Cbom untouched = cbomRepository.findById(savedUuid).orElseThrow();
        Assertions.assertEquals(CbomAssetSyncState.SYNCED, untouched.getAssetSyncState());
        Assertions.assertNull(untouched.getAssetSyncError());
    }

    /**
     * The write that records "withdrawn but still here" runs against a database that has just failed, so it is the most
     * likely of all to fail too. Unguarded it would throw out of the loop: every uuid after the failing one goes
     * unattempted, the deletions already committed are reported nowhere, and the caller gets a bare 500 instead of the
     * per-entry list this method's contract is.
     */
    @Test
    void aBulkDeleteWhoseFailureRecordFailsStillAttemptsTheRestOfTheList() {
        final UUID first = savedCbom("urn:uuid:recovery-write-fails-1");
        final UUID second = savedCbom("urn:uuid:recovery-write-fails-2");

        doThrow(new RuntimeException("DB delete error")).when(cbomRepositorySpy).delete(any(Cbom.class));
        doThrow(new RuntimeException("the connection was lost"))
                .when(syncStateWriterSpy)
                .markWithdrawnButNotDeleted(any());

        List<BulkActionMessageDto> messages = cbomService.bulkDeleteCbom(List.of(first, second));

        Assertions
                .assertEquals(2, messages.size(),
                        "the second entry is attempted even though the first's record failed");
        Assertions
                .assertEquals(List.of(first.toString(), second.toString()),
                        messages.stream().map(BulkActionMessageDto::getUuid).toList());
    }

    /**
     * A withdrawal that committed batches before failing did empty part of the inventory, so the row owes a rebuild.
     *
     * <p>
     * Every batch commits in its own transaction. Left reading {@code SYNCED}, such a row claims a contribution that is
     * partly deleted and sits on neither work list -- the backlog pass selects PENDING, the retry pass
     * IN_PROGRESS/FAILED -- so nothing ever rebuilds it.
     */
    @Test
    void aWithdrawalThatEmptiedPartOfTheInventoryBeforeFailingLeavesTheRowOwingARebuild() {
        final UUID savedUuid = savedCbom("urn:uuid:partial-withdrawal");

        doThrow(new CbomAssetDetachService.WithdrawalFailedException(
                new CbomAssetDetachService.Withdrawal(100, 4, 0, false), new RuntimeException("deadlock victim")))
                .when(detachServiceSpy)
                .withdrawWaiting(savedUuid);

        List<BulkActionMessageDto> messages = cbomService.bulkDeleteCbom(List.of(savedUuid));

        Assertions.assertEquals(1, messages.size());
        Cbom owing = cbomRepository.findById(savedUuid).orElseThrow();
        Assertions.assertEquals(CbomAssetSyncState.FAILED, owing.getAssetSyncState());
        Assertions.assertNotNull(owing.getAssetSyncError());
    }

    /**
     * A CBOM that never ingested its assets has nothing to withdraw, so a failed deletion leaves it where it is.
     *
     * <p>
     * Flipping PENDING to FAILED would move the row off the fast pending list onto the retry list -- a
     * {@code cbom.sync.ingest-retry-after} window of delay -- under a sentence that is untrue of it: nothing was
     * withdrawn.
     */
    @Test
    void aDeleteFailureLeavesARowThatOwesItsFirstIngestAlone() {
        Cbom cbom = new Cbom();
        cbom.setSerialNumber("urn:uuid:never-ingested");
        cbom.setVersion(1);
        cbom.setSpecVersion("1.6");
        final UUID savedUuid = cbomRepository.save(cbom).getUuid();
        Assertions
                .assertEquals(CbomAssetSyncState.PENDING,
                        cbomRepository.findById(savedUuid).orElseThrow().getAssetSyncState());

        doThrow(new RuntimeException("DB delete error")).when(cbomRepositorySpy).delete(any(Cbom.class));

        cbomService.bulkDeleteCbom(List.of(savedUuid));

        Cbom untouched = cbomRepository.findById(savedUuid).orElseThrow();
        Assertions.assertEquals(CbomAssetSyncState.PENDING, untouched.getAssetSyncState());
        Assertions.assertNull(untouched.getAssetSyncError());
    }

    /**
     * Recording a withdrawal's failure is not an ingest attempt, so it must not restart the retry clock.
     *
     * <p>
     * Every other write to this column stamps {@code asset_sync_attempted_at}, which is what the retry list reads to
     * tell a live claim from an abandoned one. Stamped here, the row this write just put on the backlog would be
     * excluded from it for a full retry window and then sorted behind every older candidate -- the row that most
     * urgently owes a rebuild made to wait the longest.
     */
    @Test
    void recordingAWithdrawnButUndeletedRowDoesNotRestartTheRetryClock() {
        final UUID savedUuid = savedCbom("urn:uuid:attempt-clock");
        Cbom stale = cbomRepository.findById(savedUuid).orElseThrow();
        stale.setAssetSyncAttemptedAt(OffsetDateTime.now().minusHours(6));
        cbomRepository.saveAndFlush(stale);
        // Read back rather than remembered: PostgreSQL stores microseconds, and the comparison is about whether this
        // write moved the clock, not about what the driver rounded.
        final OffsetDateTime attemptedAt = cbomRepository.findById(savedUuid).orElseThrow().getAssetSyncAttemptedAt();

        Assertions.assertEquals(1, syncStateWriter.markWithdrawnButNotDeleted(savedUuid));

        Cbom recorded = cbomRepository.findById(savedUuid).orElseThrow();
        Assertions.assertEquals(CbomAssetSyncState.FAILED, recorded.getAssetSyncState());
        Assertions
                .assertEquals(attemptedAt.toInstant(), recorded.getAssetSyncAttemptedAt().toInstant(),
                        "the attempt clock belongs to ingest attempts, and this was not one");
    }

    /**
     * An ingest that finishes just after a deletion withdrew the inventory must not write the row back to SYNCED.
     *
     * <p>
     * Success is otherwise unconditional, and neither writer holds the asset-sync lock when it runs: a node between its
     * last asset batch and its {@code markSynced} would put the row back to SYNCED with the error cleared -- the exact
     * stranded state {@code markWithdrawnButNotDeleted} exists to prevent, and invisible to both work lists.
     */
    @Test
    void anIngestFinishingAfterADeletionWithdrewTheInventoryCannotClaimTheRowIsSynced() {
        final UUID savedUuid = savedCbom("urn:uuid:marksynced-race");
        Assertions.assertEquals(1, syncStateWriter.markWithdrawnButNotDeleted(savedUuid));

        Assertions
                .assertEquals(0, syncStateWriter.markSynced(savedUuid, OffsetDateTime.now()),
                        "the ingest's claim is stale: the inventory it synced has since been withdrawn");

        Cbom stillOwing = cbomRepository.findById(savedUuid).orElseThrow();
        Assertions.assertEquals(CbomAssetSyncState.FAILED, stillOwing.getAssetSyncState());
        Assertions.assertNotNull(stillOwing.getAssetSyncError());

        // And it is not a trap: the next backlog pass claims the row, which clears the error, and its ingest records
        // success normally.
        syncStateWriter.markInProgress(savedUuid);
        Assertions.assertEquals(1, syncStateWriter.markSynced(savedUuid, OffsetDateTime.now()));
        Assertions
                .assertEquals(CbomAssetSyncState.SYNCED,
                        cbomRepository.findById(savedUuid).orElseThrow().getAssetSyncState());
    }

    /**
     * The bulk path against a real RESTRICT refusal: the translated sentence reaches the caller and the row stays.
     *
     * <p>
     * Every other bulk test throws a synthetic {@code RuntimeException}, which exercises only the generic arm of
     * {@code recordBulkDeleteFailure} and only the true direction of the carve-out that leaves the row SYNCED. Here the
     * foreign key itself refuses, through the real writer and the real driver exception.
     */
    @Test
    void aBulkDeleteTheInventoryRefusesIsTranslatedAndLeavesTheRowSynced() {
        final UUID savedUuid = savedCbom("urn:uuid:bulk-restrict-refusal");
        final UUID assetUuid = cryptoAssetWriter
                .upsertIdentity(AssetRowKeys.forFields(anAlgorithm()), anAlgorithm(), null);
        cryptoAssetSourceWriter
                .upsertSource(assetUuid, savedUuid, Map.of("primitive", "signature"), List.of(), OffsetDateTime.now());
        // The withdrawal is what the delete relies on to make the deletion possible. Suppressed, the source row
        // survives into the header delete, which is how a real refusal is reached without a second node.
        doReturn(new CbomAssetDetachService.Withdrawal(0, 0, 0, true))
                .when(detachServiceSpy)
                .withdrawWaiting(savedUuid);

        List<BulkActionMessageDto> messages = cbomService.bulkDeleteCbom(List.of(savedUuid));

        Assertions.assertEquals(1, messages.size());
        assertTrue(messages.getFirst().getMessage().contains("still referenced by the cryptographic asset inventory"),
                "the operator is told what refused it, in text this platform shaped");
        assertFalse(messages.getFirst().getMessage().contains(savedUuid.toString()),
                "the driver's DETAIL line quotes the failing row and must not reach the caller");

        Cbom untouched = cbomRepository.findById(savedUuid).orElseThrow();
        Assertions.assertEquals(CbomAssetSyncState.SYNCED, untouched.getAssetSyncState());
        Assertions.assertNull(untouched.getAssetSyncError());
    }

    private static CryptoAssetIdentityFields anAlgorithm() {
        return new CryptoAssetIdentityFields(CryptographicAssetType.ALGORITHM, "RSA", null, "rsa", "signature", "2048",
                null, null, null, null);
    }

    private UUID savedCbom(String serialNumber) {
        Cbom cbom = new Cbom();
        cbom.setSerialNumber(serialNumber);
        cbom.setVersion(1);
        cbom.setSpecVersion("1.6");
        cbom.setAssetSyncState(CbomAssetSyncState.SYNCED);
        return cbomRepository.save(cbom).getUuid();
    }

    // ---------------------------------------------------------------- cryptographic-asset ingest

    /**
     * A document the feed offers is ingested in the same run that stores its header, from the document already read.
     */
    @Test
    void theAssetsOfAStoredCbomAreIngestedAndTheRowReadsSynced() throws Exception {
        BomEntryDto entry = entry("serial-ingest", "1", OffsetDateTime.now().minusHours(1));
        mockSearchResponse(List.of(entry));
        mockDocumentWithAssets(entry, TWO_ALGORITHM_COMPONENTS);

        cbomInternalService.sync();

        Cbom stored = cbomRepository.findAll().getFirst();
        assertEquals(CbomAssetSyncState.SYNCED, stored.getAssetSyncState());
        assertNull(stored.getAssetSyncError());
        assertNotNull(stored.getAssetsSyncedAt());
        assertNotNull(stored.getAssetSyncAttemptedAt());
        assertEquals(2, cryptoAssetRepository.count());
        assertEquals(2, cryptoAssetSourceRepository.count());
    }

    /**
     * Resumability, and the reason the ingest needs a work list of its own: the feed skips every entry whose header row
     * already exists, so a CBOM whose assets were never ingested -- a crashed run, or a document uploaded through
     * Core's own API -- is invisible to it. Without the pending pass these assets would never be ingested at all.
     */
    @Test
    void aCbomWhoseAssetsWereNeverIngestedIsPickedUpByALaterRun() throws Exception {
        Cbom header = savePendingHeader("serial-pending");
        assertEquals(CbomAssetSyncState.PENDING, header.getAssetSyncState());

        mockSearchResponse(List.of());
        mockDocumentWithAssets(entry("serial-pending", "1", OffsetDateTime.now()), TWO_ALGORITHM_COMPONENTS);

        cbomInternalService.sync();

        Cbom resumed = cbomRepository.findById(header.getUuid()).orElseThrow();
        assertEquals(CbomAssetSyncState.SYNCED, resumed.getAssetSyncState());
        assertEquals(2, cryptoAssetRepository.count());
    }

    /**
     * Epic AC9: redoing a unit converges on the same rows. The state is reset the way a crashed run leaves it, so the
     * second ingest walks the same document through the same upserts rather than being skipped as already synced.
     */
    @Test
    void redoingAnIngestOfTheSameDocumentCreatesNoNewRows() throws Exception {
        BomEntryDto entry = entry("serial-idempotent", "1", OffsetDateTime.now().minusHours(1));
        mockSearchResponse(List.of(entry));
        mockDocumentWithAssets(entry, TWO_ALGORITHM_COMPONENTS);
        cbomInternalService.sync();
        long assetsAfterFirstRun = cryptoAssetRepository.count();
        long sourcesAfterFirstRun = cryptoAssetSourceRepository.count();

        Cbom stored = cbomRepository.findAll().getFirst();
        syncStateWriter.markFailed(stored.getUuid(), "interrupted");
        // The retry list holds a failed row back until cbom.sync.ingest-retry-after has passed, so the attempt is
        // aged deliberately: this test is about redoing the unit, not about when a run offers to.
        Cbom failed = cbomRepository.findById(stored.getUuid()).orElseThrow();
        failed.setAssetSyncAttemptedAt(OffsetDateTime.now().minusHours(2));
        cbomRepository.save(failed);

        cbomInternalService.sync();

        assertEquals(assetsAfterFirstRun, cryptoAssetRepository.count());
        assertEquals(sourcesAfterFirstRun, cryptoAssetSourceRepository.count());
        assertEquals(CbomAssetSyncState.SYNCED,
                cbomRepository.findById(stored.getUuid()).orElseThrow().getAssetSyncState());
    }

    /**
     * A document the repository will not hand over must leave a mark on the row. An untouched row keeps the state and
     * the attempt timestamp the work list selects on, so it would be offered again at the same position on every run,
     * spending one of the run's budget slots for ever and telling the operator nothing.
     */
    @Test
    void aPendingCbomWhoseDocumentCannotBeReadRecordsTheFailureRatherThanStayingPending() throws Exception {
        Cbom header = savePendingHeader("serial-unreadable");

        mockSearchResponse(List.of());
        mockServer
                .stubFor(WireMock
                        .get(WireMock.urlPathEqualTo("/api/v1/bom/serial-unreadable"))
                        .willReturn(WireMock.aResponse().withStatus(500)));

        cbomInternalService.sync();

        Cbom afterRun = cbomRepository.findById(header.getUuid()).orElseThrow();
        assertEquals(CbomAssetSyncState.FAILED, afterRun.getAssetSyncState());
        assertNotNull(afterRun.getAssetSyncError());
        assertNotNull(afterRun.getAssetSyncAttemptedAt());
        // Recorded, and therefore out of the pending list the next run reads.
        assertTrue(cbomRepository.findPendingAssetIngests(CbomAssetSyncState.PENDING, Limit.of(10)).isEmpty());
    }

    /**
     * A repository that answers nothing at all is not a verdict on the documents. Charging it to them would rewrite the
     * whole pending backlog as FAILED -- at the run's budget an hour, each row carrying a sentence about the repository
     * -- and the header pass's own guard cannot see this one: it returns at once when the feed deferred nothing, which
     * is the ordinary state of the run that works a backlog down.
     */
    @Test
    void anUnreachableRepositoryLeavesThePendingBacklogAloneRatherThanFailingEveryDocument() throws Exception {
        Cbom first = savePendingHeader("serial-outage-1");
        Cbom second = savePendingHeader("serial-outage-2");

        mockSearchResponse(List.of());
        mockServer
                .stubFor(WireMock
                        .get(WireMock.urlPathMatching("/api/v1/bom/serial-outage-.*"))
                        .willReturn(WireMock.aResponse().withStatus(503)));

        cbomInternalService.sync();

        assertEquals(CbomAssetSyncState.PENDING,
                cbomRepository.findById(first.getUuid()).orElseThrow().getAssetSyncState());
        assertEquals(CbomAssetSyncState.PENDING,
                cbomRepository.findById(second.getUuid()).orElseThrow().getAssetSyncState());
        assertNull(cbomRepository.findById(first.getUuid()).orElseThrow().getAssetSyncError());
    }

    /** One unreadable document among no successes is still charged to it: one document must never hold the pass. */
    @Test
    void aSingleUnreadableDocumentIsChargedToItRatherThanReadAsAnOutage() throws Exception {
        Cbom only = savePendingHeader("serial-lone-503");

        mockSearchResponse(List.of());
        mockServer
                .stubFor(WireMock
                        .get(WireMock.urlPathEqualTo("/api/v1/bom/serial-lone-503"))
                        .willReturn(WireMock.aResponse().withStatus(503)));

        cbomInternalService.sync();

        Cbom afterRun = cbomRepository.findById(only.getUuid()).orElseThrow();
        assertEquals(CbomAssetSyncState.FAILED, afterRun.getAssetSyncState());
        assertNotNull(afterRun.getAssetSyncError());
    }

    /**
     * The work list is selected, then a document is read over HTTP, and only then is a failure written -- so another
     * node can finish the same CBOM inside that window. A failure written over it would flip a genuinely synced row to
     * FAILED with an error that is not about it.
     */
    @Test
    void aFailureDoesNotOverwriteACbomAnotherRunHasAlreadySynced() {
        Cbom cbom = savePendingHeader("serial-raced");
        syncStateWriter.markSynced(cbom.getUuid(), OffsetDateTime.now());

        int written = syncStateWriter.markFailed(cbom.getUuid(), "a stale claim's verdict");

        assertEquals(0, written);
        Cbom afterRace = cbomRepository.findById(cbom.getUuid()).orElseThrow();
        assertEquals(CbomAssetSyncState.SYNCED, afterRace.getAssetSyncState());
        assertNull(afterRace.getAssetSyncError());
    }

    /**
     * A revision a later one has already ingested costs no document read at all. The check has to come before the read
     * because the read is the expense: it spends one of the run's {@code max-ingest-documents} slots and one of the
     * {@code ingestReads} that {@code settleUnreadable} weighs its outage verdict on, and a repository carrying many
     * historical revisions is exactly the population this backlog pass exists for. It also settles a superseded
     * revision whose old document has since been removed upstream, which the read would report as a 404 retried for
     * ever.
     */
    @Test
    void aSupersededRevisionIsSettledByTheBacklogPassWithoutADocumentRead() throws Exception {
        Cbom older = savePendingHeader("serial-superseded");
        Cbom newer = new Cbom();
        newer.setSerialNumber("serial-superseded");
        newer.setVersion(2);
        newer.setSpecVersion("1.6");
        newer = cbomRepository.save(newer);
        syncStateWriter.markSynced(newer.getUuid(), OffsetDateTime.now());

        mockSearchResponse(List.of());

        cbomInternalService.sync();

        mockServer.verify(0, WireMock.getRequestedFor(WireMock.urlPathEqualTo("/api/v1/bom/serial-superseded")));
        Cbom afterRun = cbomRepository.findById(older.getUuid()).orElseThrow();
        assertEquals(CbomAssetSyncState.SYNCED, afterRun.getAssetSyncState());
        assertNull(afterRun.getAssetsSyncedAt(),
                "it owes no ingest, but it never performed one either -- and the dashboard reads this column");
    }

    private Cbom savePendingHeader(String serialNumber) {
        Cbom header = new Cbom();
        header.setSerialNumber(serialNumber);
        header.setVersion(1);
        header.setSpecVersion("1.6");
        return cbomRepository.save(header);
    }

    /** The stub a document read answers with, carrying components the extractor can turn into assets. */
    private void mockDocumentWithAssets(BomEntryDto entry, String componentsJson) {
        String body = "{\"specVersion\":\"1.6\",\"metadata\":{\"component\":{\"name\":\"ingest-test\"}},"
                + "\"components\":" + componentsJson + "}";
        mockServer
                .stubFor(WireMock
                        .get(WireMock.urlPathEqualTo("/api/v1/bom/" + entry.getSerialNumber()))
                        .withQueryParam("version", WireMock.equalTo(entry.getVersion()))
                        .willReturn(WireMock
                                .aResponse()
                                .withStatus(200)
                                .withHeader("Content-Type", CONTENT_TYPE)
                                .withBody(body)));
    }
}
