package com.otilm.core.integration.service;

import com.github.tomakehurst.wiremock.WireMockServer;
import com.github.tomakehurst.wiremock.client.WireMock;
import com.otilm.api.exception.AttributeException;
import com.otilm.api.exception.NotFoundException;
import com.otilm.api.exception.ValidationException;
import com.otilm.api.model.client.attribute.RequestAttributeV3;
import com.otilm.api.model.client.attribute.ResponseAttribute;
import com.otilm.api.model.client.attribute.ResponseAttributeV3;
import com.otilm.api.model.client.certificate.SearchRequestDto;
import com.otilm.api.model.common.attribute.common.AttributeType;
import com.otilm.api.model.common.attribute.common.content.AttributeContentType;
import com.otilm.api.model.common.attribute.common.properties.CustomAttributeProperties;
import com.otilm.api.model.common.attribute.v3.CustomAttributeV3;
import com.otilm.api.model.common.attribute.v3.content.TextAttributeContentV3;
import com.otilm.api.model.core.auth.Resource;
import com.otilm.api.model.core.cbom.CbomUploadRequestDto;
import com.otilm.api.model.core.cryptoasset.CryptographicAssetType;
import com.otilm.api.model.core.search.FilterConditionOperator;
import com.otilm.api.model.core.search.FilterFieldSource;
import com.otilm.api.model.core.settings.PlatformSettingsDto;
import com.otilm.api.model.core.settings.SettingsSection;
import com.otilm.api.model.core.settings.UtilsSettingsDto;
import com.otilm.core.attribute.engine.AttributeEngine;
import com.otilm.core.cbom.asset.AssetRowKeys;
import com.otilm.core.cbom.asset.CryptoAssetIdentityFields;
import com.otilm.core.cbom.ingest.CbomAssetIngestService;
import com.otilm.core.cbom.ingest.CbomIngestTestFixtures;
import com.otilm.core.cbom.sync.CbomSyncPolicy;
import com.otilm.core.dao.entity.Cbom;
import com.otilm.core.dao.entity.cbom.CryptoAsset;
import com.otilm.core.dao.repository.CbomRepository;
import com.otilm.core.dao.repository.cbom.CryptoAssetRepository;
import com.otilm.core.model.auth.ResourceAction;
import com.otilm.core.security.authz.SecuredResource;
import com.otilm.core.security.authz.SecuredUUID;
import com.otilm.core.security.authz.SecurityFilter;
import com.otilm.core.service.CbomExternalService;
import com.otilm.core.service.CryptographicAssetExternalService;
import com.otilm.core.service.ResourceExtensionService;
import com.otilm.core.service.ResourceExternalService;
import com.otilm.core.service.writer.cbom.CryptoAssetSourceWriter;
import com.otilm.core.service.writer.cbom.CryptoAssetWriter;
import com.otilm.core.settings.SettingsCache;
import com.otilm.core.util.BaseSpringBootTest;
import jakarta.persistence.EntityManager;
import jakarta.persistence.LockModeType;
import java.time.OffsetDateTime;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.transaction.PlatformTransactionManager;
import org.springframework.transaction.support.TransactionTemplate;

import static com.otilm.core.util.builders.SearchFilterRequestDtoBuilder.aCustomAttributeFilter;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class CbomCryptoAssetCustomAttributesITest extends BaseSpringBootTest {

    private static final String ATTRIBUTE_NAME = "inventoryOwner";
    private static WireMockServer repositoryServer;

    @Autowired
    private AttributeEngine attributeEngine;

    @Autowired
    private CbomExternalService cbomService;

    @Autowired
    private CryptographicAssetExternalService assetService;

    @Autowired
    private ResourceExternalService resourceService;

    @Autowired
    @Qualifier(Resource.Codes.CRYPTO_ASSET)
    private ResourceExtensionService assetExtension;

    @Autowired
    private CbomRepository cbomRepository;

    @Autowired
    private CryptoAssetRepository assetRepository;

    @Autowired
    private CryptoAssetWriter assetWriter;

    @Autowired
    private CbomAssetIngestService ingestService;

    @Autowired
    private CryptoAssetSourceWriter sourceWriter;

    @Autowired
    private SettingsCache settingsCache;

    @Autowired
    private EntityManager entityManager;

    @Autowired
    private PlatformTransactionManager transactionManager;

    private UUID attributeUuid;
    private PlatformSettingsDto originalSettings;

    @BeforeAll
    static void startRepository() {
        repositoryServer = new WireMockServer(0);
        repositoryServer.start();
    }

    @AfterAll
    static void stopRepository() {
        repositoryServer.stop();
    }

    @BeforeEach
    void registerAttribute() throws Exception {
        originalSettings = SettingsCache.getSettings(SettingsSection.PLATFORM);
        PlatformSettingsDto settings = new PlatformSettingsDto();
        settings.setUtils(new UtilsSettingsDto());
        settings.getUtils().setCbomRepositoryUrl("http://localhost:" + repositoryServer.port());
        settingsCache.cacheSettings(SettingsSection.PLATFORM, settings);

        attributeUuid = UUID.randomUUID();
        CustomAttributeV3 definition = new CustomAttributeV3();
        definition.setUuid(attributeUuid.toString());
        definition.setName(ATTRIBUTE_NAME);
        definition.setType(AttributeType.CUSTOM);
        definition.setContentType(AttributeContentType.TEXT);
        CustomAttributeProperties properties = new CustomAttributeProperties();
        properties.setLabel("Inventory owner");
        properties.setVisible(true);
        definition.setProperties(properties);
        attributeEngine.updateCustomAttributeDefinition(definition, List.of(Resource.CBOM, Resource.CRYPTO_ASSET));
    }

    @AfterEach
    void restoreSettings() {
        repositoryServer.resetAll();
        settingsCache.cacheSettings(SettingsSection.PLATFORM, originalSettings);
    }

    @Test
    void uploadedCbomStoresAttributesForDetailAndFiltering() throws Exception {
        String serial = "urn:uuid:" + UUID.randomUUID();
        repositoryServer
                .stubFor(WireMock
                        .post(WireMock.urlPathEqualTo("/api/v1/bom"))
                        .willReturn(WireMock
                                .aResponse()
                                .withStatus(201)
                                .withHeader("Content-Type", "application/json")
                                .withBody("{\"serialNumber\":\"" + serial + "\",\"version\":1}")));
        repositoryServer
                .stubFor(WireMock
                        .get(WireMock.urlPathMatching("/api/v1/bom/.*"))
                        .withQueryParam("version", WireMock.equalTo("1"))
                        .willReturn(WireMock
                                .aResponse()
                                .withStatus(200)
                                .withHeader("Content-Type", "application/json")
                                .withBody("{\"specVersion\":\"1.6\"}")));

        CbomUploadRequestDto upload = new CbomUploadRequestDto();
        upload.setContent(new LinkedHashMap<>(Map.of("serialNumber", serial, "version", 1, "specVersion", "1.6")));
        upload.setCustomAttributes(List.of(requestContent("alice")));

        UUID cbomUuid = cbomService.createCbom(upload).getUuid();

        assertEquals("alice",
                firstValue(cbomService.getCbomDetail(SecuredUUID.fromUUID(cbomUuid)).getCustomAttributes()));
        assertEquals(List.of(cbomUuid),
                cbomService
                        .listCboms(SecurityFilter.create(), matching("alice"))
                        .getItems()
                        .stream()
                        .map(item -> item.getUuid())
                        .toList());
        assertTrue(cbomService
                .getSearchableFieldInformationByGroup()
                .stream()
                .anyMatch(group -> group.getFilterFieldSource() == FilterFieldSource.CUSTOM));

        resourceService
                .updateAttributeContentForObject(SecuredResource.fromResource(Resource.CBOM),
                        SecuredUUID.fromUUID(cbomUuid), attributeUuid, List.of());

        assertTrue(cbomService.getCbomDetail(SecuredUUID.fromUUID(cbomUuid)).getCustomAttributes().isEmpty());
        assertTrue(cbomService.listCboms(SecurityFilter.create(), matching("alice")).getItems().isEmpty());
    }

    @Test
    void assetAttributesCanBeFilteredAndRemoved() throws Exception {
        Cbom cbom = newCbom();
        CryptoAssetIdentityFields fields = assetFields("AES-256-GCM");
        String key = AssetRowKeys.forFields(fields);
        UUID assetUuid = assetWriter.upsertIdentity(key, fields, null);
        sourceWriter
                .upsertSource(assetUuid, cbom.getUuid(), Map.of("name", "AES-256-GCM"), List.of(),
                        OffsetDateTime.now());

        resourceService
                .updateAttributeContentForObject(SecuredResource.fromResource(Resource.CRYPTO_ASSET),
                        SecuredUUID.fromUUID(assetUuid), attributeUuid,
                        List.of(new TextAttributeContentV3(null, "bob")));

        assertEquals("bob",
                firstValue(assetService.getCryptographicAsset(SecuredUUID.fromUUID(assetUuid)).getCustomAttributes()));
        assertEquals(List.of(assetUuid),
                assetService
                        .listCryptographicAssets(SecurityFilter.create(), matching("bob"))
                        .getItems()
                        .stream()
                        .map(item -> item.getUuid())
                        .toList());
        assertTrue(assetService
                .getSearchableFieldInformationByGroup()
                .stream()
                .anyMatch(group -> group.getFilterFieldSource() == FilterFieldSource.CUSTOM));

        resourceService
                .updateAttributeContentForObject(SecuredResource.fromResource(Resource.CRYPTO_ASSET),
                        SecuredUUID.fromUUID(assetUuid), attributeUuid, List.of());
        assertTrue(assetService.getCryptographicAsset(SecuredUUID.fromUUID(assetUuid)).getCustomAttributes().isEmpty());
        assertTrue(assetService.listCryptographicAssets(SecurityFilter.create(), matching("bob")).getItems().isEmpty());
    }

    @Test
    void supersedingCbomPreservesSurvivorContentAndRemovesOrphanContent() throws Exception {
        String serial = "urn:uuid:" + UUID.randomUUID();
        Cbom first = newCbom(serial, 1);
        assertEquals(CbomAssetIngestService.IngestOutcome.INGESTED,
                ingestService
                        .ingest(first.getUuid(), CbomIngestTestFixtures.algorithmDocument("AES-256", "RSA-2048"),
                                OffsetDateTime.now(), CbomSyncPolicy.DEFAULTS));
        UUID survivorUuid = assetByName("aes-256").getUuid();
        UUID orphanUuid = assetByName("rsa-2048").getUuid();
        attributeEngine
                .updateObjectCustomAttributesContent(Resource.CRYPTO_ASSET, survivorUuid,
                        List.of(requestContent("alice")));
        attributeEngine
                .updateObjectCustomAttributesContent(Resource.CRYPTO_ASSET, orphanUuid, List.of(requestContent("bob")));

        Cbom second = newCbom(serial, 2);
        assertEquals(CbomAssetIngestService.IngestOutcome.INGESTED,
                ingestService
                        .ingest(second.getUuid(), CbomIngestTestFixtures.algorithmDocument("AES-256"),
                                OffsetDateTime.now(), CbomSyncPolicy.DEFAULTS));

        assertEquals(survivorUuid, assetByName("aes-256").getUuid());
        assertFalse(assetRepository.existsById(orphanUuid));
        assertEquals("alice", firstValue(
                assetService.getCryptographicAsset(SecuredUUID.fromUUID(survivorUuid)).getCustomAttributes()));
        assertTrue(attributeEngine
                .getObjectCustomAttributesContentForSystemContext(Resource.CRYPTO_ASSET, orphanUuid)
                .isEmpty());
    }

    @Test
    void supersedingOneCbomKeepsSharedAssetContent() throws Exception {
        String serial = "urn:uuid:" + UUID.randomUUID();
        Cbom first = newCbom(serial, 1);
        Cbom other = newCbom();
        assertEquals(CbomAssetIngestService.IngestOutcome.INGESTED,
                ingestService
                        .ingest(first.getUuid(), CbomIngestTestFixtures.algorithmDocument("AES-256", "RSA-2048"),
                                OffsetDateTime.now(), CbomSyncPolicy.DEFAULTS));
        UUID sharedUuid = assetByName("rsa-2048").getUuid();
        assertEquals(CbomAssetIngestService.IngestOutcome.INGESTED,
                ingestService
                        .ingest(other.getUuid(), CbomIngestTestFixtures.algorithmDocument("RSA-2048"),
                                OffsetDateTime.now(), CbomSyncPolicy.DEFAULTS));
        attributeEngine
                .updateObjectCustomAttributesContent(Resource.CRYPTO_ASSET, sharedUuid, List.of(requestContent("bob")));

        Cbom second = newCbom(serial, 2);
        assertEquals(CbomAssetIngestService.IngestOutcome.INGESTED,
                ingestService
                        .ingest(second.getUuid(), CbomIngestTestFixtures.algorithmDocument("AES-256"),
                                OffsetDateTime.now(), CbomSyncPolicy.DEFAULTS));

        assertTrue(assetRepository.existsById(sharedUuid));
        assertEquals("bob",
                firstValue(assetService.getCryptographicAsset(SecuredUUID.fromUUID(sharedUuid)).getCustomAttributes()));
    }

    @Test
    void deletingCbomAndItsLastSourceAssetDeletesBothSetsOfAttributeContent() throws Exception {
        Cbom cbom = newCbom();
        CryptoAssetIdentityFields fields = assetFields("RSA-2048");
        UUID assetUuid = assetWriter.upsertIdentity(AssetRowKeys.forFields(fields), fields, null);
        sourceWriter
                .upsertSource(assetUuid, cbom.getUuid(), Map.of("name", "RSA-2048"), List.of(), OffsetDateTime.now());
        attributeEngine
                .updateObjectCustomAttributesContent(Resource.CBOM, cbom.getUuid(), List.of(requestContent("alice")));
        attributeEngine
                .updateObjectCustomAttributesContent(Resource.CRYPTO_ASSET, assetUuid, List.of(requestContent("bob")));

        cbomService.deleteCbom(cbom.getUuid());

        assertFalse(cbomRepository.existsById(cbom.getUuid()));
        assertFalse(assetRepository.existsById(assetUuid));
        assertTrue(attributeEngine
                .getObjectCustomAttributesContentForSystemContext(Resource.CBOM, cbom.getUuid())
                .isEmpty());
        assertTrue(attributeEngine
                .getObjectCustomAttributesContentForSystemContext(Resource.CRYPTO_ASSET, assetUuid)
                .isEmpty());
    }

    @Test
    void assetAttributePermissionChainRequiresUpdateAction() {
        CryptoAssetIdentityFields fields = assetFields("ECDSA-P256");
        UUID assetUuid = assetWriter.upsertIdentity(AssetRowKeys.forFields(fields), fields, null);
        denyResourceAccess(Resource.CRYPTO_ASSET, ResourceAction.UPDATE);

        assertThrows(AccessDeniedException.class,
                () -> assetExtension.evaluatePermissionChain(SecuredUUID.fromUUID(assetUuid)));
    }

    @Test
    void invalidReplacementKeepsExistingCbomAttributeContent() throws Exception {
        UUID cbomUuid = newCbom().getUuid();
        resourceService
                .updateAttributeContentForObject(SecuredResource.fromResource(Resource.CBOM),
                        SecuredUUID.fromUUID(cbomUuid), attributeUuid,
                        List.of(new TextAttributeContentV3(null, "alice")));

        assertThrows(AttributeException.class,
                () -> resourceService
                        .updateAttributeContentForObject(SecuredResource.fromResource(Resource.CBOM),
                                SecuredUUID.fromUUID(cbomUuid), attributeUuid,
                                List.of(new TextAttributeContentV3(null, null))));

        assertEquals("alice",
                firstValue(attributeEngine.getObjectCustomAttributesContentForSystemContext(Resource.CBOM, cbomUuid)));
    }

    @Test
    void forbiddenCbomAttributeRejectsUploadBeforeRepositoryWrite() {
        denyObjectAccess(Resource.ATTRIBUTE, ResourceAction.MEMBERS);
        CbomUploadRequestDto upload = new CbomUploadRequestDto();
        upload
                .setContent(new LinkedHashMap<>(
                        Map.of("serialNumber", "urn:uuid:" + UUID.randomUUID(), "version", 1, "specVersion", "1.6")));
        upload.setCustomAttributes(List.of(requestContent("alice")));

        ValidationException error = assertThrows(ValidationException.class, () -> cbomService.createCbom(upload));
        assertTrue(error.getMessage().contains(ATTRIBUTE_NAME));
        repositoryServer.verify(0, WireMock.postRequestedFor(WireMock.urlPathEqualTo("/api/v1/bom")));
        assertEquals(0, cbomRepository.count());
    }

    @Test
    void assetUpdateWaitsForParentDeleteAndLeavesNoContent() throws Exception {
        CryptoAssetIdentityFields fields = assetFields("AES-256-GCM");
        UUID assetUuid = assetWriter.upsertIdentity(AssetRowKeys.forFields(fields), fields, null);
        CompletableFuture<Throwable> update = new CompletableFuture<>();
        CountDownLatch started = new CountDownLatch(1);

        new TransactionTemplate(transactionManager).executeWithoutResult(status -> {
            entityManager.find(CryptoAsset.class, assetUuid, LockModeType.PESSIMISTIC_WRITE);
            Thread.ofVirtual().start(() -> {
                SecurityContextHolder.getContext().setAuthentication(getAuthentication());
                started.countDown();
                try {
                    resourceService
                            .updateAttributeContentForObject(SecuredResource.fromResource(Resource.CRYPTO_ASSET),
                                    SecuredUUID.fromUUID(assetUuid), attributeUuid,
                                    List.of(new TextAttributeContentV3(null, "bob")));
                    update.complete(null);
                } catch (Exception error) {
                    update.complete(error);
                } finally {
                    SecurityContextHolder.clearContext();
                }
            });
            try {
                assertTrue(started.await(5, TimeUnit.SECONDS));
                assertThrows(TimeoutException.class, () -> update.get(500, TimeUnit.MILLISECONDS));
            } catch (InterruptedException error) {
                Thread.currentThread().interrupt();
                throw new AssertionError(error);
            }
            assertEquals(1, assetWriter.delete(assetUuid));
        });

        assertTrue(update.get(5, TimeUnit.SECONDS) instanceof NotFoundException);
        assertTrue(attributeEngine
                .getObjectCustomAttributesContentForSystemContext(Resource.CRYPTO_ASSET, assetUuid)
                .isEmpty());
    }

    private Cbom newCbom() {
        return newCbom("urn:uuid:" + UUID.randomUUID(), 1);
    }

    private Cbom newCbom(String serial, int version) {
        Cbom cbom = new Cbom();
        cbom.setSerialNumber(serial);
        cbom.setVersion(version);
        cbom.setSpecVersion("1.6");
        return cbomRepository.save(cbom);
    }

    private CryptoAsset assetByName(String name) {
        return assetRepository
                .findAll()
                .stream()
                .filter(asset -> asset.getName().equals(name))
                .findFirst()
                .orElseThrow();
    }

    private RequestAttributeV3 requestContent(String value) {
        RequestAttributeV3 content = new RequestAttributeV3();
        content.setUuid(attributeUuid);
        content.setName(ATTRIBUTE_NAME);
        content.setContent(List.of(new TextAttributeContentV3(null, value)));
        return content;
    }

    private static CryptoAssetIdentityFields assetFields(String name) {
        return new CryptoAssetIdentityFields(CryptographicAssetType.ALGORITHM, name, null, null, null, null, null, null,
                null, null);
    }

    private static SearchRequestDto matching(String value) {
        SearchRequestDto request = new SearchRequestDto();
        request
                .setFilters(List
                        .of(aCustomAttributeFilter(ATTRIBUTE_NAME, AttributeContentType.TEXT,
                                FilterConditionOperator.EQUALS, value)));
        return request;
    }

    private static String firstValue(List<ResponseAttribute> attributes) {
        ResponseAttributeV3 attribute = (ResponseAttributeV3) attributes.getFirst();
        return ((TextAttributeContentV3) attribute.getContent().getFirst()).getData();
    }
}
