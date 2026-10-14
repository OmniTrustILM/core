package com.otilm.core.integration.service;

import com.github.tomakehurst.wiremock.WireMockServer;
import com.github.tomakehurst.wiremock.client.WireMock;
import com.otilm.api.exception.AttributeException;
import com.otilm.api.exception.CbomRepositoryException;
import com.otilm.api.exception.NotFoundException;
import com.otilm.api.exception.RuleException;
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
import com.otilm.api.model.core.cryptoasset.PqcVerdict;
import com.otilm.api.model.core.other.ResourceEvent;
import com.otilm.api.model.core.search.FilterConditionOperator;
import com.otilm.api.model.core.search.FilterFieldSource;
import com.otilm.api.model.core.settings.PlatformSettingsDto;
import com.otilm.api.model.core.settings.SettingsSection;
import com.otilm.api.model.core.settings.UtilsSettingsDto;
import com.otilm.api.model.core.workflows.ActionRequestDto;
import com.otilm.api.model.core.workflows.ConditionItemRequestDto;
import com.otilm.api.model.core.workflows.ConditionRequestDto;
import com.otilm.api.model.core.workflows.ConditionType;
import com.otilm.api.model.core.workflows.ExecutionItemRequestDto;
import com.otilm.api.model.core.workflows.ExecutionRequestDto;
import com.otilm.api.model.core.workflows.ExecutionType;
import com.otilm.api.model.core.workflows.RuleRequestDto;
import com.otilm.api.model.core.workflows.TriggerRequestDto;
import com.otilm.api.model.core.workflows.TriggerType;
import com.otilm.core.api.ExceptionHandlingAdvice;
import com.otilm.core.attribute.engine.AttributeEngine;
import com.otilm.core.cbom.asset.AssetRowKeys;
import com.otilm.core.cbom.asset.CryptoAssetIdentityFields;
import com.otilm.core.cbom.client.CbomRepositoryClient;
import com.otilm.core.cbom.ingest.CbomAssetIngestService;
import com.otilm.core.cbom.ingest.CbomIngestTestFixtures;
import com.otilm.core.cbom.sync.CbomSyncPolicy;
import com.otilm.core.dao.entity.Cbom;
import com.otilm.core.dao.entity.cbom.CryptoAsset;
import com.otilm.core.dao.repository.CbomRepository;
import com.otilm.core.dao.repository.cbom.CryptoAssetRepository;
import com.otilm.core.evaluator.CbomTriggerEvaluator;
import com.otilm.core.evaluator.CryptoAssetTriggerEvaluator;
import com.otilm.core.events.handlers.CryptoAssetPqcNotReadyEventHandler;
import com.otilm.core.model.auth.ResourceAction;
import com.otilm.core.security.authz.SecuredResource;
import com.otilm.core.security.authz.SecuredUUID;
import com.otilm.core.security.authz.SecurityFilter;
import com.otilm.core.security.authz.SecurityResourceFilter;
import com.otilm.core.security.authz.opa.dto.OpaObjectAccessResult;
import com.otilm.core.service.ActionExternalService;
import com.otilm.core.service.CbomExternalService;
import com.otilm.core.service.CryptographicAssetExternalService;
import com.otilm.core.service.ResourceExtensionService;
import com.otilm.core.service.ResourceExternalService;
import com.otilm.core.service.RuleExternalService;
import com.otilm.core.service.TriggerExternalService;
import com.otilm.core.service.impl.CbomServiceImpl;
import com.otilm.core.service.writer.cbom.CryptoAssetSourceWriter;
import com.otilm.core.service.writer.cbom.CryptoAssetWriter;
import com.otilm.core.service.writer.cbom.InventoryCustomAttributeWriter;
import com.otilm.core.settings.SettingsCache;
import com.otilm.core.util.BaseSpringBootTest;
import com.otilm.core.util.CommittedEventCapture;
import com.otilm.core.util.LoopbackWireMock;
import jakarta.persistence.EntityManager;
import jakarta.persistence.EntityManagerFactory;
import jakarta.persistence.LockModeType;
import java.time.OffsetDateTime;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicReference;
import javax.sql.DataSource;
import org.hibernate.engine.spi.SharedSessionContractImplementor;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.mockito.Mockito;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.context.ConfigurableApplicationContext;
import org.springframework.orm.jpa.EntityManagerHolder;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.test.util.AopTestUtils;
import org.springframework.transaction.PlatformTransactionManager;
import org.springframework.transaction.UnexpectedRollbackException;
import org.springframework.transaction.support.TransactionSynchronizationManager;
import org.springframework.transaction.support.TransactionTemplate;

import static com.otilm.core.util.builders.SearchFilterRequestDtoBuilder.aCustomAttributeFilter;
import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.when;

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
    private EntityManagerFactory entityManagerFactory;

    @Autowired
    private PlatformTransactionManager transactionManager;

    @Autowired
    private DataSource dataSource;

    @Autowired
    private ConfigurableApplicationContext applicationContext;

    @Autowired
    private RuleExternalService ruleService;

    @Autowired
    private ActionExternalService actionService;

    @Autowired
    private TriggerExternalService triggerService;

    @Autowired
    private CryptoAssetPqcNotReadyEventHandler notReadyHandler;

    @Autowired
    private InventoryCustomAttributeWriter inventoryAttributeWriter;

    private UUID attributeUuid;
    private PlatformSettingsDto originalSettings;

    @BeforeAll
    static void startRepository() {
        repositoryServer = LoopbackWireMock.start();
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
        settings.getUtils().setCbomRepositoryUrl(LoopbackWireMock.url(repositoryServer));
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
    void lateAttributeWriteFailurePreservesTheUploadedCbomAndReportsPartialFailure() {
        String serial = "urn:uuid:" + UUID.randomUUID();
        repositoryServer
                .stubFor(WireMock
                        .post(WireMock.urlPathEqualTo("/api/v1/bom"))
                        .willReturn(WireMock
                                .aResponse()
                                .withStatus(201)
                                .withHeader("Content-Type", "application/json")
                                .withBody("{\"serialNumber\":\"" + serial + "\",\"version\":1}")));
        OpaObjectAccessResult allowed = new OpaObjectAccessResult();
        allowed.setActionAllowedForGroupOfObjects(true);
        allowed.setAllowedObjects(List.of());
        allowed.setForbiddenObjects(List.of());
        OpaObjectAccessResult forbidden = new OpaObjectAccessResult();
        forbidden.setActionAllowedForGroupOfObjects(false);
        forbidden.setAllowedObjects(List.of());
        forbidden.setForbiddenObjects(List.of(attributeUuid.toString()));
        AtomicBoolean attributeWriteSawSavedCbom = new AtomicBoolean();
        when(opaClient
                .checkObjectAccess(Mockito.any(),
                        Mockito
                                .argThat(req -> req != null && req.getProperties() != null
                                        && Resource.ATTRIBUTE.getCode().equals(req.getProperties().get("name"))
                                        && ResourceAction.MEMBERS.getCode().equals(req.getProperties().get("action"))),
                        Mockito.any(), Mockito.any()))
                .thenAnswer(call -> {
                    boolean rowSaved = cbomRepository.existsBySerialNumberAndVersion(serial, 1);
                    attributeWriteSawSavedCbom.set(rowSaved);
                    return rowSaved ? forbidden : allowed;
                });
        CbomUploadRequestDto upload = new CbomUploadRequestDto();
        upload.setContent(new LinkedHashMap<>(Map.of("serialNumber", serial, "version", 1, "specVersion", "1.6")));
        upload.setCustomAttributes(List.of(requestContent("alice")));

        Exception failure = assertThrows(Exception.class, () -> cbomService.createCbom(upload));

        assertTrue(attributeWriteSawSavedCbom.get());
        repositoryServer.verify(1, WireMock.postRequestedFor(WireMock.urlPathEqualTo("/api/v1/bom")));
        assertTrue(cbomRepository.existsBySerialNumberAndVersion(serial, 1));
        Cbom persisted = cbomRepository
                .findAll()
                .stream()
                .filter(cbom -> serial.equals(cbom.getSerialNumber()))
                .findFirst()
                .orElseThrow();
        CbomRepositoryException error = assertInstanceOf(CbomRepositoryException.class, failure);
        var response = new ExceptionHandlingAdvice().handleCbomRepositoryException(error);
        assertEquals(422, response.getStatusCode().value());
        assertTrue(response.getBody().getMessage().contains(persisted.getUuid().toString()));
        assertTrue(response.getBody().getMessage().contains("was stored"));
        assertTrue(response.getBody().getMessage().contains("Not allowed to set custom attributes: " + ATTRIBUTE_NAME));
        assertTrue(attributeEngine
                .getObjectCustomAttributesContentForSystemContext(Resource.CBOM, persisted.getUuid())
                .isEmpty());
    }

    @ParameterizedTest
    @ValueSource(booleans = {false, true})
    void repositoryUploadAndConflictRecoveryDoNotHoldADatabaseTransaction(boolean alreadyInRepository)
            throws Exception {
        String serial = "urn:uuid:" + UUID.randomUUID();
        repositoryServer
                .stubFor(WireMock
                        .post(WireMock.urlPathEqualTo("/api/v1/bom"))
                        .willReturn(WireMock
                                .aResponse()
                                .withStatus(alreadyInRepository ? 409 : 201)
                                .withHeader("Content-Type", "application/json")
                                .withBody(alreadyInRepository
                                        ? "{\"status\":409,\"detail\":\"Already exists\"}"
                                        : "{\"serialNumber\":\"" + serial + "\",\"version\":1}")));
        repositoryServer
                .stubFor(WireMock
                        .get(WireMock.urlPathMatching("/api/v1/bom/.*/versions"))
                        .willReturn(WireMock
                                .aResponse()
                                .withHeader("Content-Type", "application/json")
                                .withBody("[{\"serialNumber\":\"" + serial + "\",\"version\":\"1\"}]")));
        CbomRepositoryClient actualClient = applicationContext.getBean(CbomRepositoryClient.class);
        CbomRepositoryClient observedClient = Mockito.spy(actualClient);
        AtomicBoolean transactionSeen = new AtomicBoolean();
        AtomicBoolean connectionSeen = new AtomicBoolean();
        AtomicInteger observedCalls = new AtomicInteger();
        Mockito.doAnswer(call -> {
            observedCalls.incrementAndGet();
            transactionSeen.compareAndSet(false, TransactionSynchronizationManager.isActualTransactionActive());
            connectionSeen.compareAndSet(false, TransactionSynchronizationManager.hasResource(dataSource));
            return call.callRealMethod();
        }).when(observedClient).create(Mockito.any());
        Mockito.doAnswer(call -> {
            observedCalls.incrementAndGet();
            transactionSeen.compareAndSet(false, TransactionSynchronizationManager.isActualTransactionActive());
            connectionSeen.compareAndSet(false, TransactionSynchronizationManager.hasResource(dataSource));
            return call.callRealMethod();
        }).when(observedClient).versions(Mockito.any());
        CbomServiceImpl service = AopTestUtils.getUltimateTargetObject(cbomService);
        service.setCbomRepositoryClient(observedClient);
        CbomUploadRequestDto upload = new CbomUploadRequestDto();
        upload.setContent(new LinkedHashMap<>(Map.of("serialNumber", serial, "version", 1, "specVersion", "1.6")));
        upload.setCustomAttributes(List.of(requestContent("alice")));
        try {
            UUID uuid = cbomService.createCbom(upload).getUuid();
            assertTrue(cbomRepository.existsById(uuid));
            assertEquals("alice",
                    firstValue(attributeEngine.getObjectCustomAttributesContentForSystemContext(Resource.CBOM, uuid)));
        } finally {
            service.setCbomRepositoryClient(actualClient);
        }
        assertEquals(alreadyInRepository ? 2 : 1, observedCalls.get());
        assertFalse(transactionSeen.get(), "Repository HTTP must run outside a database transaction");
        assertFalse(connectionSeen.get(), "Repository HTTP must not retain the caller's database connection");
    }

    @ParameterizedTest
    @ValueSource(booleans = {false, true})
    void permissionLookupAfterUploadDoesNotRetainAnOpenInViewConnection(boolean latePermissionDenied) throws Exception {
        String serial = "urn:uuid:" + UUID.randomUUID();
        repositoryServer
                .stubFor(WireMock
                        .post(WireMock.urlPathEqualTo("/api/v1/bom"))
                        .willReturn(WireMock
                                .aResponse()
                                .withStatus(201)
                                .withHeader("Content-Type", "application/json")
                                .withBody("{\"serialNumber\":\"" + serial + "\",\"version\":1}")));
        OpaObjectAccessResult allowed = new OpaObjectAccessResult();
        allowed.setActionAllowedForGroupOfObjects(true);
        allowed.setAllowedObjects(List.of());
        allowed.setForbiddenObjects(List.of());
        OpaObjectAccessResult forbidden = new OpaObjectAccessResult();
        forbidden.setActionAllowedForGroupOfObjects(false);
        forbidden.setAllowedObjects(List.of());
        forbidden.setForbiddenObjects(List.of(attributeUuid.toString()));
        AtomicInteger permissionCalls = new AtomicInteger();
        Map<Integer, Boolean> connectionByPermissionCall = new LinkedHashMap<>();
        AtomicBoolean transactionSeen = new AtomicBoolean();
        EntityManager requestEntityManager = entityManagerFactory.createEntityManager();
        CbomRepositoryClient actualClient = applicationContext.getBean(CbomRepositoryClient.class);
        CbomRepositoryClient observedClient = Mockito.spy(actualClient);
        AtomicInteger uploadCalls = new AtomicInteger();
        AtomicBoolean uploadConnectionSeen = new AtomicBoolean();
        Mockito.doAnswer(call -> {
            uploadCalls.incrementAndGet();
            uploadConnectionSeen
                    .set(requestEntityManager
                            .unwrap(SharedSessionContractImplementor.class)
                            .getJdbcCoordinator()
                            .getLogicalConnection()
                            .isPhysicallyConnected());
            return call.callRealMethod();
        }).when(observedClient).create(Mockito.any());
        CbomServiceImpl service = AopTestUtils.getUltimateTargetObject(cbomService);
        service.setCbomRepositoryClient(observedClient);
        when(opaClient
                .checkObjectAccess(Mockito.any(),
                        Mockito
                                .argThat(req -> req != null && req.getProperties() != null
                                        && Resource.ATTRIBUTE.getCode().equals(req.getProperties().get("name"))
                                        && ResourceAction.MEMBERS.getCode().equals(req.getProperties().get("action"))),
                        Mockito.any(), Mockito.any()))
                .thenAnswer(call -> {
                    connectionByPermissionCall
                            .put(permissionCalls.incrementAndGet(),
                                    requestEntityManager
                                            .unwrap(SharedSessionContractImplementor.class)
                                            .getJdbcCoordinator()
                                            .getLogicalConnection()
                                            .isPhysicallyConnected());
                    transactionSeen.compareAndSet(false, TransactionSynchronizationManager.isActualTransactionActive());
                    return latePermissionDenied && permissionCalls.get() == 2 ? forbidden : allowed;
                });
        CbomUploadRequestDto upload = new CbomUploadRequestDto();
        upload.setContent(new LinkedHashMap<>(Map.of("serialNumber", serial, "version", 1, "specVersion", "1.6")));
        upload.setCustomAttributes(List.of(requestContent("alice")));
        assertFalse(TransactionSynchronizationManager.hasResource(entityManagerFactory));
        TransactionSynchronizationManager
                .bindResource(entityManagerFactory, new EntityManagerHolder(requestEntityManager));
        try {
            if (latePermissionDenied) {
                assertThrows(CbomRepositoryException.class, () -> cbomService.createCbom(upload));
            } else {
                cbomService.createCbom(upload);
            }
            assertEquals(requestEntityManager,
                    ((EntityManagerHolder) TransactionSynchronizationManager.getResource(entityManagerFactory))
                            .getEntityManager());
        } finally {
            service.setCbomRepositoryClient(actualClient);
            TransactionSynchronizationManager.unbindResource(entityManagerFactory);
            requestEntityManager.close();
        }
        assertEquals(1, uploadCalls.get());
        assertFalse(uploadConnectionSeen.get(), "Repository HTTP must not retain the request's JDBC connection");
        assertEquals(2, permissionCalls.get());
        assertFalse(transactionSeen.get(), "Attribute permission HTTP must not hold a transaction");
        assertEquals(Map.of(1, false, 2, false), connectionByPermissionCall,
                "Attribute permission HTTP must not retain the request's JDBC connection");
    }

    @Test
    void unexpectedLateAttributeFailurePreservesTheCbomWithoutExposingRuntimeDetails() {
        String serial = "urn:uuid:" + UUID.randomUUID();
        repositoryServer
                .stubFor(WireMock
                        .post(WireMock.urlPathEqualTo("/api/v1/bom"))
                        .willReturn(WireMock
                                .aResponse()
                                .withStatus(201)
                                .withHeader("Content-Type", "application/json")
                                .withBody("{\"serialNumber\":\"" + serial + "\",\"version\":1}")));
        OpaObjectAccessResult allowed = new OpaObjectAccessResult();
        allowed.setActionAllowedForGroupOfObjects(true);
        allowed.setAllowedObjects(List.of());
        allowed.setForbiddenObjects(List.of());
        when(opaClient
                .checkObjectAccess(Mockito.any(),
                        Mockito
                                .argThat(req -> req != null && req.getProperties() != null
                                        && Resource.ATTRIBUTE.getCode().equals(req.getProperties().get("name"))
                                        && ResourceAction.MEMBERS.getCode().equals(req.getProperties().get("action"))),
                        Mockito.any(), Mockito.any()))
                .thenAnswer(call -> {
                    if (cbomRepository.existsBySerialNumberAndVersion(serial, 1)) {
                        throw new IllegalStateException("PRIVATE_RUNTIME_DETAIL_2532");
                    }
                    return allowed;
                });
        CbomUploadRequestDto upload = new CbomUploadRequestDto();
        upload.setContent(new LinkedHashMap<>(Map.of("serialNumber", serial, "version", 1, "specVersion", "1.6")));
        upload.setCustomAttributes(List.of(requestContent("alice")));

        Exception failure = assertThrows(Exception.class, () -> cbomService.createCbom(upload));

        assertTrue(cbomRepository.existsBySerialNumberAndVersion(serial, 1));
        Cbom persisted = cbomRepository
                .findAll()
                .stream()
                .filter(cbom -> serial.equals(cbom.getSerialNumber()))
                .findFirst()
                .orElseThrow();
        CbomRepositoryException error = assertInstanceOf(CbomRepositoryException.class, failure);
        var response = new ExceptionHandlingAdvice().handleCbomRepositoryException(error);
        assertEquals(500, response.getStatusCode().value());
        assertTrue(response.getBody().getMessage().contains(persisted.getUuid().toString()));
        assertTrue(response.getBody().getMessage().contains("was stored"));
        assertFalse(response.getBody().getMessage().contains("PRIVATE_RUNTIME_DETAIL_2532"));
        assertTrue(attributeEngine
                .getObjectCustomAttributesContentForSystemContext(Resource.CBOM, persisted.getUuid())
                .isEmpty());
    }

    @Test
    void aCbomDeletedDuringLatePermissionLookupDoesNotAcquireOrphanAttributes() throws Exception {
        String serial = "urn:uuid:" + UUID.randomUUID();
        repositoryServer
                .stubFor(WireMock
                        .post(WireMock.urlPathEqualTo("/api/v1/bom"))
                        .willReturn(WireMock
                                .aResponse()
                                .withStatus(201)
                                .withHeader("Content-Type", "application/json")
                                .withBody("{\"serialNumber\":\"" + serial + "\",\"version\":1}")));
        CountDownLatch permissionLookupStarted = new CountDownLatch(1);
        CountDownLatch resumePermissionLookup = new CountDownLatch(1);
        AtomicReference<UUID> storedUuid = new AtomicReference<>();
        OpaObjectAccessResult allowed = new OpaObjectAccessResult();
        allowed.setActionAllowedForGroupOfObjects(true);
        allowed.setAllowedObjects(List.of());
        allowed.setForbiddenObjects(List.of());
        when(opaClient
                .checkObjectAccess(Mockito.any(),
                        Mockito
                                .argThat(req -> req != null && req.getProperties() != null
                                        && Resource.ATTRIBUTE.getCode().equals(req.getProperties().get("name"))
                                        && ResourceAction.MEMBERS.getCode().equals(req.getProperties().get("action"))),
                        Mockito.any(), Mockito.any()))
                .thenAnswer(call -> {
                    Cbom stored = cbomRepository
                            .findAll()
                            .stream()
                            .filter(cbom -> serial.equals(cbom.getSerialNumber()))
                            .findFirst()
                            .orElse(null);
                    if (stored != null) {
                        storedUuid.set(stored.getUuid());
                        permissionLookupStarted.countDown();
                        if (!resumePermissionLookup.await(15, TimeUnit.SECONDS)) {
                            throw new IllegalStateException("Attribute permission lookup was not resumed");
                        }
                    }
                    return allowed;
                });
        CbomUploadRequestDto upload = new CbomUploadRequestDto();
        upload.setContent(new LinkedHashMap<>(Map.of("serialNumber", serial, "version", 1, "specVersion", "1.6")));
        upload.setCustomAttributes(List.of(requestContent("alice")));
        var authentication = SecurityContextHolder.getContext().getAuthentication();
        try (var workers = Executors.newVirtualThreadPerTaskExecutor()) {
            CompletableFuture<Throwable> create = CompletableFuture.supplyAsync(() -> {
                SecurityContextHolder.getContext().setAuthentication(authentication);
                try {
                    cbomService.createCbom(upload);
                    return null;
                } catch (Exception error) {
                    return error;
                } finally {
                    SecurityContextHolder.clearContext();
                }
            }, workers);
            try {
                assertTrue(permissionLookupStarted.await(5, TimeUnit.SECONDS));
                cbomRepository.deleteById(storedUuid.get());
            } finally {
                resumePermissionLookup.countDown();
            }
            assertInstanceOf(CbomRepositoryException.class, create.get(5, TimeUnit.SECONDS));
        }
        assertFalse(cbomRepository.existsById(storedUuid.get()));
        assertTrue(attributeEngine
                .getObjectCustomAttributesContentForSystemContext(Resource.CBOM, storedUuid.get())
                .isEmpty());
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
    void notReadyAssetEventReadsCustomAttributeRulesAndWritesCustomAttributeActions() throws Exception {
        Cbom cbom = newCbom();
        CryptoAssetIdentityFields fields = assetFields("RSA-2048");
        UUID assetUuid = assetWriter.upsertIdentity(AssetRowKeys.forFields(fields), fields, null);
        sourceWriter
                .upsertSource(assetUuid, cbom.getUuid(), Map.of("name", "RSA-2048"), List.of(), OffsetDateTime.now());
        attributeEngine
                .updateObjectCustomAttributesContent(Resource.CRYPTO_ASSET, assetUuid,
                        List.of(requestContent("alice")));
        String attributeIdentifier = ATTRIBUTE_NAME + "|" + AttributeContentType.TEXT.name();
        ConditionItemRequestDto conditionItem = new ConditionItemRequestDto();
        conditionItem.setFieldSource(FilterFieldSource.CUSTOM);
        conditionItem.setFieldIdentifier(attributeIdentifier);
        conditionItem.setOperator(FilterConditionOperator.EQUALS);
        conditionItem.setValue("alice");
        ConditionRequestDto conditionRequest = new ConditionRequestDto();
        conditionRequest.setName("Current inventory owner");
        conditionRequest.setResource(Resource.CRYPTO_ASSET);
        conditionRequest.setType(ConditionType.CHECK_FIELD);
        conditionRequest.setItems(List.of(conditionItem));
        var condition = ruleService.createCondition(conditionRequest);
        RuleRequestDto ruleRequest = new RuleRequestDto();
        ruleRequest.setName("Owned by alice");
        ruleRequest.setResource(Resource.CRYPTO_ASSET);
        ruleRequest.setConditionsUuids(List.of(condition.getUuid()));
        var rule = ruleService.createRule(ruleRequest);
        ExecutionItemRequestDto executionItem = new ExecutionItemRequestDto();
        executionItem.setFieldSource(FilterFieldSource.CUSTOM);
        executionItem.setFieldIdentifier(attributeIdentifier);
        executionItem.setData("bob");
        ExecutionRequestDto executionRequest = new ExecutionRequestDto();
        executionRequest.setName("Assign quantum migration owner");
        executionRequest.setResource(Resource.CRYPTO_ASSET);
        executionRequest.setType(ExecutionType.SET_FIELD);
        executionRequest.setItems(List.of(executionItem));
        var execution = actionService.createExecution(executionRequest);
        ActionRequestDto actionRequest = new ActionRequestDto();
        actionRequest.setName("Assign owner");
        actionRequest.setResource(Resource.CRYPTO_ASSET);
        actionRequest.setExecutionsUuids(List.of(execution.getUuid()));
        var action = actionService.createAction(actionRequest);
        TriggerRequestDto triggerRequest = new TriggerRequestDto();
        triggerRequest.setName("Assign owner when quantum readiness is lost");
        triggerRequest.setResource(Resource.CRYPTO_ASSET);
        triggerRequest.setType(TriggerType.EVENT);
        triggerRequest.setEvent(ResourceEvent.CRYPTO_ASSET_PQC_NOT_READY);
        triggerRequest.setRulesUuids(List.of(rule.getUuid()));
        triggerRequest.setActionsUuids(List.of(action.getUuid()));
        var trigger = triggerService.createTrigger(triggerRequest);
        triggerService
                .createTriggerAssociations(ResourceEvent.CRYPTO_ASSET_PQC_NOT_READY, null, null,
                        List.of(UUID.fromString(trigger.getUuid())), false);

        try (CommittedEventCapture events = new CommittedEventCapture(applicationContext)) {
            assetWriter
                    .applyPqcVerdict(assetUuid, PqcVerdict.NOT_READY, "RSA_NOT_READY",
                            "RSA is vulnerable to quantum attacks", Map.of());
            var messages = events.messages(ResourceEvent.Codes.CRYPTO_ASSET_PQC_NOT_READY);
            assertEquals(1, messages.size());
            notReadyHandler.handleEvent(messages.getFirst());
        }

        assertEquals("bob",
                firstValue(assetService.getCryptographicAsset(SecuredUUID.fromUUID(assetUuid)).getCustomAttributes()));
        assertEquals(PqcVerdict.NOT_READY, assetRepository.findById(assetUuid).orElseThrow().getPqcVerdict());
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
    void backgroundIngestStoresAssetWithoutRequiredCustomAttributeContent() throws Exception {
        CustomAttributeV3 definition = new CustomAttributeV3();
        definition.setUuid(UUID.randomUUID().toString());
        definition.setName("requiredInventoryOwner");
        definition.setType(AttributeType.CUSTOM);
        definition.setContentType(AttributeContentType.TEXT);
        CustomAttributeProperties properties = new CustomAttributeProperties();
        properties.setLabel("Required inventory owner");
        properties.setRequired(true);
        definition.setProperties(properties);
        attributeEngine.updateCustomAttributeDefinition(definition, List.of(Resource.CRYPTO_ASSET));

        Cbom cbom = newCbom();
        assertEquals(CbomAssetIngestService.IngestOutcome.INGESTED,
                ingestService
                        .ingest(cbom.getUuid(), CbomIngestTestFixtures.algorithmDocument("AES-256"),
                                OffsetDateTime.now(), CbomSyncPolicy.DEFAULTS));

        UUID assetUuid = assetByName("aes-256").getUuid();
        assertTrue(assetRepository.existsById(assetUuid));
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
        restrictAttributeAccess(false);
        CbomUploadRequestDto upload = new CbomUploadRequestDto();
        upload
                .setContent(new LinkedHashMap<>(
                        Map.of("serialNumber", "urn:uuid:" + UUID.randomUUID(), "version", 1, "specVersion", "1.6")));
        RequestAttributeV3 attribute = requestContent("alice");
        attribute.setUuid(null);
        upload.setCustomAttributes(List.of(attribute));

        ValidationException error = assertThrows(ValidationException.class, () -> cbomService.createCbom(upload));
        assertTrue(error.getMessage().contains("Not allowed to set custom attributes: " + ATTRIBUTE_NAME));
        repositoryServer.verify(0, WireMock.postRequestedFor(WireMock.urlPathEqualTo("/api/v1/bom")));
        assertEquals(0, cbomRepository.count());
    }

    @Test
    void allowedCbomAttributeCanBeUploadedByNameOnly() throws Exception {
        restrictAttributeAccess(true);
        String serial = "urn:uuid:" + UUID.randomUUID();
        repositoryServer
                .stubFor(WireMock
                        .post(WireMock.urlPathEqualTo("/api/v1/bom"))
                        .willReturn(WireMock
                                .aResponse()
                                .withStatus(201)
                                .withHeader("Content-Type", "application/json")
                                .withBody("{\"serialNumber\":\"" + serial + "\",\"version\":1}")));
        CbomUploadRequestDto upload = new CbomUploadRequestDto();
        upload.setContent(new LinkedHashMap<>(Map.of("serialNumber", serial, "version", 1, "specVersion", "1.6")));
        RequestAttributeV3 attribute = requestContent("alice");
        attribute.setUuid(null);
        upload.setCustomAttributes(List.of(attribute));

        UUID cbomUuid = cbomService.createCbom(upload).getUuid();

        assertEquals("alice",
                firstValue(attributeEngine.getObjectCustomAttributesContentForSystemContext(Resource.CBOM, cbomUuid)));
        repositoryServer.verify(1, WireMock.postRequestedFor(WireMock.urlPathEqualTo("/api/v1/bom")));
    }

    @Test
    void invalidNameOnlyAttributeIsRejectedBeforeRepositoryWrite() {
        restrictAttributeAccess(true);
        CbomUploadRequestDto upload = new CbomUploadRequestDto();
        upload
                .setContent(new LinkedHashMap<>(
                        Map.of("serialNumber", "urn:uuid:" + UUID.randomUUID(), "version", 1, "specVersion", "1.6")));
        RequestAttributeV3 attribute = requestContent("alice");
        attribute.setUuid(null);
        attribute.setContent(List.of(new TextAttributeContentV3(null, null)));
        upload.setCustomAttributes(List.of(attribute));

        ValidationException error = assertThrows(ValidationException.class, () -> cbomService.createCbom(upload));
        assertTrue(error.getMessage().contains("malformed"));
        repositoryServer.verify(0, WireMock.postRequestedFor(WireMock.urlPathEqualTo("/api/v1/bom")));
    }

    @Test
    void requiredAttributeOutsideWritePermissionDoesNotBlockAllowedContent() throws Exception {
        UUID requiredUuid = UUID.randomUUID();
        CustomAttributeV3 definition = new CustomAttributeV3();
        definition.setUuid(requiredUuid.toString());
        definition.setName("requiredRestrictedOwner");
        definition.setType(AttributeType.CUSTOM);
        definition.setContentType(AttributeContentType.TEXT);
        CustomAttributeProperties properties = new CustomAttributeProperties();
        properties.setLabel("Restricted owner");
        properties.setRequired(true);
        definition.setProperties(properties);
        attributeEngine.updateCustomAttributeDefinition(definition, List.of(Resource.CBOM));
        restrictAttributeAccess(false, requiredUuid);

        RequestAttributeV3 attribute = requestContent("alice");
        attribute.setUuid(null);
        attributeEngine
                .validateWritableCustomAttributesContent(Resource.CBOM, List.of(attribute),
                        attributeEngine.loadCustomAttributesSecurityResourceFilter());
    }

    @Test
    void forgedUuidForForbiddenNameDoesNotDeleteExistingContent() throws Exception {
        UUID cbomUuid = newCbom().getUuid();
        attributeEngine.updateObjectCustomAttributesContent(Resource.CBOM, cbomUuid, List.of(requestContent("alice")));
        CustomAttributeV3 definition = new CustomAttributeV3();
        definition.setUuid(UUID.randomUUID().toString());
        definition.setName("restrictedOwner");
        definition.setType(AttributeType.CUSTOM);
        definition.setContentType(AttributeContentType.TEXT);
        CustomAttributeProperties properties = new CustomAttributeProperties();
        properties.setLabel("Restricted owner");
        definition.setProperties(properties);
        attributeEngine.updateCustomAttributeDefinition(definition, List.of(Resource.CBOM));
        restrictAttributeAccess(true);
        RequestAttributeV3 forged = requestContent("mallory");
        forged.setName("restrictedOwner");

        assertThrows(ValidationException.class,
                () -> attributeEngine.updateObjectCustomAttributesContent(Resource.CBOM, cbomUuid, List.of(forged)));
        assertEquals("alice",
                firstValue(attributeEngine.getObjectCustomAttributesContentForSystemContext(Resource.CBOM, cbomUuid)));
    }

    @Test
    void allowedSingleNameOnlyAttributeUsesTheResolvedDefinitionPermission() throws Exception {
        CryptoAssetIdentityFields fields = assetFields("RSA-2048");
        UUID assetUuid = assetWriter.upsertIdentity(AssetRowKeys.forFields(fields), fields, null);
        restrictAttributeAccess(true);

        assertDoesNotThrow(() -> attributeEngine
                .updateObjectCustomAttributeContent(Resource.CRYPTO_ASSET, assetUuid, null, ATTRIBUTE_NAME,
                        List.of(new TextAttributeContentV3(null, "alice")),
                        attributeEngine.loadCustomAttributesSecurityResourceFilter()));

        assertEquals("alice", firstValue(
                attributeEngine.getObjectCustomAttributesContentForSystemContext(Resource.CRYPTO_ASSET, assetUuid)));
    }

    @Test
    void forbiddenSingleNameOnlyAttributePreservesExistingContent() throws Exception {
        CryptoAssetIdentityFields fields = assetFields("RSA-2048");
        UUID assetUuid = assetWriter.upsertIdentity(AssetRowKeys.forFields(fields), fields, null);
        attributeEngine
                .updateObjectCustomAttributesContent(Resource.CRYPTO_ASSET, assetUuid,
                        List.of(requestContent("alice")));
        restrictAttributeAccess(false);
        SecurityResourceFilter attributeFilter = attributeEngine.loadCustomAttributesSecurityResourceFilter();

        ValidationException error = assertThrows(ValidationException.class,
                () -> attributeEngine
                        .updateObjectCustomAttributeContent(Resource.CRYPTO_ASSET, assetUuid, null, ATTRIBUTE_NAME,
                                List.of(new TextAttributeContentV3(null, "mallory")), attributeFilter));

        assertTrue(error.getMessage().contains("Not allowed to set custom attributes: " + ATTRIBUTE_NAME));
        assertEquals("alice", firstValue(
                attributeEngine.getObjectCustomAttributesContentForSystemContext(Resource.CRYPTO_ASSET, assetUuid)));
    }

    @Test
    void triggerSetFieldForAnAssetDeletedAfterContextCaptureLeavesNoContent() throws Exception {
        CryptoAssetIdentityFields fields = assetFields("RSA-2048");
        UUID assetUuid = assetWriter.upsertIdentity(AssetRowKeys.forFields(fields), fields, null);
        attributeEngine
                .updateObjectCustomAttributesContent(Resource.CRYPTO_ASSET, assetUuid,
                        List.of(requestContent("alice")));
        CryptoAsset eventContextAsset = assetRepository.findById(assetUuid).orElseThrow();
        AssetSetFieldEvaluator evaluator = new AssetSetFieldEvaluator(assetRepository, attributeEngine,
                inventoryAttributeWriter);

        assertEquals(1, assetWriter.delete(assetUuid));
        assertFalse(assetRepository.existsById(assetUuid));

        assertThrows(NotFoundException.class, () -> evaluator.assignOwner(eventContextAsset));

        assertTrue(attributeEngine
                .getObjectCustomAttributesContentForSystemContext(Resource.CRYPTO_ASSET, assetUuid)
                .isEmpty());
    }

    @Test
    void cbomTriggerSetFieldAfterContextCaptureAndDeletionLeavesNoContent() throws Exception {
        Cbom eventContextCbom = newCbom();
        attributeEngine
                .updateObjectCustomAttributesContent(Resource.CBOM, eventContextCbom.getUuid(),
                        List.of(requestContent("alice")));
        CbomSetFieldEvaluator evaluator = new CbomSetFieldEvaluator(attributeEngine, inventoryAttributeWriter);

        cbomService.deleteCbom(eventContextCbom.getUuid());
        assertFalse(cbomRepository.existsById(eventContextCbom.getUuid()));

        assertThrows(NotFoundException.class, () -> evaluator.assignOwner(eventContextCbom));

        assertTrue(attributeEngine
                .getObjectCustomAttributesContentForSystemContext(Resource.CBOM, eventContextCbom.getUuid())
                .isEmpty());
    }

    @Test
    void caughtAttributePermissionDenialDoesNotRollBackTheOuterTransaction() {
        UUID assetUuid = inventoryAsset();
        restrictAttributeAccess(false);
        String markerSerial = "urn:uuid:" + UUID.randomUUID();

        SecurityResourceFilter attributeFilter = attributeEngine.loadCustomAttributesSecurityResourceFilter();

        assertDoesNotThrow(() -> new TransactionTemplate(transactionManager).executeWithoutResult(status -> {
            newCbom(markerSerial, 1);
            ValidationException error = assertThrows(ValidationException.class,
                    () -> attributeEngine
                            .updateObjectCustomAttributeContent(Resource.CRYPTO_ASSET, assetUuid, null, ATTRIBUTE_NAME,
                                    List.of(new TextAttributeContentV3(null, "mallory")), attributeFilter));
            assertTrue(error.getMessage().contains("Not allowed to set custom attributes: " + ATTRIBUTE_NAME));
        }));

        assertTrue(cbomRepository.existsBySerialNumberAndVersion(markerSerial, 1));
        assertTrue(attributeEngine
                .getObjectCustomAttributesContentForSystemContext(Resource.CRYPTO_ASSET, assetUuid)
                .isEmpty());
    }

    @Test
    void committedAssetAttributeActionSurvivesLaterOuterRollback() {
        UUID assetUuid = inventoryAsset();
        CryptoAsset eventContextAsset = assetRepository.findById(assetUuid).orElseThrow();
        AssetSetFieldEvaluator evaluator = new AssetSetFieldEvaluator(assetRepository, attributeEngine,
                inventoryAttributeWriter);
        String markerSerial = "urn:uuid:" + UUID.randomUUID();

        new TransactionTemplate(transactionManager).executeWithoutResult(status -> {
            newCbom(markerSerial, 1);
            assertDoesNotThrow(() -> evaluator.assignOwner(eventContextAsset));
            status.setRollbackOnly();
        });

        assertFalse(cbomRepository.existsBySerialNumberAndVersion(markerSerial, 1));
        assertEquals("bob", firstValue(
                attributeEngine.getObjectCustomAttributesContentForSystemContext(Resource.CRYPTO_ASSET, assetUuid)));
    }

    @Test
    void committedCbomAttributeActionSurvivesLaterOuterRollback() {
        Cbom eventContextCbom = newCbom();
        CbomSetFieldEvaluator evaluator = new CbomSetFieldEvaluator(attributeEngine, inventoryAttributeWriter);
        String markerSerial = "urn:uuid:" + UUID.randomUUID();

        new TransactionTemplate(transactionManager).executeWithoutResult(status -> {
            newCbom(markerSerial, 1);
            assertDoesNotThrow(() -> evaluator.assignOwner(eventContextCbom));
            status.setRollbackOnly();
        });

        assertFalse(cbomRepository.existsBySerialNumberAndVersion(markerSerial, 1));
        assertEquals("bob", firstValue(attributeEngine
                .getObjectCustomAttributesContentForSystemContext(Resource.CBOM, eventContextCbom.getUuid())));
    }

    @Test
    void missingAssetPermissionChainRollsBackTheAmbientTransaction() {
        String serial = "urn:uuid:" + UUID.randomUUID();
        UUID missingAssetUuid = UUID.randomUUID();

        assertThrows(UnexpectedRollbackException.class,
                () -> new TransactionTemplate(transactionManager).executeWithoutResult(status -> {
                    newCbom(serial, 1);
                    assertThrows(NotFoundException.class,
                            () -> assetExtension.evaluatePermissionChain(SecuredUUID.fromUUID(missingAssetUuid)));
                }));

        assertFalse(cbomRepository.existsBySerialNumberAndVersion(serial, 1));
    }

    @Test
    void assetParentCanBeDeletedWhileAttributePermissionLookupIsBlocked() throws Exception {
        UUID assetUuid = inventoryAsset();
        attributeEngine
                .updateObjectCustomAttributesContent(Resource.CRYPTO_ASSET, assetUuid,
                        List.of(requestContent("alice")));
        CountDownLatch permissionLookupStarted = new CountDownLatch(1);
        CountDownLatch resumePermissionLookup = new CountDownLatch(1);
        OpaObjectAccessResult allowed = new OpaObjectAccessResult();
        allowed.setActionAllowedForGroupOfObjects(true);
        allowed.setAllowedObjects(List.of());
        allowed.setForbiddenObjects(List.of());
        when(opaClient
                .checkObjectAccess(Mockito.any(),
                        Mockito
                                .argThat(req -> req != null && req.getProperties() != null
                                        && Resource.ATTRIBUTE.getCode().equals(req.getProperties().get("name"))
                                        && ResourceAction.MEMBERS.getCode().equals(req.getProperties().get("action"))),
                        Mockito.any(), Mockito.any()))
                .thenAnswer(call -> {
                    permissionLookupStarted.countDown();
                    if (!resumePermissionLookup.await(15, TimeUnit.SECONDS)) {
                        throw new IllegalStateException("Attribute permission lookup was not resumed");
                    }
                    return allowed;
                });
        var authentication = SecurityContextHolder.getContext().getAuthentication();

        try (var workers = Executors.newVirtualThreadPerTaskExecutor()) {
            CompletableFuture<Throwable> update = CompletableFuture.supplyAsync(() -> {
                SecurityContextHolder.getContext().setAuthentication(authentication);
                try {
                    resourceService
                            .updateAttributeContentForObject(SecuredResource.fromResource(Resource.CRYPTO_ASSET),
                                    SecuredUUID.fromUUID(assetUuid), attributeUuid,
                                    List.of(new TextAttributeContentV3(null, "bob")));
                    return null;
                } catch (Exception error) {
                    return error;
                } finally {
                    SecurityContextHolder.clearContext();
                }
            }, workers);
            try {
                assertTrue(permissionLookupStarted.await(5, TimeUnit.SECONDS));
                CompletableFuture<Integer> deletion = CompletableFuture.supplyAsync(() -> {
                    SecurityContextHolder.getContext().setAuthentication(authentication);
                    try {
                        return assetWriter.delete(assetUuid);
                    } finally {
                        SecurityContextHolder.clearContext();
                    }
                }, workers);

                int deleted = assertDoesNotThrow(() -> deletion.get(5, TimeUnit.SECONDS),
                        "The parent delete must commit before the attribute permission lookup resumes");
                assertEquals(1, deleted);
            } finally {
                resumePermissionLookup.countDown();
            }
            assertInstanceOf(NotFoundException.class, update.get(5, TimeUnit.SECONDS));
        }

        assertFalse(assetRepository.existsById(assetUuid));
        assertTrue(attributeEngine
                .getObjectCustomAttributesContentForSystemContext(Resource.CRYPTO_ASSET, assetUuid)
                .isEmpty());
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

        assertInstanceOf(NotFoundException.class, update.get(5, TimeUnit.SECONDS));
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

    private void restrictAttributeAccess(boolean allowOnlyThisAttribute) {
        restrictAttributeAccess(allowOnlyThisAttribute, attributeUuid);
    }

    private void restrictAttributeAccess(boolean allowOnlyThisAttribute, UUID restrictedUuid) {
        OpaObjectAccessResult result = new OpaObjectAccessResult();
        result.setActionAllowedForGroupOfObjects(!allowOnlyThisAttribute);
        result.setAllowedObjects(allowOnlyThisAttribute ? List.of(restrictedUuid.toString()) : List.of());
        result.setForbiddenObjects(allowOnlyThisAttribute ? List.of() : List.of(restrictedUuid.toString()));
        when(opaClient
                .checkObjectAccess(Mockito.any(),
                        Mockito
                                .argThat(req -> req != null && req.getProperties() != null
                                        && Resource.ATTRIBUTE.getCode().equals(req.getProperties().get("name"))
                                        && ResourceAction.MEMBERS.getCode().equals(req.getProperties().get("action"))),
                        Mockito.any(), Mockito.any()))
                .thenReturn(result);
    }

    private static CryptoAssetIdentityFields assetFields(String name) {
        return new CryptoAssetIdentityFields(CryptographicAssetType.ALGORITHM, name, null, null, null, null, null, null,
                null, null);
    }

    private UUID inventoryAsset() {
        CryptoAssetIdentityFields fields = assetFields("RSA-2048");
        return assetWriter.upsertIdentity(AssetRowKeys.forFields(fields), fields, null);
    }

    private static final class AssetSetFieldEvaluator extends CryptoAssetTriggerEvaluator {

        private AssetSetFieldEvaluator(CryptoAssetRepository repository, AttributeEngine attributes,
                InventoryCustomAttributeWriter writer) {
            super(repository, writer);
            setAttributeEngine(attributes);
        }

        private void assignOwner(CryptoAsset asset) throws RuleException, NotFoundException, AttributeException {
            performSetFieldAttributeExecution(Resource.CRYPTO_ASSET,
                    ATTRIBUTE_NAME + "|" + AttributeContentType.TEXT.name(),
                    List.of(new TextAttributeContentV3(null, "bob")), asset);
        }
    }

    private static final class CbomSetFieldEvaluator extends CbomTriggerEvaluator {

        private CbomSetFieldEvaluator(AttributeEngine attributes, InventoryCustomAttributeWriter writer) {
            super(writer);
            setAttributeEngine(attributes);
        }

        private void assignOwner(Cbom cbom) throws RuleException, NotFoundException, AttributeException {
            performSetFieldAttributeExecution(Resource.CBOM, ATTRIBUTE_NAME + "|" + AttributeContentType.TEXT.name(),
                    List.of(new TextAttributeContentV3(null, "bob")), cbom);
        }
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
