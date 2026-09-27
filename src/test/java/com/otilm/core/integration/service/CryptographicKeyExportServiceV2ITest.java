package com.otilm.core.integration.service;

import ch.qos.logback.classic.Level;
import ch.qos.logback.classic.Logger;
import ch.qos.logback.classic.spi.ILoggingEvent;
import ch.qos.logback.classic.spi.ThrowableProxyUtil;
import ch.qos.logback.core.read.ListAppender;
import com.otilm.api.exception.ConnectorProblemException;
import com.otilm.api.exception.ConnectorServerException;
import com.otilm.api.exception.NotFoundException;
import com.otilm.api.exception.ValidationException;
import com.otilm.api.interfaces.core.web.CryptographicKeyController;
import com.otilm.api.model.client.connector.v2.ConnectorInterface;
import com.otilm.api.model.client.connector.v2.ConnectorVersion;
import com.otilm.api.model.client.connector.v2.FeatureFlag;
import com.otilm.api.model.client.cryptography.key.KeyExportRequestDto;
import com.otilm.api.model.client.cryptography.key.KeyRequestType;
import com.otilm.api.model.common.NameAndUuidDto;
import com.otilm.api.model.common.attribute.common.AttributeType;
import com.otilm.api.model.common.attribute.common.BaseAttribute;
import com.otilm.api.model.common.attribute.common.content.AttributeContentType;
import com.otilm.api.model.common.attribute.common.properties.MetadataAttributeProperties;
import com.otilm.api.model.common.attribute.v3.MetadataAttributeV3;
import com.otilm.api.model.common.attribute.v3.content.StringAttributeContentV3;
import com.otilm.api.model.common.enums.cryptography.KeyAlgorithm;
import com.otilm.api.model.common.enums.cryptography.KeyFormat;
import com.otilm.api.model.common.enums.cryptography.KeyType;
import com.otilm.api.model.common.error.ErrorCode;
import com.otilm.api.model.connector.cryptography.enums.TokenInstanceStatus;
import com.otilm.api.model.core.auth.Resource;
import com.otilm.api.model.core.connector.ConnectorStatus;
import com.otilm.api.model.core.cryptography.key.KeyEvent;
import com.otilm.api.model.core.cryptography.key.KeyEventStatus;
import com.otilm.api.model.core.cryptography.key.KeyState;
import com.otilm.api.model.core.cryptography.key.KeyUsage;
import com.otilm.api.model.core.logging.enums.AuditLogOutput;
import com.otilm.api.model.core.logging.enums.Operation;
import com.otilm.api.model.core.logging.enums.OperationResult;
import com.otilm.api.model.core.secret.Passphrase;
import com.otilm.api.model.core.settings.logging.AuditLoggingSettingsDto;
import com.otilm.api.model.core.settings.logging.LoggingSettingsDto;
import com.otilm.api.model.core.settings.logging.ResourceLoggingSettingsDto;
import com.otilm.core.attribute.engine.OutboundSecretLeakException;
import com.otilm.core.auth.ContextRefreshListener;
import com.otilm.core.dao.entity.AuditLog;
import com.otilm.core.dao.entity.Connector;
import com.otilm.core.dao.entity.ConnectorInterfaceEntity;
import com.otilm.core.dao.entity.CryptographicKey;
import com.otilm.core.dao.entity.CryptographicKeyEventHistory;
import com.otilm.core.dao.entity.CryptographicKeyItem;
import com.otilm.core.dao.entity.OwnerAssociation;
import com.otilm.core.dao.entity.TokenInstanceReference;
import com.otilm.core.dao.entity.TokenProfile;
import com.otilm.core.dao.repository.AuditLogRepository;
import com.otilm.core.dao.repository.ConnectorInterfaceRepository;
import com.otilm.core.dao.repository.ConnectorRepository;
import com.otilm.core.dao.repository.CryptographicKeyEventHistoryRepository;
import com.otilm.core.dao.repository.CryptographicKeyItemRepository;
import com.otilm.core.dao.repository.CryptographicKeyRepository;
import com.otilm.core.dao.repository.OwnerAssociationRepository;
import com.otilm.core.dao.repository.TokenInstanceReferenceRepository;
import com.otilm.core.dao.repository.TokenProfileRepository;
import com.otilm.core.model.auth.ResourceAction;
import com.otilm.core.model.auth.ResourceSyncRequestDto;
import com.otilm.core.model.crypto.ExportedKeyMaterial;
import com.otilm.core.model.crypto.TransferableKeyType;
import com.otilm.core.security.authz.SecuredUUID;
import com.otilm.core.service.CryptographicKeyExportExternalService;
import com.otilm.core.service.CryptographicKeyExternalService;
import com.otilm.core.service.SettingExternalService;
import com.otilm.core.util.AuthHelper;
import com.otilm.core.util.BaseSpringBootTest;
import com.otilm.core.util.ExportEnvelopeFixtures;
import com.otilm.core.util.mocks.ConnectorMockFactory;
import com.otilm.core.util.mocks.CryptographyProviderV2ConnectorMock;
import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PublicKey;
import java.time.Duration;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;
import java.util.Objects;
import java.util.Set;
import java.util.UUID;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import org.awaitility.Awaitility;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.HttpStatus;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.concurrent.DelegatingSecurityContextCallable;
import org.springframework.security.core.context.SecurityContextHolder;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.verifyNoInteractions;

/** Key export through a v2 cryptography provider: each gate, the connector's answer, and the key's history. */
@SpringBootTest
class CryptographicKeyExportServiceV2ITest extends BaseSpringBootTest {

    private static final char[] PASSPHRASE = "correct horse battery staple".toCharArray();

    @Autowired
    private CryptographicKeyExportExternalService exportService;
    @Autowired
    private CryptographicKeyExternalService cryptographicKeyService;
    @Autowired
    private ConnectorRepository connectorRepository;
    @Autowired
    private ConnectorInterfaceRepository connectorInterfaceRepository;
    @Autowired
    private TokenInstanceReferenceRepository tokenInstanceReferenceRepository;
    @Autowired
    private TokenProfileRepository tokenProfileRepository;
    @Autowired
    private CryptographicKeyRepository cryptographicKeyRepository;
    @Autowired
    private CryptographicKeyItemRepository cryptographicKeyItemRepository;
    @Autowired
    private CryptographicKeyEventHistoryRepository eventHistoryRepository;
    @Autowired
    private OwnerAssociationRepository ownerAssociationRepository;
    @Autowired
    private ConnectorMockFactory connectorMockFactory;
    @Autowired
    private CryptographicKeyController keyController;
    @Autowired
    private AuditLogRepository auditLogRepository;
    @Autowired
    private SettingExternalService settingService;
    @Autowired
    private ContextRefreshListener contextRefreshListener;
    @Autowired
    private JdbcTemplate jdbcTemplate;

    private CryptographyProviderV2ConnectorMock connectorMock;
    private Connector connector;
    private ConnectorInterfaceEntity cryptographyInterface;
    private TokenInstanceReference token;
    private TokenProfile profile;
    private CryptographicKey key;
    private KeyPair pair;
    private CryptographicKeyItem privateKey;
    private CryptographicKeyItem publicKey;

    @BeforeEach
    void setUp() throws Exception {
        connectorMock = connectorMockFactory.startCryptographyProviderV2();
        connector = persistV2Connector(connectorMock.getUrl());
        cryptographyInterface = persistCryptographyInterface();
        token = persistToken();
        profile = persistProfile();
        key = persistKey();
        KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
        generator.initialize(2048);
        pair = generator.generateKeyPair();
        privateKey = persistKeyItem(key, KeyType.PRIVATE_KEY, true, KeyState.ACTIVE, true);
        publicKey = persistPublicKeyItem(pair.getPublic());
        connectorMock.stubExportKeyAttributes("[]");
    }

    @AfterEach
    void tearDown() {
        connectorMock.stop();
    }

    @Test
    void exportKey_returnsTheConnectorsEnvelopeAndRecordsTheExport() throws Exception {
        // given
        byte[] envelope = ExportEnvelopeFixtures.pinnedEnvelope(pair.getPrivate(), PASSPHRASE);
        connectorMock.stubExportKey(exportAnswer(envelope));

        // when
        ExportedKeyMaterial exported = exportService.exportKey(key.getUuid(), privateKey.getUuid(), exportRequest());

        // then
        assertArrayEquals(envelope, exported.encryptedPrivateKeyInfo());
        assertEquals(privateKey.getName(), exported.keyItemName());
        assertEquals(KeyEventStatus.SUCCESS, onlyExportEvent().getStatus());
    }

    /** An imported key carries the reference the platform minted for it, and the connector has to echo it. */
    @Test
    void exportKey_asksForAnImportedKeyByItsReference() throws Exception {
        // given
        UUID keyReference = UUID.randomUUID();
        privateKey.setKeyReferenceUuid(keyReference);
        cryptographicKeyItemRepository.saveAndFlush(privateKey);
        byte[] envelope = ExportEnvelopeFixtures.pinnedEnvelope(pair.getPrivate(), PASSPHRASE);
        connectorMock
                .stubExportKey(ExportEnvelopeFixtures
                        .keyPairResponseJson(envelope, KeyAlgorithm.RSA, 2048, pair.getPublic(), keyReference));

        // when
        exportService.exportKey(key.getUuid(), privateKey.getUuid(), exportRequest());

        // then
        connectorMock.verifyExportKeyRequestContaining("{\"keyReference\":\"" + keyReference + "\"}");
    }

    @Test
    void exportKey_refusesAnAnswerThatDoesNotEchoTheReference() {
        // given
        privateKey.setKeyReferenceUuid(UUID.randomUUID());
        cryptographicKeyItemRepository.saveAndFlush(privateKey);
        connectorMock.stubExportKey(exportAnswer(ExportEnvelopeFixtures.pinnedEnvelope(pair.getPrivate(), PASSPHRASE)));
        UUID keyUuid = key.getUuid();
        UUID privateKeyUuid = privateKey.getUuid();
        KeyExportRequestDto request = exportRequest();

        // when
        ConnectorServerException failed = assertThrows(ConnectorServerException.class,
                () -> exportService.exportKey(keyUuid, privateKeyUuid, request));

        // then
        assertEquals("The connector failed to export key item %s.".formatted(privateKeyUuid), failed.getMessage());
    }

    /** Only key-pair algorithms exist, so the secret is described with one; there is no public key to look up. */
    @Test
    void exportKey_exportsASecretKey() throws Exception {
        // given
        profile
                .setExportableKeyTypes(
                        List.of(new TransferableKeyType(KeyRequestType.SECRET, Set.of(KeyAlgorithm.RSA))));
        tokenProfileRepository.save(profile);
        CryptographicKeyItem secret = persistKeyItem(key, KeyType.SECRET_KEY, true, KeyState.ACTIVE, true);
        byte[] envelope = ExportEnvelopeFixtures.pinnedEnvelope(pair.getPrivate(), PASSPHRASE);
        connectorMock.stubExportKey(ExportEnvelopeFixtures.secretKeyResponseJson(envelope, KeyAlgorithm.RSA, 2048));

        // when
        ExportedKeyMaterial exported = exportService.exportKey(key.getUuid(), secret.getUuid(), exportRequest());

        // then
        assertArrayEquals(envelope, exported.encryptedPrivateKeyInfo());
        assertEquals(KeyEventStatus.SUCCESS, onlyExportEvent().getStatus());
    }

    @Test
    void exportKey_refusesAKeyThatIsNotExportable() {
        // given
        CryptographicKeyItem locked = persistKeyItem(key, KeyType.PRIVATE_KEY, false, KeyState.ACTIVE, true);

        // when
        // then
        assertRefusedBeforeTheConnector(locked, "was not created or imported as exportable");
    }

    @ParameterizedTest
    @CsvSource({"COMPROMISED, true", "ACTIVE, false"})
    void exportKey_refusesAKeyThatIsNotActiveOrEnabled(KeyState state, boolean enabled) {
        // given
        CryptographicKeyItem inactive = persistKeyItem(key, KeyType.PRIVATE_KEY, true, state, enabled);

        // when
        // then
        assertRefusedBeforeTheConnector(inactive, "must be active and enabled");
    }

    @Test
    void exportKey_refusesAKeyTypeTheProfileDoesNotExport() {
        // given
        profile
                .setExportableKeyTypes(
                        List.of(new TransferableKeyType(KeyRequestType.KEY_PAIR, Set.of(KeyAlgorithm.ECDSA))));
        tokenProfileRepository.save(profile);

        // when
        // then
        assertRefusedBeforeTheConnector(privateKey, "does not export the RSA algorithm for a key pair");
    }

    @Test
    void exportKey_refusesAConnectorWithoutKeyExport() {
        // given
        cryptographyInterface.setFeatures(List.of(FeatureFlag.STATELESS));
        connectorInterfaceRepository.save(cryptographyInterface);

        // when
        // then
        assertRefusedBeforeTheConnector(privateKey, "does not export the RSA algorithm for a key pair");
    }

    @Test
    void exportKey_refusesAKeyWithoutATokenProfile() {
        // given
        CryptographicKey unscoped = new CryptographicKey();
        unscoped.setName("key-without-profile");
        unscoped = cryptographicKeyRepository.save(unscoped);
        CryptographicKeyItem item = persistKeyItem(unscoped, KeyType.PRIVATE_KEY, true, KeyState.ACTIVE, true);

        // when
        // then
        assertRefusedBeforeTheConnector(item, "has no token profile");
    }

    @Test
    void exportKey_refusesAPublicKeyItem() {
        // when
        // then
        assertRefusedBeforeTheConnector(publicKey, "only private and secret keys are exported");
    }

    @Test
    void exportKey_refusesAnItemOfAnotherKey() {
        // given
        CryptographicKeyItem elsewhere = persistKeyItem(persistKey(), KeyType.PRIVATE_KEY, true, KeyState.ACTIVE, true);
        UUID elsewhereUuid = elsewhere.getUuid();
        UUID keyUuid = key.getUuid();
        KeyExportRequestDto request = exportRequest();

        // when
        assertThrows(NotFoundException.class, () -> exportService.exportKey(keyUuid, elsewhereUuid, request));

        // then
        assertTrue(exportEvents().isEmpty());
        connectorMock.verifyExportKeyRequests(0);
    }

    @Test
    void exportKey_refusesAKeyPairWithoutAPublicKeyRecord() {
        // given
        cryptographicKeyItemRepository.delete(publicKey);

        // when
        // then
        assertRefusedBeforeTheConnector(privateKey, "holds no public key");
    }

    /** An envelope outside the protection the contract pins is the connector's fault, never handed on. */
    @Test
    void exportKey_refusesAnEnvelopeOutsideThePinnedProfile() {
        // when
        // then
        assertTheConnectorFailsWith(ExportEnvelopeFixtures.envelope(pair.getPrivate(), PASSPHRASE, 10_000));
    }

    @Test
    void exportKey_refusesAnEnvelopeThatIsNotAnEncryptedPrivateKeyInfo() {
        // when
        // then
        assertTheConnectorFailsWith(new byte[]{1, 2, 3});
    }

    /** Owning an object passes most checks on it; export has to be granted as a permission of its own. */
    @Test
    void exportKey_refusesTheKeyOwnerWithoutTheExportPermission() {
        // given
        denyResourceAccess(Resource.CRYPTOGRAPHIC_KEY, ResourceAction.EXPORT_KEY);
        NameAndUuidDto principal = AuthHelper.getUserIdentification();
        OwnerAssociation ownership = new OwnerAssociation();
        ownership.setResource(Resource.CRYPTOGRAPHIC_KEY);
        ownership.setObjectUuid(key.getUuid());
        ownership.setOwnerUuid(UUID.fromString(principal.getUuid()));
        ownership.setOwnerUsername(principal.getName());
        ownerAssociationRepository.save(ownership);
        UUID keyUuid = key.getUuid();
        UUID privateKeyUuid = privateKey.getUuid();
        KeyExportRequestDto request = exportRequest();

        // when
        assertThrows(AccessDeniedException.class, () -> exportService.exportKey(keyUuid, privateKeyUuid, request));

        // then
        assertTrue(exportEvents().isEmpty());
        connectorMock.verifyExportKeyRequests(0);
    }

    /** The export also needs the detail of the key and its profile, and its token's detail and members. */
    @ParameterizedTest
    @CsvSource({"CRYPTOGRAPHIC_KEY, DETAIL", "TOKEN_PROFILE, DETAIL", "TOKEN, DETAIL", "TOKEN, MEMBERS"})
    void exportKey_refusesWithoutAccessToTheKeyOrItsToken(Resource resource, ResourceAction action) {
        // given
        denyResourceAccess(resource, action);
        UUID keyUuid = key.getUuid();
        UUID privateKeyUuid = privateKey.getUuid();
        KeyExportRequestDto request = exportRequest();

        // when
        assertThrows(AccessDeniedException.class, () -> exportService.exportKey(keyUuid, privateKeyUuid, request));

        // then
        assertTrue(exportEvents().isEmpty());
        connectorMock.verifyExportKeyRequests(0);
    }

    @Test
    void listExportKeyAttributes_refusesWithoutTheExportPermission() {
        // given
        denyResourceAccess(Resource.CRYPTOGRAPHIC_KEY, ResourceAction.EXPORT_KEY);
        UUID keyUuid = key.getUuid();
        UUID privateKeyUuid = privateKey.getUuid();

        // when
        // then
        assertThrows(AccessDeniedException.class, () -> exportService.listExportKeyAttributes(keyUuid, privateKeyUuid));
    }

    @Test
    void listExportKeyAttributes_refusesAKeyThatIsNotExportable() {
        // given
        CryptographicKeyItem locked = persistKeyItem(key, KeyType.PRIVATE_KEY, false, KeyState.ACTIVE, true);
        UUID keyUuid = key.getUuid();
        UUID lockedUuid = locked.getUuid();

        // when
        ValidationException refused = assertThrows(ValidationException.class,
                () -> exportService.listExportKeyAttributes(keyUuid, lockedUuid));

        // then
        assertTrue(refused.getMessage().contains("was not created or imported as exportable"), refused.getMessage());
    }

    /** A key whose export is withdrawn while the connector is exporting it must not be handed out afterwards. */
    @Test
    void exportKey_refusesAKeyDemotedWhileTheConnectorExported() throws Exception {
        // given
        connectorMock
                .stubExportKeyAfter(exportAnswer(ExportEnvelopeFixtures.pinnedEnvelope(pair.getPrivate(), PASSPHRASE)),
                        2000);
        UUID keyUuid = key.getUuid();
        UUID privateKeyUuid = privateKey.getUuid();
        KeyExportRequestDto request = exportRequest();
        try (ExecutorService executor = Executors.newSingleThreadExecutor()) {
            Future<ExportedKeyMaterial> export = executor
                    .submit(DelegatingSecurityContextCallable
                            .create(() -> exportService.exportKey(keyUuid, privateKeyUuid, request),
                                    SecurityContextHolder.getContext()));
            Awaitility
                    .await("the connector received the export")
                    .atMost(Duration.ofSeconds(30))
                    .until(() -> connectorMock.exportKeyRequestsReceived() == 1);

            // when
            cryptographicKeyService.disableKeyExport(SecuredUUID.fromUUID(keyUuid), privateKeyUuid.toString());
            ExecutionException failure = assertThrows(ExecutionException.class, () -> export.get(30, TimeUnit.SECONDS));

            // then
            ValidationException refused = assertInstanceOf(ValidationException.class, failure.getCause());
            assertTrue(refused.getMessage().contains("changed while it was being exported"), refused.getMessage());
            assertEquals(KeyEventStatus.FAILED, onlyExportEvent().getStatus());
        }
    }

    /** The export's record is in the database when the file is handed out, not queued behind it. */
    @Test
    void exportKey_isAuditedBeforeTheFileIsHandedOut() throws Exception {
        // given
        auditLogsTo(AuditLogOutput.DATABASE, false);
        connectorMock.stubExportKey(exportAnswer(ExportEnvelopeFixtures.pinnedEnvelope(pair.getPrivate(), PASSPHRASE)));

        // when
        var download = keyController
                .exportKey(key.getUuid().toString(), privateKey.getUuid().toString(), exportRequest());

        // then
        assertEquals(HttpStatus.OK, download.getStatusCode());
        AuditLog auditRecord = auditLogRepository
                .findAll()
                .stream()
                .filter(log -> log.getOperation() == Operation.EXPORT)
                .findFirst()
                .orElseThrow();
        assertEquals(OperationResult.SUCCESS, auditRecord.getOperationResult());
        verifyNoInteractions(auditLogsProducer);
    }

    /**
     * An operator may turn on debug logging and verbose audit; neither may show the passphrase, whether the export
     * succeeds, the connector refuses or fails with the passphrase in its words, or its answer echoes it.
     */
    @Test
    void exportKey_leavesThePassphraseNowhere() throws Exception {
        // given
        String passphrase = new String(PASSPHRASE);
        auditLogsTo(AuditLogOutput.DATABASE, true);
        String keyUuid = key.getUuid().toString();
        String itemUuid = privateKey.getUuid().toString();
        List<String> seen = new ArrayList<>();
        ListAppender<ILoggingEvent> logs = new ListAppender<>();
        Logger root = (Logger) LoggerFactory.getLogger(org.slf4j.Logger.ROOT_LOGGER_NAME);
        Logger platform = (Logger) LoggerFactory.getLogger("com.otilm");
        Level platformLevel = platform.getLevel();
        logs.start();
        root.addAppender(logs);
        platform.setLevel(Level.DEBUG);

        // when
        try {
            connectorMock
                    .stubExportKey(exportAnswer(ExportEnvelopeFixtures.pinnedEnvelope(pair.getPrivate(), PASSPHRASE)));
            seen
                    .add(new String(keyController
                            .exportKey(keyUuid, itemUuid, exportRequest())
                            .getBody()
                            .getContentAsByteArray(), StandardCharsets.US_ASCII));
            connectorMock.stubExportKeyProblem(ErrorCode.KEY_NOT_EXPORTABLE, "refused for " + passphrase);
            seen.add(refusalOf(ValidationException.class, keyUuid, itemUuid));
            connectorMock.stubExportKeyProblem(ErrorCode.INTERNAL_SERVER_ERROR, "failed for " + passphrase);
            seen.add(refusalOf(ConnectorServerException.class, keyUuid, itemUuid));
            connectorMock.stubExportKeyLegacyRefusal("refused for " + passphrase);
            seen.add(refusalOf(ConnectorServerException.class, keyUuid, itemUuid));
            connectorMock.stubExportKey(echoingAnswer(passphrase));
            seen.add(refusalOf(OutboundSecretLeakException.class, keyUuid, itemUuid));
        } finally {
            platform.setLevel(platformLevel);
            root.detachAppender(logs);
        }

        // then
        for (ILoggingEvent event : logs.list) {
            seen.add(event.getFormattedMessage());
            if (event.getThrowableProxy() != null) {
                seen.add(ThrowableProxyUtil.asString(event.getThrowableProxy()));
            }
        }
        List<String> auditRecords = jdbcTemplate
                .queryForList("SELECT coalesce(message, '') || log_record::text FROM audit_log", String.class);
        assertTrue(auditRecords.stream().anyMatch(auditRecord -> auditRecord.contains("exportAttributes")),
                "the verbose records carry the request");
        seen.addAll(auditRecords);
        for (CryptographicKeyEventHistory event : exportEvents()) {
            seen.add(event.getMessage());
            seen.add(event.getAdditionalInformation());
        }
        assertEquals(5, exportEvents().size());
        assertEquals(5, auditRecords.size());
        assertTrue(seen.stream().filter(Objects::nonNull).noneMatch(text -> text.contains(passphrase)));
    }

    @Test
    void exportKey_isRegisteredOnKeysAtStartup() {
        // when
        ResourceSyncRequestDto keys = contextRefreshListener
                .getResources()
                .stream()
                .filter(resource -> resource.getName().getCode().equals(Resource.CRYPTOGRAPHIC_KEY.getCode()))
                .findFirst()
                .orElseThrow();

        // then
        assertTrue(keys.getActions().contains(ResourceAction.EXPORT_KEY.getCode()), keys.getActions().toString());
    }

    /** A refusal that carries no message still reaches the caller and the key's history. */
    @Test
    void exportKey_recordsAConnectorFailureThatCarriesNoMessage() {
        // given
        profile.forgetKeyTypes();
        tokenProfileRepository.save(profile);
        connectorMock.stubExportableKeyTypesProblemWithoutText();
        UUID keyUuid = key.getUuid();
        UUID privateKeyUuid = privateKey.getUuid();
        KeyExportRequestDto request = exportRequest();

        // when
        assertThrows(ConnectorProblemException.class, () -> exportService.exportKey(keyUuid, privateKeyUuid, request));

        // then
        CryptographicKeyEventHistory event = onlyExportEvent();
        assertEquals(KeyEventStatus.FAILED, event.getStatus());
        assertEquals("Key item export failed.", event.getMessage());
    }

    /** An item deleted while the connector exports it takes its history along; the refusal still reaches the caller. */
    @Test
    void exportKey_refusesAKeyItemDeletedWhileTheConnectorExported() {
        // given
        connectorMock
                .stubExportKeyAfter(exportAnswer(ExportEnvelopeFixtures.pinnedEnvelope(pair.getPrivate(), PASSPHRASE)),
                        2000);
        UUID keyUuid = key.getUuid();
        UUID privateKeyUuid = privateKey.getUuid();
        KeyExportRequestDto request = exportRequest();
        try (ExecutorService executor = Executors.newSingleThreadExecutor()) {
            Future<ExportedKeyMaterial> export = executor
                    .submit(DelegatingSecurityContextCallable
                            .create(() -> exportService.exportKey(keyUuid, privateKeyUuid, request),
                                    SecurityContextHolder.getContext()));
            Awaitility
                    .await("the connector received the export")
                    .atMost(Duration.ofSeconds(30))
                    .until(() -> connectorMock.exportKeyRequestsReceived() == 1);

            // when
            cryptographicKeyItemRepository.deleteById(privateKeyUuid);
            ExecutionException failure = assertThrows(ExecutionException.class, () -> export.get(30, TimeUnit.SECONDS));

            // then
            ValidationException refused = assertInstanceOf(ValidationException.class, failure.getCause());
            assertTrue(refused.getMessage().contains("changed while it was being exported"), refused.getMessage());
            assertEquals(1, refused.getSuppressed().length, "the history's own failure rides along");
            assertTrue(exportEvents().isEmpty());
        }
    }

    /** A connector's own words never reach the caller on this path: they may carry the passphrase back. */
    @Test
    void exportKey_mapsAConnectorRefusalToAFixedMessage() throws Exception {
        // given
        String passphrase = new String(PASSPHRASE);
        connectorMock.stubExportKeyProblem(ErrorCode.KEY_NOT_EXPORTABLE, "refused for " + passphrase);

        // when
        ValidationException refused = refuseTheExport(privateKey);

        // then
        assertTrue(refused.getMessage().contains(ErrorCode.KEY_NOT_EXPORTABLE.name()), refused.getMessage());
        assertFalse(refused.getMessage().contains(passphrase), refused.getMessage());
        CryptographicKeyEventHistory event = onlyExportEvent();
        assertEquals(KeyEventStatus.FAILED, event.getStatus());
        assertFalse(event.getMessage().contains(passphrase), event.getMessage());
    }

    @Test
    void listExportKeyAttributes_returnsTheConnectorsSchema() throws Exception {
        // given
        connectorMock
                .stubExportKeyAttributes("[{\"uuid\":\"" + UUID.randomUUID() + "\",\"name\":\"exportLabel\","
                        + "\"type\":\"data\",\"contentType\":\"string\",\"version\":3,\"properties\":{\"label\":"
                        + "\"Export label\",\"visible\":true,\"required\":false,\"readOnly\":false,\"list\":false,"
                        + "\"multiSelect\":false}}]");

        // when
        List<BaseAttribute> schema = exportService.listExportKeyAttributes(key.getUuid(), privateKey.getUuid());

        // then
        assertEquals(List.of("exportLabel"), schema.stream().map(BaseAttribute::getName).toList());
    }

    // ---- fixtures ----

    /** The connector answered for the right key, with an envelope the platform does not hand on. */
    private void assertTheConnectorFailsWith(byte[] envelope) {
        connectorMock.stubExportKey(exportAnswer(envelope));
        UUID keyUuid = key.getUuid();
        UUID privateKeyUuid = privateKey.getUuid();
        KeyExportRequestDto request = exportRequest();
        ConnectorServerException refused = assertThrows(ConnectorServerException.class,
                () -> exportService.exportKey(keyUuid, privateKeyUuid, request));
        assertEquals(HttpStatus.BAD_GATEWAY, refused.getHttpStatus());
        assertEquals(KeyEventStatus.FAILED, onlyExportEvent().getStatus());
    }

    private String refusalOf(Class<? extends Exception> expected, String keyUuid, String itemUuid) {
        KeyExportRequestDto request = exportRequest();
        return assertThrows(expected, () -> keyController.exportKey(keyUuid, itemUuid, request)).getMessage();
    }

    /** Refused by one of Core's own gates: recorded, and the connector never asked to export. */
    private void assertRefusedBeforeTheConnector(CryptographicKeyItem item, String reason) {
        ValidationException refused = refuseTheExport(item);
        assertTrue(refused.getMessage().contains(reason), refused.getMessage());
        assertEquals(KeyEventStatus.FAILED, onlyExportEvent().getStatus());
        connectorMock.verifyExportKeyRequests(0);
    }

    private ValidationException refuseTheExport(CryptographicKeyItem item) {
        UUID keyUuid = item.getKeyUuid();
        UUID itemUuid = item.getUuid();
        KeyExportRequestDto request = exportRequest();
        return assertThrows(ValidationException.class, () -> exportService.exportKey(keyUuid, itemUuid, request));
    }

    private void auditLogsTo(AuditLogOutput output, boolean verbose) {
        AuditLoggingSettingsDto auditLogs = new AuditLoggingSettingsDto();
        auditLogs.setOutput(output);
        auditLogs.setLogAllModules(true);
        auditLogs.setLogAllResources(true);
        auditLogs.setVerbose(verbose);
        LoggingSettingsDto settings = new LoggingSettingsDto();
        settings.setAuditLogs(auditLogs);
        settings.setEventLogs(new ResourceLoggingSettingsDto());
        settingService.updateLoggingSettings(settings);
    }

    private static KeyExportRequestDto exportRequest() {
        KeyExportRequestDto request = new KeyExportRequestDto();
        request.setPassphrase(new Passphrase(PASSPHRASE));
        request.setExportAttributes(List.of());
        return request;
    }

    private String exportAnswer(byte[] envelope) {
        return ExportEnvelopeFixtures.keyPairResponseJson(envelope, KeyAlgorithm.RSA, 2048, pair.getPublic());
    }

    /** A well-formed answer for the right key whose descriptor carries the passphrase back as metadata. */
    private String echoingAnswer(String passphrase) {
        String answer = exportAnswer(ExportEnvelopeFixtures.pinnedEnvelope(pair.getPrivate(), PASSPHRASE));
        String metadata = ",\"metadata\":[{\"version\":3,\"uuid\":\"" + UUID.randomUUID()
                + "\",\"name\":\"note\",\"type\":\"meta\",\"contentType\":\"string\",\"properties\":{\"label\":"
                + "\"Note\",\"visible\":true},\"content\":[{\"contentType\":\"string\",\"data\":\"" + passphrase
                + "\"}]}]}}";
        return answer.substring(0, answer.length() - 2) + metadata;
    }

    private List<CryptographicKeyEventHistory> exportEvents() {
        return eventHistoryRepository.findAll().stream().filter(event -> event.getEvent() == KeyEvent.EXPORT).toList();
    }

    private CryptographicKeyEventHistory onlyExportEvent() {
        List<CryptographicKeyEventHistory> events = exportEvents();
        assertEquals(1, events.size());
        return events.getFirst();
    }

    private Connector persistV2Connector(String url) {
        Connector value = new Connector();
        value.setName("export-provider-v2");
        value.setUrl(url);
        value.setVersion(ConnectorVersion.V2);
        value.setStatus(ConnectorStatus.CONNECTED);
        return connectorRepository.save(value);
    }

    private ConnectorInterfaceEntity persistCryptographyInterface() {
        ConnectorInterfaceEntity value = new ConnectorInterfaceEntity();
        value.setConnector(connector);
        value.setConnectorUuid(connector.getUuid());
        value.setInterfaceCode(ConnectorInterface.CRYPTOGRAPHY);
        value.setVersion("v2");
        value.setFeatures(List.of(FeatureFlag.STATELESS, FeatureFlag.KEY_EXPORT));
        value = connectorInterfaceRepository.save(value);
        connector.getInterfaces().add(value);
        return value;
    }

    private TokenInstanceReference persistToken() {
        TokenInstanceReference value = new TokenInstanceReference();
        value.setName("export-token");
        value.setConnector(connector);
        value.setConnectorUuid(connector.getUuid());
        value.setConnectorInterface(cryptographyInterface);
        value.setKind("SOFT");
        value.setStatus(TokenInstanceStatus.ACTIVATED);
        return tokenInstanceReferenceRepository.save(value);
    }

    /** A profile whose connector already answered that it exports RSA key pairs. */
    private TokenProfile persistProfile() {
        TokenProfile value = new TokenProfile();
        value.setName("export-profile-" + UUID.randomUUID());
        value.setTokenInstanceReference(token);
        value.setTokenInstanceName(token.getName());
        value.setEnabled(true);
        value.setUsage(List.of(KeyUsage.SIGN, KeyUsage.VERIFY));
        value
                .setExportableKeyTypes(
                        List.of(new TransferableKeyType(KeyRequestType.KEY_PAIR, Set.of(KeyAlgorithm.RSA))));
        return tokenProfileRepository.save(value);
    }

    private CryptographicKey persistKey() {
        CryptographicKey value = new CryptographicKey();
        value.setName("v2-exportable-key");
        value.setTokenProfile(profile);
        value.setTokenInstanceReference(token);
        return cryptographicKeyRepository.save(value);
    }

    private CryptographicKeyItem persistPublicKeyItem(PublicKey material) {
        CryptographicKeyItem value = keyItem(key, KeyType.PUBLIC_KEY, false, KeyState.ACTIVE, true);
        value.setFormat(KeyFormat.SPKI);
        value.setKeyData(Base64.getEncoder().encodeToString(material.getEncoded()));
        return cryptographicKeyItemRepository.save(value);
    }

    private CryptographicKeyItem persistKeyItem(CryptographicKey owner, KeyType type, boolean exportable,
            KeyState state, boolean enabled) {
        return cryptographicKeyItemRepository.save(keyItem(owner, type, exportable, state, enabled));
    }

    /** The export permission is written once, with the item; it cannot be granted afterwards. */
    private static CryptographicKeyItem keyItem(CryptographicKey owner, KeyType type, boolean exportable,
            KeyState state, boolean enabled) {
        MetadataAttributeV3 handle = new MetadataAttributeV3();
        handle.setUuid(UUID.randomUUID().toString());
        handle.setName("provider-handle");
        handle.setType(AttributeType.META);
        handle.setContentType(AttributeContentType.STRING);
        handle.setProperties(new MetadataAttributeProperties());
        handle.setContent(List.of(new StringAttributeContentV3("handle-" + UUID.randomUUID())));
        CryptographicKeyItem value = new CryptographicKeyItem();
        value.setName(owner.getName() + " " + type.getCode());
        value.setKey(owner);
        value.setKeyUuid(owner.getUuid());
        value.setType(type);
        value.setKeyAlgorithm(KeyAlgorithm.RSA);
        value.setFormat(KeyFormat.PRKI);
        value.setLength(2048);
        value.setState(state);
        value.setEnabled(enabled);
        value.setUsage(List.of(KeyUsage.SIGN, KeyUsage.VERIFY));
        value.setKeyMeta(List.of(handle));
        value.setExportable(exportable);
        return value;
    }
}
