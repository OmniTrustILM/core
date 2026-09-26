package com.otilm.core.integration.service;

import ch.qos.logback.classic.Level;
import ch.qos.logback.classic.Logger;
import ch.qos.logback.classic.spi.ILoggingEvent;
import ch.qos.logback.classic.spi.ThrowableProxyUtil;
import ch.qos.logback.core.read.ListAppender;
import com.fasterxml.jackson.databind.JsonNode;
import com.otilm.api.exception.ConnectorServerException;
import com.otilm.api.exception.NotFoundException;
import com.otilm.api.exception.ValidationException;
import com.otilm.api.interfaces.core.web.CryptographicKeyController;
import com.otilm.api.model.client.attribute.RequestAttribute;
import com.otilm.api.model.client.attribute.RequestAttributeV3;
import com.otilm.api.model.client.attribute.ResponseAttribute;
import com.otilm.api.model.client.connector.v2.ConnectorInterface;
import com.otilm.api.model.client.connector.v2.ConnectorVersion;
import com.otilm.api.model.client.connector.v2.FeatureFlag;
import com.otilm.api.model.client.cryptography.key.KeyImportRequestDto;
import com.otilm.api.model.client.cryptography.key.KeyRequestType;
import com.otilm.api.model.common.NameAndUuidDto;
import com.otilm.api.model.common.attribute.common.AttributeType;
import com.otilm.api.model.common.attribute.common.content.AttributeContentType;
import com.otilm.api.model.common.attribute.common.properties.CustomAttributeProperties;
import com.otilm.api.model.common.attribute.v3.CustomAttributeV3;
import com.otilm.api.model.common.attribute.v3.content.StringAttributeContentV3;
import com.otilm.api.model.common.enums.cryptography.KeyAlgorithm;
import com.otilm.api.model.common.enums.cryptography.KeyFormat;
import com.otilm.api.model.common.enums.cryptography.KeyType;
import com.otilm.api.model.common.error.ErrorCode;
import com.otilm.api.model.connector.common.v2.OperationStatus;
import com.otilm.api.model.connector.cryptography.enums.TokenInstanceStatus;
import com.otilm.api.model.connector.cryptography.v2.key.KeyPairDataResponseV2Dto;
import com.otilm.api.model.connector.cryptography.v2.key.KeyPairOperationStatusResponseV2Dto;
import com.otilm.api.model.connector.cryptography.v2.key.PrivateKeyDataResponseV2Dto;
import com.otilm.api.model.connector.cryptography.v2.key.PrivateKeyDataV2Dto;
import com.otilm.api.model.connector.cryptography.v2.key.PublicKeyDataResponseV2Dto;
import com.otilm.api.model.connector.cryptography.v2.key.PublicKeyDataV2Dto;
import com.otilm.api.model.core.auth.Resource;
import com.otilm.api.model.core.certificate.group.GroupDto;
import com.otilm.api.model.core.connector.ConnectorStatus;
import com.otilm.api.model.core.cryptography.key.KeyDetailDto;
import com.otilm.api.model.core.cryptography.key.KeyEvent;
import com.otilm.api.model.core.cryptography.key.KeyEventStatus;
import com.otilm.api.model.core.cryptography.key.KeyItemDetailDto;
import com.otilm.api.model.core.cryptography.key.KeyState;
import com.otilm.api.model.core.cryptography.key.KeyUsage;
import com.otilm.api.model.core.logging.enums.AuditLogOutput;
import com.otilm.api.model.core.logging.enums.Operation;
import com.otilm.api.model.core.logging.enums.OperationResult;
import com.otilm.api.model.core.logging.records.ResourceObjectIdentity;
import com.otilm.api.model.core.secret.Passphrase;
import com.otilm.api.model.core.secret.UploadedFile;
import com.otilm.api.model.core.settings.logging.AuditLoggingSettingsDto;
import com.otilm.api.model.core.settings.logging.LoggingSettingsDto;
import com.otilm.api.model.core.settings.logging.ResourceLoggingSettingsDto;
import com.otilm.core.attribute.engine.AttributeEngine;
import com.otilm.core.dao.entity.AuditLog;
import com.otilm.core.dao.entity.Connector;
import com.otilm.core.dao.entity.ConnectorInterfaceEntity;
import com.otilm.core.dao.entity.CryptographicKey;
import com.otilm.core.dao.entity.CryptographicKeyEventHistory;
import com.otilm.core.dao.entity.CryptographicKeyItem;
import com.otilm.core.dao.entity.Group;
import com.otilm.core.dao.entity.KeyImport;
import com.otilm.core.dao.entity.KeyImportState;
import com.otilm.core.dao.entity.OwnerAssociation;
import com.otilm.core.dao.entity.TokenInstanceReference;
import com.otilm.core.dao.entity.TokenProfile;
import com.otilm.core.dao.repository.AuditLogRepository;
import com.otilm.core.dao.repository.ConnectorInterfaceRepository;
import com.otilm.core.dao.repository.ConnectorRepository;
import com.otilm.core.dao.repository.CryptographicKeyEventHistoryRepository;
import com.otilm.core.dao.repository.CryptographicKeyItemRepository;
import com.otilm.core.dao.repository.CryptographicKeyRepository;
import com.otilm.core.dao.repository.GroupRepository;
import com.otilm.core.dao.repository.KeyImportRepository;
import com.otilm.core.dao.repository.OwnerAssociationRepository;
import com.otilm.core.dao.repository.TokenInstanceReferenceRepository;
import com.otilm.core.dao.repository.TokenProfileRepository;
import com.otilm.core.model.auth.ResourceAction;
import com.otilm.core.model.crypto.KeyMaterial;
import com.otilm.core.serialization.ObjectMapperFactory;
import com.otilm.core.service.CryptographicKeyImportExternalService;
import com.otilm.core.service.ResourceObjectAssociationService;
import com.otilm.core.service.SettingExternalService;
import com.otilm.core.service.handler.KeyImportSaga;
import com.otilm.core.service.writer.CertificateKeyWriter;
import com.otilm.core.service.writer.CryptographicKeyWriter;
import com.otilm.core.util.AuthHelper;
import com.otilm.core.util.BaseSpringBootTest;
import com.otilm.core.util.CryptographyUtil;
import com.otilm.core.util.ExportEnvelopeFixtures;
import com.otilm.core.util.mocks.ConnectorMockFactory;
import com.otilm.core.util.mocks.CryptographyProviderV2ConnectorMock;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PublicKey;
import java.security.spec.ECGenParameterSpec;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;
import java.util.Objects;
import java.util.UUID;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openssl.jcajce.JceOpenSSLPKCS8DecryptorProviderBuilder;
import org.bouncycastle.pkcs.PKCS8EncryptedPrivateKeyInfo;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;
import org.junit.jupiter.params.provider.EnumSource;
import org.junit.jupiter.params.provider.ValueSource;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.security.access.AccessDeniedException;

import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.Mockito.verifyNoInteractions;

@SpringBootTest
class CryptographicKeyImportV2ITest extends BaseSpringBootTest {

    private static final char[] PASSPHRASE = "correct horse battery staple".toCharArray();

    private static final List<KeyUsage> PROFILE_USAGES = List
            .of(KeyUsage.SIGN, KeyUsage.VERIFY, KeyUsage.ENCRYPT, KeyUsage.DECRYPT);

    private static final String REQUIRED_LABEL_SCHEMA = "[{\"uuid\":\"" + UUID.randomUUID()
            + "\",\"name\":\"importLabel\",\"type\":\"data\",\"contentType\":\"string\",\"version\":3,"
            + "\"properties\":{\"label\":\"Import label\",\"visible\":true,\"required\":true,\"readOnly\":false,"
            + "\"list\":false,\"multiSelect\":false}}]";

    @Autowired
    private CryptographicKeyImportExternalService importService;
    @Autowired
    private CryptographicKeyController keyController;
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
    private KeyImportRepository keyImportRepository;
    @Autowired
    private CertificateKeyWriter certificateKeyWriter;
    @Autowired
    private OwnerAssociationRepository ownerAssociationRepository;
    @Autowired
    private ResourceObjectAssociationService objectAssociationService;
    @Autowired
    private AuditLogRepository auditLogRepository;
    @Autowired
    private SettingExternalService settingService;
    @Autowired
    private ConnectorMockFactory connectorMockFactory;
    @Autowired
    private JdbcTemplate jdbcTemplate;
    @Autowired
    private AttributeEngine attributeEngine;
    @Autowired
    private GroupRepository groupRepository;

    private CryptographyProviderV2ConnectorMock connectorMock;
    private Connector connector;
    private ConnectorInterfaceEntity cryptographyInterface;
    private TokenInstanceReference token;
    private TokenProfile profile;
    private KeyPair pair;

    @BeforeEach
    void setUp() throws Exception {
        connectorMock = connectorMockFactory.startCryptographyProviderV2();
        connector = persistV2Connector(connectorMock.getUrl());
        cryptographyInterface = persistCryptographyInterface();
        token = persistToken();
        profile = persistProfile();
        connectorMock.stubImportableKeyTypes(KeyRequestType.KEY_PAIR, KeyAlgorithm.RSA);
        connectorMock.stubImportKeyAttributes("[]");
        pair = rsa();
    }

    @AfterEach
    void tearDown() {
        connectorMock.stop();
    }

    @Test
    void importKey_importsAKeyFromAPlainFile() throws Exception {
        // given
        connectorMock.stubImportKey(200, imported(pair.getPublic()));
        Group group = new Group();
        group.setName("importers");
        groupRepository.save(group);
        KeyImportRequestDto request = plainRequest("imported key");
        request.setGroupUuids(List.of(group.getUuid().toString()));

        // when
        KeyDetailDto detail = importKey(request);

        // then
        KeyImport attempt = onlyAttempt();
        assertThat(attempt.getState()).isEqualTo(KeyImportState.COMPLETED);
        assertThat(attempt.getKeyUuid()).hasToString(detail.getUuid());
        assertThat(detail.getName()).isEqualTo("imported key");
        assertThat(detail.getItems())
                .extracting(KeyItemDetailDto::getType)
                .containsExactlyInAnyOrder(KeyType.PUBLIC_KEY, KeyType.PRIVATE_KEY);
        assertThat(detail.getGroups()).extracting(GroupDto::getUuid).containsExactly(group.getUuid().toString());
        CryptographicKeyItem publicKey = item(attempt.getKeyUuid(), KeyType.PUBLIC_KEY);
        CryptographicKeyItem privateKey = item(attempt.getKeyUuid(), KeyType.PRIVATE_KEY);
        assertThat(publicKey.getKeyData()).isEqualTo(Base64.getEncoder().encodeToString(pair.getPublic().getEncoded()));
        assertThat(privateKey.getKeyReferenceUuid()).isEqualTo(attempt.getKeyReference());
        assertThat(List.of(publicKey, privateKey)).allSatisfy(item -> {
            assertThat(item.getState()).isEqualTo(KeyState.ACTIVE);
            assertThat(item.isEnabled()).isFalse();
        });
        assertThat(importEvents())
                .hasSize(2)
                .allSatisfy(event -> assertThat(event.getStatus()).isEqualTo(KeyEventStatus.SUCCESS));
        assertThat(ownerOf(attempt.getKeyUuid())).isEqualTo(AuthHelper.getUserIdentification().getName());
        JsonNode sent = onlyImportRequest();
        assertThat(sent.get("keyImportId").asText()).isEqualTo(attempt.getUuid().toString());
        assertThat(sent.get("keyReference").asText()).isEqualTo(attempt.getKeyReference().toString());
        assertThat(sent.get("executionMode").asText()).isEqualTo("synchronous");
        assertThat(sent.get("exportable").asBoolean()).isFalse();
        assertThat(opened(sent)).isEqualTo(pair.getPrivate().getEncoded());
    }

    @Test
    void importKey_importsAKeyFromAProtectedFile() throws Exception {
        // given
        connectorMock.stubImportKey(200, imported(pair.getPublic()));
        byte[] file = ExportEnvelopeFixtures.pinnedEnvelope(pair.getPrivate(), PASSPHRASE);

        // when
        importKey(request("imported key", file, PASSPHRASE));

        // then
        assertThat(onlyAttempt().getState()).isEqualTo(KeyImportState.COMPLETED);
        assertThat(connectorMock.importKeyRequestBodies().getFirst())
                .doesNotContain(new String(PASSPHRASE), Base64.getEncoder().encodeToString(file));
    }

    @Test
    void importKey_waitsOnAnAsynchronousConnector() throws Exception {
        // given
        declare(FeatureFlag.STATELESS, FeatureFlag.KEY_IMPORT, FeatureFlag.ASYNCHRONOUS);
        connectorMock.stubImportKey(202, accepted());
        connectorMock.stubImportKeyStatuses(status(OperationStatus.IN_PROGRESS), status(OperationStatus.COMPLETED));

        // when
        KeyDetailDto detail = importKey(plainRequest("imported key"));

        // then
        KeyImport attempt = onlyAttempt();
        assertThat(attempt.getState()).isEqualTo(KeyImportState.COMPLETED);
        assertThat(attempt.getKeyUuid()).hasToString(detail.getUuid());
        assertThat(onlyImportRequest().get("executionMode").asText()).isEqualTo("asynchronous");
    }

    @Test
    void importKey_cancelsAnImportThatDoesNotFinishInTime() throws Exception {
        // given
        declare(FeatureFlag.STATELESS, FeatureFlag.KEY_IMPORT, FeatureFlag.ASYNCHRONOUS);
        connectorMock.stubImportKey(202, accepted());
        connectorMock.stubImportKeyStatuses(status(OperationStatus.IN_PROGRESS));
        connectorMock.stubCancelImportKey();
        KeyImportRequestDto request = plainRequest("imported key");

        // when
        ConnectorServerException cancelled = assertThrows(ConnectorServerException.class, () -> importKey(request));

        // then
        assertThat(cancelled.getMessage()).isEqualTo(KeyImportSaga.CANCELLED.formatted(1));
        connectorMock.verifyCancelImportKeyRequests(1);
        assertThat(onlyAttempt().getState()).isEqualTo(KeyImportState.FAILED);
        assertThat(cryptographicKeyRepository.count()).isZero();
    }

    @ParameterizedTest
    @EnumSource(value = ErrorCode.class,
            names = {
                    "KEY_TYPE_NOT_IMPORTABLE",
                    "KEY_MATERIAL_MISMATCH",
                    "KEY_DECRYPTION_FAILED",
                    "EXPORTABLE_NOT_SUPPORTED",
                    "VALIDATION_FAILED"})
    void importKey_namesTheCodeOfARefusal(ErrorCode code) throws Exception {
        // given
        connectorMock.stubImportKeyProblem(code, "refused for reasons of the connector");
        KeyImportRequestDto request = plainRequest("imported key");

        // when
        ValidationException refused = assertThrows(ValidationException.class, () -> importKey(request));

        // then
        assertThat(refused.getMessage()).isEqualTo("The connector refused to import the key (" + code.name() + ").");
        KeyImport attempt = onlyAttempt();
        assertThat(attempt.getState()).isEqualTo(KeyImportState.FAILED);
        assertThat(attempt.getErrorMessage()).isEqualTo(refused.getMessage());
        assertThat(cryptographicKeyRepository.count()).isZero();
    }

    @Test
    void importKey_leavesAnUnansweredImportOpen() {
        // given
        connectorMock.stubImportKeyUnanswered();
        KeyImportRequestDto request = plainRequest("imported key");

        // when
        ConnectorServerException unconfirmed = assertThrows(ConnectorServerException.class, () -> importKey(request));

        // then
        assertThat(unconfirmed.getMessage()).isEqualTo(KeyImportSaga.UNCONFIRMED);
        assertThat(onlyAttempt().getState()).isEqualTo(KeyImportState.REQUESTED);
        assertThat(cryptographicKeyRepository.count()).isZero();
    }

    @Test
    void importKey_convergesOnRetryThroughTheRecordedResult() throws Exception {
        // given
        connectorMock.stubImportKeyUnanswered();
        KeyImportRequestDto first = plainRequest("imported key");
        assertThrows(ConnectorServerException.class, () -> importKey(first));
        connectorMock.stubImportKeyResult(status(OperationStatus.COMPLETED));

        // when
        KeyDetailDto detail = importKey(plainRequest("imported key"));

        // then
        KeyImport attempt = onlyAttempt();
        assertThat(attempt.getState()).isEqualTo(KeyImportState.COMPLETED);
        assertThat(attempt.getKeyUuid()).hasToString(detail.getUuid());
        connectorMock.verifyImportKeyRequests(1);
        connectorMock.verifyImportKeyResultRequests(1);
    }

    /**
     * The recorded result answers what the first request sent, so it is checked against that request's transport
     * passphrase and envelope, which the retry does not have; a result that echoes either is refused.
     */
    @ParameterizedTest
    @ValueSource(strings = {"/passphrase", "/material/encryptedPrivateKeyInfo"})
    void importKey_refusesARecordedResultThatEchoesWhatTheFirstRequestSent(String secretField) throws Exception {
        // given
        connectorMock.stubImportKeyUnanswered();
        KeyImportRequestDto first = plainRequest("imported key");
        assertThrows(ConnectorServerException.class, () -> importKey(first));
        String sentSecret = onlyImportRequest().at(secretField).asText();
        KeyPairOperationStatusResponseV2Dto recorded = status(OperationStatus.COMPLETED);
        recorded.getResult().getPrivateKeyData().setKeyMeta(List.of(KeyImportWriterITest.handle("echo", sentSecret)));
        connectorMock.stubImportKeyResult(recorded);
        KeyImportRequestDto retry = plainRequest("imported key");

        // when
        ConnectorServerException refused = assertThrows(ConnectorServerException.class, () -> importKey(retry));

        // then
        assertThat(refused.getMessage()).isEqualTo(KeyImportSaga.UNCONFIRMED);
        assertThat(onlyAttempt().getState()).isEqualTo(KeyImportState.REQUESTED);
        assertThat(cryptographicKeyRepository.count()).isZero();
        connectorMock.verifyImportKeyRequests(1);
    }

    @Test
    void importKey_resendsAnImportTheConnectorNeverAccepted() throws Exception {
        // given
        connectorMock.stubImportKeyUnanswered();
        KeyImportRequestDto first = plainRequest("imported key");
        assertThrows(ConnectorServerException.class, () -> importKey(first));
        connectorMock.stubImportKeyResultNotTracked();
        connectorMock.stubImportKey(200, imported(pair.getPublic()));

        // when
        importKey(plainRequest("imported key"));

        // then
        KeyImport attempt = onlyAttempt();
        assertThat(attempt.getState()).isEqualTo(KeyImportState.COMPLETED);
        List<JsonNode> sent = importRequests();
        assertThat(sent).hasSize(2);
        assertThat(sent)
                .extracting(body -> body.get("keyImportId").asText())
                .containsOnly(attempt.getUuid().toString());
        assertThat(sent)
                .extracting(body -> body.get("keyReference").asText())
                .containsOnly(attempt.getKeyReference().toString());
    }

    @Test
    void importKey_startsAgainWhenTheRecordedImportFailed() throws Exception {
        // given
        connectorMock.stubImportKeyUnanswered();
        KeyImportRequestDto first = plainRequest("imported key");
        assertThrows(ConnectorServerException.class, () -> importKey(first));
        connectorMock.stubImportKeyResult(status(OperationStatus.FAILED));
        connectorMock.stubImportKey(200, imported(pair.getPublic()));

        // when
        importKey(plainRequest("imported key"));

        // then
        assertThat(keyImportRepository.findAll())
                .extracting(KeyImport::getState)
                .containsExactlyInAnyOrder(KeyImportState.FAILED, KeyImportState.COMPLETED);
        assertThat(importRequests())
                .extracting(body -> body.get("keyImportId").asText())
                .hasSize(2)
                .doesNotHaveDuplicates();
    }

    @Test
    void importKey_answersARepeatedImportWithItsKey() throws Exception {
        // given
        connectorMock.stubImportKey(200, imported(pair.getPublic()));
        KeyDetailDto first = importKey(plainRequest("imported key"));

        // when
        KeyDetailDto second = importKey(plainRequest("imported key"));

        // then
        assertThat(second.getUuid()).isEqualTo(first.getUuid());
        connectorMock.verifyImportKeyRequests(1);
        assertThat(keyImportRepository.count()).isEqualTo(1);
    }

    /** The same key from another file is another import, so it meets the duplicate check rather than the retry. */
    @Test
    void importKey_refusesAKeyThePlatformAlreadyHolds() throws Exception {
        // given
        connectorMock.stubImportKey(200, imported(pair.getPublic()));
        importKey(plainRequest("imported key"));
        KeyImportRequestDto sameKeyAnotherFile = protectedRequest("the same key again");

        // when
        ValidationException refused = assertThrows(ValidationException.class, () -> importKey(sameKeyAnotherFile));

        // then
        assertThat(refused.getMessage()).isEqualTo(CryptographicKeyWriter.KEY_ALREADY_HELD);
        connectorMock.verifyImportKeyRequests(1);
    }

    @Test
    void importKey_adoptsTheKeyACertificateBroughtIn() throws Exception {
        // given
        UUID recordUuid = certificatePublicKey();
        connectorMock.stubImportKey(200, imported(pair.getPublic()));

        // when
        KeyDetailDto detail = importKey(plainRequest("imported key"));

        // then
        assertThat(detail.getUuid()).isEqualTo(recordUuid.toString());
        CryptographicKey adopted = cryptographicKeyRepository.findById(recordUuid).orElseThrow();
        assertThat(adopted.getTokenProfileUuid()).isEqualTo(profile.getUuid());
        assertThat(cryptographicKeyItemRepository.findByKeyUuidIn(List.of(recordUuid))).hasSize(2);
        assertThat(importEvents())
                .hasSize(2)
                .allSatisfy(event -> assertThat(event.getStatus()).isEqualTo(KeyEventStatus.SUCCESS));
        assertThat(ownerOf(recordUuid)).isEqualTo(AuthHelper.getUserIdentification().getName());
    }

    @Test
    void importKey_recordsAFailedAdoptionOnThePublicKey() throws Exception {
        // given
        UUID recordUuid = certificatePublicKey();
        UUID publicKeyUuid = item(recordUuid, KeyType.PUBLIC_KEY).getUuid();
        connectorMock.stubImportKeyProblem(ErrorCode.KEY_TYPE_NOT_IMPORTABLE, "refused");
        KeyImportRequestDto request = plainRequest("imported key");

        // when
        assertThrows(ValidationException.class, () -> importKey(request));

        // then
        assertThat(importEvents()).singleElement().satisfies(event -> {
            assertThat(event.getStatus()).isEqualTo(KeyEventStatus.FAILED);
            assertThat(event.getKeyUuid()).isEqualTo(publicKeyUuid);
            assertThat(event.getMessage()).contains("KEY_TYPE_NOT_IMPORTABLE");
        });
        assertThat(cryptographicKeyRepository.findById(recordUuid).orElseThrow().getTokenProfileUuid()).isNull();
    }

    @Test
    void importKey_refusesATakenName() throws Exception {
        // given
        connectorMock.stubImportKey(200, imported(pair.getPublic()));
        importKey(plainRequest("taken"));
        KeyImportRequestDto anotherKey = request("taken", rsa().getPrivate().getEncoded(), null);

        // when
        ValidationException refused = assertThrows(ValidationException.class, () -> importKey(anotherKey));

        // then
        assertThat(refused.getMessage()).isEqualTo(KeyImportSaga.NAME_TAKEN.formatted("taken"));
        connectorMock.verifyImportKeyRequests(1);
    }

    @Test
    void importKey_refusesAnExportableImportTheProfileDoesNotExport() {
        // given
        KeyImportRequestDto exportable = plainRequest("imported key");
        exportable.setExportable(true);

        // when
        ValidationException refused = assertThrows(ValidationException.class, () -> importKey(exportable));

        // then
        assertThat(refused.getMessage()).contains("cannot be imported as exportable");
        connectorMock.verifyImportKeyRequests(0);
        assertThat(keyImportRepository.count()).isZero();
    }

    @Test
    void importKey_importsAnExportableKeyWhereTheProfileExportsIt() throws Exception {
        // given
        declare(FeatureFlag.STATELESS, FeatureFlag.KEY_IMPORT, FeatureFlag.KEY_EXPORT);
        connectorMock.stubExportableKeyTypes(KeyRequestType.KEY_PAIR, KeyAlgorithm.RSA);
        connectorMock.stubImportKey(200, imported(pair.getPublic()));
        KeyImportRequestDto exportable = plainRequest("imported key");
        exportable.setExportable(true);

        // when
        importKey(exportable);

        // then
        assertThat(onlyImportRequest().get("exportable").asBoolean()).isTrue();
        assertThat(item(onlyAttempt().getKeyUuid(), KeyType.PRIVATE_KEY).isExportable()).isTrue();
    }

    @Test
    void importKey_refusesAnAlgorithmTheProfileDoesNotImport() throws Exception {
        // given
        KeyPairGenerator generator = KeyPairGenerator.getInstance("EC");
        generator.initialize(new ECGenParameterSpec("secp256r1"));
        KeyImportRequestDto ecKey = request("imported key", generator.generateKeyPair().getPrivate().getEncoded(),
                null);

        // when
        ValidationException refused = assertThrows(ValidationException.class, () -> importKey(ecKey));

        // then
        assertThat(refused.getMessage())
                .contains("does not import the " + KeyAlgorithm.ECDSA.getLabel() + " algorithm");
        connectorMock.verifyImportKeyRequests(0);
        assertThat(keyImportRepository.count()).isZero();
    }

    @Test
    void importKey_refusesATypeTheProfileDoesNotImport() {
        // given
        KeyImportRequestDto request = plainRequest("imported key");
        UUID tokenUuid = token.getUuid();
        UUID profileUuid = profile.getUuid();

        // when
        ValidationException refused = assertThrows(ValidationException.class,
                () -> importService.importKey(tokenUuid, profileUuid, KeyRequestType.SECRET, request));

        // then
        assertThat(refused.getMessage()).contains("does not import a secret key");
        assertThat(keyImportRepository.count()).isZero();
    }

    @Test
    void importKey_neverAsksAConnectorWithoutKeyImport() {
        // given
        declare(FeatureFlag.STATELESS, FeatureFlag.KEY_EXPORT);
        KeyImportRequestDto request = plainRequest("imported key");

        // when
        assertThrows(ValidationException.class, () -> importKey(request));

        // then
        connectorMock.verifyImportableKeyTypesRequests(0);
        connectorMock.verifyImportKeyRequests(0);
    }

    @Test
    void importKey_refusesAGroupThatDoesNotExistBeforeTheConnector() {
        // given
        KeyImportRequestDto unknown = plainRequest("imported key");
        unknown.setGroupUuids(List.of(UUID.randomUUID().toString()));
        KeyImportRequestDto malformed = plainRequest("imported key");
        malformed.setGroupUuids(List.of("not-a-uuid"));

        // when
        NotFoundException missing = assertThrows(NotFoundException.class, () -> importKey(unknown));
        ValidationException invalid = assertThrows(ValidationException.class, () -> importKey(malformed));

        // then
        assertThat(missing.getMessage()).contains(unknown.getGroupUuids().getFirst());
        assertThat(invalid.getMessage()).isEqualTo("Group UUID not-a-uuid is not valid.");
        connectorMock.verifyImportKeyRequests(0);
    }

    @Test
    void importKey_refusesImportAttributesOutsideTheSchema() {
        // given
        connectorMock.stubImportKeyAttributes(REQUIRED_LABEL_SCHEMA);
        KeyImportRequestDto request = plainRequest("imported key");

        // when
        assertThrows(ValidationException.class, () -> importKey(request));

        // then
        connectorMock.verifyImportKeyRequests(0);
        assertThat(keyImportRepository.count()).isZero();
    }

    @Test
    void importKey_refusesWithoutTheImportPermission() {
        // given
        denyResourceAccess(Resource.CRYPTOGRAPHIC_KEY, ResourceAction.IMPORT_KEY);
        KeyImportRequestDto request = plainRequest("imported key");

        // when
        assertThrows(AccessDeniedException.class, () -> importKey(request));

        // then
        connectorMock.verifyImportKeyRequests(0);
    }

    /** Owning an object passes most checks on it; import has to be granted as a permission of its own. */
    @Test
    void importKey_refusesTheProfileOwnerWithoutTheImportPermission() {
        // given
        denyResourceAccess(Resource.CRYPTOGRAPHIC_KEY, ResourceAction.IMPORT_KEY);
        NameAndUuidDto principal = AuthHelper.getUserIdentification();
        OwnerAssociation ownership = new OwnerAssociation();
        ownership.setResource(Resource.TOKEN_PROFILE);
        ownership.setObjectUuid(profile.getUuid());
        ownership.setOwnerUuid(UUID.fromString(principal.getUuid()));
        ownership.setOwnerUsername(principal.getName());
        ownerAssociationRepository.save(ownership);
        KeyImportRequestDto request = plainRequest("imported key");

        // when
        assertThrows(AccessDeniedException.class, () -> importKey(request));

        // then
        connectorMock.verifyImportKeyRequests(0);
    }

    @ParameterizedTest
    @CsvSource({"TOKEN_PROFILE, DETAIL", "TOKEN, DETAIL", "TOKEN, MEMBERS"})
    void importKey_refusesWithoutAccessToTheProfileOrItsToken(Resource resource, ResourceAction action) {
        // given
        denyResourceAccess(resource, action);
        KeyImportRequestDto request = plainRequest("imported key");

        // when
        assertThrows(AccessDeniedException.class, () -> importKey(request));

        // then
        connectorMock.verifyImportKeyRequests(0);
    }

    /** The import's record is in the database when the key is returned, not queued behind it. */
    @Test
    void importKey_isAuditedBeforeTheKeyIsReturned() throws Exception {
        // given
        auditLogsTo(AuditLogOutput.DATABASE, false);
        connectorMock.stubImportKey(200, imported(pair.getPublic()));

        // when
        KeyDetailDto detail = keyController
                .importKey(token.getUuid().toString(), profile.getUuid().toString(), KeyRequestType.KEY_PAIR,
                        plainRequest("imported key"));

        // then
        AuditLog auditRecord = auditLogRepository
                .findAll()
                .stream()
                .filter(log -> log.getOperation() == Operation.IMPORT)
                .findFirst()
                .orElseThrow();
        assertThat(auditRecord.getOperationResult()).isEqualTo(OperationResult.SUCCESS);
        assertThat(auditRecord.getResource()).isEqualTo(Resource.CRYPTOGRAPHIC_KEY);
        assertThat(auditRecord.getLogRecord().resource().objects())
                .extracting(ResourceObjectIdentity::uuid)
                .containsExactly(UUID.fromString(detail.getUuid()));
        assertThat(auditRecord.getAffiliatedResource()).isEqualTo(Resource.TOKEN_PROFILE);
        assertThat(auditRecord.getLogRecord().affiliatedResource().objects())
                .extracting(ResourceObjectIdentity::uuid)
                .containsExactly(profile.getUuid());
        verifyNoInteractions(auditLogsProducer);
    }

    /**
     * An operator may turn on debug logging and verbose audit; neither may show the file, its passphrase, the envelope
     * or the transport passphrase, whether the connector refuses or fails in words of its own, the outcome is unknown,
     * the file does not open, the import succeeds on a retry, is waited for, or is cancelled.
     */
    @Test
    void importKey_leavesNoSecretBehind() throws Exception {
        // given
        auditLogsTo(AuditLogOutput.DATABASE, true);
        byte[] file = ExportEnvelopeFixtures.pinnedEnvelope(pair.getPrivate(), PASSPHRASE);
        KeyPair waitedFor = rsa();
        KeyPair cancelled = rsa();
        String tokenUuid = token.getUuid().toString();
        String profileUuid = profile.getUuid().toString();
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
            connectorMock.stubImportKeyProblem(ErrorCode.KEY_DECRYPTION_FAILED, "refused " + new String(PASSPHRASE));
            seen.add(failureOf(tokenUuid, profileUuid, request("refused", file, PASSPHRASE)));
            connectorMock.stubImportKeyProblem(ErrorCode.INTERNAL_SERVER_ERROR, "failed " + new String(PASSPHRASE));
            seen.add(failureOf(tokenUuid, profileUuid, request("failed", file, PASSPHRASE)));
            seen.add(failureOf(tokenUuid, profileUuid, request("wrong", file, "wrong passphrase".toCharArray())));
            connectorMock.stubImportKeyResultNotTracked();
            connectorMock.stubImportKey(200, imported(pair.getPublic()));
            seen
                    .add(ObjectMapperFactory
                            .wire()
                            .writeValueAsString(keyController
                                    .importKey(tokenUuid, profileUuid, KeyRequestType.KEY_PAIR,
                                            request("imported", file, PASSPHRASE))));
            declare(FeatureFlag.STATELESS, FeatureFlag.KEY_IMPORT, FeatureFlag.ASYNCHRONOUS);
            connectorMock.stubImportKey(202, accepted());
            connectorMock
                    .stubImportKeyStatuses(status(OperationStatus.IN_PROGRESS, waitedFor.getPublic()),
                            status(OperationStatus.COMPLETED, waitedFor.getPublic()));
            seen
                    .add(ObjectMapperFactory
                            .wire()
                            .writeValueAsString(keyController
                                    .importKey(tokenUuid, profileUuid, KeyRequestType.KEY_PAIR,
                                            request("waited for", waitedFor.getPrivate().getEncoded(), null))));
            connectorMock.stubImportKeyStatuses(status(OperationStatus.IN_PROGRESS, cancelled.getPublic()));
            connectorMock.stubCancelImportKey();
            seen
                    .add(failureOf(tokenUuid, profileUuid,
                            request("cancelled", cancelled.getPrivate().getEncoded(), null)));
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
        seen
                .addAll(jdbcTemplate
                        .queryForList("SELECT coalesce(message, '') || log_record::text FROM audit_log", String.class));
        seen.addAll(jdbcTemplate.queryForList("SELECT row_to_json(key_import)::text FROM key_import", String.class));
        for (CryptographicKeyEventHistory event : importEvents()) {
            seen.add(event.getMessage());
            seen.add(event.getAdditionalInformation());
        }
        List<String> secrets = new ArrayList<>(List
                .of(new String(PASSPHRASE), Base64.getEncoder().encodeToString(file),
                        Base64.getEncoder().encodeToString(waitedFor.getPrivate().getEncoded()),
                        Base64.getEncoder().encodeToString(cancelled.getPrivate().getEncoded())));
        for (JsonNode sent : importRequests()) {
            secrets.add(sent.get("passphrase").asText());
            secrets.add(sent.get("material").get("encryptedPrivateKeyInfo").asText());
        }
        assertThat(importRequests()).hasSize(5);
        assertThat(seen).filteredOn(Objects::nonNull).allSatisfy(text -> assertThat(text).doesNotContain(secrets));
    }

    /** A repeat changes nothing, so the custom attributes the key has now stay, whatever the repeat states. */
    @Test
    void importKey_leavesTheKeysCustomAttributesAsTheyAreOnARepeat() throws Exception {
        // given
        connectorMock.stubImportKey(200, imported(pair.getPublic()));
        CustomAttributeV3 department = departmentAttribute();
        KeyImportRequestDto first = plainRequest("imported key");
        first.setCustomAttributes(List.of(departmentValue(department, "Sales")));
        importKey(first);

        // when
        KeyDetailDto repeated = importKey(plainRequest("imported key"));

        // then
        assertThat(repeated.getCustomAttributes()).extracting(ResponseAttribute::getName).containsExactly("department");
        connectorMock.verifyImportKeyRequests(1);
    }

    /** A repeat shows the key as it is now, so a caller who may no longer see it, once it changed hands, is refused. */
    @Test
    void importKey_refusesARepeatToACallerWhoMayNoLongerSeeTheKey() throws Exception {
        // given
        connectorMock.stubImportKey(200, imported(pair.getPublic()));
        KeyDetailDto imported = importKey(plainRequest("imported key"));
        objectAssociationService
                .setOwner(Resource.CRYPTOGRAPHIC_KEY, UUID.fromString(imported.getUuid()), UUID.randomUUID(),
                        "another");
        denyResourceAccess(Resource.CRYPTOGRAPHIC_KEY, ResourceAction.DETAIL);
        KeyImportRequestDto repeat = plainRequest("imported key");

        // when
        // then
        assertThrows(AccessDeniedException.class, () -> importKey(repeat));
        connectorMock.verifyImportKeyRequests(1);
    }

    @Test
    void importKey_refusesTheKeyOfACompromisedCertificateKey() {
        // given
        UUID recordUuid = certificatePublicKey();
        CryptographicKeyItem publicKey = item(recordUuid, KeyType.PUBLIC_KEY);
        publicKey.setState(KeyState.COMPROMISED);
        cryptographicKeyItemRepository.saveAndFlush(publicKey);
        KeyImportRequestDto request = plainRequest("imported key");

        // when
        ValidationException refused = assertThrows(ValidationException.class, () -> importKey(request));

        // then
        assertThat(refused.getMessage()).isEqualTo(CryptographicKeyWriter.KEY_NOT_ACTIVE);
        connectorMock.verifyImportKeyRequests(0);
        assertThat(keyImportRepository.count()).isZero();
    }

    // ---- fixtures ----

    private KeyDetailDto importKey(KeyImportRequestDto request) throws Exception {
        return importService.importKey(token.getUuid(), profile.getUuid(), KeyRequestType.KEY_PAIR, request);
    }

    /** The refusal as the caller sees it, through the audited endpoint. */
    private String failureOf(String tokenUuid, String profileUuid, KeyImportRequestDto request) {
        Exception failure = assertThrows(Exception.class,
                () -> keyController.importKey(tokenUuid, profileUuid, KeyRequestType.KEY_PAIR, request));
        return failure.getMessage();
    }

    private KeyImportRequestDto plainRequest(String name) {
        return request(name, pair.getPrivate().getEncoded(), null);
    }

    private KeyImportRequestDto protectedRequest(String name) {
        return request(name, ExportEnvelopeFixtures.pinnedEnvelope(pair.getPrivate(), PASSPHRASE), PASSPHRASE);
    }

    private static KeyImportRequestDto request(String name, byte[] file, char[] passphrase) {
        KeyImportRequestDto request = new KeyImportRequestDto();
        request.setName(name);
        request.setDescription("imported for the test");
        request.setFile(new UploadedFile(file));
        request.setInputPassphrase(passphrase == null ? null : new Passphrase(passphrase));
        request.setImportAttributes(List.of());
        return request;
    }

    /** The connector's synchronous answer for a key pair: its public key and handles. */
    private static KeyPairDataResponseV2Dto imported(PublicKey publicKey) {
        PublicKeyDataV2Dto publicData = new PublicKeyDataV2Dto();
        publicData.setAlgorithm(KeyAlgorithm.RSA);
        publicData.setLength(2048);
        publicData.setPublicKeySpki(publicKey.getEncoded());
        publicData.setMetadata(List.of());
        PublicKeyDataResponseV2Dto publicKeyData = new PublicKeyDataResponseV2Dto();
        publicKeyData.setKeyData(publicData);
        publicKeyData.setKeyMeta(List.of(KeyImportWriterITest.handle("public-handle", "p")));
        PrivateKeyDataV2Dto privateData = new PrivateKeyDataV2Dto();
        privateData.setAlgorithm(KeyAlgorithm.RSA);
        privateData.setLength(2048);
        privateData.setMetadata(List.of());
        PrivateKeyDataResponseV2Dto privateKeyData = new PrivateKeyDataResponseV2Dto();
        privateKeyData.setKeyData(privateData);
        privateKeyData.setKeyMeta(List.of(KeyImportWriterITest.handle("private-handle", "q")));
        KeyPairDataResponseV2Dto answer = new KeyPairDataResponseV2Dto();
        answer.setPublicKeyData(publicKeyData);
        answer.setPrivateKeyData(privateKeyData);
        answer.setKeyPairMeta(List.of(KeyImportWriterITest.handle("pair-handle", "r")));
        return answer;
    }

    private static KeyPairDataResponseV2Dto accepted() {
        KeyPairDataResponseV2Dto answer = new KeyPairDataResponseV2Dto();
        answer.setOperationMeta(List.of(KeyImportWriterITest.handle("operation", "1")));
        return answer;
    }

    private KeyPairOperationStatusResponseV2Dto status(OperationStatus status) {
        return status(status, pair.getPublic());
    }

    private static KeyPairOperationStatusResponseV2Dto status(OperationStatus status, PublicKey publicKey) {
        KeyPairOperationStatusResponseV2Dto answer = new KeyPairOperationStatusResponseV2Dto();
        answer.setStatus(status);
        if (status == OperationStatus.COMPLETED) {
            answer.setResult(imported(publicKey));
        }
        if (status == OperationStatus.FAILED || status == OperationStatus.CANCELLED) {
            answer.setReason("stopped");
        }
        return answer;
    }

    private void declare(FeatureFlag... features) {
        cryptographyInterface.setFeatures(List.of(features));
        connectorInterfaceRepository.save(cryptographyInterface);
    }

    private UUID certificatePublicKey() {
        String fingerprint = CryptographyUtil
                .calculateKeyFingerprint(new KeyMaterial(KeyFormat.SPKI,
                        Base64.getEncoder().encodeToString(pair.getPublic().getEncoded())));
        return certificateKeyWriter.uploadCertificatePublicKey("certKey_imported", pair.getPublic(), 2048, fingerprint);
    }

    private KeyImport onlyAttempt() {
        List<KeyImport> attempts = keyImportRepository.findAll();
        assertThat(attempts).hasSize(1);
        return attempts.getFirst();
    }

    private List<JsonNode> importRequests() throws Exception {
        List<JsonNode> sent = new ArrayList<>();
        for (String body : connectorMock.importKeyRequestBodies()) {
            sent.add(ObjectMapperFactory.wire().readTree(body));
        }
        return sent;
    }

    private JsonNode onlyImportRequest() throws Exception {
        List<JsonNode> sent = importRequests();
        assertThat(sent).hasSize(1);
        return sent.getFirst();
    }

    /** The key the envelope protects, opened under the transport passphrase the request carried with it. */
    private static byte[] opened(JsonNode sent) throws Exception {
        byte[] envelope = Base64.getDecoder().decode(sent.get("material").get("encryptedPrivateKeyInfo").asText());
        char[] passphrase = sent.get("passphrase").asText().toCharArray();
        return new PKCS8EncryptedPrivateKeyInfo(envelope)
                .decryptPrivateKeyInfo(new JceOpenSSLPKCS8DecryptorProviderBuilder()
                        .setProvider(BouncyCastleProvider.PROVIDER_NAME)
                        .build(passphrase))
                .getEncoded();
    }

    private CryptographicKeyItem item(UUID keyUuid, KeyType type) {
        return cryptographicKeyItemRepository
                .findByKeyUuidIn(List.of(keyUuid))
                .stream()
                .filter(item -> item.getType() == type)
                .findFirst()
                .orElseThrow();
    }

    private List<CryptographicKeyEventHistory> importEvents() {
        return eventHistoryRepository.findAll().stream().filter(event -> event.getEvent() == KeyEvent.IMPORT).toList();
    }

    private String ownerOf(UUID keyUuid) {
        return objectAssociationService.getOwner(Resource.CRYPTOGRAPHIC_KEY, keyUuid).getName();
    }

    private static KeyPair rsa() throws Exception {
        KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
        generator.initialize(2048);
        return generator.generateKeyPair();
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

    private Connector persistV2Connector(String url) {
        Connector value = new Connector();
        value.setName("import-provider-v2");
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
        value.setFeatures(List.of(FeatureFlag.STATELESS, FeatureFlag.KEY_IMPORT));
        value = connectorInterfaceRepository.save(value);
        connector.getInterfaces().add(value);
        return value;
    }

    private TokenInstanceReference persistToken() {
        TokenInstanceReference value = new TokenInstanceReference();
        value.setName("import-token-" + UUID.randomUUID());
        value.setConnector(connector);
        value.setConnectorUuid(connector.getUuid());
        value.setConnectorInterface(cryptographyInterface);
        value.setKind("SOFT");
        value.setStatus(TokenInstanceStatus.ACTIVATED);
        return tokenInstanceReferenceRepository.save(value);
    }

    private TokenProfile persistProfile() {
        TokenProfile value = new TokenProfile();
        value.setName("import-profile-" + UUID.randomUUID());
        value.setTokenInstanceReference(token);
        value.setTokenInstanceName(token.getName());
        value.setEnabled(true);
        value.setUsage(PROFILE_USAGES);
        return tokenProfileRepository.save(value);
    }

    private CustomAttributeV3 departmentAttribute() throws Exception {
        CustomAttributeV3 department = new CustomAttributeV3();
        department.setUuid(UUID.randomUUID().toString());
        department.setName("department");
        department.setType(AttributeType.CUSTOM);
        department.setContentType(AttributeContentType.STRING);
        CustomAttributeProperties properties = new CustomAttributeProperties();
        properties.setLabel("Department");
        department.setProperties(properties);
        attributeEngine.updateCustomAttributeDefinition(department, List.of(Resource.CRYPTOGRAPHIC_KEY));
        return department;
    }

    private static RequestAttribute departmentValue(CustomAttributeV3 department, String value) {
        RequestAttributeV3 attribute = new RequestAttributeV3();
        attribute.setUuid(UUID.fromString(department.getUuid()));
        attribute.setName(department.getName());
        attribute.setContentType(AttributeContentType.STRING);
        attribute.setContent(List.of(new StringAttributeContentV3(value)));
        return attribute;
    }
}
