package com.otilm.core.integration.service;

import com.fasterxml.jackson.databind.JsonNode;
import com.github.tomakehurst.wiremock.WireMockServer;
import com.otilm.api.exception.ConnectorServerException;
import com.otilm.api.exception.NotFoundException;
import com.otilm.api.exception.ValidationException;
import com.otilm.api.interfaces.core.web.CryptographicKeyController;
import com.otilm.api.model.client.attribute.RequestAttribute;
import com.otilm.api.model.client.attribute.RequestAttributeV3;
import com.otilm.api.model.client.attribute.ResponseAttribute;
import com.otilm.api.model.client.attribute.ResponseAttributeV3;
import com.otilm.api.model.client.certificate.ImportOutcome;
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
import com.otilm.api.model.connector.cryptography.v2.key.KeyPairDataResponseV2Dto;
import com.otilm.api.model.connector.cryptography.v2.key.KeyPairOperationStatusResponseV2Dto;
import com.otilm.api.model.connector.cryptography.v2.key.PrivateKeyDataResponseV2Dto;
import com.otilm.api.model.connector.cryptography.v2.key.PrivateKeyDataV2Dto;
import com.otilm.api.model.connector.cryptography.v2.key.PublicKeyDataResponseV2Dto;
import com.otilm.api.model.connector.cryptography.v2.key.PublicKeyDataV2Dto;
import com.otilm.api.model.connector.cryptography.v2.key.SecretKeyDataResponseV2Dto;
import com.otilm.api.model.connector.cryptography.v2.key.SecretKeyDataV2Dto;
import com.otilm.api.model.connector.cryptography.v2.key.SecretKeyOperationStatusResponseV2Dto;
import com.otilm.api.model.core.auth.Resource;
import com.otilm.api.model.core.certificate.group.GroupDto;
import com.otilm.api.model.core.cryptography.key.KeyDetailDto;
import com.otilm.api.model.core.cryptography.key.KeyEvent;
import com.otilm.api.model.core.cryptography.key.KeyEventStatus;
import com.otilm.api.model.core.cryptography.key.KeyItemDetailDto;
import com.otilm.api.model.core.cryptography.key.KeyState;
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
import com.otilm.core.attribute.engine.OutboundSecretContainment;
import com.otilm.core.dao.entity.AuditLog;
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
import com.otilm.core.dao.repository.CryptographicKeyEventHistoryRepository;
import com.otilm.core.dao.repository.CryptographicKeyItemRepository;
import com.otilm.core.dao.repository.CryptographicKeyRepository;
import com.otilm.core.dao.repository.GroupRepository;
import com.otilm.core.dao.repository.KeyImportRepository;
import com.otilm.core.dao.repository.OwnerAssociationRepository;
import com.otilm.core.model.auth.ResourceAction;
import com.otilm.core.model.crypto.ImportedKey;
import com.otilm.core.model.crypto.KeyMaterial;
import com.otilm.core.serialization.ObjectMapperFactory;
import com.otilm.core.service.CryptographicKeyImportExternalService;
import com.otilm.core.service.ResourceObjectAssociationService;
import com.otilm.core.service.SettingExternalService;
import com.otilm.core.service.handler.KeyImportSaga;
import com.otilm.core.service.impl.CryptographicKeyImportServiceImpl;
import com.otilm.core.service.writer.CertificateKeyWriter;
import com.otilm.core.service.writer.CryptographicKeyWriter;
import com.otilm.core.service.writer.KeyImportWriter;
import com.otilm.core.util.AuthHelper;
import com.otilm.core.util.AuthServiceWireMockStubs;
import com.otilm.core.util.BaseSpringBootTest;
import com.otilm.core.util.CryptographyUtil;
import com.otilm.core.util.ExportEnvelopeFixtures;
import com.otilm.core.util.SecretLeakProbe;
import com.otilm.core.util.mocks.CryptographyProviderV2ConnectorMock;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PublicKey;
import java.security.spec.ECGenParameterSpec;
import java.time.Duration;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;
import java.util.UUID;
import java.util.concurrent.Callable;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import javax.crypto.KeyGenerator;
import org.awaitility.Awaitility;
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
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.concurrent.DelegatingSecurityContextCallable;
import org.springframework.security.core.context.SecurityContextHolder;

import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.Mockito.verifyNoInteractions;

@SpringBootTest
class CryptographicKeyImportV2ITest extends BaseSpringBootTest {

    private static final char[] PASSPHRASE = "correct horse battery staple".toCharArray();

    /** The transport passphrase another node sent the import with. */
    private static final String RESENT = "another node's transport passphrase";

    private static final String REQUIRED_LABEL_SCHEMA = "[{\"uuid\":\"" + UUID.randomUUID()
            + "\",\"name\":\"importLabel\",\"type\":\"data\",\"contentType\":\"string\",\"version\":3,"
            + "\"properties\":{\"label\":\"Import label\",\"visible\":true,\"required\":true,\"readOnly\":false,"
            + "\"list\":false,\"multiSelect\":false}}]";

    @Autowired
    private CryptographicKeyImportExternalService importService;
    @Autowired
    private CryptographicKeyController keyController;
    @Autowired
    private V2TokenFixture v2TokenFixture;
    @Autowired
    private CryptographicKeyRepository cryptographicKeyRepository;
    @Autowired
    private CryptographicKeyItemRepository cryptographicKeyItemRepository;
    @Autowired
    private CryptographicKeyEventHistoryRepository eventHistoryRepository;
    @Autowired
    private KeyImportRepository keyImportRepository;
    @Autowired
    private KeyImportWriter keyImportWriter;
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
    private JdbcTemplate jdbcTemplate;
    @Autowired
    private AttributeEngine attributeEngine;
    @Autowired
    private GroupRepository groupRepository;

    private WireMockServer authService;
    private V2TokenFixture.V2Token v2Token;
    private CryptographyProviderV2ConnectorMock connectorMock;
    private TokenInstanceReference token;
    private TokenProfile profile;
    private KeyPair pair;

    @BeforeEach
    void setUp() throws Exception {
        v2Token = v2TokenFixture.start();
        connectorMock = v2Token.connectorMock();
        token = v2Token.token();
        profile = v2Token.profile();
        connectorMock.stubImportableKeyTypes(KeyRequestType.KEY_PAIR, KeyAlgorithm.RSA);
        connectorMock.stubImportKeyAttributes("[]");
        pair = rsa();
    }

    @AfterEach
    void tearDown() {
        connectorMock.stop();
        if (authService != null) {
            authService.stop();
        }
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

    /**
     * A retry on another node resumed the import while this request waited on it, so this request's deadline leaves the
     * import running, for the retry to learn the outcome of and register. The connector answers this request's poll
     * only after its deadline, and the test resumes the import meanwhile, as the retry does.
     */
    @Test
    void importKey_leavesAnImportAnotherNodeResumedToThatNode() throws Exception {
        // given
        declare(FeatureFlag.STATELESS, FeatureFlag.KEY_IMPORT, FeatureFlag.ASYNCHRONOUS);
        connectorMock.stubImportKey(202, accepted());
        connectorMock.stubImportKeyStatusAfter(status(OperationStatus.IN_PROGRESS), 2000);
        connectorMock.stubCancelImportKey();
        try (ExecutorService node = Executors.newSingleThreadExecutor()) {
            Future<KeyDetailDto> first = node.submit(onNode(() -> importKey(plainRequest("imported key"))));
            awaitPolling();

            // when
            keyImportWriter.resuming(onlyAttempt().getUuid());
            ExecutionException failure = assertThrows(ExecutionException.class, () -> first.get(10, TimeUnit.SECONDS));

            // then
            assertThat(failure.getCause())
                    .isInstanceOf(ConnectorServerException.class)
                    .hasMessage(KeyImportSaga.UNCONFIRMED);
            connectorMock.verifyCancelImportKeyRequests(0);
        }

        // when
        connectorMock.stubImportKeyResult(status(OperationStatus.COMPLETED));
        KeyDetailDto detail = importKey(plainRequest("imported key"));

        // then
        KeyImport attempt = onlyAttempt();
        assertThat(attempt.getState()).isEqualTo(KeyImportState.COMPLETED);
        assertThat(attempt.getKeyUuid()).hasToString(detail.getUuid());
        connectorMock.verifyImportKeyRequests(1);
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

    /**
     * A retry on another node sent the import again, with secrets of its own, while this request waited on it; an
     * answer that echoes them is refused, so they are stored nowhere. The connector is asked again once that answer is
     * stubbed, so it is that answer, not the deadline, that ends the wait.
     */
    @Test
    void importKey_refusesAnAnswerThatEchoesWhatAnotherNodeSentWhileItWaited() throws Exception {
        // given
        declare(FeatureFlag.STATELESS, FeatureFlag.KEY_IMPORT, FeatureFlag.ASYNCHRONOUS);
        connectorMock.stubImportKey(202, accepted());
        connectorMock.stubImportKeyStatuses(status(OperationStatus.IN_PROGRESS));
        KeyPairOperationStatusResponseV2Dto echoing = status(OperationStatus.COMPLETED);
        echoing.getResult().getPrivateKeyData().setKeyMeta(List.of(KeyImportWriterITest.handle("echo", RESENT)));
        List<String> seen = new ArrayList<>();
        SecretLeakProbe probe = SecretLeakProbe.capture();
        try (probe; ExecutorService node = Executors.newSingleThreadExecutor()) {
            Future<KeyDetailDto> waiting = node.submit(onNode(() -> importKey(plainRequest("imported key"))));
            awaitPolling();

            // when
            keyImportWriter.resending(onlyAttempt().getUuid(), OutboundSecretContainment.digestsOf(List.of(RESENT)));
            connectorMock.stubImportKeyStatuses(echoing);
            int pollsBeforeTheEcho = connectorMock.importKeyStatusRequestsReceived();
            ExecutionException failure = assertThrows(ExecutionException.class,
                    () -> waiting.get(10, TimeUnit.SECONDS));

            // then
            assertThat(failure.getCause())
                    .isInstanceOf(ConnectorServerException.class)
                    .hasMessage(KeyImportSaga.UNCONFIRMED);
            assertThat(connectorMock.importKeyStatusRequestsReceived()).isGreaterThan(pollsBeforeTheEcho);
            seen.addAll(probe.logged());
        }
        assertThat(onlyAttempt().getState()).isEqualTo(KeyImportState.ACCEPTED);
        assertThat(cryptographicKeyRepository.count()).isZero();
        seen.addAll(jdbcTemplate.queryForList("SELECT row_to_json(key_import)::text FROM key_import", String.class));
        seen
                .addAll(jdbcTemplate
                        .queryForList("SELECT row_to_json(cryptographic_key_item)::text FROM cryptographic_key_item",
                                String.class));
        SecretLeakProbe.assertNoneReveals(seen, RESENT);
    }

    /**
     * A retry on another node sent the import again while this request's send was on its way, so the connector's
     * refusal of this send leaves the attempt open, for the retry's send to settle.
     */
    @Test
    void importKey_leavesOpenAnAttemptAnotherNodeSentAgainWhenItsOwnSendIsRefused() throws Exception {
        // given
        connectorMock.stubImportKeyProblemAfter(ErrorCode.KEY_DECRYPTION_FAILED, "refused", 2000);
        try (ExecutorService node = Executors.newSingleThreadExecutor()) {
            Future<KeyDetailDto> refused = node.submit(onNode(() -> importKey(plainRequest("imported key"))));
            awaitSending();

            // when
            keyImportWriter.resending(onlyAttempt().getUuid(), OutboundSecretContainment.digestsOf(List.of(RESENT)));
            ExecutionException failure = assertThrows(ExecutionException.class,
                    () -> refused.get(10, TimeUnit.SECONDS));

            // then
            assertThat(failure.getCause())
                    .isInstanceOf(ConnectorServerException.class)
                    .hasMessage(KeyImportSaga.UNCONFIRMED);
        }
        assertThat(onlyAttempt().getState()).isEqualTo(KeyImportState.REQUESTED);
        assertThat(cryptographicKeyRepository.count()).isZero();
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

    /**
     * The same key from another file is another import, which finds the key the platform holds: it changes nothing,
     * asks no connector and records no attempt.
     */
    @Test
    void importKey_answersAKeyThePlatformHoldsWithoutAskingTheConnector() throws Exception {
        // given
        connectorMock.stubImportKey(200, imported(pair.getPublic()));
        KeyDetailDto held = importKey(plainRequest("imported key"));

        // when
        ImportedKey again = importKeyWithOutcome(KeyRequestType.KEY_PAIR, protectedRequest("the same key again"));

        // then
        assertThat(again.outcome()).isEqualTo(ImportOutcome.EXISTING);
        assertThat(again.key().uuid()).hasToString(held.getUuid());
        assertThat(again.key().name()).isEqualTo("imported key");
        connectorMock.verifyImportKeyRequests(1);
        assertThat(keyImportRepository.count()).isEqualTo(1);
    }

    /** A caller who may not see the key the platform holds learns nothing of it: the import is refused. */
    @Test
    void importKey_refusesAKeyItHoldsToACallerWhoMayNotSeeIt() throws Exception {
        // given
        connectorMock.stubImportKey(200, imported(pair.getPublic()));
        KeyDetailDto held = importKey(plainRequest("imported key"));
        objectAssociationService
                .setOwner(Resource.CRYPTOGRAPHIC_KEY, UUID.fromString(held.getUuid()), UUID.randomUUID(), "another");
        denyResourceAccess(Resource.CRYPTOGRAPHIC_KEY, ResourceAction.DETAIL);
        KeyImportRequestDto sameKeyAnotherFile = protectedRequest("the same key again");

        // when
        ValidationException refused = assertThrows(ValidationException.class, () -> importKey(sameKeyAnotherFile));

        // then
        assertThat(refused.getMessage()).isEqualTo(CryptographicKeyImportServiceImpl.KEY_EXISTS);
        connectorMock.verifyImportKeyRequests(1);
    }

    @Test
    void importKey_refusesAKeyThePlatformHoldsDeactivated() throws Exception {
        // given
        connectorMock.stubImportKey(200, imported(pair.getPublic()));
        KeyDetailDto held = importKey(plainRequest("imported key"));
        for (CryptographicKeyItem item : cryptographicKeyItemRepository
                .findByKeyUuidIn(List.of(UUID.fromString(held.getUuid())))) {
            item.setState(KeyState.DEACTIVATED);
            cryptographicKeyItemRepository.saveAndFlush(item);
        }
        KeyImportRequestDto sameKeyAnotherFile = protectedRequest("the same key again");

        // when
        ValidationException refused = assertThrows(ValidationException.class, () -> importKey(sameKeyAnotherFile));

        // then
        assertThat(refused.getMessage()).isEqualTo(CryptographicKeyWriter.KEY_NOT_ACTIVE);
        connectorMock.verifyImportKeyRequests(1);
        assertThat(keyImportRepository.count()).isEqualTo(1);
    }

    @Test
    void importKey_adoptsTheKeyACertificateBroughtIn() throws Exception {
        // given
        authServiceKnowsTheRequester();
        UUID recordUuid = certificatePublicKey();
        connectorMock.stubImportKey(200, imported(pair.getPublic()));

        // when
        KeyDetailDto detail = importKey(plainRequest("imported key"));

        // then
        assertThat(detail.getUuid()).isEqualTo(recordUuid.toString());
        assertThat(detail.getName()).isEqualTo("certKey_imported");
        CryptographicKey adopted = cryptographicKeyRepository.findById(recordUuid).orElseThrow();
        assertThat(adopted.getTokenProfileUuid()).isEqualTo(profile.getUuid());
        assertThat(cryptographicKeyItemRepository.findByKeyUuidIn(List.of(recordUuid))).hasSize(2);
        assertThat(importEvents())
                .hasSize(2)
                .allSatisfy(event -> assertThat(event.getStatus()).isEqualTo(KeyEventStatus.SUCCESS));
        assertThat(objectAssociationService.getOwner(Resource.CRYPTOGRAPHIC_KEY, recordUuid)).isNull();
    }

    /**
     * An import into a record another user owns, by a caller allowed to update it, adds the private key and nothing
     * else: the record keeps whose it is, its groups, its custom attributes, its name, which need not be free, and its
     * description; the imported key's items are registered under the record's name.
     */
    @Test
    void importKey_adoptsARecordAnotherUserOwnsWithoutChangingIt() throws Exception {
        // given
        authServiceKnowsTheRequester();
        UUID recordUuid = certificatePublicKey();
        UUID ownerUuid = UUID.randomUUID();
        Group recordGroup = group("record group");
        CustomAttributeV3 department = departmentAttribute();
        describedOwnedAndGrouped(recordUuid, ownerUuid, recordGroup, departmentValue(department, "Sales"));
        keyNamed("taken");
        connectorMock.stubImportKey(200, imported(pair.getPublic()));
        KeyImportRequestDto request = plainRequest("taken");
        request.setGroupUuids(List.of(group("import group").getUuid().toString()));
        request.setCustomAttributes(List.of(departmentValue(department, "Engineering")));

        // when
        ImportedKey adopted = importKeyWithOutcome(KeyRequestType.KEY_PAIR, request);

        // then
        assertThat(adopted.outcome()).isEqualTo(ImportOutcome.ADOPTED);
        assertThat(adopted.key().uuid()).isEqualTo(recordUuid);
        CryptographicKey kept = cryptographicKeyRepository.findWithGroupsByUuid(recordUuid).orElseThrow();
        assertThat(kept.getName()).isEqualTo("certKey_imported");
        assertThat(kept.getDescription()).isEqualTo("the certificate's key");
        assertThat(kept.getTokenProfileUuid()).isEqualTo(profile.getUuid());
        assertThat(kept.getGroups()).extracting(Group::getUuid).containsExactly(recordGroup.getUuid());
        assertThat(objectAssociationService.getOwner(Resource.CRYPTOGRAPHIC_KEY, recordUuid).getUuid())
                .isEqualTo(ownerUuid.toString());
        assertThat(departmentOf(recordUuid)).isEqualTo("Sales");
        assertThat(item(recordUuid, KeyType.PRIVATE_KEY).getName()).isEqualTo("certKey_imported private key");
        assertThat(onlyAttempt().getName()).isEqualTo("certKey_imported");
    }

    /**
     * A caller who may not update a record another user owns is refused before anything is recorded or asked, in the
     * words a key held otherwise is refused with, and the record is left as it was.
     */
    @Test
    void importKey_refusesARecordAnotherUserOwnsToACallerWithoutUpdate() throws Exception {
        // given
        UUID recordUuid = certificatePublicKey();
        UUID ownerUuid = UUID.randomUUID();
        Group recordGroup = group("record group");
        CustomAttributeV3 department = departmentAttribute();
        describedOwnedAndGrouped(recordUuid, ownerUuid, recordGroup, departmentValue(department, "Sales"));
        denyResourceAccess(Resource.CRYPTOGRAPHIC_KEY, ResourceAction.UPDATE);
        connectorMock.stubImportKey(200, imported(pair.getPublic()));
        KeyImportRequestDto request = plainRequest("imported key");

        // when
        ValidationException refused = assertThrows(ValidationException.class, () -> importKey(request));

        // then
        assertThat(refused.getMessage()).isEqualTo(CryptographicKeyWriter.KEY_ALREADY_HELD);
        connectorMock.verifyImportKeyRequests(0);
        assertThat(keyImportRepository.count()).isZero();
        CryptographicKey unchanged = cryptographicKeyRepository.findWithGroupsByUuid(recordUuid).orElseThrow();
        assertThat(unchanged.getName()).isEqualTo("certKey_imported");
        assertThat(unchanged.getDescription()).isEqualTo("the certificate's key");
        assertThat(unchanged.getTokenProfileUuid()).isNull();
        assertThat(unchanged.getGroups()).extracting(Group::getUuid).containsExactly(recordGroup.getUuid());
        assertThat(objectAssociationService.getOwner(Resource.CRYPTOGRAPHIC_KEY, recordUuid).getUuid())
                .isEqualTo(ownerUuid.toString());
        assertThat(departmentOf(recordUuid)).isEqualTo("Sales");
        assertThat(cryptographicKeyItemRepository.findByKeyUuidIn(List.of(recordUuid))).hasSize(1);
        assertThat(importEvents()).isEmpty();
    }

    /** The right to update is the record's: its owner has it, though the policy grants it on no key at large. */
    @Test
    void importKey_adoptsARecordTheCallerOwnsWithoutUpdateOnKeysAtLarge() throws Exception {
        // given
        NameAndUuidDto caller = AuthHelper.getUserIdentification();
        authServiceKnowsTheRequester();
        UUID recordUuid = certificatePublicKey();
        objectAssociationService
                .setOwner(Resource.CRYPTOGRAPHIC_KEY, recordUuid, UUID.fromString(caller.getUuid()), caller.getName());
        denyResourceAccess(Resource.CRYPTOGRAPHIC_KEY, ResourceAction.UPDATE);
        connectorMock.stubImportKey(200, imported(pair.getPublic()));

        // when
        ImportedKey adopted = importKeyWithOutcome(KeyRequestType.KEY_PAIR, plainRequest("imported key"));

        // then
        assertThat(adopted.outcome()).isEqualTo(ImportOutcome.ADOPTED);
        assertThat(ownerOf(recordUuid)).isEqualTo(caller.getName());
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
        assertThat(refused.getMessage()).isEqualTo(CryptographicKeyWriter.NAME_TAKEN.formatted("taken"));
        connectorMock.verifyImportKeyRequests(1);
    }

    /** A token sync names keys after the token, so two keys can share a name; it is refused as any taken name is. */
    @Test
    void importKey_refusesANameTwoKeysShare() {
        // given
        keyNamed("shared");
        keyNamed("shared");
        KeyImportRequestDto request = plainRequest("shared");

        // when
        ValidationException refused = assertThrows(ValidationException.class, () -> importKey(request));

        // then
        assertThat(refused.getMessage()).isEqualTo(CryptographicKeyWriter.NAME_TAKEN.formatted("shared"));
        connectorMock.verifyImportKeyRequests(0);
        assertThat(keyImportRepository.count()).isZero();
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
    void importKey_importsAnAesSecretKey() throws Exception {
        // given
        connectorMock.stubImportableKeyTypes(KeyRequestType.SECRET, KeyAlgorithm.AES);
        connectorMock.stubImportKey(200, importedSecretKey());
        byte[] aesKey = aes();

        // when
        KeyDetailDto detail = importSecretKey(
                secretKeyRequest("imported secret key", ExportEnvelopeFixtures.pinnedAesEnvelope(aesKey, PASSPHRASE)));

        // then
        KeyImport attempt = onlyAttempt();
        assertThat(attempt.getState()).isEqualTo(KeyImportState.COMPLETED);
        assertThat(attempt.getKeyUuid()).hasToString(detail.getUuid());
        assertThat(attempt.getSpkiFingerprint()).isNull();
        assertThat(detail.getItems()).singleElement().satisfies(item -> {
            assertThat(item.getType()).isEqualTo(KeyType.SECRET_KEY);
            assertThat(item.getKeyAlgorithm()).isEqualTo(KeyAlgorithm.AES);
            assertThat(item.getLength()).isEqualTo(256);
        });
        CryptographicKeyItem secretKey = item(attempt.getKeyUuid(), KeyType.SECRET_KEY);
        assertThat(secretKey.getFingerprint()).isNull();
        assertThat(secretKey.getKeyData()).isNull();
        assertThat(secretKey.getKeyReferenceUuid()).isEqualTo(attempt.getKeyReference());
        assertThat(importEvents()).singleElement().satisfies(event -> {
            assertThat(event.getKeyUuid()).isEqualTo(secretKey.getUuid());
            assertThat(event.getStatus()).isEqualTo(KeyEventStatus.SUCCESS);
        });
        JsonNode sent = onlyImportRequest();
        assertThat(sent.get("keyRequestType").asText()).isEqualTo(KeyRequestType.Codes.SECRET);
        assertThat(opened(sent)).isEqualTo(ExportEnvelopeFixtures.aesKeyInfo(aesKey).getEncoded());
    }

    @Test
    void importKey_refusesASecretKeyTheProfileDoesNotImport() throws Exception {
        // given
        KeyImportRequestDto request = secretKeyRequest("imported secret key",
                ExportEnvelopeFixtures.pinnedAesEnvelope(aes(), PASSPHRASE));

        // when
        ValidationException refused = assertThrows(ValidationException.class, () -> importSecretKey(request));

        // then
        assertThat(refused.getMessage())
                .isEqualTo("Token profile " + profile.getName() + " does not import a secret key.");
        connectorMock.verifyImportKeyRequests(0);
        assertThat(keyImportRepository.count()).isZero();
    }

    @Test
    void importKey_convergesOnARetryOfASecretKey() throws Exception {
        // given
        connectorMock.stubImportableKeyTypes(KeyRequestType.SECRET, KeyAlgorithm.AES);
        connectorMock.stubImportKeyUnanswered();
        byte[] file = ExportEnvelopeFixtures.pinnedAesEnvelope(aes(), PASSPHRASE);
        KeyImportRequestDto first = secretKeyRequest("imported secret key", file);
        assertThrows(ConnectorServerException.class, () -> importSecretKey(first));
        connectorMock.stubImportKeyResult(completedSecretKeyImport());

        // when
        KeyDetailDto detail = importSecretKey(secretKeyRequest("imported secret key", file));

        // then
        KeyImport attempt = onlyAttempt();
        assertThat(attempt.getState()).isEqualTo(KeyImportState.COMPLETED);
        assertThat(attempt.getKeyUuid()).hasToString(detail.getUuid());
        assertThat(cryptographicKeyItemRepository.findByKeyUuidIn(List.of(attempt.getKeyUuid())))
                .singleElement()
                .extracting(CryptographicKeyItem::getType)
                .isEqualTo(KeyType.SECRET_KEY);
        connectorMock.verifyImportKeyRequests(1);
        connectorMock.verifyImportKeyResultRequests(1);
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
        ResponseEntity<KeyDetailDto> answer = keyController
                .importKey(token.getUuid().toString(), profile.getUuid().toString(), KeyRequestType.KEY_PAIR,
                        plainRequest("imported key"));
        KeyDetailDto detail = answer.getBody();

        // then
        assertThat(answer.getStatusCode()).isEqualTo(HttpStatus.CREATED);
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

        // when
        SecretLeakProbe probe = SecretLeakProbe.capture();
        try (probe) {
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
                                            request("imported", file, PASSPHRASE))
                                    .getBody()));
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
                                            request("waited for", waitedFor.getPrivate().getEncoded(), null))
                                    .getBody()));
            connectorMock.stubImportKeyStatuses(status(OperationStatus.IN_PROGRESS, cancelled.getPublic()));
            connectorMock.stubCancelImportKey();
            seen
                    .add(failureOf(tokenUuid, profileUuid,
                            request("cancelled", cancelled.getPrivate().getEncoded(), null)));
        }

        // then
        seen.addAll(probe.logged());
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
        SecretLeakProbe.assertNoneReveals(seen, secrets.toArray(new String[0]));
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

    /**
     * A repeat shows the key as it is now, so a caller who may no longer see it, once it changed hands, is refused in
     * words that say only that the key exists.
     */
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
        ValidationException refused = assertThrows(ValidationException.class, () -> importKey(repeat));

        // then
        assertThat(refused.getMessage()).isEqualTo(CryptographicKeyImportServiceImpl.KEY_EXISTS);
        connectorMock.verifyImportKeyRequests(1);
    }

    /** A secret key has no public key, and its refusal speaks of none: it says only that the key exists. */
    @Test
    void importKey_refusesASecretKeyRepeatToACallerWhoMayNoLongerSeeIt() throws Exception {
        // given
        connectorMock.stubImportableKeyTypes(KeyRequestType.SECRET, KeyAlgorithm.AES);
        connectorMock.stubImportKey(200, importedSecretKey());
        byte[] file = ExportEnvelopeFixtures.pinnedAesEnvelope(aes(), PASSPHRASE);
        KeyDetailDto imported = importSecretKey(secretKeyRequest("imported secret key", file));
        objectAssociationService
                .setOwner(Resource.CRYPTOGRAPHIC_KEY, UUID.fromString(imported.getUuid()), UUID.randomUUID(),
                        "another");
        denyResourceAccess(Resource.CRYPTOGRAPHIC_KEY, ResourceAction.DETAIL);
        KeyImportRequestDto repeat = secretKeyRequest("imported secret key", file);

        // when
        ValidationException refused = assertThrows(ValidationException.class, () -> importSecretKey(repeat));

        // then
        assertThat(refused.getMessage()).isEqualTo(CryptographicKeyImportServiceImpl.KEY_EXISTS);
        connectorMock.verifyImportKeyRequests(1);
    }

    @Test
    void importKeyWithOutcome_reportsTheKeyItCreatedAndARepeatOfItsImportAsExisting() throws Exception {
        // given
        connectorMock.stubImportKey(200, imported(pair.getPublic()));
        ImportedKey created = importKeyWithOutcome(KeyRequestType.KEY_PAIR, plainRequest("imported key"));

        // when
        ImportedKey repeated = importKeyWithOutcome(KeyRequestType.KEY_PAIR, plainRequest("imported key"));

        // then
        assertThat(created.outcome()).isEqualTo(ImportOutcome.CREATED);
        assertThat(repeated.outcome()).isEqualTo(ImportOutcome.EXISTING);
        assertThat(repeated.key().uuid()).isEqualTo(created.key().uuid());
        connectorMock.verifyImportKeyRequests(1);
    }

    @Test
    void importKeyWithOutcome_reportsTheRecordItAdopted() throws Exception {
        // given
        authServiceKnowsTheRequester();
        UUID recordUuid = certificatePublicKey();
        connectorMock.stubImportKey(200, imported(pair.getPublic()));

        // when
        ImportedKey adopted = importKeyWithOutcome(KeyRequestType.KEY_PAIR, plainRequest("imported key"));

        // then
        assertThat(adopted.outcome()).isEqualTo(ImportOutcome.ADOPTED);
        assertThat(adopted.key().uuid()).isEqualTo(recordUuid);
    }

    /**
     * A secret key has no public key to find it by, only the key import's own record; once that record is past its
     * retention and gone, the same file imports a second key.
     */
    @Test
    void importKeyWithOutcome_importsASecretKeyAgainOnceItsImportIsPastTheRetention() throws Exception {
        // given
        connectorMock.stubImportableKeyTypes(KeyRequestType.SECRET, KeyAlgorithm.AES);
        connectorMock.stubImportKey(200, importedSecretKey());
        byte[] file = ExportEnvelopeFixtures.pinnedAesEnvelope(aes(), PASSPHRASE);
        ImportedKey first = importKeyWithOutcome(KeyRequestType.SECRET, secretKeyRequest("first secret key", file));
        keyImportRepository.deleteAll();

        // when
        ImportedKey second = importKeyWithOutcome(KeyRequestType.SECRET, secretKeyRequest("second secret key", file));

        // then
        assertThat(second.outcome()).isEqualTo(ImportOutcome.CREATED);
        assertThat(second.key().uuid()).isNotEqualTo(first.key().uuid());
        assertThat(cryptographicKeyRepository.count()).isEqualTo(2);
        connectorMock.verifyImportKeyRequests(2);
    }

    /** The key import's own record answers a secret key imported again from the same file within the retention. */
    @Test
    void importKeyWithOutcome_reportsASecretKeyImportedAgainAsExisting() throws Exception {
        // given
        connectorMock.stubImportableKeyTypes(KeyRequestType.SECRET, KeyAlgorithm.AES);
        connectorMock.stubImportKey(200, importedSecretKey());
        byte[] file = ExportEnvelopeFixtures.pinnedAesEnvelope(aes(), PASSPHRASE);
        ImportedKey created = importKeyWithOutcome(KeyRequestType.SECRET,
                secretKeyRequest("imported secret key", file));

        // when
        ImportedKey again = importKeyWithOutcome(KeyRequestType.SECRET, secretKeyRequest("imported secret key", file));

        // then
        assertThat(created.outcome()).isEqualTo(ImportOutcome.CREATED);
        assertThat(again.outcome()).isEqualTo(ImportOutcome.EXISTING);
        assertThat(again.key().uuid()).isEqualTo(created.key().uuid());
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
        return importService.importKey(token.getUuid(), profile.getUuid(), KeyRequestType.KEY_PAIR, request).detail();
    }

    private KeyDetailDto importSecretKey(KeyImportRequestDto request) throws Exception {
        return importService.importKey(token.getUuid(), profile.getUuid(), KeyRequestType.SECRET, request).detail();
    }

    private ImportedKey importKeyWithOutcome(KeyRequestType type, KeyImportRequestDto request) throws Exception {
        return importService.importKeyWithOutcome(token.getUuid(), profile.getUuid(), type, request);
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

    private static KeyImportRequestDto secretKeyRequest(String name, byte[] file) {
        return request(name, file, PASSPHRASE);
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
    static KeyPairDataResponseV2Dto imported(PublicKey publicKey) {
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

    /** The connector's synchronous answer for an AES key: its descriptor and handle. */
    static SecretKeyDataResponseV2Dto importedSecretKey() {
        SecretKeyDataV2Dto secretData = new SecretKeyDataV2Dto();
        secretData.setAlgorithm(KeyAlgorithm.AES);
        secretData.setLength(256);
        secretData.setMetadata(List.of());
        SecretKeyDataResponseV2Dto answer = new SecretKeyDataResponseV2Dto();
        answer.setKeyData(secretData);
        answer.setKeyMeta(List.of(KeyImportWriterITest.handle("secret-handle", "s")));
        return answer;
    }

    /** The connector's record of an AES key import it completed. */
    static SecretKeyOperationStatusResponseV2Dto completedSecretKeyImport() {
        SecretKeyOperationStatusResponseV2Dto answer = new SecretKeyOperationStatusResponseV2Dto();
        answer.setStatus(OperationStatus.COMPLETED);
        answer.setResult(importedSecretKey());
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

    static KeyPairOperationStatusResponseV2Dto status(OperationStatus status, PublicKey publicKey) {
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
        v2TokenFixture.declare(v2Token, features);
    }

    /** The call as another node serves it: on a thread of its own, so with connections of its own, for the caller. */
    private static <T> Callable<T> onNode(Callable<T> call) {
        return DelegatingSecurityContextCallable.create(call, SecurityContextHolder.getContext());
    }

    /** Waits until the connector received the import, which it answers only after a while. */
    private void awaitSending() {
        Awaitility
                .await("the import is sent")
                .atMost(Duration.ofSeconds(10))
                .pollInterval(Duration.ofMillis(10))
                .until(() -> !connectorMock.importKeyRequestBodies().isEmpty());
    }

    /** Waits until the import is waited on: the connector was asked how it stands. */
    private void awaitPolling() {
        Awaitility
                .await("the import is polled")
                .atMost(Duration.ofSeconds(10))
                .pollInterval(Duration.ofMillis(10))
                .until(() -> connectorMock.importKeyStatusRequestsReceived() > 0);
    }

    private UUID certificatePublicKey() {
        String fingerprint = CryptographyUtil
                .calculateKeyFingerprint(new KeyMaterial(KeyFormat.SPKI,
                        Base64.getEncoder().encodeToString(pair.getPublic().getEncoded())));
        return certificateKeyWriter.uploadCertificatePublicKey("certKey_imported", pair.getPublic(), 2048, fingerprint);
    }

    /** The auth service answers for the caller, so a check made as the requester can resolve them. */
    private void authServiceKnowsTheRequester() {
        NameAndUuidDto caller = AuthHelper.getUserIdentification();
        authService = AuthServiceWireMockStubs.startImpersonating(UUID.fromString(caller.getUuid()), caller.getName());
    }

    /** Gives the record a description, an owner, a group and a department, as another user would have. */
    private void describedOwnedAndGrouped(UUID recordUuid, UUID ownerUuid, Group group, RequestAttribute department)
            throws Exception {
        CryptographicKey described = cryptographicKeyRepository.findById(recordUuid).orElseThrow();
        described.setDescription("the certificate's key");
        cryptographicKeyRepository.saveAndFlush(described);
        objectAssociationService.setOwner(Resource.CRYPTOGRAPHIC_KEY, recordUuid, ownerUuid, "owner");
        objectAssociationService.addGroup(Resource.CRYPTOGRAPHIC_KEY, recordUuid, group.getUuid());
        attributeEngine
                .updateObjectCustomAttributesContent(Resource.CRYPTOGRAPHIC_KEY, recordUuid, List.of(department));
    }

    private Group group(String name) {
        Group group = new Group();
        group.setName(name);
        return groupRepository.save(group);
    }

    private String departmentOf(UUID keyUuid) {
        List<ResponseAttribute> attributes = attributeEngine
                .getObjectCustomAttributesContent(Resource.CRYPTOGRAPHIC_KEY, keyUuid);
        assertThat(attributes).singleElement().extracting(ResponseAttribute::getName).isEqualTo("department");
        return ((ResponseAttributeV3) attributes.getFirst()).getContent().getFirst().getData().toString();
    }

    /** A key with only a name, saved as a sync that names keys after the token does. */
    private void keyNamed(String name) {
        CryptographicKey key = new CryptographicKey();
        key.setName(name);
        cryptographicKeyRepository.saveAndFlush(key);
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

    private static byte[] aes() throws Exception {
        KeyGenerator generator = KeyGenerator.getInstance("AES");
        generator.init(256);
        return generator.generateKey().getEncoded();
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
