package com.otilm.core.integration.service;

import com.github.tomakehurst.wiremock.WireMockServer;
import com.otilm.api.model.client.attribute.RequestAttributeV3;
import com.otilm.api.model.client.attribute.ResponseAttributeV3;
import com.otilm.api.model.client.connector.v2.ConnectorInterface;
import com.otilm.api.model.client.connector.v2.ConnectorVersion;
import com.otilm.api.model.client.connector.v2.FeatureFlag;
import com.otilm.api.model.client.cryptography.key.KeyRequestType;
import com.otilm.api.model.common.NameAndUuidDto;
import com.otilm.api.model.common.attribute.common.AttributeType;
import com.otilm.api.model.common.attribute.common.content.AttributeContentType;
import com.otilm.api.model.common.attribute.common.properties.CustomAttributeProperties;
import com.otilm.api.model.common.attribute.v3.CustomAttributeV3;
import com.otilm.api.model.common.attribute.v3.content.StringAttributeContentV3;
import com.otilm.api.model.common.enums.cryptography.KeyAlgorithm;
import com.otilm.api.model.common.enums.cryptography.KeyType;
import com.otilm.api.model.common.error.ErrorCode;
import com.otilm.api.model.connector.common.v2.OperationStatus;
import com.otilm.api.model.connector.cryptography.enums.TokenInstanceStatus;
import com.otilm.api.model.connector.cryptography.v2.key.KeyPairOperationStatusResponseV2Dto;
import com.otilm.api.model.core.auth.Resource;
import com.otilm.api.model.core.connector.ConnectorStatus;
import com.otilm.api.model.core.cryptography.key.KeyState;
import com.otilm.api.model.core.cryptography.key.KeyUsage;
import com.otilm.core.attribute.engine.AttributeEngine;
import com.otilm.core.cluster.ClusterOperationSynchronizer;
import com.otilm.core.dao.entity.Connector;
import com.otilm.core.dao.entity.ConnectorInterfaceEntity;
import com.otilm.core.dao.entity.CryptographicKey;
import com.otilm.core.dao.entity.Group;
import com.otilm.core.dao.entity.KeyImport;
import com.otilm.core.dao.entity.KeyImportState;
import com.otilm.core.dao.entity.TokenInstanceReference;
import com.otilm.core.dao.entity.TokenProfile;
import com.otilm.core.dao.repository.ConnectorInterfaceRepository;
import com.otilm.core.dao.repository.ConnectorRepository;
import com.otilm.core.dao.repository.CryptographicKeyItemRepository;
import com.otilm.core.dao.repository.CryptographicKeyRepository;
import com.otilm.core.dao.repository.GroupRepository;
import com.otilm.core.dao.repository.KeyImportRepository;
import com.otilm.core.dao.repository.TokenInstanceReferenceRepository;
import com.otilm.core.dao.repository.TokenProfileRepository;
import com.otilm.core.model.auth.ResourceAction;
import com.otilm.core.model.crypto.KeyImportAttempt;
import com.otilm.core.model.crypto.KeyImportCheck;
import com.otilm.core.model.crypto.KeyImportTerms;
import com.otilm.core.model.crypto.TokenProfileFullModel;
import com.otilm.core.service.ResourceObjectAssociationService;
import com.otilm.core.service.handler.KeyImportClaimer;
import com.otilm.core.service.handler.KeyImportReconciler;
import com.otilm.core.service.handler.KeyImportSaga;
import com.otilm.core.service.handler.KeyImportSweeper;
import com.otilm.core.service.writer.CertificateKeyWriter;
import com.otilm.core.service.writer.KeyImportRetentionWriter;
import com.otilm.core.service.writer.KeyImportWriter;
import com.otilm.core.util.AuthServiceWireMockStubs;
import com.otilm.core.util.BaseSpringBootTest;
import com.otilm.core.util.mocks.ConnectorMockFactory;
import com.otilm.core.util.mocks.CryptographyProviderV2ConnectorMock;
import java.security.KeyPair;
import java.time.Duration;
import java.time.OffsetDateTime;
import java.util.List;
import java.util.Optional;
import java.util.Set;
import java.util.UUID;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import org.awaitility.Awaitility;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.transaction.PlatformTransactionManager;
import org.springframework.transaction.support.TransactionTemplate;

import static org.assertj.core.api.Assertions.assertThat;

@SpringBootTest
class KeyImportReconciliationITest extends BaseSpringBootTest {

    private static final List<String> SENT = List.of("sent-secret-digest");

    private static final UUID RECORD_OWNER = UUID.randomUUID();

    @Autowired
    private KeyImportSweeper sweeper;
    @Autowired
    private KeyImportClaimer claimer;
    @Autowired
    private KeyImportReconciler reconciler;
    @Autowired
    private KeyImportWriter keyImportWriter;
    @Autowired
    private KeyImportRetentionWriter retentionWriter;
    @Autowired
    private KeyImportRepository keyImportRepository;
    @Autowired
    private CryptographicKeyRepository cryptographicKeyRepository;
    @Autowired
    private CryptographicKeyItemRepository cryptographicKeyItemRepository;
    @Autowired
    private ResourceObjectAssociationService objectAssociationService;
    @Autowired
    private ClusterOperationSynchronizer clusterSynchronizer;
    @Autowired
    private PlatformTransactionManager transactionManager;
    @Autowired
    private JdbcTemplate jdbcTemplate;
    @Autowired
    private ConnectorMockFactory connectorMockFactory;
    @Autowired
    private ConnectorRepository connectorRepository;
    @Autowired
    private ConnectorInterfaceRepository connectorInterfaceRepository;
    @Autowired
    private TokenInstanceReferenceRepository tokenInstanceReferenceRepository;
    @Autowired
    private TokenProfileRepository tokenProfileRepository;
    @Autowired
    private CertificateKeyWriter certificateKeyWriter;
    @Autowired
    private GroupRepository groupRepository;
    @Autowired
    private AttributeEngine attributeEngine;

    private CryptographyProviderV2ConnectorMock connectorMock;
    private TokenProfileFullModel profile;
    private KeyPair pair;
    private WireMockServer authService;
    private Group recordGroup;

    @BeforeEach
    void setUp() throws Exception {
        connectorMock = connectorMockFactory.startCryptographyProviderV2();
        profile = persistedProfile(connectorMock.getUrl());
        pair = KeyImportWriterITest.rsa();
    }

    @AfterEach
    void tearDown() {
        connectorMock.stop();
        if (authService != null) {
            authService.stop();
        }
    }

    @Test
    void sweep_closesAnImportTheConnectorNeverAccepted() throws Exception {
        // given
        KeyImportAttempt attempt = dueAttempt();
        connectorMock.stubImportKeyResultNotTracked();

        // when
        sweep();

        // then
        KeyImport closed = keyImportRepository.findById(attempt.uuid()).orElseThrow();
        assertThat(closed.getState()).isEqualTo(KeyImportState.FAILED);
        assertThat(closed.getErrorMessage()).isEqualTo(KeyImportReconciler.NEVER_ACCEPTED);
    }

    @Test
    void sweep_closesAnImportThatEndedWithoutAKey() throws Exception {
        // given
        KeyImportAttempt attempt = dueAttempt();
        connectorMock.stubImportKeyResult(status(OperationStatus.FAILED));

        // when
        sweep();

        // then
        KeyImport closed = keyImportRepository.findById(attempt.uuid()).orElseThrow();
        assertThat(closed.getState()).isEqualTo(KeyImportState.FAILED);
        assertThat(closed.getErrorMessage()).isEqualTo(KeyImportSaga.NOT_IMPORTED);
    }

    @Test
    void sweep_leavesARunningImportForItsNextLook() throws Exception {
        // given
        KeyImportAttempt attempt = dueAttempt();
        connectorMock.stubImportKeyResult(status(OperationStatus.IN_PROGRESS));

        // when
        sweep();

        // then
        KeyImport running = keyImportRepository.findById(attempt.uuid()).orElseThrow();
        assertThat(running.getState()).isEqualTo(KeyImportState.REQUESTED);
        assertThat(running.getNextCheckAt()).isAfter(OffsetDateTime.now().plusMinutes(14));
    }

    @Test
    void sweep_destroysAKeyItsRequesterNeverReceived() throws Exception {
        // given
        KeyImportAttempt attempt = dueAttempt();
        connectorMock.stubImportKeyResult(status(OperationStatus.COMPLETED));
        connectorMock.stubDestroyKey();

        // when
        sweep();

        // then
        assertThat(keyImportRepository.findById(attempt.uuid()).orElseThrow().getState())
                .isEqualTo(KeyImportState.COMPENSATED);
        assertThat(connectorMock.destroyKeyRequestBodies())
                .extracting(body -> body.at("/keyMeta/0/name").asText())
                .containsExactly("private-handle", "public-handle");
        assertThat(cryptographicKeyRepository.count()).isZero();
    }

    @Test
    void sweep_registersAKeyTheConnectorWouldNotDestroyDeactivated() throws Exception {
        // given
        KeyImportAttempt attempt = dueAttempt();
        connectorMock.stubImportKeyResult(status(OperationStatus.COMPLETED));
        connectorMock.stubDestroyKeyProblem(ErrorCode.VALIDATION_FAILED);

        // when
        sweep();

        // then
        KeyImport quarantined = keyImportRepository.findById(attempt.uuid()).orElseThrow();
        assertThat(quarantined.getState()).isEqualTo(KeyImportState.QUARANTINED);
        CryptographicKey key = cryptographicKeyRepository.findById(quarantined.getKeyUuid()).orElseThrow();
        assertThat(key.getName()).isEqualTo("imported key");
        assertThat(cryptographicKeyItemRepository.findByKeyUuidIn(List.of(key.getUuid())))
                .hasSize(2)
                .allSatisfy(item -> {
                    assertThat(item.getState()).isEqualTo(KeyState.DEACTIVATED);
                    assertThat(item.isEnabled()).isFalse();
                });
        assertThat(objectAssociationService.getOwner(Resource.CRYPTOGRAPHIC_KEY, key.getUuid()).getName())
                .isEqualTo("requester");
        connectorMock.verifyDestroyKeyRequests(1);
    }

    @Test
    void sweep_compensatesAnUnansweredSecretKeyImport() throws Exception {
        // given
        KeyImportAttempt attempt = dueSecretKeyAttempt();
        connectorMock.stubImportKeyResult(CryptographicKeyImportV2ITest.completedSecretKeyImport());
        connectorMock.stubDestroyKey();

        // when
        sweep();

        // then
        assertThat(keyImportRepository.findById(attempt.uuid()).orElseThrow().getState())
                .isEqualTo(KeyImportState.COMPENSATED);
        assertThat(connectorMock.destroyKeyRequestBodies())
                .extracting(body -> body.at("/keyMeta/0/name").asText())
                .containsExactly("secret-handle");
        assertThat(cryptographicKeyRepository.count()).isZero();
    }

    /**
     * A secret key has no public key, so the key the connector would not destroy is registered as a key of its own,
     * whatever other keys hold items without a fingerprint.
     */
    @Test
    void sweep_registersASecretKeyTheConnectorWouldNotDestroyDeactivated() throws Exception {
        // given
        KeyImportAttempt keyPairImport = keyImportWriter.open(terms(), "retry-key-pair", "imported key", SENT);
        UUID keyPairUuid = keyImportWriter
                .complete(keyPairImport.uuid(),
                        KeyImportWriterITest.registration(profile, pair, keyPairImport, Set.of()))
                .orElseThrow()
                .key()
                .uuid();
        KeyImportAttempt attempt = dueSecretKeyAttempt();
        connectorMock.stubImportKeyResult(CryptographicKeyImportV2ITest.completedSecretKeyImport());
        connectorMock.stubDestroyKeyProblem(ErrorCode.VALIDATION_FAILED);

        // when
        sweep();

        // then
        KeyImport quarantined = keyImportRepository.findById(attempt.uuid()).orElseThrow();
        assertThat(quarantined.getState()).isEqualTo(KeyImportState.QUARANTINED);
        assertThat(cryptographicKeyItemRepository.findByKeyUuidIn(List.of(quarantined.getKeyUuid())))
                .singleElement()
                .satisfies(item -> {
                    assertThat(item.getType()).isEqualTo(KeyType.SECRET_KEY);
                    assertThat(item.getFingerprint()).isNull();
                    assertThat(item.getState()).isEqualTo(KeyState.DEACTIVATED);
                    assertThat(item.isEnabled()).isFalse();
                });
        assertThat(cryptographicKeyItemRepository.findByKeyUuidIn(List.of(keyPairUuid))).hasSize(2);
    }

    @Test
    void sweep_asksAgainWhenTheConnectorCannotBeReached() {
        // given
        KeyImportAttempt attempt = dueAttempt();
        connectorMock.stubImportKeyResultUnreachable();

        // when
        sweep();

        // then
        KeyImport open = keyImportRepository.findById(attempt.uuid()).orElseThrow();
        assertThat(open.getState()).isEqualTo(KeyImportState.REQUESTED);
        assertThat(open.getNextCheckAt()).isAfter(OffsetDateTime.now().plusMinutes(14));
    }

    /**
     * A connector that does not answer holds a run up for one import of its token, so the others are not kept waiting.
     */
    @Test
    void sweep_asksAConnectorThatDoesNotAnswerAboutOneImportARun() throws Exception {
        // given
        KeyImportAttempt first = dueAttempt(pair);
        KeyImportAttempt second = dueAttempt(KeyImportWriterITest.rsa());
        connectorMock.stubImportKeyResultUnreachable();

        // when
        sweep();

        // then
        connectorMock.verifyImportKeyResultRequests(1);
        assertThat(keyImportRepository.findAllById(List.of(first.uuid(), second.uuid()))).allSatisfy(attempt -> {
            assertThat(attempt.getState()).isEqualTo(KeyImportState.REQUESTED);
            assertThat(attempt.getNextCheckAt()).isAfter(OffsetDateTime.now().plusMinutes(14));
        });
    }

    @Test
    void sweep_finishesACompensationALaterLookFinds() throws Exception {
        // given
        KeyImportAttempt attempt = dueAttempt();
        connectorMock.stubImportKeyResult(status(OperationStatus.COMPLETED));
        connectorMock.stubDestroyKeyFailing();
        sweep();
        assertThat(keyImportRepository.findById(attempt.uuid()).orElseThrow().getState())
                .isEqualTo(KeyImportState.COMPENSATING);
        makeDue(attempt);
        connectorMock.stubDestroyKey();

        // when
        sweep();

        // then
        assertThat(keyImportRepository.findById(attempt.uuid()).orElseThrow().getState())
                .isEqualTo(KeyImportState.COMPENSATED);
        assertThat(cryptographicKeyRepository.count()).isZero();
    }

    /**
     * A connector that no longer knows the key may have destroyed it on an earlier look, or may no longer reach its
     * token, so the key is neither registered nor taken as destroyed; the attempt ends unresolved unless a look
     * confirms.
     */
    @Test
    void sweep_keepsUndoingAKeyTheConnectorNoLongerKnows() throws Exception {
        // given
        KeyImportAttempt attempt = dueAttempt();
        connectorMock.stubImportKeyResult(status(OperationStatus.COMPLETED));
        connectorMock.stubDestroyKeyProblem(ErrorCode.RESOURCE_NOT_FOUND);

        // when
        sweep();

        // then
        assertThat(keyImportRepository.findById(attempt.uuid()).orElseThrow().getState())
                .isEqualTo(KeyImportState.COMPENSATING);
        assertThat(cryptographicKeyRepository.count()).isZero();
    }

    @Test
    void sweep_compensatesWhenOnlyThePublicKeyStaysInTheToken() throws Exception {
        // given
        KeyImportAttempt attempt = dueAttempt();
        connectorMock.stubImportKeyResult(status(OperationStatus.COMPLETED));
        connectorMock.stubDestroyKey();
        connectorMock.stubDestroyKeyFailing("public-handle");

        // when
        sweep();

        // then
        assertThat(keyImportRepository.findById(attempt.uuid()).orElseThrow().getState())
                .isEqualTo(KeyImportState.COMPENSATED);
        connectorMock.verifyDestroyKeyRequests(2);
    }

    /**
     * The compensation is recorded once the connector destroyed the private key, before the public key is destroyed, so
     * a node that stops while that destroy is on its way leaves no compensation a later look could not finish.
     */
    @Test
    void sweep_recordsTheCompensationBeforeTheBestEffortPublicKeyDestroy() throws Exception {
        // given
        KeyImportAttempt attempt = dueAttempt();
        connectorMock.stubImportKeyResult(status(OperationStatus.COMPLETED));
        connectorMock.stubDestroyKey();
        connectorMock.stubDestroyKeyAfter("public-handle", 3000);
        try (ExecutorService node = Executors.newSingleThreadExecutor()) {
            Future<?> sweeping = node.submit(this::sweep);

            // when
            Awaitility
                    .await("the public key's destroy is on its way")
                    .atMost(Duration.ofSeconds(10))
                    .pollInterval(Duration.ofMillis(10))
                    .until(() -> connectorMock
                            .destroyKeyRequestBodies()
                            .stream()
                            .anyMatch(body -> "public-handle".equals(body.at("/keyMeta/0/name").asText())));

            // then
            assertThat(keyImportRepository.findById(attempt.uuid()).orElseThrow().getState())
                    .isEqualTo(KeyImportState.COMPENSATED);
            sweeping.get(10, TimeUnit.SECONDS);
        }
    }

    @Test
    void sweep_leavesAnImportWithinItsRetryWindowAlone() {
        // given
        KeyImportAttempt attempt = keyImportWriter.open(terms(), "retry-window", "imported key", SENT);

        // when
        sweep();

        // then
        assertThat(keyImportRepository.findById(attempt.uuid()).orElseThrow().getState())
                .isEqualTo(KeyImportState.REQUESTED);
        connectorMock.verifyImportKeyResultRequests(0);
    }

    /** Past its cutoff a missing record proves nothing, so an import the connector does not know ends unresolved. */
    @Test
    void sweep_leavesUnresolvedAnImportPastItsCutoffTheConnectorDoesNotKnow() throws Exception {
        // given
        KeyImportAttempt attempt = lateAttempt();
        connectorMock.stubImportKeyResultNotTracked();

        // when
        sweep();

        // then
        KeyImport unresolved = keyImportRepository.findById(attempt.uuid()).orElseThrow();
        assertThat(unresolved.getState()).isEqualTo(KeyImportState.UNRESOLVED);
        assertThat(unresolved.getErrorMessage()).isEqualTo(KeyImportReconciler.UNRESOLVED);
        connectorMock.verifyImportKeyResultRequests(1);
    }

    /** A record of the key outlives the cutoff, so a late look still undoes a key its requester never received. */
    @Test
    void sweep_undoesAnImportPastItsCutoffThatTheConnectorImported() throws Exception {
        // given
        KeyImportAttempt attempt = lateAttempt();
        connectorMock.stubImportKeyResult(status(OperationStatus.COMPLETED));
        connectorMock.stubDestroyKey();

        // when
        sweep();

        // then
        assertThat(keyImportRepository.findById(attempt.uuid()).orElseThrow().getState())
                .isEqualTo(KeyImportState.COMPENSATED);
        connectorMock.verifyDestroyKeyRequests(2);
    }

    @Test
    void sweep_closesAnImportPastItsCutoffThatEndedWithoutAKey() throws Exception {
        // given
        KeyImportAttempt attempt = lateAttempt();
        connectorMock.stubImportKeyResult(status(OperationStatus.FAILED));

        // when
        sweep();

        // then
        KeyImport closed = keyImportRepository.findById(attempt.uuid()).orElseThrow();
        assertThat(closed.getState()).isEqualTo(KeyImportState.FAILED);
        assertThat(closed.getErrorMessage()).isEqualTo(KeyImportSaga.NOT_IMPORTED);
    }

    /** The last look is the last one, so an import still running then ends unresolved rather than be asked again. */
    @Test
    void sweep_leavesUnresolvedAnImportPastItsCutoffStillRunning() throws Exception {
        // given
        KeyImportAttempt attempt = lateAttempt();
        connectorMock.stubImportKeyResult(status(OperationStatus.IN_PROGRESS));

        // when
        sweep();

        // then
        assertThat(keyImportRepository.findById(attempt.uuid()).orElseThrow().getState())
                .isEqualTo(KeyImportState.UNRESOLVED);
    }

    @Test
    void sweep_leavesUnresolvedAnImportPastItsCutoffTheConnectorCannotReportOn() {
        // given
        KeyImportAttempt attempt = lateAttempt();
        connectorMock.stubImportKeyResultUnreachable();

        // when
        sweep();

        // then
        assertThat(keyImportRepository.findById(attempt.uuid()).orElseThrow().getState())
                .isEqualTo(KeyImportState.UNRESOLVED);
    }

    @Test
    void sweep_leavesUnresolvedAnImportPastItsCutoffWhoseKeyTheConnectorDoesNotDestroy() throws Exception {
        // given
        KeyImportAttempt attempt = lateAttempt();
        connectorMock.stubImportKeyResult(status(OperationStatus.COMPLETED));
        connectorMock.stubDestroyKeyFailing();

        // when
        sweep();

        // then
        assertThat(keyImportRepository.findById(attempt.uuid()).orElseThrow().getState())
                .isEqualTo(KeyImportState.UNRESOLVED);
        assertThat(cryptographicKeyRepository.count()).isZero();
    }

    @Test
    void sweep_givesAnImportItsLastLookThoughItsConnectorDidNotAnswerAboutAnother() throws Exception {
        // given
        KeyImportAttempt younger = dueAttempt(pair);
        jdbcTemplate
                .update("UPDATE key_import SET next_check_at = now() - interval '2 minutes' WHERE uuid = ?",
                        younger.uuid());
        KeyImportAttempt late = lateAttempt(KeyImportWriterITest.rsa());
        connectorMock.stubImportKeyResultUnreachable();

        // when
        sweep();

        // then
        connectorMock.verifyImportKeyResultRequests(2);
        assertThat(keyImportRepository.findById(late.uuid()).orElseThrow().getState())
                .isEqualTo(KeyImportState.UNRESOLVED);
        assertThat(keyImportRepository.findById(younger.uuid()).orElseThrow().getState())
                .isEqualTo(KeyImportState.REQUESTED);
    }

    /** A request resumed the import after its last look was claimed, so the request, not that look, settles it. */
    @Test
    void reconcile_leavesAnImportPastItsCutoffToARequestThatResumedIt() throws Exception {
        // given
        KeyImportAttempt attempt = lateAttempt();
        KeyImportCheck check = claimed();
        keyImportWriter.resuming(attempt.uuid());
        connectorMock.stubImportKeyResultNotTracked();

        // when
        SecurityContextHolder.clearContext();
        reconciler.reconcile(check);

        // then
        assertThat(keyImportRepository.findById(attempt.uuid()).orElseThrow().getState())
                .isEqualTo(KeyImportState.REQUESTED);
    }

    @Test
    void sweep_asksAboutAnImportSentAgainLateInItsLife() throws Exception {
        // given
        KeyImportAttempt attempt = dueAttempt();
        jdbcTemplate
                .update("UPDATE key_import SET created_at = now() - interval '20 hours 10 minutes', "
                        + "last_sent_at = now() - interval '16 minutes' WHERE uuid = ?", attempt.uuid());
        connectorMock.stubImportKeyResultNotTracked();

        // when
        sweep();

        // then
        assertThat(keyImportRepository.findById(attempt.uuid()).orElseThrow().getState())
                .isEqualTo(KeyImportState.FAILED);
        connectorMock.verifyImportKeyResultRequests(1);
    }

    /** The platform holds the key in a token already, so the key the connector would not destroy is not registered. */
    @Test
    void sweep_leavesUnresolvedAKeyItCannotQuarantine() throws Exception {
        // given
        KeyImportAttempt attempt = dueAttempt();
        UUID holderUuid = certificateKeyWriter
                .uploadCertificatePublicKey("certKey_imported", pair.getPublic(), 2048,
                        KeyImportWriterITest.fingerprintOf(pair));
        CryptographicKey holder = cryptographicKeyRepository.findById(holderUuid).orElseThrow();
        holder.setTokenProfileUuid(profile.uuid());
        holder.setTokenInstanceReferenceUuid(profile.tokenInstanceReferenceUuid());
        cryptographicKeyRepository.saveAndFlush(holder);
        connectorMock.stubImportKeyResult(status(OperationStatus.COMPLETED));
        connectorMock.stubDestroyKeyProblem(ErrorCode.VALIDATION_FAILED);

        // when
        sweep();

        // then
        KeyImport unresolved = keyImportRepository.findById(attempt.uuid()).orElseThrow();
        assertThat(unresolved.getState()).isEqualTo(KeyImportState.UNRESOLVED);
        assertThat(unresolved.getErrorMessage()).isEqualTo(KeyImportReconciler.NOT_REGISTERED);
        assertThat(cryptographicKeyItemRepository.findByKeyUuidIn(List.of(holderUuid))).hasSize(1);
    }

    /**
     * The connector would not destroy the key of an import whose requester was never answered, and a record another
     * user owns holds its public key. The key is registered into the record once its requester is shown, as the
     * requester, to be allowed to update it, and the record keeps whose it is, its groups, its custom attributes, its
     * name and its description.
     */
    @Test
    void sweep_registersAKeyTheConnectorWouldNotDestroyIntoARecordItsRequesterMayUpdate() throws Exception {
        // given
        KeyImportAttempt attempt = dueAttempt();
        UUID recordUuid = ownedRecord();
        requesterResolvable(attempt);
        connectorMock.stubImportKeyResult(status(OperationStatus.COMPLETED));
        connectorMock.stubDestroyKeyProblem(ErrorCode.VALIDATION_FAILED);

        // when
        sweep();

        // then
        KeyImport quarantined = keyImportRepository.findById(attempt.uuid()).orElseThrow();
        assertThat(quarantined.getState()).isEqualTo(KeyImportState.QUARANTINED);
        assertThat(quarantined.getKeyUuid()).isEqualTo(recordUuid);
        assertTheRecordIsAsItWas(recordUuid);
        assertThat(cryptographicKeyRepository.findById(recordUuid).orElseThrow().getTokenProfileUuid())
                .isEqualTo(profile.uuid());
        assertThat(cryptographicKeyItemRepository.findByKeyUuidIn(List.of(recordUuid)))
                .filteredOn(item -> item.getType() == KeyType.PRIVATE_KEY)
                .singleElement()
                .satisfies(privateKey -> assertThat(privateKey.getState()).isEqualTo(KeyState.DEACTIVATED));
    }

    /** The requester may not update the record, so the key cannot be registered, and the attempt ends unresolved. */
    @Test
    void sweep_leavesUnresolvedAKeyTheConnectorWouldNotDestroyWhoseRecordItsRequesterMayNotUpdate() throws Exception {
        // given
        KeyImportAttempt attempt = dueAttempt();
        UUID recordUuid = ownedRecord();
        requesterResolvable(attempt);
        denyResourceAccess(Resource.CRYPTOGRAPHIC_KEY, ResourceAction.UPDATE);
        connectorMock.stubImportKeyResult(status(OperationStatus.COMPLETED));
        connectorMock.stubDestroyKeyProblem(ErrorCode.VALIDATION_FAILED);

        // when
        sweep();

        // then
        KeyImport unresolved = keyImportRepository.findById(attempt.uuid()).orElseThrow();
        assertThat(unresolved.getState()).isEqualTo(KeyImportState.UNRESOLVED);
        assertThat(unresolved.getErrorMessage()).isEqualTo(KeyImportReconciler.NOT_REGISTERED);
        assertTheRecordIsAsItWas(recordUuid);
        assertThat(cryptographicKeyRepository.findById(recordUuid).orElseThrow().getTokenProfileUuid()).isNull();
        assertThat(cryptographicKeyItemRepository.findByKeyUuidIn(List.of(recordUuid))).hasSize(1);
    }

    /** A retry registered the key between the claim and the connector's answer, so there is nothing to undo. */
    @Test
    void reconcile_leavesAnImportARetryRegisteredMeanwhile() throws Exception {
        // given
        KeyImportAttempt attempt = dueAttempt();
        KeyImportCheck check = claimed();
        keyImportWriter.complete(attempt.uuid(), KeyImportWriterITest.registration(profile, pair, attempt, Set.of()));
        connectorMock.stubImportKeyResult(status(OperationStatus.COMPLETED));
        connectorMock.stubDestroyKey();

        // when
        SecurityContextHolder.clearContext();
        reconciler.reconcile(check);

        // then
        assertThat(keyImportRepository.findById(attempt.uuid()).orElseThrow().getState())
                .isEqualTo(KeyImportState.COMPLETED);
        assertThat(cryptographicKeyItemRepository.count()).isEqualTo(2);
        connectorMock.verifyDestroyKeyRequests(0);
    }

    /** One attempt is claimed at a time, so each is looked at within its retry window however many are due. */
    @Test
    void claimNext_claimsOnlyTheAttemptWaitingLongest() throws Exception {
        // given
        KeyImportAttempt longest = dueAttempt(pair);
        jdbcTemplate
                .update("UPDATE key_import SET next_check_at = now() - interval '2 minutes' WHERE uuid = ?",
                        longest.uuid());
        KeyImportAttempt next = dueAttempt(KeyImportWriterITest.rsa());

        // when
        KeyImportCheck claimed = claimed();

        // then
        assertThat(claimed.attempt().uuid()).isEqualTo(longest.uuid());
        assertThat(keyImportRepository.findById(next.uuid()).orElseThrow().getNextCheckAt())
                .isBefore(OffsetDateTime.now());
    }

    @Test
    void sweep_settlesEveryDueImport() throws Exception {
        // given
        KeyImportAttempt first = dueAttempt(pair);
        KeyImportAttempt second = dueAttempt(KeyImportWriterITest.rsa());
        connectorMock.stubImportKeyResultNotTracked();

        // when
        sweep();

        // then
        assertThat(keyImportRepository.findAllById(List.of(first.uuid(), second.uuid())))
                .extracting(KeyImport::getState)
                .containsOnly(KeyImportState.FAILED);
    }

    /** A retry sent the import again after the claim, so that send's answer, not the claim's, settles it. */
    @Test
    void reconcile_leavesAnImportARetrySentAgainAfterTheClaim() throws Exception {
        // given
        KeyImportAttempt attempt = dueAttempt();
        KeyImportCheck check = claimed();
        keyImportWriter.resending(attempt.uuid(), List.of("resent-secret-digest"));
        connectorMock.stubImportKeyResult(status(OperationStatus.COMPLETED));
        connectorMock.stubDestroyKey();

        // when
        SecurityContextHolder.clearContext();
        reconciler.reconcile(check);

        // then
        assertThat(keyImportRepository.findById(attempt.uuid()).orElseThrow().getState())
                .isEqualTo(KeyImportState.REQUESTED);
        connectorMock.verifyDestroyKeyRequests(0);
    }

    /** A retry sent the import again after the claim, so the answer that it ended without a key may predate that. */
    @Test
    void reconcile_leavesAnImportThatEndedWithoutAKeyToARetrySendingItAgain() throws Exception {
        // given
        KeyImportAttempt attempt = dueAttempt();
        KeyImportCheck check = claimed();
        keyImportWriter.resending(attempt.uuid(), List.of("resent-secret-digest"));
        connectorMock.stubImportKeyResult(status(OperationStatus.FAILED));

        // when
        SecurityContextHolder.clearContext();
        reconciler.reconcile(check);

        // then
        assertThat(keyImportRepository.findById(attempt.uuid()).orElseThrow().getState())
                .isEqualTo(KeyImportState.REQUESTED);
    }

    /** A request resumed the import after the claim, so the request, not the claim's answer, settles it. */
    @Test
    void reconcile_leavesAnImportARequestResumedAfterTheClaim() throws Exception {
        // given
        KeyImportAttempt attempt = dueAttempt();
        KeyImportCheck check = claimed();
        keyImportWriter.resuming(attempt.uuid());
        connectorMock.stubImportKeyResult(status(OperationStatus.COMPLETED));
        connectorMock.stubDestroyKey();

        // when
        SecurityContextHolder.clearContext();
        reconciler.reconcile(check);

        // then
        assertThat(keyImportRepository.findById(attempt.uuid()).orElseThrow().getState())
                .isEqualTo(KeyImportState.REQUESTED);
        connectorMock.verifyDestroyKeyRequests(0);
    }

    /** Imports past their cutoff settle on their last look, and an import due behind them is still asked about. */
    @Test
    void sweep_reachesAnImportDueBehindImportsPastTheirCutoff() throws Exception {
        // given
        for (int opened = 0; opened < 3; opened++) {
            keyImportWriter.open(terms("fingerprint-" + opened), "retry-" + opened, "imported key", SENT);
        }
        jdbcTemplate
                .update("UPDATE key_import SET created_at = now() - interval '21 hours', "
                        + "last_sent_at = now() - interval '21 hours', next_check_at = now() - interval '10 minutes'");
        KeyImportAttempt due = dueAttempt();
        connectorMock.stubImportKeyResultNotTracked();

        // when
        sweep();

        // then
        assertThat(keyImportRepository.findById(due.uuid()).orElseThrow().getState()).isEqualTo(KeyImportState.FAILED);
        assertThat(jdbcTemplate
                .queryForObject("SELECT count(*) FROM key_import WHERE state = 'UNRESOLVED'", Integer.class))
                .isEqualTo(3);
    }

    @Test
    void claimNext_takesNothingWhileAnotherNodeSweeps() throws Exception {
        // given
        dueAttempt();
        TransactionTemplate otherNode = new TransactionTemplate(transactionManager);
        try (ExecutorService node = Executors.newSingleThreadExecutor()) {
            // when
            Optional<KeyImportCheck> claimed = otherNode.execute(status -> {
                assertThat(clusterSynchronizer.tryLock(ClusterOperationSynchronizer.Operation.KEY_IMPORT_SWEEP))
                        .isTrue();
                return answer(node.submit(() -> claimer.claimNext()));
            });

            // then
            assertThat(claimed).isEmpty();
        }
    }

    /** A retry sending the attempt again keeps it for another retry window, even when the sweep found it due first. */
    @Test
    void claimNext_leavesAnAttemptARetryIsSendingAgain() throws Exception {
        // given
        KeyImportAttempt attempt = dueAttempt();
        TransactionTemplate retry = new TransactionTemplate(transactionManager);
        try (ExecutorService sweeping = Executors.newSingleThreadExecutor()) {
            // when
            Future<Optional<KeyImportCheck>> claimed = retry.execute(status -> {
                keyImportWriter.resending(attempt.uuid(), List.of("resent-secret-digest"));
                int retryPid = jdbcTemplate.queryForObject("SELECT pg_backend_pid()", Integer.class);
                Future<Optional<KeyImportCheck>> claim = sweeping.submit(() -> claimer.claimNext());
                Awaitility
                        .await()
                        .atMost(Duration.ofSeconds(10))
                        .until(() -> jdbcTemplate
                                .queryForObject(
                                        "SELECT count(*) FROM pg_stat_activity WHERE ? = ANY(pg_blocking_pids(pid))",
                                        Long.class, retryPid) > 0);
                return claim;
            });

            // then
            assertThat(claimed.get(10, TimeUnit.SECONDS)).isEmpty();
        }
    }

    /**
     * The attempts that completed, failed or were compensated longer than the retention ago are deleted, while open
     * attempts, those that ended quarantined or unresolved and recent ones stay.
     */
    @Test
    void sweep_deletesTheFinishedAttemptsPastTheirRetention() {
        // given
        List<UUID> kept = List
                .of(lastChanged(KeyImportState.REQUESTED, 8), lastChanged(KeyImportState.ACCEPTED, 8),
                        lastChanged(KeyImportState.COMPENSATING, 8), lastChanged(KeyImportState.QUARANTINED, 8),
                        lastChanged(KeyImportState.UNRESOLVED, 8), lastChanged(KeyImportState.COMPLETED, 6),
                        lastChanged(KeyImportState.FAILED, 6), lastChanged(KeyImportState.COMPENSATED, 6));
        lastChanged(KeyImportState.COMPLETED, 8);
        lastChanged(KeyImportState.FAILED, 8);
        lastChanged(KeyImportState.COMPENSATED, 8);

        // when
        sweep();

        // then
        assertThat(keyImportRepository.findAll())
                .extracting(KeyImport::getUuid)
                .containsExactlyInAnyOrderElementsOf(kept);
    }

    /**
     * Every node deletes on its own timer, so a node deleting while another node's delete is under way skips the
     * attempts that delete holds rather than wait for it, and neither fails.
     */
    @Test
    void deleteFinishedBefore_skipsTheAttemptsAnotherNodeIsDeleting() {
        // given
        UUID oldest = lastChanged(KeyImportState.COMPLETED, 9);
        UUID older = lastChanged(KeyImportState.FAILED, 8);
        OffsetDateTime cutoff = OffsetDateTime.now().minusDays(7);
        TransactionTemplate otherNode = new TransactionTemplate(transactionManager);
        Integer deletedMeanwhile;
        try (ExecutorService node = Executors.newSingleThreadExecutor()) {
            // when
            deletedMeanwhile = otherNode.execute(status -> {
                assertThat(keyImportRepository.deleteFinishedBefore(cutoff, 1)).isEqualTo(1);
                return answer(node.submit(() -> retentionWriter.deleteFinishedBefore(cutoff, 10)));
            });
        }

        // then
        assertThat(deletedMeanwhile).isEqualTo(1);
        assertThat(keyImportRepository.findAllById(List.of(oldest, older))).isEmpty();
    }

    private KeyImportCheck claimed() {
        return claimer.claimNext().orElseThrow();
    }

    /** An import last sent longer ago than the connector is trusted to keep its records, and due for its last look. */
    private KeyImportAttempt lateAttempt() {
        return lateAttempt(pair);
    }

    private KeyImportAttempt lateAttempt(KeyPair keyPair) {
        KeyImportAttempt attempt = dueAttempt(keyPair);
        jdbcTemplate
                .update("UPDATE key_import SET created_at = now() - interval '21 hours', "
                        + "last_sent_at = now() - interval '21 hours' WHERE uuid = ?", attempt.uuid());
        return attempt;
    }

    /** The public key of the pair as a certificate brought it in, described, owned and grouped by another user. */
    private UUID ownedRecord() throws Exception {
        UUID recordUuid = certificateKeyWriter
                .uploadCertificatePublicKey("certKey_imported", pair.getPublic(), 2048,
                        KeyImportWriterITest.fingerprintOf(pair));
        CryptographicKey described = cryptographicKeyRepository.findById(recordUuid).orElseThrow();
        described.setDescription("the certificate's key");
        cryptographicKeyRepository.saveAndFlush(described);
        objectAssociationService.setOwner(Resource.CRYPTOGRAPHIC_KEY, recordUuid, RECORD_OWNER, "owner");
        Group group = new Group();
        group.setName("record group");
        recordGroup = groupRepository.save(group);
        objectAssociationService.addGroup(Resource.CRYPTOGRAPHIC_KEY, recordUuid, recordGroup.getUuid());
        CustomAttributeV3 department = new CustomAttributeV3();
        department.setUuid(UUID.randomUUID().toString());
        department.setName("department");
        department.setType(AttributeType.CUSTOM);
        department.setContentType(AttributeContentType.STRING);
        CustomAttributeProperties properties = new CustomAttributeProperties();
        properties.setLabel("Department");
        department.setProperties(properties);
        attributeEngine.updateCustomAttributeDefinition(department, List.of(Resource.CRYPTOGRAPHIC_KEY));
        RequestAttributeV3 sales = new RequestAttributeV3();
        sales.setUuid(UUID.fromString(department.getUuid()));
        sales.setName(department.getName());
        sales.setContentType(AttributeContentType.STRING);
        sales.setContent(List.of(new StringAttributeContentV3("Sales")));
        attributeEngine.updateObjectCustomAttributesContent(Resource.CRYPTOGRAPHIC_KEY, recordUuid, List.of(sales));
        return recordUuid;
    }

    private void assertTheRecordIsAsItWas(UUID recordUuid) {
        CryptographicKey kept = cryptographicKeyRepository.findWithGroupsByUuid(recordUuid).orElseThrow();
        assertThat(kept.getName()).isEqualTo("certKey_imported");
        assertThat(kept.getDescription()).isEqualTo("the certificate's key");
        assertThat(kept.getGroups()).extracting(Group::getUuid).containsExactly(recordGroup.getUuid());
        assertThat(objectAssociationService.getOwner(Resource.CRYPTOGRAPHIC_KEY, recordUuid).getUuid())
                .isEqualTo(RECORD_OWNER.toString());
        assertThat(attributeEngine
                .getObjectCustomAttributesContentForSystemContext(Resource.CRYPTOGRAPHIC_KEY, recordUuid))
                .singleElement()
                .satisfies(attribute -> assertThat(((ResponseAttributeV3) attribute).getContent())
                        .extracting(content -> content.getData().toString())
                        .containsExactly("Sales"));
    }

    /** The auth service answers for the attempt's requester, so the reconciliation can check as the requester. */
    private void requesterResolvable(KeyImportAttempt attempt) {
        KeyImport recorded = keyImportRepository.findById(attempt.uuid()).orElseThrow();
        authService = AuthServiceWireMockStubs
                .startImpersonating(recorded.getRequesterUuid(), recorded.getRequesterName());
    }

    /** Sweeps as the scheduler does, with no user signed in. */
    private void sweep() {
        SecurityContextHolder.clearContext();
        sweeper.sweep();
    }

    private KeyImportAttempt dueAttempt() {
        return dueAttempt(pair);
    }

    private KeyImportAttempt dueAttempt(KeyPair keyPair) {
        KeyImportAttempt attempt = keyImportWriter
                .open(terms(keyPair), "retry-" + UUID.randomUUID(), "imported key", SENT);
        makeDue(attempt);
        return attempt;
    }

    /** An AES key import, which is recorded without a fingerprint, due for its next look. */
    private KeyImportAttempt dueSecretKeyAttempt() {
        KeyImportTerms secretKey = new KeyImportTerms(profile, KeyRequestType.SECRET, KeyAlgorithm.AES, null, true,
                List.of(), new NameAndUuidDto(UUID.randomUUID().toString(), "requester"));
        KeyImportAttempt attempt = keyImportWriter
                .open(secretKey, "retry-" + UUID.randomUUID(), "imported secret key", SENT);
        makeDue(attempt);
        return attempt;
    }

    private void makeDue(KeyImportAttempt attempt) {
        jdbcTemplate
                .update("UPDATE key_import SET next_check_at = now() - interval '1 minute' WHERE uuid = ?",
                        attempt.uuid());
    }

    /** An attempt in the given state that last changed the given number of days ago, not due for a look. */
    private UUID lastChanged(KeyImportState state, int daysAgo) {
        KeyImportAttempt attempt = keyImportWriter
                .open(terms("fingerprint-" + UUID.randomUUID()), "retry-" + UUID.randomUUID(), "imported key", SENT);
        jdbcTemplate
                .update("UPDATE key_import SET state = ?, updated_at = ? WHERE uuid = ?", state.name(),
                        OffsetDateTime.now().minusDays(daysAgo), attempt.uuid());
        return attempt.uuid();
    }

    private KeyImportTerms terms() {
        return terms(pair);
    }

    private KeyImportTerms terms(KeyPair keyPair) {
        return terms(KeyImportWriterITest.fingerprintOf(keyPair));
    }

    private KeyImportTerms terms(String fingerprint) {
        return new KeyImportTerms(profile, KeyRequestType.KEY_PAIR, KeyAlgorithm.RSA, fingerprint, true, List.of(),
                new NameAndUuidDto(UUID.randomUUID().toString(), "requester"));
    }

    private KeyPairOperationStatusResponseV2Dto status(OperationStatus status) {
        return CryptographicKeyImportV2ITest.status(status, pair.getPublic());
    }

    private static <T> T answer(Future<T> pending) {
        try {
            return pending.get(10, TimeUnit.SECONDS);
        } catch (Exception e) {
            throw new IllegalStateException(e);
        }
    }

    private TokenProfileFullModel persistedProfile(String connectorUrl) {
        Connector connector = new Connector();
        connector.setName("reconciliation-provider-" + UUID.randomUUID());
        connector.setUrl(connectorUrl);
        connector.setVersion(ConnectorVersion.V2);
        connector.setStatus(ConnectorStatus.CONNECTED);
        connector = connectorRepository.save(connector);
        ConnectorInterfaceEntity cryptography = new ConnectorInterfaceEntity();
        cryptography.setConnector(connector);
        cryptography.setConnectorUuid(connector.getUuid());
        cryptography.setInterfaceCode(ConnectorInterface.CRYPTOGRAPHY);
        cryptography.setVersion("v2");
        cryptography.setFeatures(List.of(FeatureFlag.STATELESS, FeatureFlag.KEY_IMPORT));
        cryptography = connectorInterfaceRepository.save(cryptography);
        TokenInstanceReference token = new TokenInstanceReference();
        token.setName("reconciliation-token-" + UUID.randomUUID());
        token.setConnector(connector);
        token.setConnectorUuid(connector.getUuid());
        token.setConnectorInterface(cryptography);
        token.setKind("SOFT");
        token.setStatus(TokenInstanceStatus.ACTIVATED);
        token = tokenInstanceReferenceRepository.save(token);
        TokenProfile tokenProfile = new TokenProfile();
        tokenProfile.setName("reconciliation-profile-" + UUID.randomUUID());
        tokenProfile.setTokenInstanceReference(token);
        tokenProfile.setTokenInstanceName(token.getName());
        tokenProfile.setEnabled(true);
        tokenProfile.setUsage(List.of(KeyUsage.SIGN, KeyUsage.VERIFY));
        tokenProfile = tokenProfileRepository.save(tokenProfile);
        return tokenProfileRepository
                .findFullModelByUuidAndTokenInstanceReferenceUuid(tokenProfile.getUuid(), token.getUuid())
                .orElseThrow();
    }
}
