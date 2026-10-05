package com.otilm.core.integration.service;

import com.otilm.api.exception.NotFoundException;
import com.otilm.api.exception.ValidationException;
import com.otilm.api.model.client.attribute.RequestAttribute;
import com.otilm.api.model.client.attribute.RequestAttributeV3;
import com.otilm.api.model.client.attribute.ResponseAttributeV3;
import com.otilm.api.model.client.attribute.custom.CustomAttributeCreateRequestDto;
import com.otilm.api.model.client.certificate.ImportOutcome;
import com.otilm.api.model.client.connector.v2.ConnectorInterface;
import com.otilm.api.model.client.connector.v2.ConnectorVersion;
import com.otilm.api.model.client.connector.v2.FeatureFlag;
import com.otilm.api.model.client.cryptography.key.EditKeyRequestDto;
import com.otilm.api.model.client.cryptography.key.KeyCompromiseReason;
import com.otilm.api.model.client.cryptography.key.KeyRequestType;
import com.otilm.api.model.common.NameAndUuidDto;
import com.otilm.api.model.common.attribute.common.AttributeType;
import com.otilm.api.model.common.attribute.common.MetadataAttribute;
import com.otilm.api.model.common.attribute.common.content.AttributeContentType;
import com.otilm.api.model.common.attribute.common.properties.MetadataAttributeProperties;
import com.otilm.api.model.common.attribute.v2.MetadataAttributeV2;
import com.otilm.api.model.common.attribute.v2.content.StringAttributeContentV2;
import com.otilm.api.model.common.attribute.v3.content.StringAttributeContentV3;
import com.otilm.api.model.common.enums.cryptography.KeyAlgorithm;
import com.otilm.api.model.common.enums.cryptography.KeyFormat;
import com.otilm.api.model.common.enums.cryptography.KeyType;
import com.otilm.api.model.connector.cryptography.enums.TokenInstanceStatus;
import com.otilm.api.model.core.auth.Resource;
import com.otilm.api.model.core.certificate.CertificateState;
import com.otilm.api.model.core.certificate.CertificateValidationStatus;
import com.otilm.api.model.core.compliance.ComplianceStatus;
import com.otilm.api.model.core.connector.ConnectorStatus;
import com.otilm.api.model.core.cryptography.key.KeyEvent;
import com.otilm.api.model.core.cryptography.key.KeyEventStatus;
import com.otilm.api.model.core.cryptography.key.KeyState;
import com.otilm.api.model.core.cryptography.key.KeyUsage;
import com.otilm.core.attribute.engine.AttributeEngine;
import com.otilm.core.config.cache.CacheConfig;
import com.otilm.core.dao.entity.Certificate;
import com.otilm.core.dao.entity.CertificateContent;
import com.otilm.core.dao.entity.Connector;
import com.otilm.core.dao.entity.ConnectorInterfaceEntity;
import com.otilm.core.dao.entity.CryptographicKey;
import com.otilm.core.dao.entity.CryptographicKeyEventHistory;
import com.otilm.core.dao.entity.CryptographicKeyItem;
import com.otilm.core.dao.entity.Group;
import com.otilm.core.dao.entity.KeyImport;
import com.otilm.core.dao.entity.KeyImportState;
import com.otilm.core.dao.entity.TokenInstanceReference;
import com.otilm.core.dao.entity.TokenProfile;
import com.otilm.core.dao.repository.CertificateContentRepository;
import com.otilm.core.dao.repository.CertificateRepository;
import com.otilm.core.dao.repository.ConnectorInterfaceRepository;
import com.otilm.core.dao.repository.ConnectorRepository;
import com.otilm.core.dao.repository.CryptographicKeyEventHistoryRepository;
import com.otilm.core.dao.repository.CryptographicKeyItemRepository;
import com.otilm.core.dao.repository.CryptographicKeyRepository;
import com.otilm.core.dao.repository.GroupRepository;
import com.otilm.core.dao.repository.KeyImportRepository;
import com.otilm.core.dao.repository.TokenInstanceReferenceRepository;
import com.otilm.core.dao.repository.TokenProfileRepository;
import com.otilm.core.model.connector.ImmutableConnectorInterface;
import com.otilm.core.model.crypto.CryptographicKeyBasicModel;
import com.otilm.core.model.crypto.CryptographicKeyFullModel;
import com.otilm.core.model.crypto.ImmutableTokenInstanceFullModel;
import com.otilm.core.model.crypto.ImmutableTokenProfileFullModel;
import com.otilm.core.model.crypto.ImportedKey;
import com.otilm.core.model.crypto.ImportedKeyRegistration;
import com.otilm.core.model.crypto.KeyImportAttempt;
import com.otilm.core.model.crypto.KeyImportMetadata;
import com.otilm.core.model.crypto.KeyImportTerms;
import com.otilm.core.model.crypto.KeyMaterial;
import com.otilm.core.model.crypto.ProviderKeyItem;
import com.otilm.core.model.crypto.PublicKeyHolder;
import com.otilm.core.model.crypto.PublicKeyHolder.Holding;
import com.otilm.core.model.crypto.RemoteKeyReference;
import com.otilm.core.model.crypto.TokenProfileFullModel;
import com.otilm.core.security.authz.SecurityResourceFilter;
import com.otilm.core.service.AttributeExternalService;
import com.otilm.core.service.ResourceObjectAssociationService;
import com.otilm.core.service.handler.ComplianceSubjectHandler;
import com.otilm.core.service.writer.CertificateKeyWriter;
import com.otilm.core.service.writer.ComplianceSubjectWriter;
import com.otilm.core.service.writer.CryptographicKeyWriter;
import com.otilm.core.service.writer.KeyImportWriter;
import com.otilm.core.util.BaseSpringBootTest;
import com.otilm.core.util.CryptographyUtil;
import jakarta.persistence.EntityManager;
import jakarta.persistence.EntityManagerFactory;
import jakarta.persistence.Query;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.time.Duration;
import java.time.LocalDateTime;
import java.time.Month;
import java.time.OffsetDateTime;
import java.time.temporal.ChronoUnit;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;
import java.util.Map;
import java.util.Optional;
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
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.cache.Cache;
import org.springframework.cache.CacheManager;
import org.springframework.dao.DataIntegrityViolationException;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.orm.jpa.EntityManagerHolder;
import org.springframework.transaction.PlatformTransactionManager;
import org.springframework.transaction.TransactionDefinition;
import org.springframework.transaction.support.TransactionSynchronizationManager;
import org.springframework.transaction.support.TransactionTemplate;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

@SpringBootTest
class KeyImportWriterITest extends BaseSpringBootTest {

    private static final String OPEN_ATTEMPT_INDEX = "uq_key_import_open_attempt";

    private static final String OPEN_SECRET_ATTEMPT_INDEX = "uq_key_import_open_secret_attempt";

    private static final List<String> SENT = List.of("sent-secret-digest");

    private static final List<KeyUsage> PROFILE_USAGES = List
            .of(KeyUsage.SIGN, KeyUsage.VERIFY, KeyUsage.ENCRYPT, KeyUsage.DECRYPT);

    @Autowired
    private KeyImportWriter keyImportWriter;
    @Autowired
    private KeyImportRepository keyImportRepository;
    @Autowired
    private JdbcTemplate jdbcTemplate;
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
    private CertificateKeyWriter certificateKeyWriter;
    @Autowired
    private CertificateRepository certificateRepository;
    @Autowired
    private CertificateContentRepository certificateContentRepository;
    @Autowired
    private GroupRepository groupRepository;
    @Autowired
    private ResourceObjectAssociationService objectAssociationService;
    @Autowired
    private CryptographicKeyWriter cryptographicKeyWriter;
    @Autowired
    private ComplianceSubjectWriter complianceSubjectWriter;
    @Autowired
    private EntityManagerFactory entityManagerFactory;
    @Autowired
    private PlatformTransactionManager transactionManager;
    @Autowired
    private EntityManager entityManager;
    @Autowired
    private CacheManager cacheManager;
    @Autowired
    private AttributeExternalService attributeService;
    @Autowired
    private AttributeEngine attributeEngine;

    /** The entity-generated test schema cannot carry the migrations' partial indexes, so each test adds them. */
    @BeforeEach
    void addTheOpenAttemptIndexes() {
        jdbcTemplate
                .execute("CREATE UNIQUE INDEX IF NOT EXISTS \"" + OPEN_ATTEMPT_INDEX + "\" ON " + dbSchema
                        + ".\"key_import\" (\"spki_fingerprint\") WHERE \"state\" IN ('REQUESTED', 'ACCEPTED', 'COMPENSATING')");
        jdbcTemplate
                .execute("CREATE UNIQUE INDEX IF NOT EXISTS \"" + OPEN_SECRET_ATTEMPT_INDEX + "\" ON " + dbSchema
                        + ".\"key_import\" (\"idempotency_key\") WHERE \"spki_fingerprint\" IS NULL"
                        + " AND \"state\" IN ('REQUESTED', 'ACCEPTED', 'COMPENSATING')");
    }

    @AfterEach
    void dropTheOpenAttemptIndexes() {
        jdbcTemplate.execute("DROP INDEX IF EXISTS " + dbSchema + ".\"" + OPEN_ATTEMPT_INDEX + "\"");
        jdbcTemplate.execute("DROP INDEX IF EXISTS " + dbSchema + ".\"" + OPEN_SECRET_ATTEMPT_INDEX + "\"");
    }

    /** A re-send adds the digests of what it sends, so an answer is checked against every copy the connector got. */
    @Test
    void resending_addsTheDigestsOfWhatIsSentAgain() {
        // given
        KeyImportAttempt attempt = keyImportWriter.open(terms("fingerprint-f", false), "retry-f", "key", SENT);

        // when
        KeyImportAttempt resent = keyImportWriter
                .resending(attempt.uuid(), List.of("resent-secret-digest"))
                .orElseThrow();

        // then
        assertThat(resent.secretDigests()).containsExactly("sent-secret-digest", "resent-secret-digest");
        assertThat(keyImportRepository.findById(attempt.uuid()).orElseThrow().getSecretDigests())
                .containsExactly("sent-secret-digest", "resent-secret-digest");
    }

    @Test
    void resending_recordsWhenTheAttemptWasLastSent() {
        // given
        KeyImportAttempt attempt = keyImportWriter.open(terms("fingerprint-u", false), "retry-u", "key", SENT);
        jdbcTemplate
                .update("UPDATE key_import SET last_sent_at = now() - interval '1 hour' WHERE uuid = ?",
                        attempt.uuid());
        OffsetDateTime before = OffsetDateTime.now();

        // when
        keyImportWriter.resending(attempt.uuid(), List.of("resent-secret-digest"));

        // then
        assertThat(keyImportRepository.findById(attempt.uuid()).orElseThrow().getLastSentAt())
                .isAfterOrEqualTo(before)
                .isBeforeOrEqualTo(OffsetDateTime.now());
    }

    @Test
    void resending_leavesTheAttemptToItsRequesterForAnotherRetryWindow() {
        // given
        KeyImportAttempt attempt = keyImportWriter.open(terms("fingerprint-s", false), "retry-s", "key", SENT);
        keyImportWriter.dueNow(attempt.uuid());
        OffsetDateTime before = OffsetDateTime.now();

        // when
        keyImportWriter.resending(attempt.uuid(), List.of("resent-secret-digest"));

        // then
        assertThat(keyImportRepository.findById(attempt.uuid()).orElseThrow().getNextCheckAt())
                .isAfterOrEqualTo(before.plusMinutes(15))
                .isBefore(OffsetDateTime.now().plusMinutes(15).plusSeconds(1));
    }

    @Test
    void resending_leavesAnAttemptThatClosedMeanwhileUnsent() {
        // given
        KeyImportAttempt attempt = keyImportWriter.open(terms("fingerprint-g", false), "retry-g", "key", SENT);
        keyImportWriter.failUntaken(attempt, "closed meanwhile");

        // when
        Optional<KeyImportAttempt> resent = keyImportWriter.resending(attempt.uuid(), List.of("resent-secret-digest"));

        // then
        assertThat(resent).isEmpty();
        assertThat(keyImportRepository.findById(attempt.uuid()).orElseThrow().getSecretDigests()).isEqualTo(SENT);
    }

    /**
     * The request's persistence context keeps the attempt as the request read it, so the digests another node added by
     * a send since are read from the database.
     */
    @Test
    void secretDigests_readsWhatAnotherNodeAddedSinceTheRequestReadTheAttempt() throws Exception {
        // given
        KeyImportAttempt attempt = keyImportWriter.open(terms("fingerprint-z", false), "retry-z", "key", SENT);
        List<String> digests = new ArrayList<>();

        // when
        withARequestBoundEntityManager(KeyImport.class, attempt.uuid(), () -> {
            try (ExecutorService otherNode = Executors.newSingleThreadExecutor()) {
                otherNode
                        .submit(() -> keyImportWriter.resending(attempt.uuid(), List.of("resent-secret-digest")))
                        .get(10, TimeUnit.SECONDS);
            }
            digests.addAll(keyImportWriter.secretDigests(attempt.uuid()));
        });

        // then
        assertThat(digests).containsExactly("sent-secret-digest", "resent-secret-digest");
    }

    /** Another request claimed the attempt for a send, so its answer, not this request's decision, settles it. */
    @Test
    void failUntaken_leavesAnAttemptAnotherRequestResends() {
        // given
        KeyImportAttempt opened = keyImportWriter.open(terms("fingerprint-h", false), "retry-h", "key", SENT);
        keyImportWriter.resending(opened.uuid(), List.of("resent-secret-digest"));

        // when
        boolean closed = keyImportWriter.failUntaken(opened, "closed meanwhile");

        // then
        assertThat(closed).isFalse();
        assertThat(keyImportRepository.findById(opened.uuid()).orElseThrow().getState())
                .isEqualTo(KeyImportState.REQUESTED);
    }

    @Test
    void failUntaken_closesAnAttemptNobodySent() {
        // given
        KeyImportAttempt opened = keyImportWriter.open(terms("fingerprint-i", false), "retry-i", "key", SENT);

        // when
        boolean closed = keyImportWriter.failUntaken(opened, "closed meanwhile");

        // then
        assertThat(closed).isTrue();
        KeyImport failed = keyImportRepository.findById(opened.uuid()).orElseThrow();
        assertThat(failed.getState()).isEqualTo(KeyImportState.FAILED);
        assertThat(failed.getErrorMessage()).isEqualTo("closed meanwhile");
    }

    @Test
    void open_leavesTheAttemptToItsRequesterForTheRetryWindow() {
        // given
        OffsetDateTime before = OffsetDateTime.now();

        // when
        KeyImportAttempt attempt = keyImportWriter.open(terms("fingerprint-j", false), "retry-j", "key", SENT);

        // then
        OffsetDateTime nextCheck = keyImportRepository.findById(attempt.uuid()).orElseThrow().getNextCheckAt();
        assertThat(nextCheck)
                .isAfterOrEqualTo(before.plusMinutes(15).truncatedTo(ChronoUnit.MICROS))
                .isBefore(OffsetDateTime.now().plusMinutes(15).plusSeconds(1));
    }

    @Test
    void open_recordsTheAttemptUnderIdentifiersOfItsOwn() {
        // given
        KeyImportTerms terms = terms("fingerprint-a", true);

        // when
        KeyImportAttempt attempt = keyImportWriter.open(terms, "retry-a", "signing key", SENT);

        // then
        KeyImport recorded = keyImportRepository.findById(attempt.uuid()).orElseThrow();
        assertThat(attempt.state()).isEqualTo(KeyImportState.REQUESTED);
        assertThat(recorded.getState()).isEqualTo(KeyImportState.REQUESTED);
        assertThat(recorded.getKeyReference()).isEqualTo(attempt.keyReference()).isNotEqualTo(attempt.uuid());
        assertThat(recorded.getIdempotencyKey()).isEqualTo("retry-a");
        assertThat(recorded.getSecretDigests()).isEqualTo(SENT);
        assertThat(recorded.getRequesterUuid()).hasToString(terms.requester().getUuid());
        assertThat(recorded.getRequesterName()).isEqualTo("requester");
        assertThat(recorded.getTokenProfileUuid()).isEqualTo(terms.profile().uuid());
        assertThat(recorded.getTokenInstanceUuid()).isEqualTo(terms.profile().tokenInstanceReferenceUuid());
        assertThat(recorded.getKeyRequestType()).isEqualTo(KeyRequestType.KEY_PAIR);
        assertThat(recorded.getKeyAlgorithm()).isEqualTo(KeyAlgorithm.RSA);
        assertThat(recorded.getSpkiFingerprint()).isEqualTo("fingerprint-a");
        assertThat(recorded.getName()).isEqualTo("signing key");
        assertThat(recorded.isExportable()).isTrue();
        assertThat(recorded.getOperationMeta()).isNull();
        assertThat(recorded.getKeyUuid()).isNull();
        assertThat(recorded.getCreatedAt()).isNotNull();
    }

    @Test
    void open_refusesASecondOpenAttemptForTheSameKey() {
        // given
        keyImportWriter.open(terms("fingerprint-b", false), "retry-b", "key", SENT);
        KeyImportTerms sameKey = terms("fingerprint-b", false);

        // when
        // then
        assertThatThrownBy(() -> keyImportWriter.open(sameKey, "another-retry", "key", SENT))
                .isInstanceOf(DataIntegrityViolationException.class);
    }

    /** Another import of a key the reconciliation is undoing would put a second copy in the token meanwhile. */
    @Test
    void open_refusesAnImportOfAKeyBeingUndone() {
        // given
        KeyImportAttempt undone = keyImportWriter.open(terms("fingerprint-v", false), "retry-v", "key", SENT);
        keyImportWriter.compensating(undone);
        KeyImportTerms sameKey = terms("fingerprint-v", false);

        // when
        // then
        assertThatThrownBy(() -> keyImportWriter.open(sameKey, "retry-v", "key", SENT))
                .isInstanceOf(DataIntegrityViolationException.class);
    }

    @Test
    void open_startsAgainOnceTheOpenAttemptFailed() {
        // given
        KeyImportAttempt first = keyImportWriter.open(terms("fingerprint-c", false), "retry-c", "key", SENT);
        keyImportWriter.failUntaken(first, "The connector could not import the key.");

        // when
        KeyImportAttempt second = keyImportWriter.open(terms("fingerprint-c", false), "retry-c", "key", SENT);

        // then
        assertThat(second.uuid()).isNotEqualTo(first.uuid());
        KeyImport failed = keyImportRepository.findById(first.uuid()).orElseThrow();
        assertThat(failed.getState()).isEqualTo(KeyImportState.FAILED);
        assertThat(failed.getErrorMessage()).isEqualTo("The connector could not import the key.");
    }

    /** A secret key has no fingerprint, so its import is known by its idempotency key. */
    @Test
    void open_refusesASecondOpenAttemptOfTheSameSecretKeyImport() {
        // given
        KeyImportTerms secretKey = secretKeyTerms(persistedProfile());
        keyImportWriter.open(secretKey, "retry-secret", "key", SENT);

        // when
        // then
        assertThatThrownBy(() -> keyImportWriter.open(secretKey, "retry-secret", "key", SENT))
                .isInstanceOf(DataIntegrityViolationException.class);
    }

    /** A retry while the reconciliation undoes the import would put a second copy of the secret key in the token. */
    @Test
    void open_refusesASecretKeyImportBeingUndone() {
        // given
        KeyImportTerms secretKey = secretKeyTerms(persistedProfile());
        KeyImportAttempt undone = keyImportWriter.open(secretKey, "retry-secret-undone", "key", SENT);
        keyImportWriter.compensating(undone);

        // when
        // then
        assertThatThrownBy(() -> keyImportWriter.open(secretKey, "retry-secret-undone", "key", SENT))
                .isInstanceOf(DataIntegrityViolationException.class);
    }

    @Test
    void open_startsASecretKeyImportAgainOnceItsAttemptClosed() {
        // given
        KeyImportTerms secretKey = secretKeyTerms(persistedProfile());
        KeyImportAttempt first = keyImportWriter.open(secretKey, "retry-secret-closed", "key", SENT);
        keyImportWriter.compensating(first);
        keyImportWriter.compensated(first.uuid());

        // when
        KeyImportAttempt second = keyImportWriter.open(secretKey, "retry-secret-closed", "key", SENT);

        // then
        assertThat(second.uuid()).isNotEqualTo(first.uuid());
        assertThat(keyImportRepository.findById(first.uuid()).orElseThrow().getState())
                .isEqualTo(KeyImportState.COMPENSATED);
    }

    /** Only the same import is held back, so other imports of secret keys open meanwhile. */
    @Test
    void open_letsAnotherSecretKeyImportOpenMeanwhile() {
        // given
        TokenProfileFullModel profile = persistedProfile();
        KeyImportAttempt first = keyImportWriter.open(secretKeyTerms(profile), "retry-secret-one", "key", SENT);

        // when
        KeyImportAttempt other = keyImportWriter.open(secretKeyTerms(profile), "retry-secret-other", "key", SENT);

        // then
        assertThat(keyImportRepository.findAllById(List.of(first.uuid(), other.uuid())))
                .extracting(KeyImport::getState)
                .containsExactly(KeyImportState.REQUESTED, KeyImportState.REQUESTED);
    }

    @Test
    void accept_storesTheHandleOfAnImportTheConnectorRuns() {
        // given
        KeyImportAttempt attempt = keyImportWriter.open(terms("fingerprint-d", false), "retry-d", "key", SENT);

        // when
        keyImportWriter.accept(attempt.uuid(), List.of(handle("operation", "1")));

        // then
        KeyImport recorded = keyImportRepository.findById(attempt.uuid()).orElseThrow();
        assertThat(recorded.getState()).isEqualTo(KeyImportState.ACCEPTED);
        assertThat(recorded.getOperationMeta()).extracting(MetadataAttribute::getName).containsExactly("operation");
    }

    @Test
    void failUntakenAndAccept_leaveASettledAttemptAsItIs() {
        // given
        KeyImportAttempt attempt = keyImportWriter.open(terms("fingerprint-e", false), "retry-e", "key", SENT);
        keyImportWriter.failUntaken(attempt, "first");

        // when
        boolean closedAgain = keyImportWriter.failUntaken(attempt, "second");
        keyImportWriter.accept(attempt.uuid(), List.of(handle("operation", "2")));

        // then
        assertThat(closedAgain).isFalse();
        KeyImport recorded = keyImportRepository.findById(attempt.uuid()).orElseThrow();
        assertThat(recorded.getState()).isEqualTo(KeyImportState.FAILED);
        assertThat(recorded.getErrorMessage()).isEqualTo("first");
        assertThat(recorded.getOperationMeta()).isNull();
    }

    /** A later look finishes a compensation an earlier one started. */
    @Test
    void compensating_takesAnOpenAttemptOrOneAlreadyTaken() {
        // given
        KeyImportAttempt attempt = keyImportWriter.open(terms("fingerprint-k", false), "retry-k", "key", SENT);

        // when
        boolean taken = keyImportWriter.compensating(attempt);
        boolean takenAgain = keyImportWriter.compensating(attempt);

        // then
        assertThat(taken).isTrue();
        assertThat(takenAgain).isTrue();
        assertThat(keyImportRepository.findById(attempt.uuid()).orElseThrow().getState())
                .isEqualTo(KeyImportState.COMPENSATING);
    }

    /** A retry sent the attempt again after its claim, so the claim's answer may carry what that send carried. */
    @Test
    void compensating_leavesAnAttemptSentAgainSinceItsClaim() {
        // given
        KeyImportAttempt claimed = keyImportWriter.open(terms("fingerprint-t", false), "retry-t", "key", SENT);
        keyImportWriter.resending(claimed.uuid(), List.of("resent-secret-digest"));

        // when
        boolean taken = keyImportWriter.compensating(claimed);

        // then
        assertThat(taken).isFalse();
        assertThat(keyImportRepository.findById(claimed.uuid()).orElseThrow().getState())
                .isEqualTo(KeyImportState.REQUESTED);
    }

    @Test
    void resuming_leavesTheAttemptToTheRequestForAnotherRetryWindow() {
        // given
        KeyImportAttempt attempt = keyImportWriter.open(terms("fingerprint-w", false), "retry-w", "key", SENT);
        keyImportWriter.dueNow(attempt.uuid());
        OffsetDateTime before = OffsetDateTime.now();

        // when
        keyImportWriter.resuming(attempt.uuid());

        // then
        assertThat(keyImportRepository.findById(attempt.uuid()).orElseThrow().getNextCheckAt())
                .isAfterOrEqualTo(before.plusMinutes(15).truncatedTo(ChronoUnit.MICROS))
                .isBefore(OffsetDateTime.now().plusMinutes(15).plusSeconds(1));
    }

    /** A resume returns the attempt as the request leaves it, so the request can tell whether another took it since. */
    @Test
    void resuming_returnsTheAttemptAsTheRequestLeavesIt() {
        // given
        KeyImportAttempt read = keyImportWriter.open(terms("fingerprint-aa", false), "retry-aa", "key", SENT);

        // when
        KeyImportAttempt resumed = keyImportWriter.resuming(read.uuid());

        // then
        assertThat(keyImportWriter.untaken(resumed)).isTrue();
        assertThat(keyImportWriter.untaken(read)).isFalse();
    }

    /** An attempt that closed, or that another request sent again, since it was read is no longer the reader's. */
    @Test
    void untaken_isFalseForAnAttemptClosedOrSentAgainSinceItWasRead() {
        // given
        KeyImportAttempt closed = keyImportWriter.open(terms("fingerprint-ab", false), "retry-ab", "key", SENT);
        KeyImportAttempt resent = keyImportWriter.open(terms("fingerprint-ac", false), "retry-ac", "key", SENT);
        keyImportWriter.failUntaken(closed, "closed meanwhile");
        keyImportWriter.resending(resent.uuid(), List.of("resent-secret-digest"));

        // when
        // then
        assertThat(keyImportWriter.untaken(closed)).isFalse();
        assertThat(keyImportWriter.untaken(resent)).isFalse();
    }

    /** A request resumed the attempt after its claim, and may be registering its key now. */
    @Test
    void compensating_leavesAnAttemptARequestResumedSinceItsClaim() {
        // given
        KeyImportAttempt claimed = keyImportWriter.open(terms("fingerprint-x", false), "retry-x", "key", SENT);
        keyImportWriter.resuming(claimed.uuid());

        // when
        boolean taken = keyImportWriter.compensating(claimed);

        // then
        assertThat(taken).isFalse();
        assertThat(keyImportRepository.findById(claimed.uuid()).orElseThrow().getState())
                .isEqualTo(KeyImportState.REQUESTED);
    }

    @Test
    void compensated_settlesOnlyACompensatingAttempt() {
        // given
        KeyImportAttempt open = keyImportWriter.open(terms("fingerprint-l", false), "retry-l", "key", SENT);
        KeyImportAttempt taken = keyImportWriter.open(terms("fingerprint-m", false), "retry-m", "key", SENT);
        keyImportWriter.compensating(taken);

        // when
        keyImportWriter.compensated(open.uuid());
        keyImportWriter.compensated(taken.uuid());

        // then
        assertThat(keyImportRepository.findById(open.uuid()).orElseThrow().getState())
                .isEqualTo(KeyImportState.REQUESTED);
        assertThat(keyImportRepository.findById(taken.uuid()).orElseThrow().getState())
                .isEqualTo(KeyImportState.COMPENSATED);
    }

    @Test
    void unresolved_settlesAnUnsettledAttempt() {
        // given
        KeyImportAttempt open = keyImportWriter.open(terms("fingerprint-n", false), "retry-n", "key", SENT);
        KeyImportAttempt taken = keyImportWriter.open(terms("fingerprint-o", false), "retry-o", "key", SENT);
        keyImportWriter.compensating(taken);

        // when
        boolean openClosed = keyImportWriter.unresolved(open, "unresolved");
        boolean takenClosed = keyImportWriter.unresolved(taken, "unresolved");

        // then
        assertThat(openClosed).isTrue();
        assertThat(takenClosed).isTrue();
        assertThat(keyImportRepository.findAllById(List.of(open.uuid(), taken.uuid()))).allSatisfy(attempt -> {
            assertThat(attempt.getState()).isEqualTo(KeyImportState.UNRESOLVED);
            assertThat(attempt.getErrorMessage()).isEqualTo("unresolved");
        });
    }

    /** A request resumed the attempt since it was read, so that request, not the reader, settles it. */
    @Test
    void unresolved_leavesAnAttemptARequestTookSinceItWasRead() {
        // given
        KeyImportAttempt read = keyImportWriter.open(terms("fingerprint-y", false), "retry-y", "key", SENT);
        keyImportWriter.resuming(read.uuid());

        // when
        boolean closed = keyImportWriter.unresolved(read, "unresolved");

        // then
        assertThat(closed).isFalse();
        assertThat(keyImportRepository.findById(read.uuid()).orElseThrow().getState())
                .isEqualTo(KeyImportState.REQUESTED);
    }

    @Test
    void reschedule_setsTheNextCheck() {
        // given
        KeyImportAttempt attempt = keyImportWriter.open(terms("fingerprint-p", false), "retry-p", "key", SENT);
        OffsetDateTime nextCheck = OffsetDateTime.now().plusHours(1).truncatedTo(ChronoUnit.SECONDS);

        // when
        keyImportWriter.reschedule(attempt.uuid(), nextCheck);

        // then
        assertThat(keyImportRepository.findById(attempt.uuid()).orElseThrow().getNextCheckAt())
                .isAtSameInstantAs(nextCheck);
    }

    @Test
    void dueNow_makesAnUnsettledAttemptDue() {
        // given
        KeyImportAttempt attempt = keyImportWriter.open(terms("fingerprint-q", false), "retry-q", "key", SENT);

        // when
        keyImportWriter.dueNow(attempt.uuid());

        // then
        assertThat(keyImportRepository.findById(attempt.uuid()).orElseThrow().getNextCheckAt())
                .isBeforeOrEqualTo(OffsetDateTime.now());
    }

    @Test
    void theSettlingTransitions_leaveASettledAttemptAsItIs() {
        // given
        KeyImportAttempt attempt = keyImportWriter.open(terms("fingerprint-r", false), "retry-r", "key", SENT);
        keyImportWriter.failUntaken(attempt, "first");
        OffsetDateTime nextCheck = keyImportRepository.findById(attempt.uuid()).orElseThrow().getNextCheckAt();

        // when
        boolean taken = keyImportWriter.compensating(attempt);
        keyImportWriter.compensated(attempt.uuid());
        keyImportWriter.unresolved(attempt, "second");
        keyImportWriter.reschedule(attempt.uuid(), OffsetDateTime.now().plusHours(1));
        keyImportWriter.dueNow(attempt.uuid());

        // then
        assertThat(taken).isFalse();
        KeyImport settled = keyImportRepository.findById(attempt.uuid()).orElseThrow();
        assertThat(settled.getState()).isEqualTo(KeyImportState.FAILED);
        assertThat(settled.getErrorMessage()).isEqualTo("first");
        assertThat(settled.getNextCheckAt()).isAtSameInstantAs(nextCheck);
    }

    // ---- fixtures ----

    private static KeyImportTerms terms(String fingerprint, boolean exportable) {
        UUID connectorUuid = UUID.randomUUID();
        ImmutableConnectorInterface cryptography = new ImmutableConnectorInterface(UUID.randomUUID(),
                ConnectorInterface.CRYPTOGRAPHY, "v2", List.of());
        ImmutableTokenInstanceFullModel token = new ImmutableTokenInstanceFullModel(UUID.randomUUID(), null, "token",
                TokenInstanceStatus.ACTIVATED, "SOFT", connectorUuid, "connector", cryptography.uuid(), cryptography,
                Set.of());
        ImmutableTokenProfileFullModel profile = new ImmutableTokenProfileFullModel(UUID.randomUUID(), "profile", null,
                token.name(), token.uuid(), true, List.of(KeyUsage.SIGN), token, connectorUuid, Map.of(), Map.of(), 0);
        NameAndUuidDto requester = new NameAndUuidDto(UUID.randomUUID().toString(), "requester");
        return new KeyImportTerms(profile, KeyRequestType.KEY_PAIR, KeyAlgorithm.RSA, fingerprint, exportable,
                List.of(), requester);
    }

    static MetadataAttribute handle(String name, String value) {
        MetadataAttributeV2 attribute = new MetadataAttributeV2();
        attribute.setUuid(UUID.randomUUID().toString());
        attribute.setName(name);
        attribute.setType(AttributeType.META);
        attribute.setContentType(AttributeContentType.STRING);
        MetadataAttributeProperties properties = new MetadataAttributeProperties();
        properties.setLabel(name);
        properties.setVisible(true);
        attribute.setProperties(properties);
        attribute.setContent(List.of(new StringAttributeContentV2(value)));
        return attribute;
    }

    @Test
    void complete_registersANewKeyWithTheImportedItems() throws Exception {
        // given
        TokenProfileFullModel profile = persistedProfile();
        KeyPair pair = rsa();
        Group group = persistedGroup();
        KeyImportAttempt attempt = keyImportWriter.open(terms(profile, pair), "retry-new", "imported key", SENT);

        // when
        ImportedKey imported = keyImportWriter
                .complete(attempt.uuid(), registration(profile, pair, attempt, Set.of(group.getUuid())))
                .orElseThrow();

        // then
        assertThat(imported.outcome()).isEqualTo(ImportOutcome.CREATED);
        CryptographicKeyFullModel key = imported.key();
        assertThat(key.name()).isEqualTo("imported key");
        assertThat(key.description()).isEqualTo("imported for the test");
        assertThat(key.tokenProfileUuid()).isEqualTo(profile.uuid());
        assertThat(key.tokenInstanceReferenceUuid()).isEqualTo(profile.tokenInstanceReferenceUuid());
        CryptographicKeyItem publicKey = item(key.uuid(), KeyType.PUBLIC_KEY);
        CryptographicKeyItem privateKey = item(key.uuid(), KeyType.PRIVATE_KEY);
        assertThat(publicKey.getKeyData()).isEqualTo(Base64.getEncoder().encodeToString(pair.getPublic().getEncoded()));
        assertThat(publicKey.getFormat()).isEqualTo(KeyFormat.SPKI);
        assertThat(publicKey.getFingerprint()).isEqualTo(fingerprintOf(pair));
        assertThat(publicKey.getKeyMeta()).extracting(MetadataAttribute::getName).containsExactly("public-handle");
        assertThat(publicKey.getKeyReferenceUuid()).isNull();
        assertThat(publicKey.getUsage()).containsExactlyInAnyOrder(KeyUsage.VERIFY, KeyUsage.ENCRYPT);
        assertThat(privateKey.getKeyMeta()).extracting(MetadataAttribute::getName).containsExactly("private-handle");
        assertThat(privateKey.getKeyReferenceUuid()).isEqualTo(attempt.keyReference());
        assertThat(privateKey.getKeyData()).isNull();
        assertThat(privateKey.isExportable()).isTrue();
        assertThat(privateKey.getUsage()).containsExactlyInAnyOrder(KeyUsage.SIGN, KeyUsage.DECRYPT);
        assertThat(List.of(publicKey, privateKey)).allSatisfy(item -> {
            assertThat(item.getState()).isEqualTo(KeyState.ACTIVE);
            assertThat(item.isEnabled()).isFalse();
        });
        assertThat(importEvents(KeyEventStatus.SUCCESS))
                .containsExactlyInAnyOrder(publicKey.getUuid(), privateKey.getUuid());
        assertThat(objectAssociationService.getOwner(Resource.CRYPTOGRAPHIC_KEY, key.uuid()).getName())
                .isEqualTo("requester");
        assertThat(cryptographicKeyRepository.findWithGroupsByUuid(key.uuid()).orElseThrow().getGroups())
                .extracting(Group::getUuid)
                .containsExactly(group.getUuid());
        KeyImport completed = keyImportRepository.findById(attempt.uuid()).orElseThrow();
        assertThat(completed.getState()).isEqualTo(KeyImportState.COMPLETED);
        assertThat(completed.getKeyUuid()).isEqualTo(key.uuid());
    }

    /**
     * A secret key has no public key, so it is registered as a key of its own, whatever other keys hold items without a
     * fingerprint, and no certificate is linked to it.
     */
    @Test
    void complete_registersASecretKeyAsAKeyOfItsOwn() throws Exception {
        // given
        TokenProfileFullModel profile = persistedProfile();
        KeyPair pair = rsa();
        KeyImportAttempt keyPairImport = keyImportWriter
                .open(terms(profile, pair), "retry-key-pair", "imported key", SENT);
        UUID keyPairUuid = keyImportWriter
                .complete(keyPairImport.uuid(), registration(profile, pair, keyPairImport, Set.of()))
                .orElseThrow()
                .key()
                .uuid();
        UUID certificateUuid = persistedCertificateOf(null);
        KeyImportAttempt attempt = keyImportWriter
                .open(secretKeyTerms(profile), "retry-secret-key", "imported secret key", SENT);

        // when
        CryptographicKeyFullModel key = keyImportWriter
                .complete(attempt.uuid(), secretKeyRegistration(profile, attempt))
                .orElseThrow()
                .key();

        // then
        assertThat(key.uuid()).isNotEqualTo(keyPairUuid);
        assertThat(cryptographicKeyItemRepository.findByKeyUuidIn(List.of(key.uuid())))
                .singleElement()
                .satisfies(secretKey -> {
                    assertThat(secretKey.getType()).isEqualTo(KeyType.SECRET_KEY);
                    assertThat(secretKey.getFingerprint()).isNull();
                    assertThat(secretKey.getKeyReferenceUuid()).isEqualTo(attempt.keyReference());
                    assertThat(secretKey.getKeyMeta())
                            .extracting(MetadataAttribute::getName)
                            .containsExactly("secret-handle");
                });
        assertThat(cryptographicKeyItemRepository.findByKeyUuidIn(List.of(keyPairUuid))).hasSize(2);
        assertThat(certificateRepository.findById(certificateUuid).orElseThrow().getKeyUuid()).isNull();
        KeyImport completed = keyImportRepository.findById(attempt.uuid()).orElseThrow();
        assertThat(completed.getState()).isEqualTo(KeyImportState.COMPLETED);
        assertThat(completed.getSpkiFingerprint()).isNull();
    }

    @Test
    void complete_adoptsThePublicKeyACertificateBroughtIn() throws Exception {
        // given
        TokenProfileFullModel profile = persistedProfile();
        KeyPair pair = rsa();
        UUID recordUuid = certificatePublicKey(pair);
        UUID certificateUuid = persistedCertificateOf(recordUuid);
        UUID publicItemUuid = item(recordUuid, KeyType.PUBLIC_KEY).getUuid();
        KeyImportAttempt attempt = keyImportWriter.open(terms(profile, pair), "retry-adopt", "imported key", SENT);

        // when
        ImportedKey imported = keyImportWriter
                .complete(attempt.uuid(), registration(profile, pair, attempt, Set.of()).adopting(recordUuid))
                .orElseThrow();

        // then
        assertThat(imported.outcome()).isEqualTo(ImportOutcome.ADOPTED);
        CryptographicKeyFullModel key = imported.key();
        assertThat(key.uuid()).isEqualTo(recordUuid);
        assertThat(key.name()).isEqualTo("certKey_imported");
        assertThat(key.tokenProfileUuid()).isEqualTo(profile.uuid());
        CryptographicKeyItem publicKey = item(recordUuid, KeyType.PUBLIC_KEY);
        CryptographicKeyItem privateKey = item(recordUuid, KeyType.PRIVATE_KEY);
        assertThat(publicKey.getUuid()).isEqualTo(publicItemUuid);
        assertThat(publicKey.getKeyMeta()).extracting(MetadataAttribute::getName).containsExactly("public-handle");
        assertThat(publicKey.getUsage()).containsExactlyInAnyOrder(KeyUsage.VERIFY, KeyUsage.ENCRYPT);
        assertThat(publicKey.isEnabled()).isTrue();
        assertThat(privateKey.getKeyReferenceUuid()).isEqualTo(attempt.keyReference());
        assertThat(privateKey.isEnabled()).isFalse();
        assertThat(certificateRepository.findById(certificateUuid).orElseThrow().getKeyUuid()).isEqualTo(recordUuid);
        assertThat(importEvents(KeyEventStatus.SUCCESS))
                .containsExactlyInAnyOrder(publicKey.getUuid(), privateKey.getUuid());
        assertThat(objectAssociationService.getOwner(Resource.CRYPTOGRAPHIC_KEY, recordUuid)).isNull();
    }

    /**
     * An import changes nothing of a record that exists but its token and items: the record keeps whose it is, its
     * groups, its custom attributes, its name and its description, whatever the import states for a key of its own.
     */
    @Test
    void complete_adoptsARecordWithoutChangingItsOwnerGroupsAttributesNameOrDescription() throws Exception {
        // given
        TokenProfileFullModel profile = persistedProfile();
        KeyPair pair = rsa();
        UUID recordUuid = certificatePublicKey(pair);
        CryptographicKey described = cryptographicKeyRepository.findById(recordUuid).orElseThrow();
        described.setDescription("the certificate's key");
        cryptographicKeyRepository.saveAndFlush(described);
        UUID ownerUuid = UUID.randomUUID();
        objectAssociationService.setOwner(Resource.CRYPTOGRAPHIC_KEY, recordUuid, ownerUuid, "owner");
        Group recordGroup = persistedGroup();
        objectAssociationService.addGroup(Resource.CRYPTOGRAPHIC_KEY, recordUuid, recordGroup.getUuid());
        CustomAttributeCreateRequestDto definition = new CustomAttributeCreateRequestDto();
        definition.setName("department-" + UUID.randomUUID());
        definition.setLabel("Department");
        definition.setResources(List.of(Resource.CRYPTOGRAPHIC_KEY));
        definition.setContentType(AttributeContentType.STRING);
        UUID definitionUuid = UUID.fromString(attributeService.createCustomAttribute(definition).getUuid());
        attributeEngine
                .updateObjectCustomAttributesContent(Resource.CRYPTOGRAPHIC_KEY, recordUuid,
                        List.of(department(definitionUuid, definition.getName(), "Sales")));
        KeyImportAttempt attempt = keyImportWriter.open(terms(profile, pair), "retry-keep", "imported key", SENT);
        ImportedKeyRegistration registration = registration(profile, pair, attempt, Set.of(persistedGroup().getUuid()),
                List.of(department(definitionUuid, definition.getName(), "Engineering"))).adopting(recordUuid);

        // when
        ImportedKey imported = keyImportWriter.complete(attempt.uuid(), registration).orElseThrow();

        // then
        assertThat(imported.outcome()).isEqualTo(ImportOutcome.ADOPTED);
        CryptographicKey adopted = cryptographicKeyRepository.findWithGroupsByUuid(recordUuid).orElseThrow();
        assertThat(adopted.getName()).isEqualTo("certKey_imported");
        assertThat(adopted.getDescription()).isEqualTo("the certificate's key");
        assertThat(adopted.getTokenProfileUuid()).isEqualTo(profile.uuid());
        assertThat(adopted.getGroups()).extracting(Group::getUuid).containsExactly(recordGroup.getUuid());
        NameAndUuidDto owner = objectAssociationService.getOwner(Resource.CRYPTOGRAPHIC_KEY, recordUuid);
        assertThat(owner.getUuid()).isEqualTo(ownerUuid.toString());
        assertThat(attributeEngine.getObjectCustomAttributesContent(Resource.CRYPTOGRAPHIC_KEY, recordUuid))
                .singleElement()
                .satisfies(attribute -> assertThat(((ResponseAttributeV3) attribute).getContent())
                        .extracting(content -> content.getData().toString())
                        .containsExactly("Sales"));
        assertThat(cryptographicKeyItemRepository.findByKeyUuidIn(List.of(recordUuid))).hasSize(2);
    }

    /**
     * The requester's right to update the record was checked before the registration; a record that came to hold the
     * public key since was not checked, so the registration takes nothing and leaves the attempt open.
     */
    @Test
    void complete_refusesARecordItWasNotToldItMayAdopt() throws Exception {
        // given
        TokenProfileFullModel profile = persistedProfile();
        KeyPair pair = rsa();
        KeyImportAttempt attempt = keyImportWriter.open(terms(profile, pair), "retry-late", "imported key", SENT);
        UUID recordUuid = certificatePublicKey(pair);
        ImportedKeyRegistration registration = registration(profile, pair, attempt, Set.of());
        UUID attemptUuid = attempt.uuid();

        // when
        // then
        assertThatThrownBy(() -> keyImportWriter.complete(attemptUuid, registration))
                .isInstanceOf(CryptographicKeyWriter.UncheckedRecordException.class);
        assertThat(cryptographicKeyItemRepository.findByKeyUuidIn(List.of(recordUuid))).hasSize(1);
        assertThat(cryptographicKeyRepository.findById(recordUuid).orElseThrow().getTokenProfileUuid()).isNull();
        assertThat(keyImportRepository.findById(attemptUuid).orElseThrow().getState())
                .isEqualTo(KeyImportState.REQUESTED);
    }

    @Test
    void complete_refusesAKeyThePlatformHoldsOtherwise() throws Exception {
        // given
        TokenProfileFullModel profile = persistedProfile();
        KeyPair pair = rsa();
        UUID recordUuid = certificatePublicKey(pair);
        CryptographicKey holder = cryptographicKeyRepository.findById(recordUuid).orElseThrow();
        holder.setTokenProfileUuid(profile.uuid());
        holder.setTokenInstanceReferenceUuid(profile.tokenInstanceReferenceUuid());
        cryptographicKeyRepository.saveAndFlush(holder);
        KeyImportAttempt attempt = keyImportWriter.open(terms(profile, pair), "retry-held", "imported key", SENT);
        ImportedKeyRegistration registration = registration(profile, pair, attempt, Set.of());
        UUID attemptUuid = attempt.uuid();

        // when
        // then
        assertThatThrownBy(() -> keyImportWriter.complete(attemptUuid, registration))
                .isInstanceOf(ValidationException.class)
                .hasMessageContaining(CryptographicKeyWriter.KEY_ALREADY_HELD);
        assertThat(cryptographicKeyItemRepository.findByKeyUuidIn(List.of(recordUuid))).hasSize(1);
        assertThat(keyImportRepository.findById(attempt.uuid()).orElseThrow().getState())
                .isEqualTo(KeyImportState.REQUESTED);
    }

    /**
     * The name was checked before the connector was asked, a connector round trip ago; a key registered under it since
     * refuses the new key, and the attempt stays open for the reconciliation to undo the key.
     */
    @Test
    void complete_refusesANameTakenSinceTheCheck() throws Exception {
        // given
        TokenProfileFullModel profile = persistedProfile();
        KeyPair pair = rsa();
        KeyImportAttempt attempt = keyImportWriter.open(terms(profile, pair), "retry-name-since", "imported key", SENT);
        KeyPair other = rsa();
        KeyImportAttempt named = keyImportWriter.open(terms(profile, other), "retry-name-first", "imported key", SENT);
        UUID keyUuid = keyImportWriter
                .complete(named.uuid(), registration(profile, other, named, Set.of()))
                .orElseThrow()
                .key()
                .uuid();
        ImportedKeyRegistration registration = registration(profile, pair, attempt, Set.of());
        UUID attemptUuid = attempt.uuid();

        // when
        // then
        assertThatThrownBy(() -> keyImportWriter.complete(attemptUuid, registration))
                .isInstanceOf(ValidationException.class)
                .hasMessageContaining(CryptographicKeyWriter.NAME_TAKEN.formatted("imported key"));
        assertThat(keyImportRepository.findById(attemptUuid).orElseThrow().getState())
                .isEqualTo(KeyImportState.REQUESTED);
        assertThat(cryptographicKeyRepository.findAll()).extracting(CryptographicKey::getUuid).containsExactly(keyUuid);
    }

    /** A retry racing the original request both learn the import completed; the key is registered once. */
    @Test
    void complete_answersWithTheKeyAConcurrentRequestRegistered() throws Exception {
        // given
        TokenProfileFullModel profile = persistedProfile();
        KeyPair pair = rsa();
        KeyImportAttempt attempt = keyImportWriter.open(terms(profile, pair), "retry-twice", "imported key", SENT);
        ImportedKeyRegistration registration = registration(profile, pair, attempt, Set.of());
        UUID first = keyImportWriter.complete(attempt.uuid(), registration).orElseThrow().key().uuid();

        // when
        ImportedKey second = keyImportWriter.complete(attempt.uuid(), registration).orElseThrow();

        // then
        assertThat(second.key().uuid()).isEqualTo(first);
        assertThat(second.outcome()).isEqualTo(ImportOutcome.EXISTING);
        assertThat(cryptographicKeyItemRepository.findByKeyUuidIn(List.of(first))).hasSize(2);
        assertThat(cryptographicKeyRepository.count()).isEqualTo(1);
    }

    @Test
    void complete_registersNothingForAnAttemptThatImportedNothing() throws Exception {
        // given
        TokenProfileFullModel profile = persistedProfile();
        KeyPair pair = rsa();
        KeyImportAttempt attempt = keyImportWriter.open(terms(profile, pair), "retry-failed", "imported key", SENT);
        keyImportWriter.failUntaken(attempt, "The connector could not import the key.");

        // when
        Optional<ImportedKey> key = keyImportWriter
                .complete(attempt.uuid(), registration(profile, pair, attempt, Set.of()));

        // then
        assertThat(key).isEmpty();
        assertThat(cryptographicKeyRepository.count()).isZero();
    }

    /** A group removed after the request was checked rolls the whole registration back; the attempt stays open. */
    @Test
    void complete_registersNothingWhenAGroupIsGone() throws Exception {
        // given
        TokenProfileFullModel profile = persistedProfile();
        KeyPair pair = rsa();
        KeyImportAttempt attempt = keyImportWriter.open(terms(profile, pair), "retry-group", "imported key", SENT);
        ImportedKeyRegistration registration = registration(profile, pair, attempt, Set.of(UUID.randomUUID()));
        UUID attemptUuid = attempt.uuid();

        // when
        // then
        assertThatThrownBy(() -> keyImportWriter.complete(attemptUuid, registration))
                .isInstanceOf(NotFoundException.class);
        assertThat(cryptographicKeyRepository.count()).isZero();
        assertThat(keyImportRepository.findById(attempt.uuid()).orElseThrow().getState())
                .isEqualTo(KeyImportState.REQUESTED);
    }

    /**
     * An operator's compromise that holds the record's public key while the adoption runs is waited for, and the
     * adoption refuses the compromised record instead of writing over the compromise.
     */
    @Test
    void complete_waitsForACompromiseOfTheRecordAndRefusesIt() throws Exception {
        // given
        TokenProfileFullModel profile = persistedProfile();
        KeyPair pair = rsa();
        UUID recordUuid = certificatePublicKey(pair);
        UUID publicKeyUuid = item(recordUuid, KeyType.PUBLIC_KEY).getUuid();
        KeyImportAttempt attempt = keyImportWriter
                .open(terms(profile, pair), "retry-while-compromised", "imported key", SENT);
        ImportedKeyRegistration registration = registration(profile, pair, attempt, Set.of());
        TransactionTemplate transaction = new TransactionTemplate(transactionManager);
        try (ExecutorService importer = Executors.newSingleThreadExecutor()) {
            // when
            Future<Optional<ImportedKey>> outcome = transaction.execute(status -> {
                jdbcTemplate
                        .update("UPDATE cryptographic_key_item SET state = 'COMPROMISED' WHERE uuid = ?",
                                publicKeyUuid);
                int lockHolderPid = jdbcTemplate.queryForObject("SELECT pg_backend_pid()", Integer.class);
                Future<Optional<ImportedKey>> adoption = importer
                        .submit(() -> keyImportWriter.complete(attempt.uuid(), registration));
                Awaitility
                        .await()
                        .atMost(Duration.ofSeconds(10))
                        .until(() -> jdbcTemplate
                                .queryForObject(
                                        "SELECT count(*) FROM pg_stat_activity WHERE ? = ANY(pg_blocking_pids(pid))",
                                        Long.class, lockHolderPid) > 0);
                return adoption;
            });

            // then
            assertThatThrownBy(() -> outcome.get(10, TimeUnit.SECONDS))
                    .isInstanceOf(ExecutionException.class)
                    .cause()
                    .isInstanceOf(ValidationException.class)
                    .hasMessageContaining(CryptographicKeyWriter.KEY_NOT_ACTIVE);
            assertThat(item(recordUuid, KeyType.PUBLIC_KEY).getState()).isEqualTo(KeyState.COMPROMISED);
        }
    }

    /** Custom attributes are stored with the key, so a registration that cannot store them registers nothing. */
    @Test
    void complete_registersNothingWhenTheCustomAttributesCannotBeStored() throws Exception {
        // given
        TokenProfileFullModel profile = persistedProfile();
        KeyPair pair = rsa();
        KeyImportAttempt attempt = keyImportWriter.open(terms(profile, pair), "retry-attributes", "imported key", SENT);
        RequestAttributeV3 undefined = new RequestAttributeV3();
        undefined.setUuid(UUID.randomUUID());
        undefined.setName("undefined-" + UUID.randomUUID());
        undefined.setContentType(AttributeContentType.STRING);
        undefined.setContent(List.of(new StringAttributeContentV3("value")));
        ImportedKeyRegistration registration = registration(profile, pair, attempt, Set.of(), List.of(undefined));

        // when
        // then
        assertThatThrownBy(() -> keyImportWriter.complete(attempt.uuid(), registration)).isInstanceOf(Exception.class);
        assertThat(keyImportRepository.findById(attempt.uuid()).orElseThrow().getState())
                .isEqualTo(KeyImportState.REQUESTED);
        assertThat(cryptographicKeyItemRepository.findByFingerprint(fingerprintOf(pair))).isEmpty();
    }

    /** A public key an operator marked compromised is not taken over by an import, even one that got this far. */
    @Test
    void complete_refusesToAdoptARecordThatIsNoLongerActive() throws Exception {
        // given
        TokenProfileFullModel profile = persistedProfile();
        KeyPair pair = rsa();
        UUID recordUuid = certificatePublicKey(pair);
        CryptographicKeyItem publicKey = item(recordUuid, KeyType.PUBLIC_KEY);
        publicKey.setState(KeyState.COMPROMISED);
        cryptographicKeyItemRepository.saveAndFlush(publicKey);
        KeyImportAttempt attempt = keyImportWriter
                .open(terms(profile, pair), "retry-compromised", "imported key", SENT);
        ImportedKeyRegistration registration = registration(profile, pair, attempt, Set.of());
        UUID attemptUuid = attempt.uuid();

        // when
        // then
        assertThatThrownBy(() -> keyImportWriter.complete(attemptUuid, registration))
                .isInstanceOf(ValidationException.class)
                .hasMessageContaining(CryptographicKeyWriter.KEY_NOT_ACTIVE);
        assertThat(cryptographicKeyItemRepository.findByKeyUuidIn(List.of(recordUuid))).hasSize(1);
        assertThat(keyImportRepository.findById(attempt.uuid()).orElseThrow().getState())
                .isEqualTo(KeyImportState.REQUESTED);
    }

    /**
     * A deletion works from the items it read; an import that adopted the key meanwhile added one it never saw, so the
     * deletion stops rather than take the imported private key with it.
     */
    @Test
    void deletion_keepsAKeyAnImportAdoptedMeanwhile() throws Exception {
        // given
        TokenProfileFullModel profile = persistedProfile();
        KeyPair pair = rsa();
        UUID recordUuid = certificatePublicKey(pair);
        CryptographicKeyBasicModel readByTheDeletion = cryptographicKeyRepository
                .findBasicModelByUuid(recordUuid)
                .orElseThrow();
        UUID publicKeyUuid = item(recordUuid, KeyType.PUBLIC_KEY).getUuid();
        KeyImportAttempt attempt = keyImportWriter.open(terms(profile, pair), "retry-deleted", "imported key", SENT);
        keyImportWriter.complete(attempt.uuid(), registration(profile, pair, attempt, Set.of()).adopting(recordUuid));
        Set<UUID> itemsRead = Set.of(publicKeyUuid);

        // when
        // then
        assertThatThrownBy(() -> cryptographicKeyWriter.deleteKeyWithAssociations(readByTheDeletion, itemsRead))
                .isInstanceOf(ValidationException.class);
        assertThat(cryptographicKeyRepository.findById(recordUuid)).isPresent();
        assertThat(item(recordUuid, KeyType.PRIVATE_KEY).getKeyReferenceUuid()).isEqualTo(attempt.keyReference());
    }

    /**
     * A request checks the record before and after its attempt opens, and again before it registers the key; each check
     * sees what changed since the one before.
     */
    @Test
    void publicKeyReads_readTheRecordAfresh() throws Exception {
        // given
        KeyPair pair = rsa();
        UUID recordUuid = certificatePublicKey(pair);
        UUID publicKeyUuid = item(recordUuid, KeyType.PUBLIC_KEY).getUuid();
        String fingerprint = fingerprintOf(pair);

        // when
        // then
        withARequestBoundEntityManager(CryptographicKey.class, recordUuid, () -> {
            assertThat(cryptographicKeyWriter.publicKeyHolder(fingerprint))
                    .hasValueSatisfying(holder -> assertThat(holder.publicKeyItemUuid()).isEqualTo(publicKeyUuid));
            assertThat(cryptographicKeyWriter.adoptableRecord(fingerprint)).contains(recordUuid);
            behindTheCaller("UPDATE cryptographic_key_item SET state = 'COMPROMISED' WHERE uuid = :uuid",
                    Map.of("uuid", publicKeyUuid));
            assertThatThrownBy(() -> cryptographicKeyWriter.publicKeyHolder(fingerprint))
                    .isInstanceOf(ValidationException.class)
                    .hasMessageContaining(CryptographicKeyWriter.KEY_NOT_ACTIVE);
            assertThat(cryptographicKeyWriter.adoptableRecord(fingerprint)).isEmpty();
        });
    }

    /**
     * The record a registration may adopt is an active public-key-only record. A key of its own, a record no longer
     * active and a public key a token holds without its private key are left to the registration, which refuses them
     * under its lock.
     */
    @Test
    void adoptableRecord_answersOnlyAnActiveRecord() throws Exception {
        // given
        KeyPair adoptable = rsa();
        UUID recordUuid = certificatePublicKey(adoptable);
        KeyPair adopted = rsa();
        UUID adoptedUuid = certificatePublicKey(adopted);
        adopt(adopted, "retry-adopted");
        CryptographicKey ownKey = cryptographicKeyRepository.findById(adoptedUuid).orElseThrow();
        KeyPair compromised = rsa();
        CryptographicKeyItem compromisedKey = item(certificatePublicKey(compromised), KeyType.PUBLIC_KEY);
        compromisedKey.setState(KeyState.COMPROMISED);
        cryptographicKeyItemRepository.saveAndFlush(compromisedKey);
        KeyPair tokenHeld = rsa();
        CryptographicKey inAToken = cryptographicKeyRepository.findById(certificatePublicKey(tokenHeld)).orElseThrow();
        inAToken.setTokenProfileUuid(ownKey.getTokenProfileUuid());
        inAToken.setTokenInstanceReferenceUuid(ownKey.getTokenInstanceReferenceUuid());
        cryptographicKeyRepository.saveAndFlush(inAToken);

        // when
        // then
        assertThat(cryptographicKeyWriter.adoptableRecord(fingerprintOf(adoptable))).contains(recordUuid);
        assertThat(cryptographicKeyWriter.adoptableRecord(fingerprintOf(adopted))).isEmpty();
        assertThat(cryptographicKeyWriter.adoptableRecord(fingerprintOf(compromised))).isEmpty();
        assertThat(cryptographicKeyWriter.adoptableRecord(fingerprintOf(tokenHeld))).isEmpty();
        assertThat(cryptographicKeyWriter.adoptableRecord(fingerprintOf(rsa()))).isEmpty();
    }

    /** A certificate's public key is a record an import may adopt; once adopted, it is a key of its own. */
    @Test
    void publicKeyHolder_tellsARecordFromAKeyOfItsOwn() throws Exception {
        // given
        KeyPair pair = rsa();
        UUID recordUuid = certificatePublicKey(pair);
        String fingerprint = fingerprintOf(pair);
        PublicKeyHolder adoptable = cryptographicKeyWriter.publicKeyHolder(fingerprint).orElseThrow();

        // when
        adopt(pair, "retry-holder");
        PublicKeyHolder key = cryptographicKeyWriter.publicKeyHolder(fingerprint).orElseThrow();

        // then
        assertThat(adoptable.holding()).isEqualTo(Holding.PUBLIC_KEY_ONLY);
        assertThat(adoptable.key().uuid()).isEqualTo(recordUuid);
        assertThat(key.holding()).isEqualTo(Holding.KEY_PAIR);
        assertThat(key.key().uuid()).isEqualTo(recordUuid);
        assertThat(key.key().items()).hasSize(2);
        assertThat(cryptographicKeyWriter.publicKeyHolder(fingerprintOf(rsa()))).isEmpty();
    }

    /** A key whose private key is deactivated is held but not active, as a record no longer active is. */
    @Test
    void publicKeyHolder_refusesAKeyNoLongerActive() throws Exception {
        // given
        KeyPair pair = rsa();
        UUID keyUuid = certificatePublicKey(pair);
        adopt(pair, "retry-deactivated");
        CryptographicKeyItem privateKey = item(keyUuid, KeyType.PRIVATE_KEY);
        privateKey.setState(KeyState.DEACTIVATED);
        cryptographicKeyItemRepository.saveAndFlush(privateKey);
        String fingerprint = fingerprintOf(pair);

        // when
        // then
        assertThatThrownBy(() -> cryptographicKeyWriter.publicKeyHolder(fingerprint))
                .isInstanceOf(ValidationException.class)
                .hasMessageContaining(CryptographicKeyWriter.KEY_NOT_ACTIVE);
    }

    /** A token holds the public key but the platform not its private key, so the key is neither a record nor held. */
    @Test
    void publicKeyHolder_tellsAPublicKeyATokenHoldsWithoutItsPrivateKey() throws Exception {
        // given
        TokenProfileFullModel profile = persistedProfile();
        KeyPair pair = rsa();
        UUID holderUuid = certificatePublicKey(pair);
        CryptographicKey holder = cryptographicKeyRepository.findById(holderUuid).orElseThrow();
        holder.setTokenProfileUuid(profile.uuid());
        holder.setTokenInstanceReferenceUuid(profile.tokenInstanceReferenceUuid());
        cryptographicKeyRepository.saveAndFlush(holder);

        // when
        Optional<PublicKeyHolder> held = cryptographicKeyWriter.publicKeyHolder(fingerprintOf(pair));

        // then
        assertThat(held).hasValueSatisfying(inAToken -> {
            assertThat(inAToken.holding()).isEqualTo(Holding.PUBLIC_KEY_IN_TOKEN);
            assertThat(inAToken.key().uuid()).isEqualTo(holderUuid);
        });
    }

    /**
     * A deletion decides from what it read whether a token destroys an item first, so an item of a key an import
     * adopted since is refused rather than removed from the inventory alone.
     */
    @Test
    void anItemDeletionThatReadTheKeyBeforeAnAdoptionIsRefused() throws Exception {
        // given
        KeyPair pair = rsa();
        UUID recordUuid = certificatePublicKey(pair);
        UUID publicKeyUuid = item(recordUuid, KeyType.PUBLIC_KEY).getUuid();
        CryptographicKeyBasicModel readByTheDeletion = cryptographicKeyRepository
                .findBasicModelByUuid(recordUuid)
                .orElseThrow();
        adopt(pair, "retry-item-deletion");

        // when
        // then
        assertThatThrownBy(() -> cryptographicKeyWriter.deleteKeyItem(readByTheDeletion, publicKeyUuid))
                .isInstanceOf(ValidationException.class);
        assertThat(cryptographicKeyItemRepository.findById(publicKeyUuid)).isPresent();
    }

    @Test
    void aBulkItemDeletionThatReadTheKeyBeforeAnAdoptionIsRefused() throws Exception {
        // given
        KeyPair pair = rsa();
        UUID recordUuid = certificatePublicKey(pair);
        List<UUID> publicKey = List.of(item(recordUuid, KeyType.PUBLIC_KEY).getUuid());
        List<CryptographicKeyBasicModel> readByTheDeletion = List
                .of(cryptographicKeyRepository.findBasicModelByUuid(recordUuid).orElseThrow());
        adopt(pair, "retry-bulk-deletion");

        // when
        // then
        assertThatThrownBy(() -> cryptographicKeyWriter.deleteKeyItemsWithAssociations(publicKey, readByTheDeletion))
                .isInstanceOf(ValidationException.class);
        assertThat(cryptographicKeyItemRepository.findByUuidIn(publicKey)).hasSize(1);
    }

    /** A destruction without a token is local only, so it is refused for a key an import adopted since it looked. */
    @Test
    void aLocalDestructionThatReadTheKeyBeforeAnAdoptionIsRefused() throws Exception {
        // given
        KeyPair pair = rsa();
        UUID recordUuid = certificatePublicKey(pair);
        UUID publicKeyUuid = item(recordUuid, KeyType.PUBLIC_KEY).getUuid();
        CryptographicKeyBasicModel readByTheDestruction = cryptographicKeyRepository
                .findBasicModelByUuid(recordUuid)
                .orElseThrow();
        adopt(pair, "retry-destruction");

        // when
        // then
        assertThatThrownBy(() -> cryptographicKeyWriter.finalizeKeyItemDestruction(readByTheDestruction, publicKeyUuid))
                .isInstanceOf(ValidationException.class);
        assertThat(item(recordUuid, KeyType.PUBLIC_KEY).getState()).isNotEqualTo(KeyState.DESTROYED);
    }

    /**
     * A compliance check stores its result on the item it read before its connector calls; the handle an import gave
     * the item meanwhile survives the result.
     */
    @Test
    void aComplianceResultOnACopyReadBeforeAnAdoptionKeepsTheAdoptedHandle() throws Exception {
        // given
        KeyPair pair = rsa();
        UUID recordUuid = certificatePublicKey(pair);
        CryptographicKeyItem readByTheCheck = item(recordUuid, KeyType.PUBLIC_KEY);
        ComplianceSubjectHandler<CryptographicKeyItem> handler = new ComplianceSubjectHandler<>(false,
                Resource.CRYPTOGRAPHIC_KEY_ITEM, null, cryptographicKeyItemRepository, complianceSubjectWriter,
                entityManager);
        handler.initSubjectComplianceResult(readByTheCheck);
        adopt(pair, "retry-compliance");
        LocalDateTime beforeTheResult = LocalDateTime.of(2020, Month.JANUARY, 1, 0, 0);
        jdbcTemplate
                .update("UPDATE cryptographic_key_item SET updated_at = ? WHERE uuid = ?", beforeTheResult,
                        readByTheCheck.getUuid());

        // when
        ComplianceStatus status = handler.finalizeComplianceCheck(readByTheCheck.getUuid(), null);

        // then
        CryptographicKeyItem checked = item(recordUuid, KeyType.PUBLIC_KEY);
        assertThat(checked.getComplianceStatus()).isEqualTo(status);
        assertThat(checked.getUpdatedAt()).isAfter(beforeTheResult);
        assertThat(checked.getKeyMeta()).extracting(MetadataAttribute::getName).containsExactly("public-handle");
    }

    /**
     * A compromise whose request read the public key before an import adopted it writes only what it changed, so the
     * handle the adoption gave the item survives.
     */
    @Test
    void aCompromiseThatReadTheItemBeforeAnAdoptionKeepsTheAdoptedHandle() throws Exception {
        // given
        TokenProfileFullModel profile = persistedProfile();
        KeyPair pair = rsa();
        UUID recordUuid = certificatePublicKey(pair);
        UUID publicKeyUuid = item(recordUuid, KeyType.PUBLIC_KEY).getUuid();
        KeyImportAttempt attempt = keyImportWriter.open(terms(profile, pair), "retry-stale-item", "imported key", SENT);
        ImportedKeyRegistration registration = registration(profile, pair, attempt, Set.of()).adopting(recordUuid);

        // when
        withARequestBoundEntityManager(CryptographicKey.class, recordUuid, () -> {
            entityManager.find(CryptographicKeyItem.class, publicKeyUuid);
            try (ExecutorService elsewhere = Executors.newSingleThreadExecutor()) {
                elsewhere
                        .submit(() -> keyImportWriter.complete(attempt.uuid(), registration))
                        .get(10, TimeUnit.SECONDS);
            }
            cryptographicKeyWriter.setKeyItemCompromised(publicKeyUuid, KeyCompromiseReason.UNAUTHORIZED_DISCLOSURE);
        });

        // then
        CryptographicKeyItem compromised = item(recordUuid, KeyType.PUBLIC_KEY);
        assertThat(compromised.getState()).isEqualTo(KeyState.COMPROMISED);
        assertThat(compromised.getKeyMeta()).extracting(MetadataAttribute::getName).containsExactly("public-handle");
    }

    /**
     * An edit whose request read the key before an import adopted it writes only what it changed, so the token the
     * adoption gave the key survives the edit.
     */
    @Test
    void anEditThatReadTheKeyBeforeAnAdoptionKeepsTheAdoptedToken() throws Exception {
        // given
        TokenProfileFullModel profile = persistedProfile();
        UUID recordUuid = certificatePublicKey(rsa());
        EditKeyRequestDto rename = new EditKeyRequestDto();
        rename.setName("renamed key");

        // when
        withARequestBoundEntityManager(CryptographicKey.class, recordUuid, () -> {
            behindTheCaller(
                    "UPDATE cryptographic_key SET token_profile_uuid = :profile, token_instance_uuid = :token"
                            + " WHERE uuid = :uuid",
                    Map
                            .of("profile", profile.uuid(), "token", profile.tokenInstanceReferenceUuid(), "uuid",
                                    recordUuid));
            cryptographicKeyWriter.update(recordUuid, rename, null, SecurityResourceFilter.create());
        });

        // then
        CryptographicKey edited = cryptographicKeyRepository.findById(recordUuid).orElseThrow();
        assertThat(edited.getName()).isEqualTo("renamed key");
        assertThat(edited.getTokenProfileUuid()).isEqualTo(profile.uuid());
        assertThat(edited.getTokenInstanceReferenceUuid()).isEqualTo(profile.tokenInstanceReferenceUuid());
    }

    /** The reconciliation took the attempt, so a retry that reaches registration afterwards registers nothing. */
    @Test
    void complete_leavesAnAttemptTheReconciliationCompensates() throws Exception {
        // given
        TokenProfileFullModel profile = persistedProfile();
        KeyPair pair = rsa();
        KeyImportAttempt attempt = keyImportWriter
                .open(terms(profile, pair), "retry-compensated", "imported key", SENT);
        keyImportWriter.compensating(attempt);

        // when
        Optional<ImportedKey> key = keyImportWriter
                .complete(attempt.uuid(), registration(profile, pair, attempt, Set.of()));

        // then
        assertThat(key).isEmpty();
        assertThat(cryptographicKeyItemRepository.findByFingerprint(fingerprintOf(pair))).isEmpty();
        assertThat(keyImportRepository.findById(attempt.uuid()).orElseThrow().getState())
                .isEqualTo(KeyImportState.COMPENSATING);
    }

    @Test
    void quarantine_registersTheKeyDeactivatedAndDisabled() throws Exception {
        // given
        TokenProfileFullModel profile = persistedProfile();
        KeyPair pair = rsa();
        KeyImportAttempt attempt = keyImportWriter.open(terms(profile, pair), "retry-quarantine", "imported key", SENT);
        keyImportWriter.compensating(attempt);

        // when
        Optional<UUID> keyUuid = keyImportWriter
                .quarantine(attempt.uuid(), quarantineRegistration(profile, pair, attempt));

        // then
        KeyImport settled = keyImportRepository.findById(attempt.uuid()).orElseThrow();
        assertThat(settled.getState()).isEqualTo(KeyImportState.QUARANTINED);
        assertThat(settled.getKeyUuid()).isEqualTo(keyUuid.orElseThrow());
        List<CryptographicKeyItem> items = cryptographicKeyItemRepository.findByKeyUuidIn(List.of(keyUuid.get()));
        assertThat(items).hasSize(2).allSatisfy(item -> {
            assertThat(item.getState()).isEqualTo(KeyState.DEACTIVATED);
            assertThat(item.isEnabled()).isFalse();
        });
        assertThat(importEvents(KeyEventStatus.FAILED))
                .containsExactlyInAnyOrderElementsOf(items.stream().map(CryptographicKeyItem::getUuid).toList());
        assertThat(importEvents(KeyEventStatus.SUCCESS)).isEmpty();
    }

    @Test
    void quarantine_keepsTheStateOfAnAdoptedCertificateKey() throws Exception {
        // given
        TokenProfileFullModel profile = persistedProfile();
        KeyPair pair = rsa();
        UUID recordUuid = certificatePublicKey(pair);
        KeyImportAttempt attempt = keyImportWriter
                .open(terms(profile, pair), "retry-quarantine-adopt", "imported key", SENT);
        keyImportWriter.compensating(attempt);

        // when
        keyImportWriter.quarantine(attempt.uuid(), quarantineRegistration(profile, pair, attempt).adopting(recordUuid));

        // then
        CryptographicKeyItem publicKey = item(recordUuid, KeyType.PUBLIC_KEY);
        CryptographicKeyItem privateKey = item(recordUuid, KeyType.PRIVATE_KEY);
        assertThat(publicKey.getState()).isEqualTo(KeyState.ACTIVE);
        assertThat(publicKey.isEnabled()).isTrue();
        assertThat(privateKey.getState()).isEqualTo(KeyState.DEACTIVATED);
        assertThat(privateKey.isEnabled()).isFalse();
        assertThat(cryptographicKeyRepository.findById(recordUuid).orElseThrow().getName())
                .isEqualTo("certKey_imported");
        assertThat(objectAssociationService.getOwner(Resource.CRYPTOGRAPHIC_KEY, recordUuid)).isNull();
    }

    /** The record keeps its name, so the name the attempt keeps need not be free for the record to be adopted. */
    @Test
    void quarantine_adoptsARecordThoughAnotherKeyHasTheAttemptsName() throws Exception {
        // given
        TokenProfileFullModel profile = persistedProfile();
        KeyPair pair = rsa();
        UUID recordUuid = certificatePublicKey(pair);
        KeyImportAttempt attempt = keyImportWriter
                .open(terms(profile, pair), "retry-quarantine-named", "imported key", SENT);
        keyImportWriter.compensating(attempt);
        KeyPair other = rsa();
        KeyImportAttempt named = keyImportWriter
                .open(terms(profile, other), "retry-quarantine-name", "imported key", SENT);
        keyImportWriter.complete(named.uuid(), registration(profile, other, named, Set.of()));

        // when
        Optional<UUID> keyUuid = keyImportWriter
                .quarantine(attempt.uuid(), quarantineRegistration(profile, pair, attempt).adopting(recordUuid));

        // then
        assertThat(keyUuid).contains(recordUuid);
        assertThat(keyImportRepository.findById(attempt.uuid()).orElseThrow().getState())
                .isEqualTo(KeyImportState.QUARANTINED);
    }

    /** The adopted public key changed with the quarantine, so a copy cached before it is dropped. */
    @Test
    void quarantine_evictsTheAdoptedPublicKeyFromTheCache() throws Exception {
        // given
        TokenProfileFullModel profile = persistedProfile();
        KeyPair pair = rsa();
        UUID recordUuid = certificatePublicKey(pair);
        UUID publicKeyUuid = item(recordUuid, KeyType.PUBLIC_KEY).getUuid();
        Cache cache = cacheManager.getCache(CacheConfig.CRYPTOGRAPHIC_KEY_ITEM_CACHE);
        cache.put(publicKeyUuid, "cached before the quarantine");
        KeyImportAttempt attempt = keyImportWriter
                .open(terms(profile, pair), "retry-quarantine-cache", "imported key", SENT);
        keyImportWriter.compensating(attempt);

        // when
        keyImportWriter.quarantine(attempt.uuid(), quarantineRegistration(profile, pair, attempt).adopting(recordUuid));

        // then
        assertThat(cache.get(publicKeyUuid)).isNull();
    }

    /** The attempt keeps no custom attributes, so a quarantine writes none, whatever keys must carry otherwise. */
    @Test
    void quarantine_registersTheKeyWhereKeysRequireACustomAttribute() throws Exception {
        // given
        CustomAttributeCreateRequestDto required = new CustomAttributeCreateRequestDto();
        required.setName("required-" + UUID.randomUUID());
        required.setLabel("Required");
        required.setResources(List.of(Resource.CRYPTOGRAPHIC_KEY));
        required.setContentType(AttributeContentType.STRING);
        required.setRequired(true);
        attributeService.createCustomAttribute(required);
        TokenProfileFullModel profile = persistedProfile();
        KeyPair pair = rsa();
        KeyImportAttempt attempt = keyImportWriter
                .open(terms(profile, pair), "retry-quarantine-required", "imported key", SENT);
        keyImportWriter.compensating(attempt);

        // when
        Optional<UUID> keyUuid = keyImportWriter
                .quarantine(attempt.uuid(), quarantineRegistration(profile, pair, attempt));

        // then
        assertThat(keyUuid).isPresent();
        assertThat(keyImportRepository.findById(attempt.uuid()).orElseThrow().getState())
                .isEqualTo(KeyImportState.QUARANTINED);
    }

    /** A second look that also found the key undestroyable leaves the key the first one registered. */
    @Test
    void quarantine_registersTheKeyOnce() throws Exception {
        // given
        TokenProfileFullModel profile = persistedProfile();
        KeyPair pair = rsa();
        KeyImportAttempt attempt = keyImportWriter
                .open(terms(profile, pair), "retry-quarantine-once", "imported key", SENT);
        keyImportWriter.compensating(attempt);
        UUID keyUuid = keyImportWriter
                .quarantine(attempt.uuid(), quarantineRegistration(profile, pair, attempt))
                .orElseThrow();

        // when
        Optional<UUID> again = keyImportWriter
                .quarantine(attempt.uuid(), quarantineRegistration(profile, pair, attempt));

        // then
        assertThat(again).isEmpty();
        assertThat(cryptographicKeyRepository.findAll()).extracting(CryptographicKey::getUuid).containsExactly(keyUuid);
    }

    /** The platform holds the key in a token already, so the key the connector would not destroy is not registered. */
    @Test
    void quarantine_refusesAKeyThePlatformHoldsOtherwise() throws Exception {
        // given
        TokenProfileFullModel profile = persistedProfile();
        KeyPair pair = rsa();
        UUID holderUuid = certificatePublicKey(pair);
        CryptographicKey holder = cryptographicKeyRepository.findById(holderUuid).orElseThrow();
        holder.setTokenProfileUuid(profile.uuid());
        holder.setTokenInstanceReferenceUuid(profile.tokenInstanceReferenceUuid());
        cryptographicKeyRepository.saveAndFlush(holder);
        KeyImportAttempt taken = keyImportWriter.open(terms(profile, pair), "retry-taken", "imported key", SENT);
        keyImportWriter.compensating(taken);
        ImportedKeyRegistration registration = quarantineRegistration(profile, pair, taken);
        UUID takenUuid = taken.uuid();

        // when
        // then
        assertThatThrownBy(() -> keyImportWriter.quarantine(takenUuid, registration))
                .isInstanceOf(ValidationException.class)
                .hasMessageContaining(CryptographicKeyWriter.KEY_ALREADY_HELD);
        assertThat(keyImportRepository.findById(takenUuid).orElseThrow().getState())
                .isEqualTo(KeyImportState.COMPENSATING);
        assertThat(cryptographicKeyItemRepository.findByKeyUuidIn(List.of(holderUuid))).hasSize(1);
    }

    /** The requester gave the name to another key once the import went unconfirmed, and keys are known by name. */
    @Test
    void quarantine_refusesANameAnotherKeyHas() throws Exception {
        // given
        TokenProfileFullModel profile = persistedProfile();
        KeyPair pair = rsa();
        KeyImportAttempt taken = keyImportWriter.open(terms(profile, pair), "retry-name-taken", "imported key", SENT);
        keyImportWriter.compensating(taken);
        KeyPair other = rsa();
        KeyImportAttempt named = keyImportWriter.open(terms(profile, other), "retry-name-given", "imported key", SENT);
        UUID keyUuid = keyImportWriter
                .complete(named.uuid(), registration(profile, other, named, Set.of()))
                .orElseThrow()
                .key()
                .uuid();
        ImportedKeyRegistration registration = quarantineRegistration(profile, pair, taken);
        UUID takenUuid = taken.uuid();

        // when
        // then
        assertThatThrownBy(() -> keyImportWriter.quarantine(takenUuid, registration))
                .isInstanceOf(ValidationException.class)
                .hasMessageContaining(CryptographicKeyWriter.NAME_TAKEN.formatted("imported key"));
        assertThat(keyImportRepository.findById(takenUuid).orElseThrow().getState())
                .isEqualTo(KeyImportState.COMPENSATING);
        assertThat(cryptographicKeyRepository.findAll()).extracting(CryptographicKey::getUuid).containsExactly(keyUuid);
    }

    // ---- registration fixtures ----

    private TokenProfileFullModel persistedProfile() {
        Connector connector = new Connector();
        connector.setName("import-connector-" + UUID.randomUUID());
        connector.setUrl("http://connector.test");
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
        token.setName("import-token-" + UUID.randomUUID());
        token.setConnector(connector);
        token.setConnectorUuid(connector.getUuid());
        token.setConnectorInterface(cryptography);
        token.setKind("SOFT");
        token.setStatus(TokenInstanceStatus.ACTIVATED);
        token = tokenInstanceReferenceRepository.save(token);
        TokenProfile profile = new TokenProfile();
        profile.setName("import-profile-" + UUID.randomUUID());
        profile.setTokenInstanceReference(token);
        profile.setTokenInstanceName(token.getName());
        profile.setEnabled(true);
        profile.setUsage(PROFILE_USAGES);
        profile = tokenProfileRepository.save(profile);
        return tokenProfileRepository
                .findFullModelByUuidAndTokenInstanceReferenceUuid(profile.getUuid(), token.getUuid())
                .orElseThrow();
    }

    private static KeyImportTerms terms(TokenProfileFullModel profile, KeyPair pair) {
        return new KeyImportTerms(profile, KeyRequestType.KEY_PAIR, KeyAlgorithm.RSA, fingerprintOf(pair), true,
                List.of(), new NameAndUuidDto(UUID.randomUUID().toString(), "requester"));
    }

    static ImportedKeyRegistration registration(TokenProfileFullModel profile, KeyPair pair, KeyImportAttempt attempt,
            Set<UUID> groups) {
        return registration(profile, pair, attempt, groups, List.of());
    }

    private static ImportedKeyRegistration registration(TokenProfileFullModel profile, KeyPair pair,
            KeyImportAttempt attempt, Set<UUID> groups, List<RequestAttribute> customAttributes) {
        KeyMaterial publicMaterial = new KeyMaterial(KeyFormat.SPKI,
                Base64.getEncoder().encodeToString(pair.getPublic().getEncoded()));
        ProviderKeyItem publicKey = new ProviderKeyItem("imported key public key", KeyType.PUBLIC_KEY, KeyAlgorithm.RSA,
                2048, new RemoteKeyReference.MetadataReference(List.of(handle("public-handle", "p"))), publicMaterial,
                List.of());
        ProviderKeyItem privateKey = new ProviderKeyItem("imported key private key", KeyType.PRIVATE_KEY,
                KeyAlgorithm.RSA, 2048,
                new RemoteKeyReference.MetadataReference(List.of(handle("private-handle", "q"))), null, List.of());
        return new ImportedKeyRegistration(profile, List.of(publicKey, privateKey), attempt.keyReference(),
                fingerprintOf(pair), true,
                new KeyImportMetadata("imported key", "imported for the test", groups, customAttributes),
                new NameAndUuidDto(UUID.randomUUID().toString(), "requester"), false, null);
    }

    private static KeyImportTerms secretKeyTerms(TokenProfileFullModel profile) {
        return new KeyImportTerms(profile, KeyRequestType.SECRET, KeyAlgorithm.AES, null, true, List.of(),
                new NameAndUuidDto(UUID.randomUUID().toString(), "requester"));
    }

    /** An imported AES key as the connector describes it: one secret item, and no public key to fingerprint. */
    private static ImportedKeyRegistration secretKeyRegistration(TokenProfileFullModel profile,
            KeyImportAttempt attempt) {
        ProviderKeyItem secretKey = new ProviderKeyItem("imported secret key", KeyType.SECRET_KEY, KeyAlgorithm.AES,
                256, new RemoteKeyReference.MetadataReference(List.of(handle("secret-handle", "s"))), null, List.of());
        return new ImportedKeyRegistration(profile, List.of(secretKey), attempt.keyReference(), null, true,
                new KeyImportMetadata("imported secret key", "imported for the test", Set.of(), List.of()),
                new NameAndUuidDto(UUID.randomUUID().toString(), "requester"), false, null);
    }

    /** The key of an attempt the reconciliation could not undo, registered with what the attempt keeps. */
    private static ImportedKeyRegistration quarantineRegistration(TokenProfileFullModel profile, KeyPair pair,
            KeyImportAttempt attempt) {
        ImportedKeyRegistration imported = registration(profile, pair, attempt, Set.of());
        return new ImportedKeyRegistration(profile, imported.items(), attempt.keyReference(), fingerprintOf(pair), true,
                new KeyImportMetadata("imported key", null, Set.of(), null), imported.owner(), true, null);
    }

    /** An import that adopts the certificate's public key record, completed by another request. */
    private void adopt(KeyPair pair, String idempotencyKey) throws Exception {
        TokenProfileFullModel profile = persistedProfile();
        UUID recordUuid = cryptographicKeyItemRepository
                .findByFingerprint(fingerprintOf(pair))
                .orElseThrow()
                .getKeyUuid();
        KeyImportAttempt attempt = keyImportWriter.open(terms(profile, pair), idempotencyKey, "imported key", SENT);
        keyImportWriter.complete(attempt.uuid(), registration(profile, pair, attempt, Set.of()).adopting(recordUuid));
    }

    private static RequestAttribute department(UUID definitionUuid, String name, String value) {
        RequestAttributeV3 attribute = new RequestAttributeV3();
        attribute.setUuid(definitionUuid);
        attribute.setName(name);
        attribute.setContentType(AttributeContentType.STRING);
        attribute.setContent(List.of(new StringAttributeContentV3(value)));
        return attribute;
    }

    private UUID certificatePublicKey(KeyPair pair) {
        return certificateKeyWriter
                .uploadCertificatePublicKey("certKey_imported", pair.getPublic(), 2048, fingerprintOf(pair));
    }

    private UUID persistedCertificateOf(UUID keyUuid) {
        CertificateContent content = new CertificateContent();
        content.setContent("certificate-" + UUID.randomUUID());
        content = certificateContentRepository.saveAndFlush(content);
        Certificate certificate = new Certificate();
        certificate.setCommonName("imported");
        certificate.setSubjectDn("CN=imported");
        certificate.setIssuerDn("CN=issuer");
        certificate.setSerialNumber(UUID.randomUUID().toString());
        certificate.setState(CertificateState.ISSUED);
        certificate.setValidationStatus(CertificateValidationStatus.VALID);
        certificate.setCertificateContentId(content.getId());
        certificate.setKeyUuid(keyUuid);
        return certificateRepository.saveAndFlush(certificate).getUuid();
    }

    private Group persistedGroup() {
        Group group = new Group();
        group.setName("import-group-" + UUID.randomUUID());
        return groupRepository.save(group);
    }

    private CryptographicKeyItem item(UUID keyUuid, KeyType type) {
        return cryptographicKeyItemRepository
                .findByKeyUuidIn(List.of(keyUuid))
                .stream()
                .filter(item -> item.getType() == type)
                .findFirst()
                .orElseThrow();
    }

    private List<UUID> importEvents(KeyEventStatus status) {
        return eventHistoryRepository
                .findAll()
                .stream()
                .filter(event -> event.getEvent() == KeyEvent.IMPORT && event.getStatus() == status)
                .map(CryptographicKeyEventHistory::getKeyUuid)
                .toList();
    }

    static KeyPair rsa() throws Exception {
        KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
        generator.initialize(2048);
        return generator.generateKeyPair();
    }

    static String fingerprintOf(KeyPair pair) {
        return CryptographyUtil
                .calculateKeyFingerprint(new KeyMaterial(KeyFormat.SPKI,
                        Base64.getEncoder().encodeToString(pair.getPublic().getEncoded())));
    }

    /**
     * Binds one EntityManager to the thread for the call, as a request does, with the entity already loaded in it, so
     * the call's reads answer from that persistence context.
     */
    private void withARequestBoundEntityManager(Class<?> loadedType, UUID loadedUuid, RequestCall call)
            throws Exception {
        EntityManager bound = entityManagerFactory.createEntityManager();
        TransactionSynchronizationManager.bindResource(entityManagerFactory, new EntityManagerHolder(bound));
        try {
            bound.find(loadedType, loadedUuid);
            call.run();
        } finally {
            TransactionSynchronizationManager.unbindResource(entityManagerFactory);
            bound.close();
        }
    }

    /** Written around JPA, so the caller's persistence context cannot learn of it, as a request on another node is. */
    private void behindTheCaller(String update, Map<String, Object> parameters) {
        TransactionTemplate template = new TransactionTemplate(transactionManager);
        template.setPropagationBehavior(TransactionDefinition.PROPAGATION_REQUIRES_NEW);
        template.executeWithoutResult(status -> {
            Query query = entityManager.createNativeQuery(update);
            parameters.forEach(query::setParameter);
            query.executeUpdate();
        });
    }

    @FunctionalInterface
    private interface RequestCall {

        void run() throws Exception;
    }
}
