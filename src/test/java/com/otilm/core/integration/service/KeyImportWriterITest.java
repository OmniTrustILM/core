package com.otilm.core.integration.service;

import com.otilm.api.exception.NotFoundException;
import com.otilm.api.exception.ValidationException;
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
import com.otilm.core.model.crypto.RemoteKeyReference;
import com.otilm.core.model.crypto.TokenProfileFullModel;
import com.otilm.core.security.authz.SecurityResourceFilter;
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

    /** The entity-generated test schema cannot carry the migration's partial index, so each test adds it. */
    @BeforeEach
    void addTheOpenAttemptIndex() {
        jdbcTemplate
                .execute("CREATE UNIQUE INDEX IF NOT EXISTS \"" + OPEN_ATTEMPT_INDEX + "\" ON " + dbSchema
                        + ".\"key_import\" (\"spki_fingerprint\") WHERE \"state\" IN ('REQUESTED', 'ACCEPTED')");
    }

    @AfterEach
    void dropTheOpenAttemptIndex() {
        jdbcTemplate.execute("DROP INDEX IF EXISTS " + dbSchema + ".\"" + OPEN_ATTEMPT_INDEX + "\"");
    }

    /** A re-send adds the digests of what it sends, so an answer is checked against every copy the connector got. */
    @Test
    void resending_addsTheDigestsOfWhatIsSentAgain() {
        // given
        KeyImportAttempt attempt = keyImportWriter.open(terms("fingerprint-f", false), "retry-f", "key", SENT);

        // when
        KeyImportAttempt resent = keyImportWriter.resending(attempt.uuid(), List.of("resent-secret-digest"));

        // then
        assertThat(resent.secretDigests()).containsExactly("sent-secret-digest", "resent-secret-digest");
        assertThat(keyImportRepository.findById(attempt.uuid()).orElseThrow().getSecretDigests())
                .containsExactly("sent-secret-digest", "resent-secret-digest");
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

    @Test
    void open_startsAgainOnceTheOpenAttemptFailed() {
        // given
        KeyImportAttempt first = keyImportWriter.open(terms("fingerprint-c", false), "retry-c", "key", SENT);
        keyImportWriter.fail(first.uuid(), "The connector could not import the key.");

        // when
        KeyImportAttempt second = keyImportWriter.open(terms("fingerprint-c", false), "retry-c", "key", SENT);

        // then
        assertThat(second.uuid()).isNotEqualTo(first.uuid());
        KeyImport failed = keyImportRepository.findById(first.uuid()).orElseThrow();
        assertThat(failed.getState()).isEqualTo(KeyImportState.FAILED);
        assertThat(failed.getErrorMessage()).isEqualTo("The connector could not import the key.");
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
    void failAndAccept_leaveASettledAttemptAsItIs() {
        // given
        KeyImportAttempt attempt = keyImportWriter.open(terms("fingerprint-e", false), "retry-e", "key", SENT);
        keyImportWriter.fail(attempt.uuid(), "first");

        // when
        keyImportWriter.fail(attempt.uuid(), "second");
        keyImportWriter.accept(attempt.uuid(), List.of(handle("operation", "2")));

        // then
        KeyImport recorded = keyImportRepository.findById(attempt.uuid()).orElseThrow();
        assertThat(recorded.getState()).isEqualTo(KeyImportState.FAILED);
        assertThat(recorded.getErrorMessage()).isEqualTo("first");
        assertThat(recorded.getOperationMeta()).isNull();
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
        CryptographicKeyFullModel key = keyImportWriter
                .complete(attempt.uuid(), registration(profile, pair, attempt, Set.of(group.getUuid())))
                .orElseThrow()
                .key();

        // then
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
        CryptographicKeyFullModel key = keyImportWriter
                .complete(attempt.uuid(), registration(profile, pair, attempt, Set.of()))
                .orElseThrow()
                .key();

        // then
        assertThat(key.uuid()).isEqualTo(recordUuid);
        assertThat(key.name()).isEqualTo("imported key");
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
        assertThat(objectAssociationService.getOwner(Resource.CRYPTOGRAPHIC_KEY, recordUuid).getName())
                .isEqualTo("requester");
    }

    /** The gate saw no key; a certificate uploaded since brought the public key in, so the import adopts it. */
    @Test
    void complete_adoptsARecordThatAppearedAfterTheGate() throws Exception {
        // given
        TokenProfileFullModel profile = persistedProfile();
        KeyPair pair = rsa();
        KeyImportAttempt attempt = keyImportWriter.open(terms(profile, pair), "retry-late", "imported key", SENT);
        UUID recordUuid = certificatePublicKey(pair);

        // when
        CryptographicKeyFullModel key = keyImportWriter
                .complete(attempt.uuid(), registration(profile, pair, attempt, Set.of()))
                .orElseThrow()
                .key();

        // then
        assertThat(key.uuid()).isEqualTo(recordUuid);
        assertThat(cryptographicKeyItemRepository.findByKeyUuidIn(List.of(recordUuid))).hasSize(2);
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
        assertThat(second.repeat()).isTrue();
        assertThat(cryptographicKeyItemRepository.findByKeyUuidIn(List.of(first))).hasSize(2);
        assertThat(cryptographicKeyRepository.count()).isEqualTo(1);
    }

    @Test
    void complete_registersNothingForAnAttemptThatImportedNothing() throws Exception {
        // given
        TokenProfileFullModel profile = persistedProfile();
        KeyPair pair = rsa();
        KeyImportAttempt attempt = keyImportWriter.open(terms(profile, pair), "retry-failed", "imported key", SENT);
        keyImportWriter.fail(attempt.uuid(), "The connector could not import the key.");

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
        keyImportWriter.complete(attempt.uuid(), registration(profile, pair, attempt, Set.of()));
        Set<UUID> itemsRead = Set.of(publicKeyUuid);

        // when
        // then
        assertThatThrownBy(() -> cryptographicKeyWriter.deleteKeyWithAssociations(readByTheDeletion, itemsRead))
                .isInstanceOf(ValidationException.class);
        assertThat(cryptographicKeyRepository.findById(recordUuid)).isPresent();
        assertThat(item(recordUuid, KeyType.PRIVATE_KEY).getKeyReferenceUuid()).isEqualTo(attempt.keyReference());
    }

    /** A request checks the record before and after its attempt opens; the second check sees what changed between. */
    @Test
    void adoptablePublicKey_readsTheRecordAfresh() throws Exception {
        // given
        KeyPair pair = rsa();
        UUID recordUuid = certificatePublicKey(pair);
        UUID publicKeyUuid = item(recordUuid, KeyType.PUBLIC_KEY).getUuid();
        String fingerprint = fingerprintOf(pair);

        // when
        // then
        withARequestBoundEntityManager(recordUuid, () -> {
            assertThat(cryptographicKeyWriter.adoptablePublicKey(fingerprint)).contains(publicKeyUuid);
            behindTheCaller("UPDATE cryptographic_key_item SET state = 'COMPROMISED' WHERE uuid = :uuid",
                    Map.of("uuid", publicKeyUuid));
            assertThatThrownBy(() -> cryptographicKeyWriter.adoptablePublicKey(fingerprint))
                    .isInstanceOf(ValidationException.class)
                    .hasMessageContaining(CryptographicKeyWriter.KEY_NOT_ACTIVE);
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
                Resource.CRYPTOGRAPHIC_KEY_ITEM, null, cryptographicKeyItemRepository, complianceSubjectWriter);
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
        ImportedKeyRegistration registration = registration(profile, pair, attempt, Set.of());

        // when
        withARequestBoundEntityManager(recordUuid, () -> {
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
        withARequestBoundEntityManager(recordUuid, () -> {
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

    private static ImportedKeyRegistration registration(TokenProfileFullModel profile, KeyPair pair,
            KeyImportAttempt attempt, Set<UUID> groups) {
        KeyMaterial publicMaterial = new KeyMaterial(KeyFormat.SPKI,
                Base64.getEncoder().encodeToString(pair.getPublic().getEncoded()));
        ProviderKeyItem publicKey = new ProviderKeyItem("imported key public key", KeyType.PUBLIC_KEY, KeyAlgorithm.RSA,
                2048, new RemoteKeyReference.MetadataReference(List.of(handle("public-handle", "p"))), publicMaterial,
                List.of());
        ProviderKeyItem privateKey = new ProviderKeyItem("imported key private key", KeyType.PRIVATE_KEY,
                KeyAlgorithm.RSA, 2048,
                new RemoteKeyReference.MetadataReference(List.of(handle("private-handle", "q"))), null, List.of());
        return new ImportedKeyRegistration(profile, List.of(publicKey, privateKey), attempt.keyReference(),
                fingerprintOf(pair), true, new KeyImportMetadata("imported key", "imported for the test", groups),
                new NameAndUuidDto(UUID.randomUUID().toString(), "requester"));
    }

    /** An import that adopts the certificate's public key record, completed by another request. */
    private void adopt(KeyPair pair, String idempotencyKey) throws Exception {
        TokenProfileFullModel profile = persistedProfile();
        KeyImportAttempt attempt = keyImportWriter.open(terms(profile, pair), idempotencyKey, "imported key", SENT);
        keyImportWriter.complete(attempt.uuid(), registration(profile, pair, attempt, Set.of()));
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

    private static KeyPair rsa() throws Exception {
        KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
        generator.initialize(2048);
        return generator.generateKeyPair();
    }

    private static String fingerprintOf(KeyPair pair) {
        return CryptographyUtil
                .calculateKeyFingerprint(new KeyMaterial(KeyFormat.SPKI,
                        Base64.getEncoder().encodeToString(pair.getPublic().getEncoded())));
    }

    /**
     * Binds one EntityManager to the thread for the call, as a request does, with the key already loaded in it, so the
     * call's reads answer from that persistence context.
     */
    private void withARequestBoundEntityManager(UUID keyUuid, RequestCall call) throws Exception {
        EntityManager bound = entityManagerFactory.createEntityManager();
        TransactionSynchronizationManager.bindResource(entityManagerFactory, new EntityManagerHolder(bound));
        try {
            bound.find(CryptographicKey.class, keyUuid);
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
