package com.otilm.core.service.handler;

import com.otilm.api.exception.ConnectorServerException;
import com.otilm.api.exception.ValidationError;
import com.otilm.api.exception.ValidationException;
import com.otilm.api.model.client.certificate.ImportOutcome;
import com.otilm.api.model.client.cryptography.key.KeyRequestType;
import com.otilm.api.model.common.NameAndUuidDto;
import com.otilm.api.model.common.attribute.common.MetadataAttribute;
import com.otilm.api.model.common.attribute.v2.MetadataAttributeV2;
import com.otilm.api.model.common.enums.cryptography.KeyAlgorithm;
import com.otilm.api.model.common.enums.cryptography.KeyFormat;
import com.otilm.api.model.common.enums.cryptography.KeyType;
import com.otilm.api.model.core.cryptography.key.KeyEvent;
import com.otilm.api.model.core.cryptography.key.KeyEventStatus;
import com.otilm.api.model.core.secret.Passphrase;
import com.otilm.core.attribute.engine.OutboundSecretContainment;
import com.otilm.core.attribute.engine.OutboundSecretLeakException;
import com.otilm.core.config.KeyImportProperties;
import com.otilm.core.dao.entity.KeyImport;
import com.otilm.core.dao.entity.KeyImportState;
import com.otilm.core.dao.repository.CryptographicKeyRepository;
import com.otilm.core.dao.repository.KeyImportRepository;
import com.otilm.core.key.normalization.NormalizedKey;
import com.otilm.core.model.crypto.CryptographicKeyFullModel;
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
import com.otilm.core.model.crypto.TokenInstanceFullModel;
import com.otilm.core.model.crypto.TokenProfileFullModel;
import com.otilm.core.service.CryptographicKeyEventHistoryService;
import com.otilm.core.service.handler.key.ImportAnswer;
import com.otilm.core.service.handler.key.KeyProviderAdapter;
import com.otilm.core.service.handler.key.KeyProviderAdapterFactory;
import com.otilm.core.service.writer.CryptographicKeyWriter;
import com.otilm.core.service.writer.KeyImportWriter;
import java.security.KeyPairGenerator;
import java.sql.SQLException;
import java.time.Duration;
import java.time.OffsetDateTime;
import java.util.Base64;
import java.util.List;
import java.util.Optional;
import java.util.Set;
import java.util.UUID;
import java.util.concurrent.atomic.AtomicReference;
import java.util.stream.Stream;
import org.hibernate.exception.ConstraintViolationException;
import org.hibernate.exception.ConstraintViolationException.ConstraintKind;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Named;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;
import org.mockito.ArgumentCaptor;
import org.mockito.InOrder;
import org.springframework.dao.DataIntegrityViolationException;
import org.springframework.http.HttpStatus;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.junit.jupiter.api.Assertions.assertTimeoutPreemptively;
import static org.junit.jupiter.api.Named.named;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.inOrder;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;

class KeyImportSagaTest {

    private static final String RETRY = "retry";

    private static final List<String> SENT = List.of("sent-secret-digest");
    private static final List<MetadataAttribute> HANDLE = List.of(meta("operation"));

    /** The message of a violation, which no refusal may repeat. */
    private static final String VIOLATION_MESSAGE = "constraint violated";

    private static final String UNIQUE_VIOLATION = "23505";

    private static final String FOREIGN_KEY_VIOLATION = "23503";

    private final KeyImportRepository keyImportRepository = mock(KeyImportRepository.class);
    private final CryptographicKeyRepository cryptographicKeyRepository = mock(CryptographicKeyRepository.class);
    private final CryptographicKeyWriter cryptographicKeyWriter = mock(CryptographicKeyWriter.class);
    private final KeyImportWriter keyImportWriter = mock(KeyImportWriter.class);
    private final CryptographicKeyEventHistoryService eventHistory = mock(CryptographicKeyEventHistoryService.class);
    private final KeyImportGates keyImportGates = mock(KeyImportGates.class);
    private final KeyProviderAdapterFactory adapterFactory = mock(KeyProviderAdapterFactory.class);
    private final KeyProviderAdapter adapter = mock(KeyProviderAdapter.class);
    private final CryptographicKeyFullModel registered = mock(CryptographicKeyFullModel.class);

    private KeyImportSaga saga;
    private KeyImportTerms terms;
    private NormalizedKey key;
    private KeyImportTerms secretKeyTerms;
    private NormalizedKey secretKey;
    private KeyImportMetadata metadata;
    private KeyImportAttempt attempt;
    private List<String> keyDigests;

    @BeforeEach
    void setUp() throws Exception {
        saga = new KeyImportSaga(keyImportRepository, cryptographicKeyRepository, cryptographicKeyWriter,
                keyImportWriter, eventHistory, keyImportGates, adapterFactory, new KeyImportProperties(
                        Duration.ofMillis(300), Duration.ofMillis(10), Duration.ofHours(20), null, null, null));
        TokenProfileFullModel profile = mock(TokenProfileFullModel.class);
        TokenInstanceFullModel token = mock(TokenInstanceFullModel.class);
        when(profile.tokenInstance()).thenReturn(token);
        when(adapterFactory.forToken(token)).thenReturn(adapter);
        KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
        generator.initialize(2048);
        byte[] spki = generator.generateKeyPair().getPublic().getEncoded();
        key = new NormalizedKey(KeyRequestType.KEY_PAIR, KeyAlgorithm.RSA, 2048, spki, new byte[]{1},
                new Passphrase("transport".toCharArray()));
        keyDigests = OutboundSecretContainment.digestsOf(key.transportSecrets());
        terms = new KeyImportTerms(profile, KeyRequestType.KEY_PAIR, KeyAlgorithm.RSA, "fingerprint", false, List.of(),
                new NameAndUuidDto(UUID.randomUUID().toString(), "requester"));
        secretKey = new NormalizedKey(KeyRequestType.SECRET, KeyAlgorithm.AES, 256, null, new byte[]{2},
                new Passphrase("secret transport".toCharArray()));
        secretKeyTerms = new KeyImportTerms(profile, KeyRequestType.SECRET, KeyAlgorithm.AES, null, false, List.of(),
                terms.requester());
        metadata = new KeyImportMetadata("imported key", null, Set.of(), List.of());
        attempt = new KeyImportAttempt(UUID.randomUUID(), UUID.randomUUID(), KeyImportState.REQUESTED, null,
                OffsetDateTime.now(), SENT, null);
        when(cryptographicKeyRepository.existsByName(anyString())).thenReturn(false);
        when(cryptographicKeyWriter.publicKeyHolder("fingerprint")).thenReturn(Optional.empty());
        when(keyImportRepository.findFirstByIdempotencyKeyAndStateInOrderByCreatedAtDesc(eq(RETRY), any()))
                .thenReturn(Optional.empty());
        when(keyImportWriter.open(terms, RETRY, "imported key", keyDigests)).thenReturn(attempt);
        when(keyImportWriter
                .open(secretKeyTerms, RETRY, "imported key",
                        OutboundSecretContainment.digestsOf(secretKey.transportSecrets())))
                .thenReturn(attempt);
        when(keyImportWriter.complete(eq(attempt.uuid()), any()))
                .thenReturn(Optional.of(new ImportedKey(registered, ImportOutcome.CREATED)));
        when(keyImportWriter.secretDigests(any())).thenReturn(SENT);
        when(keyImportWriter.untaken(any())).thenReturn(true);
        when(keyImportWriter.failUntaken(any(), any())).thenReturn(true);
    }

    @Test
    void importKey_registersTheKeyTheConnectorImported() throws Exception {
        // given
        when(adapter.importKey(terms, attempt, key, "imported key")).thenReturn(imported(key.subjectPublicKeyInfo()));

        // when
        ImportedKey result = saga.importKey(terms, RETRY, key, metadata);

        // then
        assertThat(result.key()).isSameAs(registered);
        assertThat(result.outcome()).isEqualTo(ImportOutcome.CREATED);
        verify(keyImportWriter).complete(eq(attempt.uuid()), any(ImportedKeyRegistration.class));
        verify(keyImportWriter, never()).failUntaken(any(), any());
    }

    @Test
    void importKey_answersARepeatedImportWithTheKeyItRegistered() throws Exception {
        // given
        KeyImport completed = new KeyImport();
        completed.setKeyUuid(UUID.randomUUID());
        when(keyImportRepository
                .findFirstByIdempotencyKeyAndStateInOrderByCreatedAtDesc(RETRY, Set.of(KeyImportState.COMPLETED)))
                .thenReturn(Optional.of(completed));
        when(keyImportWriter.registeredKey(completed.getKeyUuid())).thenReturn(Optional.of(registered));
        when(cryptographicKeyRepository.existsByName("imported key")).thenReturn(true);

        // when
        ImportedKey result = saga.importKey(terms, RETRY, key, metadata);

        // then
        assertThat(result.key()).isSameAs(registered);
        assertThat(result.outcome()).isEqualTo(ImportOutcome.EXISTING);
        verify(keyImportWriter, never()).open(any(), any(), any(), any());
    }

    /**
     * A retry looked for the same import before it completed, and found the name the import registered the key under
     * taken: the import is looked for once more, and answers with its key.
     */
    @Test
    void importKey_answersTheSameImportCompletedMeanwhileUnderTheName() throws Exception {
        // given
        KeyImport completed = new KeyImport();
        completed.setKeyUuid(UUID.randomUUID());
        when(keyImportRepository
                .findFirstByIdempotencyKeyAndStateInOrderByCreatedAtDesc(RETRY, Set.of(KeyImportState.COMPLETED)))
                .thenReturn(Optional.empty(), Optional.of(completed));
        when(keyImportWriter.registeredKey(completed.getKeyUuid())).thenReturn(Optional.of(registered));
        when(cryptographicKeyRepository.existsByName("imported key")).thenReturn(true);

        // when
        ImportedKey result = saga.importKey(terms, RETRY, key, metadata);

        // then
        assertThat(result.key()).isSameAs(registered);
        assertThat(result.outcome()).isEqualTo(ImportOutcome.EXISTING);
        verify(keyImportWriter, never()).open(any(), any(), any(), any());
    }

    /**
     * The attempt that refused this one is the same import's, which takes the record a moment later, so no failure is
     * recorded in the record's history.
     */
    @Test
    void importKey_recordsNoFailureOnTheRecordWhileTheSameImportIsOpen() {
        // given
        PublicKeyHolder adoptable = publicKeyRecord(UUID.randomUUID());
        when(cryptographicKeyWriter.publicKeyHolder("fingerprint")).thenReturn(Optional.of(adoptable));
        when(keyImportWriter.open(terms, RETRY, "certificate key", keyDigests))
                .thenThrow(new DataIntegrityViolationException("uq_key_import_open_attempt"));
        KeyImport open = new KeyImport();
        open.setUuid(UUID.randomUUID());
        when(keyImportRepository
                .findFirstByIdempotencyKeyAndStateInOrderByCreatedAtDesc(RETRY,
                        Set.of(KeyImportState.REQUESTED, KeyImportState.ACCEPTED)))
                .thenReturn(Optional.empty(), Optional.of(open));

        // when
        // then
        assertThatThrownBy(() -> saga.importKey(terms, RETRY, key, metadata))
                .isInstanceOf(ValidationException.class)
                .hasMessageContaining(KeyImportSaga.ALREADY_IMPORTING);
        verifyNoInteractions(eventHistory);
    }

    /**
     * The attempt that refused this one was the same import's, which completed before this request looked for it: the
     * import is looked for once more and answers with its key, and no failure is recorded on the record it adopted.
     */
    @Test
    void importKey_answersTheSameImportThatCompletedAfterItsAttemptRefusedThisOne() throws Exception {
        // given
        PublicKeyHolder adoptable = publicKeyRecord(UUID.randomUUID());
        when(cryptographicKeyWriter.publicKeyHolder("fingerprint")).thenReturn(Optional.of(adoptable));
        when(keyImportWriter.open(terms, RETRY, "certificate key", keyDigests))
                .thenThrow(new DataIntegrityViolationException("uq_key_import_open_attempt"));
        KeyImport completed = new KeyImport();
        completed.setKeyUuid(UUID.randomUUID());
        when(keyImportRepository
                .findFirstByIdempotencyKeyAndStateInOrderByCreatedAtDesc(RETRY, Set.of(KeyImportState.COMPLETED)))
                .thenReturn(Optional.empty(), Optional.of(completed));
        when(keyImportWriter.registeredKey(completed.getKeyUuid())).thenReturn(Optional.of(registered));

        // when
        ImportedKey result = saga.importKey(terms, RETRY, key, metadata);

        // then
        assertThat(result.key()).isSameAs(registered);
        assertThat(result.outcome()).isEqualTo(ImportOutcome.EXISTING);
        verifyNoInteractions(eventHistory);
    }

    /** Another import of the key holds the open attempt, so this import's failure is the record's to show. */
    @Test
    void importKey_recordsTheFailureOnTheRecordWhileAnotherImportIsOpen() {
        // given
        UUID publicKeyUuid = UUID.randomUUID();
        PublicKeyHolder adoptable = publicKeyRecord(publicKeyUuid);
        when(cryptographicKeyWriter.publicKeyHolder("fingerprint")).thenReturn(Optional.of(adoptable));
        when(keyImportWriter.open(terms, RETRY, "certificate key", keyDigests))
                .thenThrow(new DataIntegrityViolationException("uq_key_import_open_attempt"));

        // when
        assertThatThrownBy(() -> saga.importKey(terms, RETRY, key, metadata)).isInstanceOf(ValidationException.class);

        // then
        verify(eventHistory)
                .addEventHistory(KeyEvent.IMPORT, KeyEventStatus.FAILED, KeyImportSaga.ALREADY_IMPORTING, null,
                        publicKeyUuid);
    }

    @Test
    void importKey_refusesANameAnotherKeyHas() {
        // given
        when(cryptographicKeyRepository.existsByName("imported key")).thenReturn(true);

        // when
        // then
        assertThatThrownBy(() -> saga.importKey(terms, RETRY, key, metadata))
                .isInstanceOf(ValidationException.class)
                .hasMessageContaining("A key named imported key already exists.");
        verify(keyImportWriter, never()).open(any(), any(), any(), any());
    }

    /** The platform holds the key pair in a key of its own, so the import changes nothing and asks no connector. */
    @Test
    void importKey_answersAKeyThePlatformHoldsWithoutAskingTheConnector() throws Exception {
        // given
        CryptographicKeyFullModel held = mock(CryptographicKeyFullModel.class);
        when(cryptographicKeyWriter.publicKeyHolder("fingerprint"))
                .thenReturn(Optional.of(new PublicKeyHolder(held, UUID.randomUUID(), Holding.KEY_PAIR)));

        // when
        ImportedKey result = saga.importKey(terms, RETRY, key, metadata);

        // then
        assertThat(result.key()).isSameAs(held);
        assertThat(result.outcome()).isEqualTo(ImportOutcome.EXISTING);
        verify(keyImportWriter, never()).open(any(), any(), any(), any());
        verify(adapter, never()).importKey(any(), any(), any(), any());
        verify(cryptographicKeyRepository, never()).existsByName(any());
    }

    @Test
    void importKey_refusesAKeyNoLongerActiveBeforeAnAttemptOpens() {
        // given
        when(cryptographicKeyWriter.publicKeyHolder("fingerprint"))
                .thenThrow(new ValidationException(ValidationError.create(CryptographicKeyWriter.KEY_NOT_ACTIVE)));

        // when
        // then
        assertThatThrownBy(() -> saga.importKey(terms, RETRY, key, metadata))
                .isInstanceOf(ValidationException.class)
                .hasMessageContaining(CryptographicKeyWriter.KEY_NOT_ACTIVE);
        verify(keyImportWriter, never()).open(any(), any(), any(), any());
    }

    /**
     * A token holds the public key without its private key, so the key is not one the inventory holds: the gates refuse
     * the import before anything is recorded or asked.
     */
    @Test
    void importKey_refusesAPublicKeyATokenHoldsWithoutItsPrivateKeyBeforeAnAttemptOpens() {
        // given
        PublicKeyHolder inAToken = new PublicKeyHolder(mock(CryptographicKeyFullModel.class), UUID.randomUUID(),
                Holding.PUBLIC_KEY_IN_TOKEN);
        when(cryptographicKeyWriter.publicKeyHolder("fingerprint")).thenReturn(Optional.of(inAToken));
        doThrow(new ValidationException(ValidationError.create("in a token without its private key")))
                .when(keyImportGates)
                .requireImportableInto(inAToken);

        // when
        // then
        assertThatThrownBy(() -> saga.importKey(terms, RETRY, key, metadata))
                .isInstanceOf(ValidationException.class)
                .hasMessageContaining("in a token without its private key");
        verify(keyImportWriter, never()).open(any(), any(), any(), any());
        verifyNoInteractions(adapter);
    }

    @Test
    void importKey_recordsTheFailureOnThePublicKeyItWouldAdopt() throws Exception {
        // given
        UUID publicKeyUuid = UUID.randomUUID();
        PublicKeyHolder adoptable = publicKeyRecord(publicKeyUuid);
        when(cryptographicKeyWriter.publicKeyHolder("fingerprint")).thenReturn(Optional.of(adoptable));
        when(keyImportWriter.open(terms, RETRY, "certificate key", keyDigests)).thenReturn(attempt);
        when(adapter.importKey(terms, attempt, key, "certificate key"))
                .thenThrow(new ValidationException(
                        ValidationError.create("The connector refused (KEY_TYPE_NOT_IMPORTABLE).")));

        // when
        assertThatThrownBy(() -> saga.importKey(terms, RETRY, key, metadata)).isInstanceOf(ValidationException.class);

        // then
        verify(eventHistory)
                .addEventHistory(KeyEvent.IMPORT, KeyEventStatus.FAILED,
                        "The connector refused (KEY_TYPE_NOT_IMPORTABLE).", null, publicKeyUuid);
    }

    @Test
    void importKey_closesARefusedImport() throws Exception {
        // given
        when(adapter.importKey(terms, attempt, key, "imported key"))
                .thenThrow(new ValidationException(ValidationError.create("refused (KEY_DECRYPTION_FAILED)")));

        // when
        assertThatThrownBy(() -> saga.importKey(terms, RETRY, key, metadata)).isInstanceOf(ValidationException.class);

        // then
        verify(keyImportWriter).failUntaken(attempt, "refused (KEY_DECRYPTION_FAILED)");
    }

    /** Another request sent the attempt again while the connector refused this send, so that request settles it. */
    @Test
    void importKey_leavesARefusedAttemptAnotherRequestSentAgainToThatRequest() throws Exception {
        // given
        when(adapter.importKey(terms, attempt, key, "imported key"))
                .thenThrow(new ValidationException(ValidationError.create("refused (KEY_DECRYPTION_FAILED)")));
        when(keyImportWriter.failUntaken(attempt, "refused (KEY_DECRYPTION_FAILED)")).thenReturn(false);

        // when
        // then
        assertThatThrownBy(() -> saga.importKey(terms, RETRY, key, metadata))
                .isInstanceOf(ConnectorServerException.class)
                .hasMessage(KeyImportSaga.UNCONFIRMED);
    }

    @Test
    void importKey_leavesAnImportWithoutAnAnswerOpen() throws Exception {
        // given
        when(adapter.importKey(terms, attempt, key, "imported key"))
                .thenThrow(new ConnectorServerException("The connector failed to import the key.",
                        HttpStatus.BAD_GATEWAY));

        // when
        // then
        assertThatThrownBy(() -> saga.importKey(terms, RETRY, key, metadata))
                .isInstanceOf(ConnectorServerException.class)
                .hasMessage(KeyImportSaga.UNCONFIRMED);
        verify(keyImportWriter, never()).failUntaken(any(), any());
        verify(keyImportWriter, never()).complete(any(), any());
    }

    @Test
    void importKey_waitsOnAnAsynchronousImportUntilItCompletes() throws Exception {
        // given
        when(adapter.importKey(terms, attempt, key, "imported key")).thenReturn(new ImportAnswer.Running(HANDLE));
        when(adapter.importKeyStatus(terms.profile(), HANDLE, SENT, "imported key"))
                .thenReturn(new ImportAnswer.Running(HANDLE))
                .thenReturn(imported(key.subjectPublicKeyInfo()));

        // when
        ImportedKey result = saga.importKey(terms, RETRY, key, metadata);

        // then
        assertThat(result.key()).isSameAs(registered);
        verify(keyImportWriter).accept(attempt.uuid(), HANDLE);
    }

    /** Another request sent the attempt again while this one waited, so the next poll is checked against both sends. */
    @Test
    void importKey_checksTheNextPollAgainstWhatAnotherSendAdded() throws Exception {
        // given
        List<String> bothSends = List.of("sent-secret-digest", "resent-secret-digest");
        when(adapter.importKey(terms, attempt, key, "imported key")).thenReturn(new ImportAnswer.Running(HANDLE));
        when(keyImportWriter.secretDigests(attempt.uuid())).thenReturn(SENT, bothSends);
        when(adapter.importKeyStatus(terms.profile(), HANDLE, bothSends, "imported key"))
                .thenReturn(imported(key.subjectPublicKeyInfo()));

        // when
        ImportedKey result = saga.importKey(terms, RETRY, key, metadata);

        // then
        assertThat(result.key()).isSameAs(registered);
        verify(adapter).importKeyStatus(terms.profile(), HANDLE, bothSends, "imported key");
    }

    /**
     * Another request sent the attempt again while a poll was on its way, so the answer was checked against digests
     * that miss what that request sent, and may echo it: the connector is asked once more, and the echo refused.
     */
    @Test
    void importKey_asksAgainWhenAnotherRequestSentTheAttemptDuringAPoll() throws Exception {
        // given
        List<String> bothSends = List.of("sent-secret-digest", "resent-secret-digest");
        AtomicReference<List<String>> recorded = new AtomicReference<>(SENT);
        when(keyImportWriter.secretDigests(attempt.uuid())).thenAnswer(read -> recorded.get());
        when(adapter.importKey(terms, attempt, key, "imported key")).thenReturn(new ImportAnswer.Running(HANDLE));
        when(adapter.importKeyStatus(terms.profile(), HANDLE, SENT, "imported key")).thenAnswer(asked -> {
            recorded.set(bothSends);
            return imported(key.subjectPublicKeyInfo());
        });
        when(adapter.importKeyStatus(terms.profile(), HANDLE, bothSends, "imported key"))
                .thenThrow(new OutboundSecretLeakException("The answer echoes a secret."));

        // when
        // then
        assertThatThrownBy(() -> saga.importKey(terms, RETRY, key, metadata))
                .isInstanceOf(ConnectorServerException.class)
                .hasMessage(KeyImportSaga.UNCONFIRMED);
        verify(adapter).importKeyStatus(terms.profile(), HANDLE, bothSends, "imported key");
        verify(keyImportWriter, never()).complete(any(), any());
    }

    /**
     * Another request sent the attempt again while a poll was on its way, so the question is asked once more; that
     * answer, checked against both sends, registers the key.
     */
    @Test
    void importKey_registersTheKeyFromTheQuestionAskedOnceMore() throws Exception {
        // given
        List<String> bothSends = List.of("sent-secret-digest", "resent-secret-digest");
        AtomicReference<List<String>> recorded = new AtomicReference<>(SENT);
        when(keyImportWriter.secretDigests(attempt.uuid())).thenAnswer(read -> recorded.get());
        when(adapter.importKey(terms, attempt, key, "imported key")).thenReturn(new ImportAnswer.Running(HANDLE));
        when(adapter.importKeyStatus(terms.profile(), HANDLE, SENT, "imported key")).thenAnswer(asked -> {
            recorded.set(bothSends);
            return new ImportAnswer.Running(HANDLE);
        });
        when(adapter.importKeyStatus(terms.profile(), HANDLE, bothSends, "imported key"))
                .thenReturn(imported(key.subjectPublicKeyInfo()));

        // when
        ImportedKey result = saga.importKey(terms, RETRY, key, metadata);

        // then
        assertThat(result.key()).isSameAs(registered);
        verify(adapter).importKeyStatus(terms.profile(), HANDLE, bothSends, "imported key");
    }

    /** Other requests sent the attempt again while each of two questions was on its way, so no answer is confirmed. */
    @Test
    void importKey_leavesAnImportOtherRequestsKeepSendingUnconfirmed() throws Exception {
        // given
        List<String> twoSends = List.of("sent-secret-digest", "resent-secret-digest");
        List<String> threeSends = List.of("sent-secret-digest", "resent-secret-digest", "resent-again-digest");
        AtomicReference<List<String>> recorded = new AtomicReference<>(SENT);
        when(keyImportWriter.secretDigests(attempt.uuid())).thenAnswer(read -> recorded.get());
        when(adapter.importKey(terms, attempt, key, "imported key")).thenReturn(new ImportAnswer.Running(HANDLE));
        when(adapter.importKeyStatus(terms.profile(), HANDLE, SENT, "imported key")).thenAnswer(asked -> {
            recorded.set(twoSends);
            return imported(key.subjectPublicKeyInfo());
        });
        when(adapter.importKeyStatus(terms.profile(), HANDLE, twoSends, "imported key")).thenAnswer(asked -> {
            recorded.set(threeSends);
            return imported(key.subjectPublicKeyInfo());
        });

        // when
        // then
        assertThatThrownBy(() -> saga.importKey(terms, RETRY, key, metadata))
                .isInstanceOf(ConnectorServerException.class)
                .hasMessage(KeyImportSaga.UNCONFIRMED);
        verify(adapter, never()).importKeyStatus(terms.profile(), HANDLE, threeSends, "imported key");
        verify(keyImportWriter, never()).complete(any(), any());
    }

    /**
     * Another request sent the attempt again while this send was on its way, so the answer may carry what that request
     * sent: it is dropped, and the connector's record of the import is asked for and checked against both sends.
     */
    @Test
    void importKey_asksAgainWhenAnotherRequestSentTheAttemptDuringTheSend() throws Exception {
        // given
        List<String> bothSends = List.of("sent-secret-digest", "resent-secret-digest");
        when(adapter.importKey(terms, attempt, key, "imported key")).thenReturn(new ImportAnswer.Running(HANDLE));
        when(keyImportWriter.secretDigests(attempt.uuid())).thenReturn(bothSends);
        when(adapter.importKeyResult(terms.profile(), attempt.uuid(), bothSends, "imported key"))
                .thenReturn(imported(key.subjectPublicKeyInfo()));

        // when
        ImportedKey result = saga.importKey(terms, RETRY, key, metadata);

        // then
        assertThat(result.key()).isSameAs(registered);
        verify(keyImportWriter, never()).accept(any(), any());
        verify(adapter, never()).importKeyStatus(any(), any(), any(), any());
    }

    @Test
    void importKey_cancelsAnImportThatDoesNotFinishInTime() throws Exception {
        // given
        when(adapter.importKey(terms, attempt, key, "imported key")).thenReturn(new ImportAnswer.Running(HANDLE));
        when(adapter.importKeyStatus(terms.profile(), HANDLE, SENT, "imported key"))
                .thenReturn(new ImportAnswer.Running(HANDLE));
        when(adapter.cancelImportKey(HANDLE)).thenReturn(true);

        // when
        // then
        assertThatThrownBy(() -> saga.importKey(terms, RETRY, key, metadata))
                .isInstanceOf(ConnectorServerException.class)
                .hasMessage(KeyImportSaga.CANCELLED.formatted(0));
        verify(keyImportWriter).failUntaken(attempt, KeyImportSaga.CANCELLED.formatted(0));
    }

    /** Another request took the attempt since this one did, and waits on the import itself, so it is left running. */
    @Test
    void importKey_leavesAnImportAnotherRequestTookRunning() throws Exception {
        // given
        when(adapter.importKey(terms, attempt, key, "imported key")).thenReturn(new ImportAnswer.Running(HANDLE));
        when(adapter.importKeyStatus(terms.profile(), HANDLE, SENT, "imported key"))
                .thenReturn(new ImportAnswer.Running(HANDLE));
        when(adapter.cancelImportKey(HANDLE)).thenReturn(true);
        when(keyImportWriter.untaken(attempt)).thenReturn(false);

        // when
        // then
        assertThatThrownBy(() -> saga.importKey(terms, RETRY, key, metadata))
                .isInstanceOf(ConnectorServerException.class)
                .hasMessage(KeyImportSaga.UNCONFIRMED);
        verify(adapter, never()).cancelImportKey(any());
        verify(keyImportWriter, never()).failUntaken(any(), any());
    }

    /** A request that resumed an import cancels it at its deadline once nobody took it since the request resumed it. */
    @Test
    void importKey_cancelsAnImportItResumedAndStillHolds() throws Exception {
        // given
        KeyImportAttempt accepted = new KeyImportAttempt(UUID.randomUUID(), UUID.randomUUID(), KeyImportState.ACCEPTED,
                HANDLE, OffsetDateTime.now(), SENT, OffsetDateTime.now());
        openAttempt(accepted);
        KeyImportAttempt resumed = new KeyImportAttempt(accepted.uuid(), accepted.keyReference(),
                KeyImportState.ACCEPTED, HANDLE, accepted.createdAt(), SENT, accepted.nextCheckAt().plusMinutes(15));
        when(keyImportWriter.resuming(accepted.uuid())).thenReturn(resumed);
        when(keyImportWriter.untaken(accepted)).thenReturn(false);
        when(adapter.importKeyResult(terms.profile(), accepted.uuid(), SENT, "imported key"))
                .thenReturn(new ImportAnswer.Running(null));
        when(adapter.importKeyStatus(terms.profile(), HANDLE, SENT, "imported key"))
                .thenReturn(new ImportAnswer.Running(HANDLE));
        when(adapter.cancelImportKey(HANDLE)).thenReturn(true);

        // when
        // then
        assertThatThrownBy(() -> saga.importKey(terms, RETRY, key, metadata))
                .isInstanceOf(ConnectorServerException.class)
                .hasMessage(KeyImportSaga.CANCELLED.formatted(0));
        verify(keyImportWriter).untaken(resumed);
        verify(keyImportWriter).failUntaken(resumed, KeyImportSaga.CANCELLED.formatted(0));
    }

    /** A poll interval longer than the time an import may take does not hold the request past its deadline. */
    @Test
    void importKey_cancelsInTimeWhenThePollIntervalOutlastsTheDeadline() throws Exception {
        // given
        KeyImportSaga impatient = new KeyImportSaga(keyImportRepository, cryptographicKeyRepository,
                cryptographicKeyWriter, keyImportWriter, eventHistory, keyImportGates, adapterFactory,
                new KeyImportProperties(Duration.ofMillis(100), Duration.ofHours(1), Duration.ofHours(20), null, null,
                        null));
        when(adapter.importKey(terms, attempt, key, "imported key")).thenReturn(new ImportAnswer.Running(HANDLE));
        when(adapter.importKeyStatus(terms.profile(), HANDLE, SENT, "imported key"))
                .thenReturn(new ImportAnswer.Running(HANDLE));
        when(adapter.cancelImportKey(HANDLE)).thenReturn(true);

        // when
        // then
        assertTimeoutPreemptively(Duration.ofSeconds(10),
                () -> assertThatThrownBy(() -> impatient.importKey(terms, RETRY, key, metadata))
                        .isInstanceOf(ConnectorServerException.class)
                        .hasMessage(KeyImportSaga.CANCELLED.formatted(0)));
    }

    @Test
    void importKey_leavesAnImportTheConnectorDidNotAbortOpen() throws Exception {
        // given
        when(adapter.importKey(terms, attempt, key, "imported key")).thenReturn(new ImportAnswer.Running(HANDLE));
        when(adapter.importKeyStatus(terms.profile(), HANDLE, SENT, "imported key"))
                .thenReturn(new ImportAnswer.Running(HANDLE));
        when(adapter.cancelImportKey(HANDLE)).thenReturn(false);

        // when
        // then
        assertThatThrownBy(() -> saga.importKey(terms, RETRY, key, metadata))
                .isInstanceOf(ConnectorServerException.class)
                .hasMessage(KeyImportSaga.UNCONFIRMED);
        verify(keyImportWriter, never()).failUntaken(any(), any());
    }

    @Test
    void importKey_closesAnImportThatEndsWithoutAKey() throws Exception {
        // given
        when(adapter.importKey(terms, attempt, key, "imported key")).thenReturn(new ImportAnswer.Running(HANDLE));
        when(adapter.importKeyStatus(terms.profile(), HANDLE, SENT, "imported key"))
                .thenReturn(new ImportAnswer.NotImported());

        // when
        // then
        assertThatThrownBy(() -> saga.importKey(terms, RETRY, key, metadata))
                .isInstanceOf(ConnectorServerException.class)
                .hasMessage(KeyImportSaga.NOT_IMPORTED);
        verify(keyImportWriter).failUntaken(attempt, KeyImportSaga.NOT_IMPORTED);
    }

    /** Another request took the attempt while this one waited, so the import ending without a key is its to record. */
    @Test
    void importKey_leavesAnImportThatEndedWithoutAKeyToTheRequestThatTookIt() throws Exception {
        // given
        when(adapter.importKey(terms, attempt, key, "imported key")).thenReturn(new ImportAnswer.Running(HANDLE));
        when(adapter.importKeyStatus(terms.profile(), HANDLE, SENT, "imported key"))
                .thenReturn(new ImportAnswer.NotImported());
        when(keyImportWriter.failUntaken(attempt, KeyImportSaga.NOT_IMPORTED)).thenReturn(false);

        // when
        // then
        assertThatThrownBy(() -> saga.importKey(terms, RETRY, key, metadata))
                .isInstanceOf(ConnectorServerException.class)
                .hasMessage(KeyImportSaga.UNCONFIRMED);
    }

    @Test
    void importKey_leavesAnImportOpenWhenItsStatusCannotBeRead() throws Exception {
        // given
        when(adapter.importKey(terms, attempt, key, "imported key")).thenReturn(new ImportAnswer.Running(HANDLE));
        when(adapter.importKeyStatus(terms.profile(), HANDLE, SENT, "imported key"))
                .thenThrow(new ConnectorServerException("The connector failed to report on the key import.",
                        HttpStatus.BAD_GATEWAY));

        // when
        // then
        assertThatThrownBy(() -> saga.importKey(terms, RETRY, key, metadata))
                .isInstanceOf(ConnectorServerException.class)
                .hasMessage(KeyImportSaga.UNCONFIRMED);
        verify(keyImportWriter, never()).failUntaken(any(), any());
    }

    @Test
    void importKey_resendsAnOpenAttemptTheConnectorNeverAccepted() throws Exception {
        // given
        openAttempt(attempt);
        when(adapter.importKeyResult(terms.profile(), attempt.uuid(), SENT, "imported key"))
                .thenReturn(new ImportAnswer.NotAccepted());
        List<String> bothSends = Stream.concat(SENT.stream(), keyDigests.stream()).toList();
        KeyImportAttempt resent = new KeyImportAttempt(attempt.uuid(), attempt.keyReference(), KeyImportState.REQUESTED,
                null, attempt.createdAt(), bothSends, null);
        AtomicReference<List<String>> recorded = new AtomicReference<>(SENT);
        when(keyImportWriter.secretDigests(attempt.uuid())).thenAnswer(read -> recorded.get());
        when(keyImportWriter.resending(attempt.uuid(), keyDigests)).thenAnswer(resend -> {
            recorded.set(bothSends);
            return Optional.of(resent);
        });
        when(adapter.importKey(terms, resent, key, "imported key")).thenReturn(imported(key.subjectPublicKeyInfo()));

        // when
        saga.importKey(terms, RETRY, key, metadata);

        // then
        InOrder resend = inOrder(keyImportWriter, adapter);
        resend.verify(keyImportWriter).resending(attempt.uuid(), keyDigests);
        resend.verify(adapter).importKey(terms, resent, key, "imported key");
        verify(keyImportWriter, never()).open(any(), any(), any(), any());
    }

    @Test
    void importKey_doesNotResendAnAttemptThatClosedMeanwhile() throws Exception {
        // given
        openAttempt(attempt);
        when(adapter.importKeyResult(terms.profile(), attempt.uuid(), SENT, "imported key"))
                .thenReturn(new ImportAnswer.NotAccepted());
        when(keyImportWriter.resending(attempt.uuid(), keyDigests)).thenReturn(Optional.empty());

        // when
        // then
        assertThatThrownBy(() -> saga.importKey(terms, RETRY, key, metadata))
                .isInstanceOf(ConnectorServerException.class)
                .hasMessage(KeyImportSaga.UNCONFIRMED);
        verify(adapter, never()).importKey(any(), any(), any(), any());
    }

    @Test
    void importKey_startsAfreshWhenTheOpenAttemptImportedNothing() throws Exception {
        // given
        KeyImportAttempt stale = new KeyImportAttempt(UUID.randomUUID(), UUID.randomUUID(), KeyImportState.ACCEPTED,
                HANDLE, OffsetDateTime.now(), SENT, null);
        openAttempt(stale);
        when(adapter.importKeyResult(terms.profile(), stale.uuid(), SENT, "imported key"))
                .thenReturn(new ImportAnswer.NotImported());
        when(adapter.importKey(terms, attempt, key, "imported key")).thenReturn(imported(key.subjectPublicKeyInfo()));

        // when
        saga.importKey(terms, RETRY, key, metadata);

        // then
        verify(keyImportWriter).failUntaken(stale, KeyImportSaga.NOT_IMPORTED);
        verify(keyImportWriter).open(terms, RETRY, "imported key", keyDigests);
    }

    /**
     * Another request took the open attempt since this one resumed it, so that request settles it: this one neither
     * closes it nor starts another.
     */
    @Test
    void importKey_leavesAnOpenAttemptThatImportedNothingToTheRequestThatTookIt() throws Exception {
        // given
        KeyImportAttempt stale = new KeyImportAttempt(UUID.randomUUID(), UUID.randomUUID(), KeyImportState.ACCEPTED,
                HANDLE, OffsetDateTime.now(), SENT, null);
        openAttempt(stale);
        when(adapter.importKeyResult(terms.profile(), stale.uuid(), SENT, "imported key"))
                .thenReturn(new ImportAnswer.NotImported());
        when(keyImportWriter.failUntaken(stale, KeyImportSaga.NOT_IMPORTED)).thenReturn(false);

        // when
        // then
        assertThatThrownBy(() -> saga.importKey(terms, RETRY, key, metadata))
                .isInstanceOf(ConnectorServerException.class)
                .hasMessage(KeyImportSaga.UNCONFIRMED);
        verify(keyImportWriter, never()).open(any(), any(), any(), any());
    }

    @Test
    void importKey_waitsOnAnOpenAttemptByItsStoredHandle() throws Exception {
        // given
        KeyImportAttempt accepted = new KeyImportAttempt(UUID.randomUUID(), UUID.randomUUID(), KeyImportState.ACCEPTED,
                HANDLE, OffsetDateTime.now(), SENT, null);
        openAttempt(accepted);
        when(adapter.importKeyResult(terms.profile(), accepted.uuid(), SENT, "imported key"))
                .thenReturn(new ImportAnswer.Running(null));
        when(adapter.importKeyStatus(terms.profile(), HANDLE, SENT, "imported key"))
                .thenReturn(imported(key.subjectPublicKeyInfo()));
        when(keyImportWriter.complete(eq(accepted.uuid()), any()))
                .thenReturn(Optional.of(new ImportedKey(registered, ImportOutcome.CREATED)));

        // when
        ImportedKey result = saga.importKey(terms, RETRY, key, metadata);

        // then
        assertThat(result.key()).isSameAs(registered);
        verify(adapter, never()).importKey(any(), any(), any(), any());
    }

    @Test
    void importKey_asksTheRecordedResultAgainForAnAttemptWithoutAHandle() throws Exception {
        // given
        openAttempt(attempt);
        when(adapter.importKeyResult(terms.profile(), attempt.uuid(), SENT, "imported key"))
                .thenReturn(new ImportAnswer.Running(null))
                .thenReturn(imported(key.subjectPublicKeyInfo()));

        // when
        ImportedKey result = saga.importKey(terms, RETRY, key, metadata);

        // then
        assertThat(result.key()).isSameAs(registered);
        verify(adapter, never()).importKeyStatus(any(), any(), any(), any());
    }

    @Test
    void importKey_registersAnOpenAttemptTheConnectorCompleted() throws Exception {
        // given
        openAttempt(attempt);
        when(adapter.importKeyResult(terms.profile(), attempt.uuid(), SENT, "imported key"))
                .thenReturn(imported(key.subjectPublicKeyInfo()));

        // when
        ImportedKey result = saga.importKey(terms, RETRY, key, metadata);

        // then
        assertThat(result.key()).isSameAs(registered);
        verify(adapter, never()).importKey(any(), any(), any(), any());
    }

    /** A request at the attempt again owns it for another retry window, whether it sends it again or not. */
    @Test
    void importKey_takesTheAttemptItResumesForTheRetryWindow() throws Exception {
        // given
        openAttempt(attempt);
        when(adapter.importKeyResult(terms.profile(), attempt.uuid(), SENT, "imported key"))
                .thenReturn(imported(key.subjectPublicKeyInfo()));

        // when
        saga.importKey(terms, RETRY, key, metadata);

        // then
        verify(keyImportWriter).resuming(attempt.uuid());
    }

    /** The key in the token is not the key in the file, so the reconciliation is to destroy it at once. */
    @Test
    void importKey_handsAnImportOfAnotherKeyToTheReconciliation() throws Exception {
        // given
        when(adapter.importKey(terms, attempt, key, "imported key")).thenReturn(imported(new byte[]{9, 9, 9}));

        // when
        // then
        assertThatThrownBy(() -> saga.importKey(terms, RETRY, key, metadata))
                .isInstanceOf(ConnectorServerException.class)
                .hasMessage(KeyImportSaga.UNCONFIRMED);
        verify(keyImportWriter, never()).complete(any(), any());
        verify(keyImportWriter).dueNow(attempt.uuid());
    }

    /** The public key proves the key, and the items must describe it too: an item of another algorithm is refused. */
    @Test
    void importKey_leavesAnImportDescribedWithAnotherAlgorithmOpen() throws Exception {
        // given
        ImportAnswer.Imported answer = imported(key.subjectPublicKeyInfo());
        ProviderKeyItem privateKey = answer.items().get(1);
        ProviderKeyItem mislabelled = new ProviderKeyItem(privateKey.name(), privateKey.type(), KeyAlgorithm.ECDSA,
                privateKey.length(), privateKey.reference(), privateKey.material(), privateKey.metadata());
        when(adapter.importKey(terms, attempt, key, "imported key"))
                .thenReturn(new ImportAnswer.Imported(answer.type(), List.of(answer.items().get(0), mislabelled)));

        // when
        // then
        assertThatThrownBy(() -> saga.importKey(terms, RETRY, key, metadata))
                .isInstanceOf(ConnectorServerException.class)
                .hasMessage(KeyImportSaga.UNCONFIRMED);
        verify(keyImportWriter, never()).complete(any(), any());
    }

    @Test
    void importKey_leavesAnImportOfAnotherTypeOpen() throws Exception {
        // given
        ImportAnswer.Imported asPair = imported(key.subjectPublicKeyInfo());
        when(adapter.importKey(terms, attempt, key, "imported key"))
                .thenReturn(new ImportAnswer.Imported(KeyRequestType.SECRET, asPair.items()));

        // when
        // then
        assertThatThrownBy(() -> saga.importKey(terms, RETRY, key, metadata))
                .isInstanceOf(ConnectorServerException.class)
                .hasMessage(KeyImportSaga.UNCONFIRMED);
        verify(keyImportWriter, never()).complete(any(), any());
    }

    /** A secret key has no public key: it adopts no record, and it is registered without a fingerprint. */
    @Test
    void importKey_registersASecretKeyWithoutAFingerprint() throws Exception {
        // given
        ImportAnswer.Imported answer = importedSecretKey(secretKeyItem(KeyType.SECRET_KEY, KeyAlgorithm.AES, 256));
        when(adapter.importKey(secretKeyTerms, attempt, secretKey, "imported key")).thenReturn(answer);

        // when
        ImportedKey result = saga.importKey(secretKeyTerms, RETRY, secretKey, metadata);

        // then
        assertThat(result.key()).isSameAs(registered);
        ArgumentCaptor<ImportedKeyRegistration> registration = ArgumentCaptor.forClass(ImportedKeyRegistration.class);
        verify(keyImportWriter).complete(eq(attempt.uuid()), registration.capture());
        assertThat(registration.getValue().spkiFingerprint()).isNull();
        assertThat(registration.getValue().items()).isEqualTo(answer.items());
        verify(cryptographicKeyWriter, never()).publicKeyHolder(any());
    }

    /** A secret key has no public key, so the answer must be one secret key of the key's algorithm and length. */
    @ParameterizedTest
    @MethodSource("answersWithAnotherSecretKey")
    void importKey_handsAnImportAnsweredWithAnotherSecretKeyToTheReconciliation(ImportAnswer.Imported answer)
            throws Exception {
        // given
        when(adapter.importKey(secretKeyTerms, attempt, secretKey, "imported key")).thenReturn(answer);

        // when
        // then
        assertThatThrownBy(() -> saga.importKey(secretKeyTerms, RETRY, secretKey, metadata))
                .isInstanceOf(ConnectorServerException.class)
                .hasMessage(KeyImportSaga.UNCONFIRMED);
        verify(keyImportWriter, never()).complete(any(), any());
        verify(keyImportWriter).dueNow(attempt.uuid());
    }

    static Stream<Named<ImportAnswer.Imported>> answersWithAnotherSecretKey() {
        ProviderKeyItem aes = secretKeyItem(KeyType.SECRET_KEY, KeyAlgorithm.AES, 256);
        return Stream
                .of(named("of another algorithm",
                        importedSecretKey(secretKeyItem(KeyType.SECRET_KEY, KeyAlgorithm.UNKNOWN, 256))),
                        named("of another length",
                                importedSecretKey(secretKeyItem(KeyType.SECRET_KEY, KeyAlgorithm.AES, 128))),
                        named("as another kind of item",
                                importedSecretKey(secretKeyItem(KeyType.PRIVATE_KEY, KeyAlgorithm.AES, 256))),
                        named("with a second item",
                                new ImportAnswer.Imported(KeyRequestType.SECRET, List.of(aes, aes))),
                        named("as a key pair", new ImportAnswer.Imported(KeyRequestType.KEY_PAIR, List.of(aes))));
    }

    /** A key registered meanwhile twice over leaves the key the connector holds to the reconciliation. */
    @Test
    void importKey_handsALostRaceToTheReconciliation() throws Exception {
        // given
        when(adapter.importKey(terms, attempt, key, "imported key")).thenReturn(imported(key.subjectPublicKeyInfo()));
        when(keyImportWriter.complete(eq(attempt.uuid()), any())).thenThrow(violationOf(UNIQUE_VIOLATION));

        // when
        // then
        assertThatThrownBy(() -> saga.importKey(terms, RETRY, key, metadata))
                .isInstanceOf(ValidationException.class)
                .hasMessageContaining(CryptographicKeyWriter.KEY_ALREADY_HELD)
                .hasMessageNotContaining(VIOLATION_MESSAGE);
        verify(keyImportWriter, never()).failUntaken(any(), any());
        verify(keyImportWriter, times(2)).complete(eq(attempt.uuid()), any());
        verify(keyImportWriter).dueNow(attempt.uuid());
    }

    /** Only the unique public key shows a key registered meanwhile; any other violation fails the import as it is. */
    @Test
    void importKey_failsOnAnIntegrityViolationOtherThanTheUniquePublicKey() throws Exception {
        // given
        DataIntegrityViolationException another = violationOf(FOREIGN_KEY_VIOLATION);
        when(adapter.importKey(terms, attempt, key, "imported key")).thenReturn(imported(key.subjectPublicKeyInfo()));
        when(keyImportWriter.complete(eq(attempt.uuid()), any())).thenThrow(another);

        // when
        // then
        assertThatThrownBy(() -> saga.importKey(terms, RETRY, key, metadata)).isSameAs(another);
        verify(keyImportWriter).complete(eq(attempt.uuid()), any());
        verify(keyImportWriter).dueNow(attempt.uuid());
    }

    @Test
    void importKey_failsWhenTheSecondRegistrationMeetsAnotherViolation() throws Exception {
        // given
        DataIntegrityViolationException another = violationOf(FOREIGN_KEY_VIOLATION);
        when(adapter.importKey(terms, attempt, key, "imported key")).thenReturn(imported(key.subjectPublicKeyInfo()));
        when(keyImportWriter.complete(eq(attempt.uuid()), any()))
                .thenThrow(violationOf(UNIQUE_VIOLATION))
                .thenThrow(another);

        // when
        // then
        assertThatThrownBy(() -> saga.importKey(terms, RETRY, key, metadata)).isSameAs(another);
        verify(keyImportWriter, times(2)).complete(eq(attempt.uuid()), any());
        verify(keyImportWriter).dueNow(attempt.uuid());
    }

    /**
     * A record that came to hold the public key while the key was registered makes the registration fail; the second
     * one takes the record, once its requester is shown to be allowed to update it.
     */
    @ParameterizedTest
    @MethodSource("registeredMeanwhile")
    void importKey_registersOnceMoreWhenARecordCameToHoldThePublicKey(RuntimeException registeredMeanwhile)
            throws Exception {
        // given
        UUID recordUuid = UUID.randomUUID();
        when(adapter.importKey(terms, attempt, key, "imported key")).thenReturn(imported(key.subjectPublicKeyInfo()));
        when(keyImportGates.adoptableBy(terms.requester(), "fingerprint"))
                .thenReturn(Optional.empty(), Optional.of(recordUuid));
        when(keyImportWriter.complete(eq(attempt.uuid()), any()))
                .thenThrow(registeredMeanwhile)
                .thenReturn(Optional.of(new ImportedKey(registered, ImportOutcome.ADOPTED)));

        // when
        ImportedKey result = saga.importKey(terms, RETRY, key, metadata);

        // then
        assertThat(result.outcome()).isEqualTo(ImportOutcome.ADOPTED);
        ArgumentCaptor<ImportedKeyRegistration> registrations = ArgumentCaptor.forClass(ImportedKeyRegistration.class);
        verify(keyImportWriter, times(2)).complete(eq(attempt.uuid()), registrations.capture());
        assertThat(registrations.getAllValues())
                .extracting(ImportedKeyRegistration::adoptableRecord)
                .containsExactly(null, recordUuid);
        verify(keyImportWriter, never()).dueNow(any());
    }

    static Stream<Named<RuntimeException>> registeredMeanwhile() {
        return Stream
                .of(named("found once the public key was looked for",
                        new CryptographicKeyWriter.UncheckedRecordException()),
                        named("found by the unique fingerprint", violationOf(UNIQUE_VIOLATION)));
    }

    /** A record that appeared meanwhile, which the requester may not update, is not taken: the import is refused. */
    @Test
    void importKey_refusesARecordThatAppearedMeanwhileWhenItsRequesterMayNotUpdateIt() throws Exception {
        // given
        when(adapter.importKey(terms, attempt, key, "imported key")).thenReturn(imported(key.subjectPublicKeyInfo()));
        when(keyImportGates.adoptableBy(terms.requester(), "fingerprint"))
                .thenReturn(Optional.empty())
                .thenThrow(new ValidationException(ValidationError.create(CryptographicKeyWriter.KEY_ALREADY_HELD)));
        when(keyImportWriter.complete(eq(attempt.uuid()), any())).thenThrow(violationOf(UNIQUE_VIOLATION));

        // when
        // then
        assertThatThrownBy(() -> saga.importKey(terms, RETRY, key, metadata))
                .isInstanceOf(ValidationException.class)
                .hasMessageContaining(CryptographicKeyWriter.KEY_ALREADY_HELD);
        verify(keyImportWriter).complete(eq(attempt.uuid()), any());
        verify(keyImportWriter).dueNow(attempt.uuid());
    }

    /** The registration takes only the record its requester was shown, just before, to be allowed to update. */
    @Test
    void importKey_registersTheKeyIntoTheRecordItsRequesterMayUpdate() throws Exception {
        // given
        UUID recordUuid = UUID.randomUUID();
        when(adapter.importKey(terms, attempt, key, "imported key")).thenReturn(imported(key.subjectPublicKeyInfo()));
        when(keyImportGates.adoptableBy(terms.requester(), "fingerprint")).thenReturn(Optional.of(recordUuid));

        // when
        saga.importKey(terms, RETRY, key, metadata);

        // then
        ArgumentCaptor<ImportedKeyRegistration> registration = ArgumentCaptor.forClass(ImportedKeyRegistration.class);
        verify(keyImportWriter).complete(eq(attempt.uuid()), registration.capture());
        assertThat(registration.getValue().adoptableRecord()).isEqualTo(recordUuid);
        assertThat(registration.getValue().owner()).isEqualTo(terms.requester());
    }

    /**
     * An import into a public-key-only record needs the right to update the record; the record keeps its name, so the
     * name the import states need not be free, and the imported key's items are registered under the record's name.
     */
    @Test
    void importKey_importsIntoARecordTheCallerMayUpdateUnderTheRecordsName() throws Exception {
        // given
        PublicKeyHolder adoptable = publicKeyRecord(UUID.randomUUID());
        when(cryptographicKeyWriter.publicKeyHolder("fingerprint")).thenReturn(Optional.of(adoptable));
        when(cryptographicKeyRepository.existsByName("imported key")).thenReturn(true);
        when(keyImportWriter.open(terms, RETRY, "certificate key", keyDigests)).thenReturn(attempt);
        when(adapter.importKey(terms, attempt, key, "certificate key"))
                .thenReturn(imported(key.subjectPublicKeyInfo()));

        // when
        ImportedKey result = saga.importKey(terms, RETRY, key, metadata);

        // then
        assertThat(result.key()).isSameAs(registered);
        verify(keyImportGates, times(2)).requireImportableInto(adoptable);
        verify(cryptographicKeyRepository, never()).existsByName(any());
    }

    /** A caller who may not update the record is refused before anything is recorded or asked. */
    @Test
    void importKey_refusesARecordTheCallerMayNotUpdateBeforeAnAttemptOpens() {
        // given
        PublicKeyHolder adoptable = publicKeyRecord(UUID.randomUUID());
        when(cryptographicKeyWriter.publicKeyHolder("fingerprint")).thenReturn(Optional.of(adoptable));
        doThrow(new ValidationException(ValidationError.create(CryptographicKeyWriter.KEY_ALREADY_HELD)))
                .when(keyImportGates)
                .requireImportableInto(adoptable);

        // when
        // then
        assertThatThrownBy(() -> saga.importKey(terms, RETRY, key, metadata))
                .isInstanceOf(ValidationException.class)
                .hasMessageContaining(CryptographicKeyWriter.KEY_ALREADY_HELD);
        verify(keyImportWriter, never()).open(any(), any(), any(), any());
        verifyNoInteractions(adapter, eventHistory);
    }

    /** A retry would be refused the same way, so the key the connector holds is left to the reconciliation. */
    @Test
    void importKey_handsAKeyThePlatformRefusesToRegisterToTheReconciliation() throws Exception {
        // given
        when(adapter.importKey(terms, attempt, key, "imported key")).thenReturn(imported(key.subjectPublicKeyInfo()));
        when(keyImportWriter.complete(eq(attempt.uuid()), any()))
                .thenThrow(new ValidationException(ValidationError.create(CryptographicKeyWriter.KEY_NOT_ACTIVE)));

        // when
        // then
        assertThatThrownBy(() -> saga.importKey(terms, RETRY, key, metadata))
                .isInstanceOf(ValidationException.class)
                .hasMessageContaining(CryptographicKeyWriter.KEY_NOT_ACTIVE);
        verify(keyImportWriter).dueNow(attempt.uuid());
    }

    @Test
    void importKey_refusesAnImportOfAKeyAlreadyBeingImported() {
        // given
        when(keyImportWriter.open(terms, RETRY, "imported key", keyDigests))
                .thenThrow(new DataIntegrityViolationException("uq_key_import_open_attempt"));

        // when
        // then
        assertThatThrownBy(() -> saga.importKey(terms, RETRY, key, metadata))
                .isInstanceOf(ValidationException.class)
                .hasMessageContaining(KeyImportSaga.ALREADY_IMPORTING)
                .hasMessageNotContaining("uq_key_import_open_attempt");
    }

    @Test
    void importKey_leavesAnAttemptClosedMeanwhileUnconfirmed() throws Exception {
        // given
        when(adapter.importKey(terms, attempt, key, "imported key")).thenReturn(imported(key.subjectPublicKeyInfo()));
        when(keyImportWriter.complete(eq(attempt.uuid()), any())).thenReturn(Optional.empty());

        // when
        // then
        assertThatThrownBy(() -> saga.importKey(terms, RETRY, key, metadata))
                .isInstanceOf(ConnectorServerException.class)
                .hasMessage(KeyImportSaga.UNCONFIRMED);
    }

    @Test
    void importKey_closesItsAttemptUnsentWhenTheSameImportCompletedMeanwhile() throws Exception {
        // given
        KeyImport completed = new KeyImport();
        completed.setKeyUuid(UUID.randomUUID());
        when(keyImportRepository
                .findFirstByIdempotencyKeyAndStateInOrderByCreatedAtDesc(RETRY, Set.of(KeyImportState.COMPLETED)))
                .thenReturn(Optional.empty(), Optional.of(completed));
        when(keyImportWriter.registeredKey(completed.getKeyUuid())).thenReturn(Optional.of(registered));

        // when
        ImportedKey result = saga.importKey(terms, RETRY, key, metadata);

        // then
        assertThat(result.key()).isSameAs(registered);
        assertThat(result.outcome()).isEqualTo(ImportOutcome.EXISTING);
        verify(keyImportWriter).failUntaken(eq(attempt), anyString());
        verify(adapter, never()).importKey(any(), any(), any(), any());
    }

    /** Another import registered the key after this one looked; this one changes nothing and sends nothing. */
    @Test
    void importKey_closesItsAttemptUnsentWhenTheKeyWasRegisteredMeanwhile() throws Exception {
        // given
        CryptographicKeyFullModel held = mock(CryptographicKeyFullModel.class);
        when(cryptographicKeyWriter.publicKeyHolder("fingerprint"))
                .thenReturn(Optional.empty())
                .thenReturn(Optional.of(new PublicKeyHolder(held, UUID.randomUUID(), Holding.KEY_PAIR)));

        // when
        ImportedKey result = saga.importKey(terms, RETRY, key, metadata);

        // then
        assertThat(result.key()).isSameAs(held);
        assertThat(result.outcome()).isEqualTo(ImportOutcome.EXISTING);
        verify(keyImportWriter).failUntaken(eq(attempt), anyString());
        verify(adapter, never()).importKey(any(), any(), any(), any());
    }

    @Test
    void importKey_closesItsAttemptUnsentWhenTheRecordIsNoLongerActive() throws Exception {
        // given
        when(cryptographicKeyWriter.publicKeyHolder("fingerprint"))
                .thenReturn(Optional.empty())
                .thenThrow(new ValidationException(ValidationError.create(CryptographicKeyWriter.KEY_NOT_ACTIVE)));

        // when
        // then
        assertThatThrownBy(() -> saga.importKey(terms, RETRY, key, metadata))
                .isInstanceOf(ValidationException.class)
                .hasMessageContaining(CryptographicKeyWriter.KEY_NOT_ACTIVE);
        verify(keyImportWriter).failUntaken(attempt, CryptographicKeyWriter.KEY_NOT_ACTIVE);
        verify(adapter, never()).importKey(any(), any(), any(), any());
    }

    /** Past the connector's retention a missing record no longer means the import was never accepted. */
    @Test
    void importKey_doesNotSendAgainAnAttemptTheConnectorMayNoLongerRecord() throws Exception {
        // given
        KeyImportAttempt old = new KeyImportAttempt(UUID.randomUUID(), UUID.randomUUID(), KeyImportState.REQUESTED,
                null, OffsetDateTime.now().minusHours(21), SENT, null);
        openAttempt(old);
        when(adapter.importKeyResult(terms.profile(), old.uuid(), SENT, "imported key"))
                .thenReturn(new ImportAnswer.NotAccepted());

        // when
        // then
        assertThatThrownBy(() -> saga.importKey(terms, RETRY, key, metadata))
                .isInstanceOf(ConnectorServerException.class)
                .hasMessage(KeyImportSaga.UNCONFIRMED);
        verify(adapter, never()).importKey(any(), any(), any(), any());
        verify(keyImportWriter, never()).failUntaken(any(), any());
    }

    // ---- fixtures ----

    /** A public-key-only record holding the key's public key, as the platform holds a certificate's key. */
    private static PublicKeyHolder publicKeyRecord(UUID publicKeyItemUuid) {
        CryptographicKeyFullModel publicKeyOnly = mock(CryptographicKeyFullModel.class);
        when(publicKeyOnly.uuid()).thenReturn(UUID.randomUUID());
        when(publicKeyOnly.name()).thenReturn("certificate key");
        return new PublicKeyHolder(publicKeyOnly, publicKeyItemUuid, Holding.PUBLIC_KEY_ONLY);
    }

    private void openAttempt(KeyImportAttempt open) {
        KeyImport row = new KeyImport();
        row.setUuid(open.uuid());
        row.setKeyReference(open.keyReference());
        row.setState(open.state());
        row.setOperationMeta(open.operationMeta());
        row.setCreatedAt(open.createdAt());
        row.setSecretDigests(open.secretDigests());
        when(keyImportRepository
                .findFirstByIdempotencyKeyAndStateInOrderByCreatedAtDesc(RETRY,
                        Set.of(KeyImportState.REQUESTED, KeyImportState.ACCEPTED)))
                .thenReturn(Optional.of(row));
        when(keyImportWriter.resuming(open.uuid())).thenReturn(open);
    }

    private static ImportAnswer.Imported imported(byte[] spki) {
        ProviderKeyItem publicKey = new ProviderKeyItem("imported key public key", KeyType.PUBLIC_KEY, KeyAlgorithm.RSA,
                2048, new RemoteKeyReference.MetadataReference(List.of(meta("public"))),
                new KeyMaterial(KeyFormat.SPKI, Base64.getEncoder().encodeToString(spki)), List.of());
        ProviderKeyItem privateKey = new ProviderKeyItem("imported key private key", KeyType.PRIVATE_KEY,
                KeyAlgorithm.RSA, 2048, new RemoteKeyReference.MetadataReference(List.of(meta("private"))), null,
                List.of());
        return new ImportAnswer.Imported(KeyRequestType.KEY_PAIR, List.of(publicKey, privateKey));
    }

    private static ImportAnswer.Imported importedSecretKey(ProviderKeyItem item) {
        return new ImportAnswer.Imported(KeyRequestType.SECRET, List.of(item));
    }

    private static ProviderKeyItem secretKeyItem(KeyType type, KeyAlgorithm algorithm, int length) {
        return new ProviderKeyItem("imported key", type, algorithm, length,
                new RemoteKeyReference.MetadataReference(List.of(meta("secret"))), null, List.of());
    }

    private static MetadataAttribute meta(String name) {
        MetadataAttributeV2 attribute = new MetadataAttributeV2();
        attribute.setName(name);
        return attribute;
    }

    /**
     * A violation shaped the way PostgreSQL delivers one through Hibernate: of kind OTHER whatever the constraint, with
     * the SQL state in the JDBC cause.
     */
    private static DataIntegrityViolationException violationOf(String sqlState) {
        return new DataIntegrityViolationException(VIOLATION_MESSAGE, new ConstraintViolationException(
                VIOLATION_MESSAGE, new SQLException(VIOLATION_MESSAGE, sqlState), ConstraintKind.OTHER, "constraint"));
    }
}
