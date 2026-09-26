package com.otilm.core.service.handler;

import com.otilm.api.exception.ConnectorServerException;
import com.otilm.api.exception.ValidationError;
import com.otilm.api.exception.ValidationException;
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
import com.otilm.core.config.KeyImportProperties;
import com.otilm.core.dao.entity.CryptographicKey;
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
import java.time.Duration;
import java.time.OffsetDateTime;
import java.util.Base64;
import java.util.List;
import java.util.Optional;
import java.util.Set;
import java.util.UUID;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.mockito.InOrder;
import org.springframework.dao.DataIntegrityViolationException;
import org.springframework.http.HttpStatus;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.junit.jupiter.api.Assertions.assertTimeoutPreemptively;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.inOrder;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

class KeyImportSagaTest {

    private static final String RETRY = "retry";

    private static final List<String> SENT = List.of("sent-secret-digest");
    private static final List<MetadataAttribute> HANDLE = List.of(meta("operation"));

    private final KeyImportRepository keyImportRepository = mock(KeyImportRepository.class);
    private final CryptographicKeyRepository cryptographicKeyRepository = mock(CryptographicKeyRepository.class);
    private final CryptographicKeyWriter cryptographicKeyWriter = mock(CryptographicKeyWriter.class);
    private final KeyImportWriter keyImportWriter = mock(KeyImportWriter.class);
    private final CryptographicKeyEventHistoryService eventHistory = mock(CryptographicKeyEventHistoryService.class);
    private final KeyProviderAdapterFactory adapterFactory = mock(KeyProviderAdapterFactory.class);
    private final KeyProviderAdapter adapter = mock(KeyProviderAdapter.class);
    private final CryptographicKeyFullModel registered = mock(CryptographicKeyFullModel.class);

    private KeyImportSaga saga;
    private KeyImportTerms terms;
    private NormalizedKey key;
    private KeyImportMetadata metadata;
    private KeyImportAttempt attempt;
    private List<String> keyDigests;

    @BeforeEach
    void setUp() throws Exception {
        saga = new KeyImportSaga(keyImportRepository, cryptographicKeyRepository, cryptographicKeyWriter,
                keyImportWriter, eventHistory, adapterFactory,
                new KeyImportProperties(Duration.ofMillis(300), Duration.ofMillis(10), Duration.ofHours(20)));
        TokenProfileFullModel profile = mock(TokenProfileFullModel.class);
        TokenInstanceFullModel token = mock(TokenInstanceFullModel.class);
        when(profile.tokenInstance()).thenReturn(token);
        when(adapterFactory.forToken(token)).thenReturn(adapter);
        KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
        generator.initialize(2048);
        byte[] spki = generator.generateKeyPair().getPublic().getEncoded();
        key = new NormalizedKey(KeyAlgorithm.RSA, spki, new byte[]{1}, new Passphrase("transport".toCharArray()));
        keyDigests = OutboundSecretContainment.digestsOf(key.transportSecrets());
        terms = new KeyImportTerms(profile, KeyRequestType.KEY_PAIR, KeyAlgorithm.RSA, "fingerprint", false, List.of(),
                new NameAndUuidDto(UUID.randomUUID().toString(), "requester"));
        metadata = new KeyImportMetadata("imported key", null, Set.of(), List.of());
        attempt = new KeyImportAttempt(UUID.randomUUID(), UUID.randomUUID(), KeyImportState.REQUESTED, null,
                OffsetDateTime.now(), SENT);
        when(cryptographicKeyRepository.findByName(anyString())).thenReturn(Optional.empty());
        when(cryptographicKeyWriter.adoptablePublicKey("fingerprint")).thenReturn(Optional.empty());
        when(keyImportRepository.findFirstByIdempotencyKeyAndStateInOrderByCreatedAtDesc(eq(RETRY), any()))
                .thenReturn(Optional.empty());
        when(keyImportWriter.open(terms, RETRY, "imported key", keyDigests)).thenReturn(attempt);
        when(keyImportWriter.complete(eq(attempt.uuid()), any()))
                .thenReturn(Optional.of(new ImportedKey(registered, false)));
    }

    @Test
    void importKey_registersTheKeyTheConnectorImported() throws Exception {
        // given
        when(adapter.importKey(terms, attempt, key, "imported key")).thenReturn(imported(key.subjectPublicKeyInfo()));

        // when
        ImportedKey result = saga.importKey(terms, RETRY, key, metadata);

        // then
        assertThat(result.key()).isSameAs(registered);
        assertThat(result.repeat()).isFalse();
        verify(keyImportWriter).complete(eq(attempt.uuid()), any(ImportedKeyRegistration.class));
        verify(keyImportWriter, never()).fail(any(), any());
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
        when(cryptographicKeyRepository.findByName("imported key")).thenReturn(Optional.of(new CryptographicKey()));

        // when
        ImportedKey result = saga.importKey(terms, RETRY, key, metadata);

        // then
        assertThat(result.key()).isSameAs(registered);
        assertThat(result.repeat()).isTrue();
        verify(keyImportWriter, never()).open(any(), any(), any(), any());
    }

    @Test
    void importKey_refusesANameAnotherKeyHas() {
        // given
        when(cryptographicKeyRepository.findByName("imported key")).thenReturn(Optional.of(new CryptographicKey()));

        // when
        // then
        assertThatThrownBy(() -> saga.importKey(terms, RETRY, key, metadata))
                .isInstanceOf(ValidationException.class)
                .hasMessageContaining("A key named imported key already exists.");
        verify(keyImportWriter, never()).open(any(), any(), any(), any());
    }

    @ParameterizedTest
    @ValueSource(strings = {CryptographicKeyWriter.KEY_ALREADY_HELD, CryptographicKeyWriter.KEY_NOT_ACTIVE})
    void importKey_refusesAPublicKeyThePlatformHoldsBeforeAnAttemptOpens(String refusal) {
        // given
        when(cryptographicKeyWriter.adoptablePublicKey("fingerprint"))
                .thenThrow(new ValidationException(ValidationError.create(refusal)));

        // when
        // then
        assertThatThrownBy(() -> saga.importKey(terms, RETRY, key, metadata))
                .isInstanceOf(ValidationException.class)
                .hasMessageContaining(refusal);
        verify(keyImportWriter, never()).open(any(), any(), any(), any());
    }

    @Test
    void importKey_recordsTheFailureOnThePublicKeyItWouldAdopt() throws Exception {
        // given
        UUID publicKeyUuid = UUID.randomUUID();
        when(cryptographicKeyWriter.adoptablePublicKey("fingerprint")).thenReturn(Optional.of(publicKeyUuid));
        when(adapter.importKey(terms, attempt, key, "imported key"))
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
        verify(keyImportWriter).fail(attempt.uuid(), "refused (KEY_DECRYPTION_FAILED)");
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
        verify(keyImportWriter, never()).fail(any(), any());
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
        verify(keyImportWriter).fail(attempt.uuid(), KeyImportSaga.CANCELLED.formatted(0));
    }

    /** A poll interval longer than the time an import may take does not hold the request past its deadline. */
    @Test
    void importKey_cancelsInTimeWhenThePollIntervalOutlastsTheDeadline() throws Exception {
        // given
        KeyImportSaga impatient = new KeyImportSaga(keyImportRepository, cryptographicKeyRepository,
                cryptographicKeyWriter, keyImportWriter, eventHistory, adapterFactory,
                new KeyImportProperties(Duration.ofMillis(100), Duration.ofHours(1), Duration.ofHours(20)));
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
        verify(keyImportWriter, never()).fail(any(), any());
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
        verify(keyImportWriter).fail(attempt.uuid(), KeyImportSaga.NOT_IMPORTED);
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
        verify(keyImportWriter, never()).fail(any(), any());
    }

    @Test
    void importKey_resendsAnOpenAttemptTheConnectorNeverAccepted() throws Exception {
        // given
        openAttempt(attempt);
        when(adapter.importKeyResult(terms.profile(), attempt.uuid(), SENT, "imported key"))
                .thenReturn(new ImportAnswer.NotAccepted());
        KeyImportAttempt resent = new KeyImportAttempt(attempt.uuid(), attempt.keyReference(), KeyImportState.REQUESTED,
                null, attempt.createdAt(), keyDigests);
        when(keyImportWriter.resending(attempt.uuid(), keyDigests)).thenReturn(Optional.of(resent));
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
                HANDLE, OffsetDateTime.now(), SENT);
        openAttempt(stale);
        when(adapter.importKeyResult(terms.profile(), stale.uuid(), SENT, "imported key"))
                .thenReturn(new ImportAnswer.NotImported());
        when(adapter.importKey(terms, attempt, key, "imported key")).thenReturn(imported(key.subjectPublicKeyInfo()));

        // when
        saga.importKey(terms, RETRY, key, metadata);

        // then
        verify(keyImportWriter).fail(stale.uuid(), KeyImportSaga.NOT_IMPORTED);
        verify(keyImportWriter).open(terms, RETRY, "imported key", keyDigests);
    }

    @Test
    void importKey_waitsOnAnOpenAttemptByItsStoredHandle() throws Exception {
        // given
        KeyImportAttempt accepted = new KeyImportAttempt(UUID.randomUUID(), UUID.randomUUID(), KeyImportState.ACCEPTED,
                HANDLE, OffsetDateTime.now(), SENT);
        openAttempt(accepted);
        when(adapter.importKeyResult(terms.profile(), accepted.uuid(), SENT, "imported key"))
                .thenReturn(new ImportAnswer.Running(null));
        when(adapter.importKeyStatus(terms.profile(), HANDLE, SENT, "imported key"))
                .thenReturn(imported(key.subjectPublicKeyInfo()));
        when(keyImportWriter.complete(eq(accepted.uuid()), any()))
                .thenReturn(Optional.of(new ImportedKey(registered, false)));

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

    @Test
    void importKey_leavesAnImportOfAnotherKeyOpen() throws Exception {
        // given
        when(adapter.importKey(terms, attempt, key, "imported key")).thenReturn(imported(new byte[]{9, 9, 9}));

        // when
        // then
        assertThatThrownBy(() -> saga.importKey(terms, RETRY, key, metadata))
                .isInstanceOf(ConnectorServerException.class)
                .hasMessage(KeyImportSaga.UNCONFIRMED);
        verify(keyImportWriter, never()).complete(any(), any());
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

    @Test
    void importKey_refusesAKeyRegisteredMeanwhileAndLeavesTheAttemptOpen() throws Exception {
        // given
        when(adapter.importKey(terms, attempt, key, "imported key")).thenReturn(imported(key.subjectPublicKeyInfo()));
        when(keyImportWriter.complete(eq(attempt.uuid()), any()))
                .thenThrow(new DataIntegrityViolationException("duplicate fingerprint"));

        // when
        // then
        assertThatThrownBy(() -> saga.importKey(terms, RETRY, key, metadata))
                .isInstanceOf(ValidationException.class)
                .hasMessageContaining(CryptographicKeyWriter.KEY_ALREADY_HELD)
                .hasMessageNotContaining("duplicate fingerprint");
        verify(keyImportWriter, never()).fail(any(), any());
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
        assertThat(result.repeat()).isTrue();
        verify(keyImportWriter).failUnsent(eq(attempt), anyString());
        verify(adapter, never()).importKey(any(), any(), any(), any());
    }

    @Test
    void importKey_closesItsAttemptUnsentWhenTheKeyWasRegisteredMeanwhile() throws Exception {
        // given
        when(cryptographicKeyWriter.adoptablePublicKey("fingerprint"))
                .thenReturn(Optional.empty())
                .thenThrow(new ValidationException(ValidationError.create(CryptographicKeyWriter.KEY_ALREADY_HELD)));

        // when
        // then
        assertThatThrownBy(() -> saga.importKey(terms, RETRY, key, metadata))
                .isInstanceOf(ValidationException.class)
                .hasMessageContaining(CryptographicKeyWriter.KEY_ALREADY_HELD);
        verify(keyImportWriter).failUnsent(attempt, CryptographicKeyWriter.KEY_ALREADY_HELD);
        verify(adapter, never()).importKey(any(), any(), any(), any());
    }

    /** Past the connector's retention a missing record no longer means the import was never accepted. */
    @Test
    void importKey_doesNotSendAgainAnAttemptTheConnectorMayNoLongerRecord() throws Exception {
        // given
        KeyImportAttempt old = new KeyImportAttempt(UUID.randomUUID(), UUID.randomUUID(), KeyImportState.REQUESTED,
                null, OffsetDateTime.now().minusHours(21), SENT);
        openAttempt(old);
        when(adapter.importKeyResult(terms.profile(), old.uuid(), SENT, "imported key"))
                .thenReturn(new ImportAnswer.NotAccepted());

        // when
        // then
        assertThatThrownBy(() -> saga.importKey(terms, RETRY, key, metadata))
                .isInstanceOf(ConnectorServerException.class)
                .hasMessage(KeyImportSaga.UNCONFIRMED);
        verify(adapter, never()).importKey(any(), any(), any(), any());
        verify(keyImportWriter, never()).fail(any(), any());
    }

    // ---- fixtures ----

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

    private static MetadataAttribute meta(String name) {
        MetadataAttributeV2 attribute = new MetadataAttributeV2();
        attribute.setName(name);
        return attribute;
    }
}
