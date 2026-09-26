package com.otilm.core.service.handler;

import com.otilm.api.exception.AttributeException;
import com.otilm.api.exception.ConnectorException;
import com.otilm.api.exception.ConnectorServerException;
import com.otilm.api.exception.NotFoundException;
import com.otilm.api.exception.PlatformException;
import com.otilm.api.exception.ValidationError;
import com.otilm.api.exception.ValidationException;
import com.otilm.api.model.common.attribute.common.MetadataAttribute;
import com.otilm.api.model.core.cryptography.key.KeyEvent;
import com.otilm.api.model.core.cryptography.key.KeyEventStatus;
import com.otilm.core.attribute.engine.OutboundSecretContainment;
import com.otilm.core.config.KeyImportProperties;
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
import com.otilm.core.service.CryptographicKeyEventHistoryService;
import com.otilm.core.service.handler.key.ImportAnswer;
import com.otilm.core.service.handler.key.KeyProviderAdapter;
import com.otilm.core.service.handler.key.KeyProviderAdapterFactory;
import com.otilm.core.service.writer.CryptographicKeyWriter;
import com.otilm.core.service.writer.KeyImportWriter;
import java.time.Duration;
import java.time.Instant;
import java.util.Base64;
import java.util.EnumSet;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import java.util.Set;
import java.util.UUID;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.dao.DataIntegrityViolationException;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Component;

/**
 * Carries a normalized key across the connector boundary and into the inventory, so that the platform and the connector
 * never disagree about what was imported. The attempt is recorded before the connector is asked; it is closed as failed
 * only when the connector says nothing was imported, and completed only with a key that is the key in the file. Any
 * other outcome leaves it open, for a retry or the reconciliation to learn what the connector holds.
 */
@Component
public class KeyImportSaga {

    public static final String NAME_TAKEN = "A key named %s already exists.";
    public static final String UNCONFIRMED = "The key import was not confirmed. Retry it to learn its outcome.";
    public static final String NOT_IMPORTED = "The connector could not import the key.";
    public static final String CANCELLED = "The key import did not finish within %d seconds and was cancelled.";
    public static final String ALREADY_IMPORTING = "The same key is already being imported. Try again once that import has finished.";

    private static final String IMPORT_FAILED = "Key import failed.";

    private static final String COMPLETED_MEANWHILE = "The same import completed meanwhile.";

    private static final Logger logger = LoggerFactory.getLogger(KeyImportSaga.class);

    private static final Set<KeyImportState> OPEN = EnumSet.of(KeyImportState.REQUESTED, KeyImportState.ACCEPTED);

    private final KeyImportRepository keyImportRepository;
    private final CryptographicKeyRepository cryptographicKeyRepository;
    private final CryptographicKeyWriter cryptographicKeyWriter;
    private final KeyImportWriter keyImportWriter;
    private final CryptographicKeyEventHistoryService eventHistoryService;
    private final KeyProviderAdapterFactory keyProviderAdapterFactory;
    private final KeyImportProperties properties;

    public KeyImportSaga(KeyImportRepository keyImportRepository, CryptographicKeyRepository cryptographicKeyRepository,
            CryptographicKeyWriter cryptographicKeyWriter, KeyImportWriter keyImportWriter,
            CryptographicKeyEventHistoryService eventHistoryService,
            KeyProviderAdapterFactory keyProviderAdapterFactory, KeyImportProperties properties) {
        this.keyImportRepository = keyImportRepository;
        this.cryptographicKeyRepository = cryptographicKeyRepository;
        this.cryptographicKeyWriter = cryptographicKeyWriter;
        this.keyImportWriter = keyImportWriter;
        this.eventHistoryService = eventHistoryService;
        this.keyProviderAdapterFactory = keyProviderAdapterFactory;
        this.properties = properties;
    }

    /**
     * Imports the key into the token profile and registers it. A repeat of an import already registered answers with
     * its key; otherwise the name and the public key are checked against what the platform holds, and an open attempt
     * of the same import is resumed rather than a second one started. A failure of an import that would adopt a
     * public-key-only record is recorded in that record's history.
     *
     * @param idempotencyKey what makes a later request the same import
     * @return the registered key
     */
    public ImportedKey importKey(KeyImportTerms terms, String idempotencyKey, NormalizedKey key,
            KeyImportMetadata metadata) throws ConnectorException, NotFoundException, AttributeException {
        Optional<CryptographicKeyFullModel> repeated = repeatedImport(idempotencyKey);
        if (repeated.isPresent()) {
            return new ImportedKey(repeated.get(), true);
        }
        requireNameFree(metadata.name());
        Optional<UUID> adoptedPublicKey = cryptographicKeyWriter.adoptablePublicKey(terms.spkiFingerprint());
        try {
            Call call = new Call(keyProviderAdapterFactory.forToken(terms.profile().tokenInstance()), terms, key,
                    metadata);
            Optional<Progress> resumed = resumed(call, idempotencyKey);
            if (resumed.isPresent()) {
                return registered(call, resumed.get().attempt(), awaited(call, resumed.get()));
            }
            return begun(call, idempotencyKey);
        } catch (ConnectorException | NotFoundException | AttributeException | RuntimeException e) {
            adoptedPublicKey.ifPresent(publicKey -> recordFailure(publicKey, e));
            throw e;
        }
    }

    private Optional<CryptographicKeyFullModel> repeatedImport(String idempotencyKey) {
        return keyImportRepository
                .findFirstByIdempotencyKeyAndStateInOrderByCreatedAtDesc(idempotencyKey,
                        Set.of(KeyImportState.COMPLETED))
                .flatMap(completed -> keyImportWriter.registeredKey(completed.getKeyUuid()));
    }

    private void requireNameFree(String name) {
        if (cryptographicKeyRepository.findByName(name).isPresent()) {
            throw new ValidationException(ValidationError.create(NAME_TAKEN.formatted(name)));
        }
    }

    /**
     * An open attempt of the same import, resumed from the connector's record of it: one the connector never accepted
     * is sent again under its own identifier, while the connector still keeps its records; one that ended without a key
     * is closed, so the import starts afresh.
     */
    private Optional<Progress> resumed(Call call, String idempotencyKey) throws ConnectorServerException {
        Optional<KeyImportAttempt> open = keyImportRepository
                .findFirstByIdempotencyKeyAndStateInOrderByCreatedAtDesc(idempotencyKey, OPEN)
                .map(KeyImportAttempt::of);
        if (open.isEmpty()) {
            return Optional.empty();
        }
        KeyImportAttempt attempt = open.get();
        ImportAnswer recorded = polled(call, attempt, null);
        if (recorded instanceof ImportAnswer.NotAccepted) {
            if (pastRetention(attempt)) {
                throw unconfirmed(attempt);
            }
            Optional<KeyImportAttempt> resent = keyImportWriter.resending(attempt.uuid(), secretDigests(call));
            if (resent.isEmpty()) {
                throw unconfirmed(attempt);
            }
            return Optional.of(new Progress(resent.get(), sent(call, resent.get())));
        }
        if (recorded instanceof ImportAnswer.NotImported) {
            keyImportWriter.fail(attempt.uuid(), NOT_IMPORTED);
            return Optional.empty();
        }
        return Optional.of(new Progress(attempt, recorded));
    }

    /**
     * Whether the connector may no longer keep a record of the attempt, so that its not knowing the attempt no longer
     * shows the attempt was never accepted.
     */
    private boolean pastRetention(KeyImportAttempt attempt) {
        return attempt.createdAt().toInstant().plus(properties.unresolvedAfter()).isBefore(Instant.now());
    }

    /**
     * Records a new attempt and imports the key through it. When the same import completed, or the key can no longer be
     * imported as a new key or into its record, after this request looked, the attempt is closed unsent: the key it
     * would put in the token could not be registered.
     */
    private ImportedKey begun(Call call, String idempotencyKey)
            throws ConnectorServerException, NotFoundException, AttributeException {
        KeyImportAttempt attempt;
        try {
            attempt = keyImportWriter.open(call.terms(), idempotencyKey, call.metadata().name(), secretDigests(call));
        } catch (DataIntegrityViolationException anotherOpen) {
            throw new ValidationException(ValidationError.create(ALREADY_IMPORTING));
        }
        Optional<CryptographicKeyFullModel> meanwhile = repeatedImport(idempotencyKey);
        if (meanwhile.isPresent()) {
            keyImportWriter.failUnsent(attempt, COMPLETED_MEANWHILE);
            return new ImportedKey(meanwhile.get(), true);
        }
        try {
            cryptographicKeyWriter.adoptablePublicKey(call.terms().spkiFingerprint());
        } catch (ValidationException held) {
            keyImportWriter.failUnsent(attempt, held.getMessage());
            throw held;
        }
        Progress progress = new Progress(attempt, sent(call, attempt));
        return registered(call, attempt, awaited(call, progress));
    }

    /** What the attempt keeps in place of the secrets the call sends, to check every answer about it against. */
    private static List<String> secretDigests(Call call) {
        return OutboundSecretContainment.digestsOf(call.key().transportSecrets());
    }

    /** Sends the import; the handle of one the connector runs asynchronously is stored before it is waited on. */
    private ImportAnswer sent(Call call, KeyImportAttempt attempt) throws ConnectorServerException {
        ImportAnswer answer;
        try {
            answer = call.adapter().importKey(call.terms(), attempt, call.key(), call.metadata().name());
        } catch (ValidationException refusal) {
            keyImportWriter.fail(attempt.uuid(), refusal.getMessage());
            throw refusal;
        } catch (ConnectorException | RuntimeException e) {
            throw unconfirmed(attempt);
        }
        if (answer instanceof ImportAnswer.Running(List<MetadataAttribute> operationMeta)) {
            keyImportWriter.accept(attempt.uuid(), operationMeta);
        }
        return answer;
    }

    /**
     * The imported key, waited for while the connector runs the import, for as long as an import request may wait. An
     * import still running then is cancelled; one the connector does not abort stays open.
     */
    private ImportAnswer.Imported awaited(Call call, Progress progress) throws ConnectorServerException {
        KeyImportAttempt attempt = progress.attempt();
        Instant deadline = Instant.now().plus(properties.requestTimeout());
        ImportAnswer answer = progress.answer();
        while (answer instanceof ImportAnswer.Running(List<MetadataAttribute> operationMeta)) {
            List<MetadataAttribute> handle = operationMeta != null ? operationMeta : attempt.operationMeta();
            if (!Instant.now().isBefore(deadline)) {
                throw abandoned(call, attempt, handle);
            }
            pause(attempt, deadline);
            answer = polled(call, attempt, handle);
        }
        if (answer instanceof ImportAnswer.Imported imported) {
            return imported;
        }
        if (answer instanceof ImportAnswer.NotImported) {
            throw failed(attempt, NOT_IMPORTED);
        }
        throw unconfirmed(attempt);
    }

    /** How the import stands: by its handle when the attempt has one, otherwise by its import identifier. */
    private ImportAnswer polled(Call call, KeyImportAttempt attempt, List<MetadataAttribute> handle)
            throws ConnectorServerException {
        try {
            return handle == null
                    ? call
                            .adapter()
                            .importKeyResult(call.terms().profile(), attempt.uuid(), attempt.secretDigests(),
                                    call.metadata().name())
                    : call
                            .adapter()
                            .importKeyStatus(call.terms().profile(), handle, attempt.secretDigests(),
                                    call.metadata().name());
        } catch (ConnectorException | RuntimeException e) {
            throw unconfirmed(attempt);
        }
    }

    private ConnectorServerException abandoned(Call call, KeyImportAttempt attempt, List<MetadataAttribute> handle) {
        if (handle != null && call.adapter().cancelImportKey(handle)) {
            return failed(attempt, CANCELLED.formatted(properties.requestTimeout().toSeconds()));
        }
        return unconfirmed(attempt);
    }

    /** Waits the poll interval, but not past the deadline. */
    private void pause(KeyImportAttempt attempt, Instant deadline) throws ConnectorServerException {
        long untilDeadline = Math.max(0, Duration.between(Instant.now(), deadline).toMillis());
        try {
            Thread.sleep(Math.min(properties.pollInterval().toMillis(), untilDeadline));
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            throw unconfirmed(attempt);
        }
    }

    /**
     * Registers the key once it is shown to be the key in the file, of the type asked for and described with its
     * algorithm. A key registered meanwhile with the same public key refuses the import; the attempt stays open, so the
     * imported key is not left unaccounted.
     */
    private ImportedKey registered(Call call, KeyImportAttempt attempt, ImportAnswer.Imported imported)
            throws ConnectorServerException, NotFoundException, AttributeException {
        KeyImportTerms terms = call.terms();
        String expected = Base64.getEncoder().encodeToString(call.key().subjectPublicKeyInfo());
        boolean ofTheKeysAlgorithm = imported
                .items()
                .stream()
                .allMatch(item -> item.algorithm() == call.key().algorithm());
        if (imported.type() != terms.type() || !Objects.equals(imported.publicKey(), expected) || !ofTheKeysAlgorithm) {
            logger.warn("Key import {} was answered with a key other than the one in the file", attempt.uuid());
            throw unconfirmed(attempt);
        }
        ImportedKeyRegistration registration = new ImportedKeyRegistration(terms.profile(), imported.items(),
                attempt.keyReference(), terms.spkiFingerprint(), terms.exportable(), call.metadata(),
                terms.requester());
        Optional<ImportedKey> key;
        try {
            key = keyImportWriter.complete(attempt.uuid(), registration);
        } catch (DataIntegrityViolationException lostRace) {
            throw new ValidationException(ValidationError.create(CryptographicKeyWriter.KEY_ALREADY_HELD));
        }
        if (key.isEmpty()) {
            throw unconfirmed(attempt);
        }
        logger.info("Key {} imported into token profile {}", key.get().key().uuid(), terms.profile().uuid());
        return key.get();
    }

    private ConnectorServerException failed(KeyImportAttempt attempt, String message) {
        keyImportWriter.fail(attempt.uuid(), message);
        return new ConnectorServerException(message, HttpStatus.BAD_GATEWAY);
    }

    private static ConnectorServerException unconfirmed(KeyImportAttempt attempt) {
        logger.warn("Key import {} was not confirmed; it stays open until its outcome is learned", attempt.uuid());
        return new ConnectorServerException(UNCONFIRMED, HttpStatus.BAD_GATEWAY);
    }

    /** The platform's own messages are recorded; anything else is recorded as a failure without its words. */
    private void recordFailure(UUID publicKeyItemUuid, Exception failure) {
        String message = failure instanceof PlatformException && failure.getMessage() != null
                ? failure.getMessage()
                : IMPORT_FAILED;
        try {
            eventHistoryService
                    .addEventHistory(KeyEvent.IMPORT, KeyEventStatus.FAILED, message, null, publicKeyItemUuid);
        } catch (RuntimeException historyFailure) {
            failure.addSuppressed(historyFailure);
        }
    }

    private record Call(KeyProviderAdapter adapter, KeyImportTerms terms, NormalizedKey key,
            KeyImportMetadata metadata) {
    }

    private record Progress(KeyImportAttempt attempt, ImportAnswer answer) {
    }
}
