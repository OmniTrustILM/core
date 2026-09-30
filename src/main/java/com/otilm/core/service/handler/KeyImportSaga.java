package com.otilm.core.service.handler;

import com.otilm.api.exception.AttributeException;
import com.otilm.api.exception.ConnectorException;
import com.otilm.api.exception.ConnectorServerException;
import com.otilm.api.exception.NotFoundException;
import com.otilm.api.exception.PlatformException;
import com.otilm.api.exception.ValidationError;
import com.otilm.api.exception.ValidationException;
import com.otilm.api.model.client.certificate.ImportOutcome;
import com.otilm.api.model.client.cryptography.key.KeyRequestType;
import com.otilm.api.model.common.attribute.common.MetadataAttribute;
import com.otilm.api.model.common.enums.cryptography.KeyType;
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
import com.otilm.core.model.crypto.ProviderKeyItem;
import com.otilm.core.model.crypto.PublicKeyHolder;
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

    public static final String UNCONFIRMED = "The key import was not confirmed. Retry it to learn its outcome.";
    public static final String NOT_IMPORTED = "The connector could not import the key.";
    public static final String CANCELLED = "The key import did not finish within %d seconds and was cancelled.";
    public static final String ALREADY_IMPORTING = "The same key is already being imported. Try again once that import has finished.";

    private static final String IMPORT_FAILED = "Key import failed.";

    private static final String COMPLETED_MEANWHILE = "The same import completed meanwhile.";

    private static final String REGISTERED_MEANWHILE = "The key was registered meanwhile.";

    private static final Logger logger = LoggerFactory.getLogger(KeyImportSaga.class);

    private static final Set<KeyImportState> OPEN = EnumSet.of(KeyImportState.REQUESTED, KeyImportState.ACCEPTED);

    private final KeyImportRepository keyImportRepository;
    private final CryptographicKeyRepository cryptographicKeyRepository;
    private final CryptographicKeyWriter cryptographicKeyWriter;
    private final KeyImportWriter keyImportWriter;
    private final CryptographicKeyEventHistoryService eventHistoryService;
    private final KeyImportGates keyImportGates;
    private final KeyProviderAdapterFactory keyProviderAdapterFactory;
    private final KeyImportProperties properties;

    public KeyImportSaga(KeyImportRepository keyImportRepository, CryptographicKeyRepository cryptographicKeyRepository,
            CryptographicKeyWriter cryptographicKeyWriter, KeyImportWriter keyImportWriter,
            CryptographicKeyEventHistoryService eventHistoryService, KeyImportGates keyImportGates,
            KeyProviderAdapterFactory keyProviderAdapterFactory, KeyImportProperties properties) {
        this.keyImportRepository = keyImportRepository;
        this.cryptographicKeyRepository = cryptographicKeyRepository;
        this.cryptographicKeyWriter = cryptographicKeyWriter;
        this.keyImportWriter = keyImportWriter;
        this.eventHistoryService = eventHistoryService;
        this.keyImportGates = keyImportGates;
        this.keyProviderAdapterFactory = keyProviderAdapterFactory;
        this.properties = properties;
    }

    /**
     * Imports the key into the token profile and registers it. Before any connector is asked: a repeat of an import
     * already registered answers with its key, and so does a key pair whose public key the platform holds in an active
     * key of its own; a key pair whose public key an active public-key-only record holds is imported into the record
     * when the caller may update it, and refused otherwise; a key held but no longer active is refused; and a new key
     * needs a name no other key has. An open attempt of the same import is resumed rather than a second one started.
     * The items of a key imported into a record are registered under the record's name, which the record keeps. A
     * failure of an import that would adopt a public-key-only record is recorded in that record's history.
     *
     * @param idempotencyKey what makes a later request the same import
     * @return the registered key
     */
    public ImportedKey importKey(KeyImportTerms terms, String idempotencyKey, NormalizedKey key,
            KeyImportMetadata metadata) throws ConnectorException, NotFoundException, AttributeException {
        Optional<CryptographicKeyFullModel> repeated = repeatedImport(idempotencyKey);
        if (repeated.isPresent()) {
            return existing(repeated.get());
        }
        Optional<PublicKeyHolder> holder = holderOf(terms);
        if (holder.isPresent() && !holder.get().publicKeyOnly()) {
            return existing(holder.get().key());
        }
        if (holder.isEmpty() && cryptographicKeyRepository.existsByName(metadata.name())) {
            // The same import may have completed, under this name, since it was looked for.
            return repeatedImport(idempotencyKey).map(KeyImportSaga::existing).orElseThrow(() -> nameTaken(metadata));
        }
        String label = holder.map(adoptable -> adoptable.key().name()).orElse(metadata.name());
        Optional<UUID> adoptedPublicKey = holder.map(PublicKeyHolder::publicKeyItemUuid);
        try {
            Call call = new Call(keyProviderAdapterFactory.forToken(terms.profile().tokenInstance()), terms, key,
                    metadata, label);
            Optional<Progress> resumed = resumed(call, idempotencyKey);
            if (resumed.isPresent()) {
                return registered(call, resumed.get().attempt(), awaited(call, resumed.get()));
            }
            return begun(call, idempotencyKey);
        } catch (ConnectorException | NotFoundException | AttributeException | RuntimeException e) {
            if (!(e instanceof SameImportOpen)) {
                adoptedPublicKey.ifPresent(publicKey -> recordFailure(publicKey, e));
            }
            throw e;
        }
    }

    private Optional<CryptographicKeyFullModel> repeatedImport(String idempotencyKey) {
        return keyImportRepository
                .findFirstByIdempotencyKeyAndStateInOrderByCreatedAtDesc(idempotencyKey,
                        Set.of(KeyImportState.COMPLETED))
                .flatMap(completed -> keyImportWriter.registeredKey(completed.getKeyUuid()));
    }

    private static ValidationException nameTaken(KeyImportMetadata metadata) {
        return new ValidationException(
                ValidationError.create(CryptographicKeyWriter.NAME_TAKEN.formatted(metadata.name())));
    }

    /**
     * The key holding the key pair's public key: a key of its own, or a public-key-only record the import would adopt,
     * which the caller may update. A secret key has no public key, so nothing holds it.
     *
     * @throws ValidationException when the platform holds the public key in a key no longer active, or otherwise, or in
     * a record the caller may not update
     */
    private Optional<PublicKeyHolder> holderOf(KeyImportTerms terms) {
        if (terms.type() == KeyRequestType.SECRET) {
            return Optional.empty();
        }
        Optional<PublicKeyHolder> holder = cryptographicKeyWriter.publicKeyHolder(terms.spkiFingerprint());
        holder
                .filter(PublicKeyHolder::publicKeyOnly)
                .ifPresent(adoptable -> keyImportGates.requireUpdatable(adoptable.key().uuid()));
        return holder;
    }

    /** The key the inventory held already, which the import changed nothing of. */
    private static ImportedKey existing(CryptographicKeyFullModel key) {
        return new ImportedKey(key, ImportOutcome.EXISTING);
    }

    /**
     * An open attempt of the same import, resumed from the connector's record of it: one the connector never accepted
     * is sent again under its own identifier, while the connector still keeps its records; one that ended without a key
     * is closed, so the import starts afresh, unless another request took it since this one resumed it, which settles
     * it instead.
     */
    private Optional<Progress> resumed(Call call, String idempotencyKey) throws ConnectorServerException {
        Optional<KeyImportAttempt> open = keyImportRepository
                .findFirstByIdempotencyKeyAndStateInOrderByCreatedAtDesc(idempotencyKey, OPEN)
                .map(KeyImportAttempt::of);
        if (open.isEmpty()) {
            return Optional.empty();
        }
        KeyImportAttempt attempt = keyImportWriter.resuming(open.get().uuid());
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
            if (!keyImportWriter.failUntaken(attempt, NOT_IMPORTED)) {
                throw unconfirmed(attempt);
            }
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
     * Records a new attempt and imports the key through it; another attempt open for the same key refuses it, unless
     * that attempt was the same import's and has completed since, which answers with its key. When the same import
     * completed, or the key came to be held in a key of its own, or can no longer be imported as a new key or into its
     * record, after this request looked, the attempt is closed unsent: the key it would put in the token could not be
     * registered.
     */
    private ImportedKey begun(Call call, String idempotencyKey)
            throws ConnectorServerException, NotFoundException, AttributeException {
        KeyImportAttempt attempt;
        try {
            attempt = keyImportWriter.open(call.terms(), idempotencyKey, call.label(), secretDigests(call));
        } catch (DataIntegrityViolationException anotherOpen) {
            if (sameImportOpen(idempotencyKey)) {
                throw new SameImportOpen();
            }
            // The attempt that refused this one may have been the same import's, completed since.
            Optional<CryptographicKeyFullModel> completed = repeatedImport(idempotencyKey);
            if (completed.isPresent()) {
                return existing(completed.get());
            }
            throw new ValidationException(ValidationError.create(ALREADY_IMPORTING));
        }
        Optional<CryptographicKeyFullModel> meanwhile = repeatedImport(idempotencyKey);
        if (meanwhile.isPresent()) {
            keyImportWriter.failUntaken(attempt, COMPLETED_MEANWHILE);
            return existing(meanwhile.get());
        }
        Optional<PublicKeyHolder> holder;
        try {
            holder = holderOf(call.terms());
        } catch (ValidationException held) {
            keyImportWriter.failUntaken(attempt, held.getMessage());
            throw held;
        }
        if (holder.isPresent() && !holder.get().publicKeyOnly()) {
            keyImportWriter.failUntaken(attempt, REGISTERED_MEANWHILE);
            return existing(holder.get().key());
        }
        Progress progress = new Progress(attempt, sent(call, attempt));
        return registered(call, attempt, awaited(call, progress));
    }

    /** Whether the same import has an attempt open, which is then the attempt open for the key. */
    private boolean sameImportOpen(String idempotencyKey) {
        return keyImportRepository
                .findFirstByIdempotencyKeyAndStateInOrderByCreatedAtDesc(idempotencyKey, OPEN)
                .isPresent();
    }

    /** What the attempt keeps in place of the secrets the call sends, to check every answer about it against. */
    private static List<String> secretDigests(Call call) {
        return OutboundSecretContainment.digestsOf(call.key().transportSecrets());
    }

    /**
     * Sends the import; the handle of one the connector runs asynchronously is stored before it is waited on. When
     * another request sent the attempt again while this send was on its way, the answer may carry what that request
     * sent: it is dropped, and the connector's record of the import is asked for instead, checked against every send. A
     * refusal closes the attempt, unless another request took it since, which settles it instead.
     */
    private ImportAnswer sent(Call call, KeyImportAttempt attempt) throws ConnectorServerException {
        ImportAnswer answer;
        try {
            answer = call.adapter().importKey(call.terms(), attempt, call.key(), call.label());
        } catch (ValidationException refusal) {
            if (keyImportWriter.failUntaken(attempt, refusal.getMessage())) {
                throw refusal;
            }
            throw unconfirmed(attempt);
        } catch (ConnectorException | RuntimeException e) {
            throw unconfirmed(attempt);
        }
        if (!keyImportWriter.secretDigests(attempt.uuid()).equals(attempt.secretDigests())) {
            return polled(call, attempt, null);
        }
        if (answer instanceof ImportAnswer.Running(List<MetadataAttribute> operationMeta)) {
            keyImportWriter.accept(attempt.uuid(), operationMeta);
        }
        return answer;
    }

    /**
     * The imported key, waited for while the connector runs the import, for as long as an import request may wait. An
     * import still running then is cancelled, unless another request took the attempt since this one did and waits on
     * the import itself; one the connector does not abort stays open.
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

    /**
     * How the import stands: by its handle when the attempt has one, otherwise by its import identifier. The answer is
     * checked against the digests the attempt holds, which include those of any send another request made since this
     * one read the attempt. A send another request made while the question was on its way may be echoed in the answer,
     * so the digests are read again once it arrives: when they changed, the question is asked once more with them, and
     * when they changed during that question too, the import is not confirmed.
     */
    private ImportAnswer polled(Call call, KeyImportAttempt attempt, List<MetadataAttribute> handle)
            throws ConnectorServerException {
        List<String> checkedAgainst = keyImportWriter.secretDigests(attempt.uuid());
        ImportAnswer answer = asked(call, attempt, handle, checkedAgainst);
        List<String> recorded = keyImportWriter.secretDigests(attempt.uuid());
        if (recorded.equals(checkedAgainst)) {
            return answer;
        }
        ImportAnswer again = asked(call, attempt, handle, recorded);
        if (!keyImportWriter.secretDigests(attempt.uuid()).equals(recorded)) {
            throw unconfirmed(attempt);
        }
        return again;
    }

    private ImportAnswer asked(Call call, KeyImportAttempt attempt, List<MetadataAttribute> handle,
            List<String> secretDigests) throws ConnectorServerException {
        try {
            return handle == null
                    ? call
                            .adapter()
                            .importKeyResult(call.terms().profile(), attempt.uuid(), secretDigests, call.label())
                    : call.adapter().importKeyStatus(call.terms().profile(), handle, secretDigests, call.label());
        } catch (ConnectorException | RuntimeException e) {
            throw unconfirmed(attempt);
        }
    }

    private ConnectorServerException abandoned(Call call, KeyImportAttempt attempt, List<MetadataAttribute> handle) {
        if (handle != null && keyImportWriter.untaken(attempt) && call.adapter().cancelImportKey(handle)) {
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
     * algorithm. A key or record that came to hold the public key while the key was registered makes the registration
     * fail; it is registered once more, which takes such a record once its requester is shown to be allowed to update
     * it, and refuses anything else. An imported key that is not the key in the file, or that the platform refuses to
     * register, is handed to the reconciliation at once, which undoes it; the attempt stays open meanwhile, so the
     * imported key is not left unaccounted.
     */
    private ImportedKey registered(Call call, KeyImportAttempt attempt, ImportAnswer.Imported imported)
            throws ConnectorServerException, NotFoundException, AttributeException {
        KeyImportTerms terms = call.terms();
        if (imported.type() != terms.type() || !isTheKeyInTheFile(imported, call.key())) {
            logger.warn("Key import {} was answered with a key other than the one in the file", attempt.uuid());
            keyImportWriter.dueNow(attempt.uuid());
            throw unconfirmed(attempt);
        }
        ImportedKeyRegistration registration = new ImportedKeyRegistration(terms.profile(), imported.items(),
                attempt.keyReference(), terms.spkiFingerprint(), terms.exportable(), call.metadata(), terms.requester(),
                false, null);
        ImportedKey key;
        try {
            key = completed(attempt, registration);
        } catch (DataIntegrityViolationException | CryptographicKeyWriter.UncheckedRecordException heldMeanwhile) {
            key = completedOnceMore(attempt, registration);
        }
        logger.info("Key {} imported into token profile {}", key.key().uuid(), terms.profile().uuid());
        return key;
    }

    /**
     * Registers the key and completes the attempt with it, taking the public-key-only record that holds the public key
     * now once its requester is shown to be allowed to update it. A refusal hands the attempt to the reconciliation.
     */
    private ImportedKey completed(KeyImportAttempt attempt, ImportedKeyRegistration registration)
            throws ConnectorServerException, NotFoundException, AttributeException {
        Optional<ImportedKey> key;
        try {
            UUID adoptable = keyImportGates
                    .adoptableBy(registration.owner(), registration.spkiFingerprint())
                    .orElse(null);
            key = keyImportWriter.complete(attempt.uuid(), registration.adopting(adoptable));
        } catch (ValidationException | NotFoundException | AttributeException refused) {
            keyImportWriter.dueNow(attempt.uuid());
            throw refused;
        }
        if (key.isEmpty()) {
            throw unconfirmed(attempt);
        }
        return key.get();
    }

    /** The second registration; a key held meanwhile again refuses the import, and hands it to the reconciliation. */
    private ImportedKey completedOnceMore(KeyImportAttempt attempt, ImportedKeyRegistration registration)
            throws ConnectorServerException, NotFoundException, AttributeException {
        try {
            return completed(attempt, registration);
        } catch (DataIntegrityViolationException | CryptographicKeyWriter.UncheckedRecordException heldMeanwhile) {
            keyImportWriter.dueNow(attempt.uuid());
            throw new ValidationException(ValidationError.create(CryptographicKeyWriter.KEY_ALREADY_HELD));
        }
    }

    /**
     * Whether the imported items describe the key in the file. A key pair is shown by its public key, and each of its
     * items must be of its algorithm. A secret key has no public key, so its one item must be a secret key of its
     * algorithm and length.
     */
    private static boolean isTheKeyInTheFile(ImportAnswer.Imported imported, NormalizedKey key) {
        if (key.type() == KeyRequestType.SECRET) {
            return imported.items().size() == 1 && isSecretKeyOf(imported.items().getFirst(), key);
        }
        String expected = Base64.getEncoder().encodeToString(key.subjectPublicKeyInfo());
        return Objects.equals(imported.publicKey(), expected)
                && imported.items().stream().allMatch(item -> item.algorithm() == key.algorithm());
    }

    private static boolean isSecretKeyOf(ProviderKeyItem item, NormalizedKey key) {
        return item.type() == KeyType.SECRET_KEY && item.algorithm() == key.algorithm()
                && item.length() == key.length();
    }

    /**
     * Closes the attempt as failed, unless another request took it since this one last left it: that request settles
     * it, so this one does not confirm how the import ended.
     */
    private ConnectorServerException failed(KeyImportAttempt attempt, String message) {
        return keyImportWriter.failUntaken(attempt, message)
                ? new ConnectorServerException(message, HttpStatus.BAD_GATEWAY)
                : unconfirmed(attempt);
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

    /**
     * What an import sends the connector.
     *
     * @param label the name the imported key's items are registered under: the key's own, or that of the record it is
     * imported into
     */
    private record Call(KeyProviderAdapter adapter, KeyImportTerms terms, NormalizedKey key, KeyImportMetadata metadata,
            String label) {
    }

    private record Progress(KeyImportAttempt attempt, ImportAnswer answer) {
    }

    /**
     * The refusal of an attempt while the same import has one open: that import goes on to take the record, so the
     * refusal is no failure of the import to record in the record's history.
     */
    private static final class SameImportOpen extends ValidationException {

        private SameImportOpen() {
            super(ValidationError.create(ALREADY_IMPORTING));
        }
    }
}
