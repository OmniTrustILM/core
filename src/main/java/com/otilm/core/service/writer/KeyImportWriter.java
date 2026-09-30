package com.otilm.core.service.writer;

import com.otilm.api.exception.AttributeException;
import com.otilm.api.exception.NotFoundException;
import com.otilm.api.exception.ValidationException;
import com.otilm.api.model.client.certificate.ImportOutcome;
import com.otilm.api.model.common.attribute.common.MetadataAttribute;
import com.otilm.core.config.KeyImportProperties;
import com.otilm.core.config.cache.CacheConfig;
import com.otilm.core.config.cache.CacheEvictor;
import com.otilm.core.dao.entity.CryptographicKey;
import com.otilm.core.dao.entity.KeyImport;
import com.otilm.core.dao.entity.KeyImportState;
import com.otilm.core.dao.repository.CryptographicKeyRepository;
import com.otilm.core.dao.repository.KeyImportRepository;
import com.otilm.core.model.crypto.CryptographicKeyFullModel;
import com.otilm.core.model.crypto.ImmutableCryptographicKeyFullModel;
import com.otilm.core.model.crypto.ImportedKey;
import com.otilm.core.model.crypto.ImportedKeyRegistration;
import com.otilm.core.model.crypto.KeyImportAttempt;
import com.otilm.core.model.crypto.KeyImportTerms;
import com.otilm.core.model.crypto.RegisteredKey;
import jakarta.persistence.EntityManager;
import java.time.OffsetDateTime;
import java.time.ZoneOffset;
import java.time.temporal.ChronoUnit;
import java.util.List;
import java.util.Optional;
import java.util.UUID;
import java.util.stream.Stream;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

/**
 * Records the import attempts. Each write is a transaction of its own, made before or after a connector call and never
 * across one, so the record always shows how far the import got.
 */
@Service
public class KeyImportWriter {

    private final KeyImportRepository keyImportRepository;
    private final CryptographicKeyRepository cryptographicKeyRepository;
    private final CryptographicKeyWriter cryptographicKeyWriter;
    private final CacheEvictor cacheEvictor;
    private final EntityManager entityManager;
    private final KeyImportProperties properties;

    public KeyImportWriter(KeyImportRepository keyImportRepository,
            CryptographicKeyRepository cryptographicKeyRepository, CryptographicKeyWriter cryptographicKeyWriter,
            CacheEvictor cacheEvictor, EntityManager entityManager, KeyImportProperties properties) {
        this.keyImportRepository = keyImportRepository;
        this.cryptographicKeyRepository = cryptographicKeyRepository;
        this.cryptographicKeyWriter = cryptographicKeyWriter;
        this.cacheEvictor = cacheEvictor;
        this.entityManager = entityManager;
        this.properties = properties;
    }

    /**
     * Records a new attempt before the connector is asked, under an import identifier and a key reference of its own.
     *
     * @param name the name the imported key's items are registered under: its own, or that of the record it is to be
     * imported into
     * @param secretDigests the digests of the secrets the attempt is to be sent with
     * @throws org.springframework.dao.DataIntegrityViolationException while another attempt is open for the same key,
     * or for the same import of a secret key
     */
    @Transactional(rollbackFor = Exception.class)
    public KeyImportAttempt open(KeyImportTerms terms, String idempotencyKey, String name, List<String> secretDigests) {
        KeyImport attempt = new KeyImport();
        attempt.setUuid(UUID.randomUUID());
        attempt.setKeyReference(UUID.randomUUID());
        attempt.setIdempotencyKey(idempotencyKey);
        attempt.setRequesterUuid(UUID.fromString(terms.requester().getUuid()));
        attempt.setRequesterName(terms.requester().getName());
        attempt.setTokenInstanceUuid(terms.profile().tokenInstanceReferenceUuid());
        attempt.setTokenProfileUuid(terms.profile().uuid());
        attempt.setKeyRequestType(terms.type());
        attempt.setKeyAlgorithm(terms.algorithm());
        attempt.setSpkiFingerprint(terms.spkiFingerprint());
        attempt.setName(name);
        attempt.setExportable(terms.exportable());
        attempt.setState(KeyImportState.REQUESTED);
        attempt.setSecretDigests(secretDigests);
        sent(attempt);
        return KeyImportAttempt.of(keyImportRepository.saveAndFlush(attempt));
    }

    /**
     * Claims an attempt for another send and adds the digests of the secrets it is to be sent with, before it is sent,
     * so that an answer about it is checked against every copy the connector may have received. An attempt that closed
     * meanwhile is not claimed. The requester keeps a claimed attempt for another retry window, so the reconciliation
     * does not ask about it while the send is on its way.
     *
     * @return the claimed attempt, or nothing when it is no longer open
     */
    @Transactional(rollbackFor = Exception.class)
    public Optional<KeyImportAttempt> resending(UUID attemptUuid, List<String> secretDigests) {
        KeyImport attempt = locked(attemptUuid);
        if (!attempt.getState().isOpen()) {
            return Optional.empty();
        }
        attempt
                .setSecretDigests(
                        Stream.concat(attempt.getSecretDigests().stream(), secretDigests.stream()).distinct().toList());
        sent(attempt);
        return Optional.of(KeyImportAttempt.of(attempt));
    }

    /**
     * The digests of the secrets the attempt was sent with, read afresh: another request may have sent it again since
     * this one read it, with secrets of its own.
     */
    @Transactional(readOnly = true)
    public List<String> secretDigests(UUID attemptUuid) {
        KeyImport attempt = keyImportRepository
                .findById(attemptUuid)
                .orElseThrow(() -> new IllegalStateException("Key import " + attemptUuid + " is not recorded."));
        entityManager.refresh(attempt);
        return attempt.getSecretDigests();
    }

    /**
     * Closes an attempt as it was read, unless a request took it since, to send it again or to resume it: that request
     * settles the attempt instead. A request closes this way an attempt it opened and never sent, or one whose send the
     * connector refused, reported as ending without a key or confirmed it cancelled, and the reconciliation one the
     * connector answered about after it claimed it.
     *
     * @param read the attempt as the caller last left it
     * @return whether the attempt was closed
     */
    @Transactional(rollbackFor = Exception.class)
    public boolean failUntaken(KeyImportAttempt read, String errorMessage) {
        KeyImport attempt = locked(read.uuid());
        if (!attempt.getState().isOpen() || !untakenSince(attempt, read)) {
            return false;
        }
        attempt.setState(KeyImportState.FAILED);
        attempt.setErrorMessage(errorMessage);
        return true;
    }

    /** Stores the handle of an import the connector runs asynchronously, unless the attempt has settled. */
    @Transactional(rollbackFor = Exception.class)
    public void accept(UUID attemptUuid, List<MetadataAttribute> operationMeta) {
        KeyImport attempt = locked(attemptUuid);
        if (attempt.getState().isOpen()) {
            attempt.setState(KeyImportState.ACCEPTED);
            attempt.setOperationMeta(operationMeta);
        }
    }

    /**
     * Registers the imported key and completes the attempt with it, both or neither. An attempt a concurrent request
     * completed answers with the key it registered, which this request found in the inventory.
     *
     * @return the registered key, or nothing when the attempt closed without a key meanwhile
     * @throws ValidationException when the platform now holds the key otherwise, or another key now has the name of a
     * key of its own; the attempt stays open
     * @throws CryptographicKeyWriter.UncheckedRecordException when a public-key-only record now holds the public key
     * that the registration was not told its requester may update; the attempt stays open
     */
    @Transactional(rollbackFor = Exception.class)
    public Optional<ImportedKey> complete(UUID attemptUuid, ImportedKeyRegistration registration)
            throws AttributeException, NotFoundException {
        KeyImport attempt = locked(attemptUuid);
        if (attempt.getState() == KeyImportState.COMPLETED) {
            return current(attempt.getKeyUuid()).map(key -> new ImportedKey(key, ImportOutcome.EXISTING));
        }
        if (!attempt.getState().isOpen()) {
            return Optional.empty();
        }
        RegisteredKey registered = cryptographicKeyWriter.registerImportedKey(registration);
        attempt.setState(KeyImportState.COMPLETED);
        attempt.setKeyUuid(registered.uuid());
        Optional<CryptographicKeyFullModel> key = current(registered.uuid());
        key.ifPresent(this::evictItems);
        return key.map(inventoried -> new ImportedKey(inventoried, registered.outcome()));
    }

    /**
     * Takes an open attempt for the reconciliation to undo, before it destroys the key the requester was never answered
     * with; a retry then finds the attempt closed. An attempt already taken is taken again, so a later look finishes
     * what an earlier one started. An attempt a request took since it was claimed is left to that request: one that
     * sent it again carried secrets the claim's answer was not checked against, and one that resumed it may be
     * registering its key.
     *
     * @param claimed the attempt as the reconciliation claimed it
     * @return whether the attempt is the reconciliation's to undo
     */
    @Transactional(rollbackFor = Exception.class)
    public boolean compensating(KeyImportAttempt claimed) {
        KeyImport attempt = locked(claimed.uuid());
        if (!untakenSince(attempt, claimed)) {
            return false;
        }
        if (attempt.getState().isOpen()) {
            attempt.setState(KeyImportState.COMPENSATING);
        }
        return attempt.getState() == KeyImportState.COMPENSATING;
    }

    /** Closes an attempt the reconciliation took, once its key is destroyed. */
    @Transactional(rollbackFor = Exception.class)
    public void compensated(UUID attemptUuid) {
        KeyImport attempt = locked(attemptUuid);
        if (attempt.getState() == KeyImportState.COMPENSATING) {
            attempt.setState(KeyImportState.COMPENSATED);
        }
    }

    /**
     * Registers the key of an attempt the reconciliation took, deactivated, when the connector refused to destroy it,
     * and closes the attempt with it, both or neither.
     *
     * @return the registered key, or nothing when the attempt is no longer the reconciliation's
     * @throws ValidationException when the platform holds the key otherwise, or another key has the name of a key of
     * its own; the attempt stays as it is
     * @throws CryptographicKeyWriter.UncheckedRecordException when a public-key-only record holds the public key that
     * the registration was not told its requester may update; the attempt stays as it is
     */
    @Transactional(rollbackFor = Exception.class)
    public Optional<UUID> quarantine(UUID attemptUuid, ImportedKeyRegistration registration)
            throws AttributeException, NotFoundException {
        KeyImport attempt = locked(attemptUuid);
        if (attempt.getState() != KeyImportState.COMPENSATING) {
            return Optional.empty();
        }
        UUID keyUuid = cryptographicKeyWriter.registerImportedKey(registration).uuid();
        attempt.setState(KeyImportState.QUARANTINED);
        attempt.setKeyUuid(keyUuid);
        current(keyUuid).ifPresent(this::evictItems);
        return Optional.of(keyUuid);
    }

    /**
     * Closes an attempt as it was read whose outcome could not be learned, while it is unsettled, unless a request took
     * it since: that request settles it instead.
     *
     * @param read the attempt as the caller read it
     * @return whether the attempt was closed
     */
    @Transactional(rollbackFor = Exception.class)
    public boolean unresolved(KeyImportAttempt read, String errorMessage) {
        KeyImport attempt = locked(read.uuid());
        if (!attempt.getState().isUnsettled() || !untakenSince(attempt, read)) {
            return false;
        }
        attempt.setState(KeyImportState.UNRESOLVED);
        attempt.setErrorMessage(errorMessage);
        return true;
    }

    /** Sets when the reconciliation next looks at the attempt, while it is unsettled. */
    @Transactional(rollbackFor = Exception.class)
    public void reschedule(UUID attemptUuid, OffsetDateTime nextCheckAt) {
        schedule(locked(attemptUuid), nextCheckAt);
    }

    /** Hands the attempt to the reconciliation's next look, while it is unsettled. */
    @Transactional(rollbackFor = Exception.class)
    public void dueNow(UUID attemptUuid) {
        schedule(locked(attemptUuid), now());
    }

    /**
     * Leaves an open attempt a request is at again to that request for another retry window, as a send does, so the
     * reconciliation does not undo it meanwhile.
     *
     * @return the attempt as the request leaves it
     */
    @Transactional(rollbackFor = Exception.class)
    public KeyImportAttempt resuming(UUID attemptUuid) {
        KeyImport attempt = locked(attemptUuid);
        if (attempt.getState().isOpen()) {
            attempt.setNextCheckAt(now().plus(properties.retryWindow()));
        }
        return KeyImportAttempt.of(attempt);
    }

    /**
     * Whether an attempt is still open and nobody took it since the caller last left it, to send it again or to resume
     * it: a request that took it since settles it instead.
     *
     * @param left the attempt as the caller last left it
     */
    @Transactional(rollbackFor = Exception.class)
    public boolean untaken(KeyImportAttempt left) {
        KeyImport attempt = locked(left.uuid());
        return attempt.getState().isOpen() && untakenSince(attempt, left);
    }

    /** Records a send, which leaves the attempt to its requester for a retry window. */
    private void sent(KeyImport attempt) {
        OffsetDateTime now = now();
        attempt.setLastSentAt(now);
        attempt.setNextCheckAt(now.plus(properties.retryWindow()));
    }

    private static void schedule(KeyImport attempt, OffsetDateTime nextCheckAt) {
        if (attempt.getState().isUnsettled()) {
            attempt.setNextCheckAt(nextCheckAt.truncatedTo(ChronoUnit.MICROS));
        }
    }

    /** Whether nobody took the attempt since it was read: a send adds digests, and every taker moves its next look. */
    private static boolean untakenSince(KeyImport attempt, KeyImportAttempt read) {
        return attempt.getSecretDigests().equals(read.secretDigests())
                && attempt.getNextCheckAt().isEqual(read.nextCheckAt());
    }

    /** Now, as precisely as the database keeps it, so a time read back equals the one written. */
    private static OffsetDateTime now() {
        return OffsetDateTime.now(ZoneOffset.UTC).truncatedTo(ChronoUnit.MICROS);
    }

    /** The key as the database holds it now, while it still exists. */
    @Transactional(rollbackFor = Exception.class)
    public Optional<CryptographicKeyFullModel> registeredKey(UUID keyUuid) {
        return current(keyUuid);
    }

    /** Drops the registered key's items from the cache, which may hold an item the key adopted. */
    private void evictItems(CryptographicKeyFullModel key) {
        key.items().forEach(item -> cacheEvictor.evict(CacheConfig.CRYPTOGRAPHIC_KEY_ITEM_CACHE, item.uuid()));
    }

    /** Read afresh: an earlier read in the request may have left an older copy of the key and its items. */
    private Optional<CryptographicKeyFullModel> current(UUID keyUuid) {
        Optional<CryptographicKey> key = cryptographicKeyRepository.findByUuid(keyUuid);
        key.ifPresent(entityManager::refresh);
        return key.map(ImmutableCryptographicKeyFullModel::from);
    }

    /** The attempt, locked and read afresh: an earlier read in the request may have left an older copy. */
    private KeyImport locked(UUID attemptUuid) {
        KeyImport attempt = keyImportRepository
                .findForUpdateByUuid(attemptUuid)
                .orElseThrow(() -> new IllegalStateException("Key import " + attemptUuid + " is not recorded."));
        entityManager.refresh(attempt);
        return attempt;
    }
}
