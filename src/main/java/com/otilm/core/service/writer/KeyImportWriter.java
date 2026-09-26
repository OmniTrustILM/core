package com.otilm.core.service.writer;

import com.otilm.api.exception.AttributeException;
import com.otilm.api.exception.NotFoundException;
import com.otilm.api.exception.ValidationError;
import com.otilm.api.exception.ValidationException;
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
import jakarta.persistence.EntityManager;
import java.time.OffsetDateTime;
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
     * @param name the name the key is to be registered under
     * @param secretDigests the digests of the secrets the attempt is to be sent with
     * @throws org.springframework.dao.DataIntegrityViolationException while another import of the same key is open
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
     * Closes an attempt this request opened and never sent, unless another request claimed it for a send meanwhile, as
     * the digests it added show: that send's answer settles the attempt instead.
     */
    @Transactional(rollbackFor = Exception.class)
    public void failUnsent(KeyImportAttempt opened, String errorMessage) {
        KeyImport attempt = locked(opened.uuid());
        if (attempt.getState().isOpen() && attempt.getSecretDigests().equals(opened.secretDigests())) {
            attempt.setState(KeyImportState.FAILED);
            attempt.setErrorMessage(errorMessage);
        }
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

    /** Closes an attempt that imported nothing, unless it has settled already. */
    @Transactional(rollbackFor = Exception.class)
    public void fail(UUID attemptUuid, String errorMessage) {
        KeyImport attempt = locked(attemptUuid);
        if (attempt.getState().isOpen()) {
            attempt.setState(KeyImportState.FAILED);
            attempt.setErrorMessage(errorMessage);
        }
    }

    /**
     * Registers the imported key and completes the attempt with it, both or neither. An attempt a concurrent request
     * completed answers with the key it registered.
     *
     * @return the registered key, or nothing when the attempt closed without a key meanwhile
     * @throws ValidationException when the platform now holds the key otherwise; the attempt stays open
     */
    @Transactional(rollbackFor = Exception.class)
    public Optional<ImportedKey> complete(UUID attemptUuid, ImportedKeyRegistration registration)
            throws AttributeException, NotFoundException {
        KeyImport attempt = locked(attemptUuid);
        if (attempt.getState() == KeyImportState.COMPLETED) {
            return current(attempt.getKeyUuid()).map(key -> new ImportedKey(key, true));
        }
        if (!attempt.getState().isOpen()) {
            return Optional.empty();
        }
        UUID keyUuid = cryptographicKeyWriter.registerImportedKey(registration);
        attempt.setState(KeyImportState.COMPLETED);
        attempt.setKeyUuid(keyUuid);
        Optional<CryptographicKeyFullModel> key = current(keyUuid);
        key.ifPresent(this::evictItems);
        return key.map(registered -> new ImportedKey(registered, false));
    }

    /**
     * Takes an open attempt for the reconciliation to undo, before it destroys the key the requester was never answered
     * with; a retry then finds the attempt closed. An attempt already taken is taken again, so a later look finishes
     * what an earlier one started. An attempt sent again since it was claimed is left to that send, whose secrets the
     * claim's answer was not checked against.
     *
     * @param claimed the attempt as the reconciliation claimed it
     * @return whether the attempt is the reconciliation's to undo
     */
    @Transactional(rollbackFor = Exception.class)
    public boolean compensating(KeyImportAttempt claimed) {
        KeyImport attempt = locked(claimed.uuid());
        if (!attempt.getSecretDigests().equals(claimed.secretDigests())) {
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
     * @throws ValidationException when the platform holds the key otherwise, or another key has its name; the attempt
     * stays as it is
     */
    @Transactional(rollbackFor = Exception.class)
    public Optional<UUID> quarantine(UUID attemptUuid, ImportedKeyRegistration registration)
            throws AttributeException, NotFoundException {
        KeyImport attempt = locked(attemptUuid);
        if (attempt.getState() != KeyImportState.COMPENSATING) {
            return Optional.empty();
        }
        String name = registration.metadata().name();
        if (cryptographicKeyRepository.existsByName(name)) {
            throw new ValidationException(ValidationError.create(CryptographicKeyWriter.NAME_TAKEN.formatted(name)));
        }
        UUID keyUuid = cryptographicKeyWriter.registerImportedKey(registration);
        attempt.setState(KeyImportState.QUARANTINED);
        attempt.setKeyUuid(keyUuid);
        current(keyUuid).ifPresent(this::evictItems);
        return Optional.of(keyUuid);
    }

    /** Closes an attempt whose outcome could not be learned, while it is unsettled. */
    @Transactional(rollbackFor = Exception.class)
    public void unresolved(UUID attemptUuid, String errorMessage) {
        KeyImport attempt = locked(attemptUuid);
        if (attempt.getState().isUnsettled()) {
            attempt.setState(KeyImportState.UNRESOLVED);
            attempt.setErrorMessage(errorMessage);
        }
    }

    /** Sets when the reconciliation next looks at the attempt, while it is unsettled. */
    @Transactional(rollbackFor = Exception.class)
    public void reschedule(UUID attemptUuid, OffsetDateTime nextCheckAt) {
        schedule(locked(attemptUuid), nextCheckAt);
    }

    /** Hands the attempt to the reconciliation's next look, while it is unsettled. */
    @Transactional(rollbackFor = Exception.class)
    public void dueNow(UUID attemptUuid) {
        schedule(locked(attemptUuid), OffsetDateTime.now());
    }

    /** Records a send, which leaves the attempt to its requester for a retry window. */
    private void sent(KeyImport attempt) {
        OffsetDateTime now = OffsetDateTime.now();
        attempt.setLastSentAt(now);
        attempt.setNextCheckAt(now.plus(properties.retryWindow()));
    }

    private static void schedule(KeyImport attempt, OffsetDateTime nextCheckAt) {
        if (attempt.getState().isUnsettled()) {
            attempt.setNextCheckAt(nextCheckAt);
        }
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
