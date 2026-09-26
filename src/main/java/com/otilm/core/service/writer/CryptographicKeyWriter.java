package com.otilm.core.service.writer;

import com.otilm.api.exception.AttributeException;
import com.otilm.api.exception.NotFoundException;
import com.otilm.api.exception.ValidationError;
import com.otilm.api.exception.ValidationException;
import com.otilm.api.model.client.cryptography.key.EditKeyItemDto;
import com.otilm.api.model.client.cryptography.key.EditKeyRequestDto;
import com.otilm.api.model.client.cryptography.key.KeyCompromiseReason;
import com.otilm.api.model.client.cryptography.key.KeyRequestDto;
import com.otilm.api.model.common.NameAndUuidDto;
import com.otilm.api.model.common.attribute.common.MetadataAttribute;
import com.otilm.api.model.common.enums.cryptography.KeyAlgorithm;
import com.otilm.api.model.common.enums.cryptography.KeyType;
import com.otilm.api.model.core.auth.Resource;
import com.otilm.api.model.core.cryptography.key.KeyEvent;
import com.otilm.api.model.core.cryptography.key.KeyEventStatus;
import com.otilm.api.model.core.cryptography.key.KeyState;
import com.otilm.api.model.core.cryptography.key.KeyUsage;
import com.otilm.core.attribute.engine.AttributeEngine;
import com.otilm.core.attribute.engine.records.ObjectAttributeContentInfo;
import com.otilm.core.dao.entity.CryptographicKey;
import com.otilm.core.dao.entity.CryptographicKeyItem;
import com.otilm.core.dao.entity.TokenProfile;
import com.otilm.core.dao.entity.UniquelyIdentified;
import com.otilm.core.dao.repository.CertificateRepository;
import com.otilm.core.dao.repository.CryptographicKeyItemRepository;
import com.otilm.core.dao.repository.CryptographicKeyRepository;
import com.otilm.core.dao.repository.TokenProfileRepository;
import com.otilm.core.model.crypto.CryptographicKeyBasicModel;
import com.otilm.core.model.crypto.CryptographicKeyFullModel;
import com.otilm.core.model.crypto.CryptographicKeyItemBasicModel;
import com.otilm.core.model.crypto.ImmutableCryptographicKeyBasicModel;
import com.otilm.core.model.crypto.ImmutableCryptographicKeyFullModel;
import com.otilm.core.model.crypto.ImportedKeyRegistration;
import com.otilm.core.model.crypto.KeyImportMetadata;
import com.otilm.core.model.crypto.ProviderKeyItem;
import com.otilm.core.model.crypto.RemoteKeyReference;
import com.otilm.core.model.crypto.TokenInstanceBasicModel;
import com.otilm.core.model.crypto.TokenProfileBasicModel;
import com.otilm.core.model.crypto.TokenProfileFullModel;
import com.otilm.core.security.authz.SecurityResourceFilter;
import com.otilm.core.service.CertificateInternalService;
import com.otilm.core.service.CryptographicKeyEventHistoryService;
import com.otilm.core.service.ResourceObjectAssociationService;
import com.otilm.core.util.CryptographyUtil;
import jakarta.persistence.EntityManager;
import jakarta.persistence.LockModeType;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import java.util.Set;
import java.util.UUID;
import java.util.stream.Collectors;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.context.annotation.Lazy;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import static java.util.function.Predicate.not;

@Service
public class CryptographicKeyWriter {

    private static final Logger logger = LoggerFactory.getLogger(CryptographicKeyWriter.class);

    /** The refusal of an import whose public key the platform already holds in a key of its own. */
    public static final String KEY_ALREADY_HELD = "A key with the same public key already exists.";

    /** The refusal of an import into a public-key-only record that is no longer active. */
    private static final String KEY_CHANGED = "Key %s changed meanwhile. Try again.";

    public static final String KEY_NOT_ACTIVE = "A key with the same public key exists but is not active, so the key cannot be imported into it.";

    private final CryptographicKeyRepository cryptographicKeyRepository;
    private final CryptographicKeyItemRepository cryptographicKeyItemRepository;
    private final TokenProfileRepository tokenProfileRepository;
    private final ResourceObjectAssociationService objectAssociationService;
    private final AttributeEngine attributeEngine;
    private final EntityManager entityManager;
    private final CertificateRepository certificateRepository;
    private final CommentWriter commentWriter;
    private final CryptographicKeyEventHistoryService keyEventHistoryService;
    private final CertificateInternalService certificateService;

    public CryptographicKeyWriter(CryptographicKeyRepository cryptographicKeyRepository,
            CryptographicKeyItemRepository cryptographicKeyItemRepository,
            TokenProfileRepository tokenProfileRepository, ResourceObjectAssociationService objectAssociationService,
            AttributeEngine attributeEngine, EntityManager entityManager, CertificateRepository certificateRepository,
            CommentWriter commentWriter, CryptographicKeyEventHistoryService keyEventHistoryService,
            @Lazy CertificateInternalService certificateService) {
        this.cryptographicKeyRepository = cryptographicKeyRepository;
        this.cryptographicKeyItemRepository = cryptographicKeyItemRepository;
        this.tokenProfileRepository = tokenProfileRepository;
        this.objectAssociationService = objectAssociationService;
        this.attributeEngine = attributeEngine;
        this.entityManager = entityManager;
        this.certificateRepository = certificateRepository;
        this.commentWriter = commentWriter;
        this.keyEventHistoryService = keyEventHistoryService;
        this.certificateService = certificateService;
    }

    /**
     * Creates a parent key and all its items, metadata, creation history, and matching certificate associations. All
     * changes are committed together and rolled back if any step fails.
     *
     * @param request request supplying the key's name and description
     * @param tokenProfile profile associated with the key and supplying usages; may be null for discovery
     * @param tokenInstance token instance containing the key
     * @param items non-null list of provider items to persist
     * @param isDiscovered whether the items were discovered rather than created
     * @param enabled initial enabled state of all items
     * @return immutable basic model of the saved parent key
     * @throws AttributeException if any item's metadata cannot be stored
     */
    @Transactional(rollbackFor = Exception.class)
    public CryptographicKeyBasicModel createKeyWithItems(KeyRequestDto request, TokenProfileBasicModel tokenProfile,
            TokenInstanceBasicModel tokenInstance, List<ProviderKeyItem> items, boolean isDiscovered, boolean enabled)
            throws AttributeException {
        UUID tokenProfileUuid = tokenProfile == null ? null : tokenProfile.uuid();
        CryptographicKeyBasicModel savedKey = save(request.getName(), request.getDescription(), tokenProfileUuid,
                tokenInstance.uuid());
        // Core owns the permission: nothing reported by a connector may grant it, whatever the request states.
        boolean exportable = !isDiscovered && Boolean.TRUE.equals(request.getExportable());
        KeyItemOrigin origin = creationOrigin(tokenProfile, tokenInstance, isDiscovered);
        for (ProviderKeyItem item : items) {
            createKeyContent(tokenProfile, tokenInstance, item, savedKey, enabled, exportable, origin);
        }
        return savedKey;
    }

    private static KeyItemOrigin creationOrigin(TokenProfileBasicModel tokenProfile,
            TokenInstanceBasicModel tokenInstance, boolean isDiscovered) {
        if (isDiscovered) {
            return new KeyItemOrigin(KeyEvent.CREATE, "Key Discovered from Token Instance " + tokenInstance.name(),
                    null);
        }
        assert tokenProfile != null;
        return new KeyItemOrigin(KeyEvent.CREATE,
                "Key Created from Token Profile " + tokenProfile.name() + " on Token Instance " + tokenInstance.name(),
                null);
    }

    /**
     * Registers an imported key: as a key of its own, or by adopting the public-key-only record the platform already
     * holds for its public key, which gains the token profile and the private key and keeps its certificates. The
     * requester becomes the owner and the groups are added, whichever it is.
     *
     * @return the UUID of the registered key
     * @throws ValidationException when the platform holds the public key otherwise than as a public-key-only record
     * @throws NotFoundException when a group no longer exists
     */
    @Transactional(rollbackFor = Exception.class)
    public UUID registerImportedKey(ImportedKeyRegistration registration) throws AttributeException, NotFoundException {
        Optional<CryptographicKeyItem> held = cryptographicKeyItemRepository
                .findByFingerprint(registration.spkiFingerprint());
        UUID keyUuid = held.isPresent()
                ? adoptPublicKeyRecord(held.get().getKeyUuid(), registration)
                : registerNewImportedKey(registration);
        NameAndUuidDto owner = registration.owner();
        objectAssociationService
                .setOwner(Resource.CRYPTOGRAPHIC_KEY, keyUuid, UUID.fromString(owner.getUuid()), owner.getName());
        for (UUID groupUuid : registration.metadata().groupUuids()) {
            objectAssociationService.addGroup(Resource.CRYPTOGRAPHIC_KEY, keyUuid, groupUuid);
        }
        // The unique fingerprint is the last guard against a key registered meanwhile; flushing through the
        // repository reports it as a data integrity violation.
        cryptographicKeyItemRepository.flush();
        return keyUuid;
    }

    private UUID registerNewImportedKey(ImportedKeyRegistration registration) throws AttributeException {
        TokenProfileFullModel profile = registration.profile();
        KeyImportMetadata metadata = registration.metadata();
        CryptographicKeyBasicModel key = save(metadata.name(), metadata.description(), profile.uuid(),
                profile.tokenInstanceReferenceUuid());
        KeyItemOrigin origin = importOrigin(profile, registration.keyReference());
        for (ProviderKeyItem item : registration.items()) {
            createKeyContent(profile, profile.tokenInstance(), item, key, false, registration.exportable(), origin);
        }
        return key.uuid();
    }

    /**
     * The public key item of the public-key-only record an import would adopt, or nothing for a key the platform does
     * not hold. The record is read afresh: an earlier read in the request may have left an older copy.
     *
     * @throws ValidationException when the platform holds the key otherwise, or holds a record no longer active
     */
    @Transactional
    public Optional<UUID> adoptablePublicKey(String spkiFingerprint) {
        Optional<CryptographicKeyItem> held = cryptographicKeyItemRepository.findByFingerprint(spkiFingerprint);
        if (held.isEmpty()) {
            return Optional.empty();
        }
        CryptographicKey holder = held.get().getKey();
        entityManager.refresh(holder);
        requireAdoptable(holder);
        return Optional.of(held.get().getUuid());
    }

    /**
     * Adopts the record read afresh under its lock, and under the locks of its items, since an operator changes an item
     * under the item's own lock; a record that gained a token or a private key, or is no longer active, is refused.
     */
    private UUID adoptPublicKeyRecord(UUID recordUuid, ImportedKeyRegistration registration) throws AttributeException {
        CryptographicKey adopted = cryptographicKeyRepository
                .findForUpdateByUuid(recordUuid)
                .orElseThrow(() -> new ValidationException(ValidationError.create(KEY_ALREADY_HELD)));
        entityManager.refresh(adopted);
        adopted.getItems().forEach(item -> entityManager.refresh(item, LockModeType.PESSIMISTIC_WRITE));
        requireAdoptable(adopted);
        TokenProfileFullModel profile = registration.profile();
        adopted.setTokenProfileUuid(profile.uuid());
        adopted.setTokenInstanceReferenceUuid(profile.tokenInstanceReferenceUuid());
        adopted.setName(registration.metadata().name());
        adopted.setDescription(registration.metadata().description());
        CryptographicKeyItem publicKey = adopted.getItems().iterator().next();
        CryptographicKeyBasicModel key = ImmutableCryptographicKeyBasicModel.from(adopted);
        KeyItemOrigin origin = importOrigin(profile, registration.keyReference());
        for (ProviderKeyItem item : registration.items()) {
            if (item.type() == KeyType.PUBLIC_KEY) {
                adoptPublicKeyItem(publicKey, item, profile, key, origin);
            } else {
                createKeyContent(profile, profile.tokenInstance(), item, key, false, registration.exportable(), origin);
            }
        }
        return adopted.getUuid();
    }

    /**
     * Locks the key and reads it afresh, refusing one that no longer has the token the caller read: an import adopted
     * it meanwhile, so what the caller decided about destroying its items through a token no longer holds.
     */
    private void requireTokenAsRead(CryptographicKeyBasicModel keyRead) {
        cryptographicKeyRepository.findForUpdateByUuid(keyRead.uuid()).ifPresent(locked -> {
            entityManager.refresh(locked);
            if (!Objects.equals(locked.getTokenInstanceReferenceUuid(), keyRead.tokenInstanceReferenceUuid())) {
                throw new ValidationException(ValidationError.create(KEY_CHANGED.formatted(keyRead.uuid())));
            }
        });
    }

    private static void requireAdoptable(CryptographicKey held) {
        if (!held.isPublicKeyOnly()) {
            throw new ValidationException(ValidationError.create(KEY_ALREADY_HELD));
        }
        if (!held.isAdoptable()) {
            throw new ValidationException(ValidationError.create(KEY_NOT_ACTIVE));
        }
    }

    private void adoptPublicKeyItem(CryptographicKeyItem publicKey, ProviderKeyItem item, TokenProfileFullModel profile,
            CryptographicKeyBasicModel key, KeyItemOrigin origin) throws AttributeException {
        if (item.reference() instanceof RemoteKeyReference.MetadataReference(List<MetadataAttribute> keyMeta)) {
            publicKey.setKeyMeta(keyMeta);
        }
        publicKey.setUsage(usagesFor(profile, KeyType.PUBLIC_KEY, publicKey.getKeyAlgorithm()));
        keyEventHistoryService
                .addEventHistory(origin.event(), KeyEventStatus.SUCCESS, origin.historyMessage(), null,
                        publicKey.getUuid());
        storeItemMetadata(item, publicKey.getUuid(), profile.tokenInstance(), key);
    }

    private static KeyItemOrigin importOrigin(TokenProfileFullModel profile, UUID keyReference) {
        return new KeyItemOrigin(KeyEvent.IMPORT, "Key Imported to Token Profile " + profile.name()
                + " on Token Instance " + profile.tokenInstance().name(), keyReference);
    }

    /** Only the halves Core would ever hand out carry the permission; a public key is readable regardless. */
    private static boolean holdsPrivateMaterial(KeyType type) {
        return type == KeyType.PRIVATE_KEY || type == KeyType.SECRET_KEY;
    }

    private void createKeyContent(TokenProfileBasicModel tokenProfile, TokenInstanceBasicModel tokenInstance,
            ProviderKeyItem item, CryptographicKeyBasicModel cryptographicKey, boolean enabled, boolean exportable,
            KeyItemOrigin origin) throws AttributeException {
        logger.atDebug().addArgument(cryptographicKey::toIdentifierString).log("Creating the Key Content for {}");
        CryptographicKeyItem keyItem = new CryptographicKeyItem();
        keyItem.setName(item.name());
        keyItem.setKeyUuid(cryptographicKey.uuid());
        keyItem.setType(item.type());
        keyItem.setKeyAlgorithm(item.algorithm());
        if (item.material() != null) {
            keyItem.setKeyData(item.material().serializedValue());
            keyItem.setFormat(item.material().format());
        }
        String fingerprint = CryptographyUtil.calculateKeyFingerprint(item.material());
        keyItem.setFingerprint(fingerprint);

        keyItem.setLength(item.length());
        if (item.reference() instanceof RemoteKeyReference.UuidReference(UUID uuid)) {
            keyItem.setKeyReferenceUuid(uuid);
        } else if (item.reference() instanceof RemoteKeyReference.MetadataReference(List<MetadataAttribute> keyMeta)) {
            keyItem.setKeyMeta(keyMeta);
        }
        if (origin.keyReference() != null && holdsPrivateMaterial(item.type())) {
            keyItem.setKeyReferenceUuid(origin.keyReference());
        }
        keyItem.setState(KeyState.ACTIVE);
        keyItem.setEnabled(enabled);
        keyItem.setExportable(exportable && holdsPrivateMaterial(item.type()));
        if (tokenProfile != null) {
            keyItem.setUsage(usagesFor(tokenProfile, item.type(), item.algorithm()));
        }

        cryptographicKeyItemRepository.save(keyItem);
        keyEventHistoryService
                .addEventHistory(origin.event(), KeyEventStatus.SUCCESS, origin.historyMessage(), null,
                        keyItem.getUuid());
        storeItemMetadata(item, keyItem.getUuid(), tokenInstance, cryptographicKey);
        if (item.type().equals(KeyType.PUBLIC_KEY)) {
            certificateService.updateCertificateKeys(cryptographicKey.uuid(), keyItem.getFingerprint());
        }
    }

    /** The profile's usages the key type and algorithm may carry. */
    private static List<KeyUsage> usagesFor(TokenProfileBasicModel tokenProfile, KeyType type, KeyAlgorithm algorithm) {
        return tokenProfile
                .usages()
                .stream()
                .filter(not(CryptographyUtil.getForbiddenUsages(type, algorithm)::contains))
                .toList();
    }

    private void storeItemMetadata(ProviderKeyItem item, UUID keyItemUuid, TokenInstanceBasicModel tokenInstance,
            CryptographicKeyBasicModel cryptographicKey) throws AttributeException {
        attributeEngine
                .updateMetadataAttributes(item.metadata(),
                        ObjectAttributeContentInfo
                                .builder(Resource.CRYPTOGRAPHIC_KEY, keyItemUuid)
                                .connector(tokenInstance.connectorUuid())
                                .source(Resource.CRYPTOGRAPHIC_KEY, cryptographicKey.uuid())
                                .sourceName(cryptographicKey.name())
                                .build());
    }

    /**
     * Deletes a local key and its associations in one transaction.
     *
     * <p>
     * Certificate references are cleared, and key and item attributes, owner/group associations, and key comments are
     * removed. JPA deletion cascades from the key to its items and their event histories.
     *
     * @param key model identifying the parent key to delete
     */
    @Transactional
    public void deleteKeyWithAssociations(CryptographicKeyBasicModel key) {
        removeKeyWithAssociations(key.uuid());
    }

    /**
     * Deletes a local key the caller read, with its remaining items and its associations, in one transaction. An item
     * the caller did not read was added since, by an import adopting the key, so the deletion stops rather than take
     * that item along.
     *
     * @param key model identifying the parent key to delete
     * @param itemsRead the key's items as the caller read them
     * @throws ValidationException when the key holds an item the caller did not read
     */
    @Transactional
    public void deleteKeyWithAssociations(CryptographicKeyBasicModel key, Set<UUID> itemsRead) {
        Optional<CryptographicKey> locked = cryptographicKeyRepository.findForUpdateByUuid(key.uuid());
        if (locked.isPresent()) {
            entityManager.refresh(locked.get());
            boolean added = locked.get().getItems().stream().anyMatch(item -> !itemsRead.contains(item.getUuid()));
            if (added) {
                throw new ValidationException(ValidationError.create(KEY_CHANGED.formatted(key.uuid())));
            }
        }
        removeKeyWithAssociations(key.uuid());
    }

    private void removeKeyWithAssociations(UUID keyUuid) {
        List<UUID> itemUuids = cryptographicKeyItemRepository
                .findByKeyUuidIn(List.of(keyUuid))
                .stream()
                .map(UniquelyIdentified::getUuid)
                .toList();
        certificateRepository.clearKeyAssociations(keyUuid);
        certificateRepository.clearAltKeyAssociations(keyUuid);
        attributeEngine.bulkDeleteObjectAttributeContent(Resource.CRYPTOGRAPHIC_KEY, itemUuids);
        attributeEngine.deleteObjectAttributeContent(Resource.CRYPTOGRAPHIC_KEY, keyUuid);
        objectAssociationService.removeObjectAssociations(Resource.CRYPTOGRAPHIC_KEY, keyUuid);
        commentWriter.deleteAllForObject(Resource.CRYPTOGRAPHIC_KEY, keyUuid);
        cryptographicKeyRepository.deleteById(keyUuid);
    }

    /**
     * Deletes a parent and its associations only if no key items remain. Missing parents are ignored.
     *
     * @param key model identifying the parent key to check
     */
    @Transactional
    public void deleteKeyIfEmpty(CryptographicKeyBasicModel key) {
        Optional<CryptographicKey> lockedKey = cryptographicKeyRepository.findForUpdateByUuid(key.uuid());
        if (lockedKey.isPresent() && !cryptographicKeyItemRepository.existsByKeyUuid(key.uuid())) {
            // Association deletion must not leave references to removed entities in the persistence context.
            lockedKey.get().setOwner(null);
            lockedKey.get().getGroups().clear();
            deleteKeyWithAssociations(key);
        }
    }

    /**
     * Deletes selected local key items and their attributes and history. Parents left without items are deleted with
     * their certificate references, attributes, owner/group associations, and comments. All changes commit or roll back
     * together; parents with remaining items are preserved. Parent rows are locked in UUID order before loading items
     * so concurrent sibling deletions cannot both leave the parent behind.
     *
     * @param keyItemUuids non-null list of item UUIDs to delete; missing items are ignored
     * @param parentsRead the parents as the caller read them, locked to serialize concurrent sibling deletions; must
     * contain the parent of every selected item
     * @return number of existing items deleted, counting duplicate UUIDs only once
     * @throws ValidationException when a parent gained a token since the caller read it
     */
    @Transactional
    public int deleteKeyItemsWithAssociations(List<UUID> keyItemUuids,
            List<? extends CryptographicKeyBasicModel> parentsRead) {
        if (keyItemUuids.isEmpty()) {
            return 0;
        }
        parentsRead
                .stream()
                .sorted(Comparator.comparing(CryptographicKeyBasicModel::uuid))
                .forEach(this::requireTokenAsRead);
        List<CryptographicKeyItem> keyItems = cryptographicKeyItemRepository.findByUuidIn(keyItemUuids);
        if (keyItems.isEmpty()) {
            return 0;
        }

        List<UUID> emptyKeyUuids = new ArrayList<>();
        for (CryptographicKeyItem keyItem : keyItems) {
            CryptographicKey key = keyItem.getKey();
            key.getItems().remove(keyItem);
            if (key.getItems().isEmpty()) {
                key.setOwner(null);
                key.getGroups().clear();
                emptyKeyUuids.add(key.getUuid());
            }
        }

        List<UUID> existingItemUuids = keyItems.stream().map(UniquelyIdentified::getUuid).toList();
        attributeEngine.bulkDeleteObjectAttributeContent(Resource.CRYPTOGRAPHIC_KEY, existingItemUuids);
        cryptographicKeyItemRepository.deleteAll(keyItems);

        if (!emptyKeyUuids.isEmpty()) {
            certificateRepository.clearKeyAssociationsIn(emptyKeyUuids);
            certificateRepository.clearAltKeyAssociationsIn(emptyKeyUuids);
            attributeEngine.bulkDeleteObjectAttributeContent(Resource.CRYPTOGRAPHIC_KEY, emptyKeyUuids);
            objectAssociationService.bulkRemoveObjectAssociations(Resource.CRYPTOGRAPHIC_KEY, emptyKeyUuids);
            emptyKeyUuids.forEach(keyUuid -> commentWriter.deleteAllForObject(Resource.CRYPTOGRAPHIC_KEY, keyUuid));
            cryptographicKeyRepository.deleteAllById(emptyKeyUuids);
        }
        return keyItems.size();
    }

    /**
     * Deletes a local key item with its attribute links and event history without loading the item.
     *
     * <p>
     * Event history is removed by the database foreign key cascade.
     * </p>
     *
     * @param keyRead the item's key as the caller read it
     * @param keyItemUuid UUID of the key item to delete
     * @return {@code true} if the item was deleted; {@code false} if it did not exist
     * @throws ValidationException when the key gained a token since the caller read it
     */
    @Transactional
    public boolean deleteKeyItem(CryptographicKeyBasicModel keyRead, UUID keyItemUuid) {
        requireTokenAsRead(keyRead);
        attributeEngine.deleteObjectAttributeContent(Resource.CRYPTOGRAPHIC_KEY, keyItemUuid);
        return cryptographicKeyItemRepository.deleteItemByUuid(keyItemUuid) > 0;
    }

    /**
     * Updates a key item's enabled state and update timestamp only when its stored state differs.
     *
     * <p>
     * The conditional update joins the current transaction or starts one if none exists. Pending changes are flushed
     * before the update, and the persistence context is cleared afterward. Event history and cache invalidation are the
     * caller's responsibility.
     *
     * @param uuid UUID of the key item to update
     * @param enabled requested enabled state
     * @return {@code true} if the item changed; {@code false} if it does not exist or already has the requested state
     */
    @Transactional
    public boolean setKeyItemEnabled(UUID uuid, boolean enabled) {
        boolean hasChanged = cryptographicKeyItemRepository.updateEnabledIfChanged(uuid, enabled) > 0;
        if (hasChanged) {
            keyEventHistoryService
                    .addEventHistory(enabled ? KeyEvent.ENABLE : KeyEvent.DISABLE, KeyEventStatus.SUCCESS,
                            "Key " + (enabled ? "enabled." : "disabled."), null, uuid);
        }
        return hasChanged;
    }

    /**
     * Withdraws the export permission from a key item and records the change in its history.
     *
     * @param keyItemUuid UUID of the key item
     * @return {@code true} if the item was exportable and is no longer
     */
    @Transactional
    public boolean disableKeyItemExport(UUID keyItemUuid) {
        boolean hasChanged = cryptographicKeyItemRepository.clearExportableIfSet(keyItemUuid) > 0;
        if (hasChanged) {
            keyEventHistoryService
                    .addEventHistory(KeyEvent.EXPORT_DISABLED, KeyEventStatus.SUCCESS, "Key export disabled.", null,
                            keyItemUuid);
        }
        return hasChanged;
    }

    /**
     * Marks a pre-active, active, or deactivated key item as compromised and replaces its compromise reason. The state,
     * reason, and success event are saved atomically. An invalid state leaves the item unchanged and records a failed
     * event instead.
     *
     * @param keyItemUuid UUID of the item to mark as compromised
     * @param reason compromise reason, or {@code null} if none is supplied
     * @return an empty optional on success, or a message identifying the item and its invalid state
     * @throws NotFoundException if the item does not exist
     */
    @Transactional(rollbackFor = Exception.class)
    public Optional<String> setKeyItemCompromised(UUID keyItemUuid, KeyCompromiseReason reason)
            throws NotFoundException {
        CryptographicKeyItem keyItem = cryptographicKeyItemRepository
                .findForUpdateByUuid(keyItemUuid)
                .orElseThrow(() -> new NotFoundException(CryptographicKeyItem.class, keyItemUuid));
        KeyState currentState = keyItem.getState();
        if (currentState != KeyState.PRE_ACTIVE && currentState != KeyState.ACTIVE
                && currentState != KeyState.DEACTIVATED) {
            String message = "Key item %s cannot be marked as compromised: its current state is %s."
                    .formatted(keyItemUuid, currentState.getLabel());
            keyEventHistoryService
                    .addEventHistory(KeyEvent.COMPROMISED, KeyEventStatus.FAILED, message, null, keyItemUuid);
            return Optional.of(message);
        }
        keyItem.setState(KeyState.COMPROMISED);
        keyItem.setReason(reason);
        cryptographicKeyItemRepository.save(keyItem);
        keyEventHistoryService
                .addEventHistory(KeyEvent.COMPROMISED, KeyEventStatus.SUCCESS,
                        "Key compromised. Reason: " + reason + ".", null, keyItemUuid);
        return Optional.empty();
    }

    /**
     * Replaces a key item's usages and records the change in one transaction. Unsupported usages leave the item
     * unchanged and produce a failed event.
     *
     * @param keyItemUuid UUID of the item to update
     * @param usages non-null list of requested usages; an empty list clears the usages
     * @return an empty optional on success, or a message identifying the item and its unsupported usages
     * @throws NotFoundException if the item does not exist
     */
    @Transactional(rollbackFor = Exception.class)
    public Optional<String> updateUsage(UUID keyItemUuid, List<KeyUsage> usages) throws NotFoundException {
        CryptographicKeyItem keyItem = cryptographicKeyItemRepository
                .findForUpdateByUuid(keyItemUuid)
                .orElseThrow(() -> new NotFoundException(CryptographicKeyItem.class, keyItemUuid));
        List<KeyUsage> forbiddenUsages = CryptographyUtil
                .getForbiddenUsages(keyItem.getType(), keyItem.getKeyAlgorithm())
                .stream()
                .filter(usages::contains)
                .toList();
        if (!forbiddenUsages.isEmpty()) {
            String nonAllowedUsages = forbiddenUsages.stream().map(KeyUsage::getCode).collect(Collectors.joining(", "));
            String message = "Unsupported usages of key " + keyItemUuid + ": " + nonAllowedUsages + ".";
            keyEventHistoryService
                    .addEventHistory(KeyEvent.UPDATE_USAGE, KeyEventStatus.FAILED, message, null, keyItemUuid);
            return Optional.of(message);
        }
        String oldUsage = keyItem.getUsage().stream().map(KeyUsage::getCode).collect(Collectors.joining(", "));
        keyItem.setUsage(usages);
        cryptographicKeyItemRepository.save(keyItem);
        String newUsage = usages.stream().map(KeyUsage::getCode).collect(Collectors.joining(", "));
        keyEventHistoryService
                .addEventHistory(KeyEvent.UPDATE_USAGE, KeyEventStatus.SUCCESS,
                        "Key usages updated from " + oldUsage + " to " + newUsage + ".", null, keyItemUuid);
        return Optional.empty();
    }

    /**
     * Clears local key material and marks the item destroyed, preserving its current compromise classification and
     * reason. Updates the audit timestamp and records a successful destruction event, including on repeated calls.
     *
     * @param keyRead the item's key as the caller read it
     * @param keyItemUuid non-null UUID of the key item to finalize
     * @throws NotFoundException if the item no longer exists
     * @throws ValidationException when the key gained a token since the caller read it
     */
    @Transactional(rollbackFor = NotFoundException.class)
    public void finalizeKeyItemDestruction(CryptographicKeyBasicModel keyRead, UUID keyItemUuid)
            throws NotFoundException {
        requireTokenAsRead(keyRead);
        if (cryptographicKeyItemRepository.finalizeKeyItemDestruction(keyItemUuid) == 0) {
            throw new NotFoundException(CryptographicKeyItem.class, keyItemUuid);
        }
        keyEventHistoryService
                .addEventHistory(KeyEvent.DESTROY, KeyEventStatus.SUCCESS, "Key destroyed.", null, keyItemUuid);
    }

    /**
     * Creates a parent key record with the requested name, description, and token associations.
     *
     * @param name the key's name
     * @param description the key's description, or {@code null}
     * @param tokenProfileUuid UUID of the associated token profile, or {@code null} if unassigned
     * @param tokenInstanceReferenceUuid UUID of the associated token instance, or {@code null} if unassigned
     * @return immutable basic model of the saved key
     */
    private CryptographicKeyBasicModel save(String name, String description, UUID tokenProfileUuid,
            UUID tokenInstanceReferenceUuid) {
        CryptographicKey key = new CryptographicKey();
        key.setName(name);
        key.setDescription(description);
        key.setTokenProfileUuid(tokenProfileUuid);
        key.setTokenInstanceReferenceUuid(tokenInstanceReferenceUuid);

        CryptographicKey savedKey = cryptographicKeyRepository.save(key);
        logger.atDebug().addArgument(savedKey::toIdentifierString).log("Cryptographic Key saved: {}");
        return ImmutableCryptographicKeyBasicModel.from(savedKey);
    }

    /**
     * Attempts to assign the current user as owner and updates the requested group associations, returning the key's
     * full model with the resulting associations.
     *
     * @param key model identifying the key to update
     * @param groupUuids UUIDs of the groups to associate with the key; null preserves groups, and an empty set clears
     * them
     * @return immutable full model of the key after updating its owner and group associations
     * @throws NotFoundException if the key or a required association target cannot be found
     */
    @Transactional(rollbackFor = Exception.class)
    public CryptographicKeyFullModel updateOwnerAndGroups(CryptographicKeyBasicModel key, Set<UUID> groupUuids)
            throws NotFoundException {
        objectAssociationService.setOwnerFromProfile(Resource.CRYPTOGRAPHIC_KEY, key.uuid());
        if (groupUuids != null) {
            objectAssociationService.setGroups(Resource.CRYPTOGRAPHIC_KEY, key.uuid(), groupUuids);
        }
        CryptographicKey updatedKey = cryptographicKeyRepository
                .findByUuid(key.uuid())
                .orElseThrow(() -> new NotFoundException(CryptographicKey.class.getSimpleName(), key.uuid()));
        entityManager.flush();
        entityManager.refresh(updatedKey);
        return ImmutableCryptographicKeyFullModel.from(updatedKey);
    }

    /**
     * Updates a key's details, associations, and custom attributes in one transaction.
     *
     * <p>
     * A null or empty name preserves the current name. Null description, token profile, group list, and owner values
     * preserve their respective current values. Custom attributes are processed by the attribute engine using the
     * supplied permissions. The saved key is flushed and refreshed before its full model is built. Any exception rolls
     * back the transaction.
     *
     * @param uuid UUID of the parent key to update
     * @param request requested detail, group, and custom attribute changes
     * @param owner owner to assign, or {@code null} to preserve the current owner
     * @param customAttributePermissions permissions applied to custom attribute changes
     * @return immutable full model of the refreshed key
     * @throws NotFoundException if the key or a required association target cannot be found
     * @throws AttributeException if custom attribute processing fails
     */
    @Transactional(rollbackFor = Exception.class)
    public CryptographicKeyFullModel update(UUID uuid, EditKeyRequestDto request, NameAndUuidDto owner,
            SecurityResourceFilter customAttributePermissions) throws NotFoundException, AttributeException {
        CryptographicKey key = cryptographicKeyRepository
                .findByUuid(uuid)
                .orElseThrow(() -> new NotFoundException(CryptographicKey.class, uuid));
        if (request.getName() != null && !request.getName().isEmpty()) {
            key.setName(request.getName());
        }
        if (request.getDescription() != null) {
            key.setDescription(request.getDescription());
        }
        if (request.getTokenProfileUuid() != null) {
            UUID tokenProfileUuid = UUID.fromString(request.getTokenProfileUuid());
            TokenProfile tokenProfile = tokenProfileRepository.getReferenceById(tokenProfileUuid);
            key.setTokenProfile(tokenProfile);
        }
        CryptographicKey savedKey = cryptographicKeyRepository.save(key);

        if (request.getGroupUuids() != null) {
            Set<UUID> groupUuids = request.getGroupUuids().stream().map(UUID::fromString).collect(Collectors.toSet());
            objectAssociationService.setGroups(Resource.CRYPTOGRAPHIC_KEY, uuid, groupUuids);
        }
        if (owner != null) {
            objectAssociationService
                    .setOwner(Resource.CRYPTOGRAPHIC_KEY, uuid, UUID.fromString(owner.getUuid()), owner.getName());
        }
        attributeEngine
                .updateObjectCustomAttributesContent(Resource.CRYPTOGRAPHIC_KEY, uuid, request.getCustomAttributes(),
                        customAttributePermissions);
        entityManager.flush();
        entityManager.refresh(savedKey);
        return ImmutableCryptographicKeyFullModel.from(savedKey);
    }

    /**
     * Updates the name of an item belonging to the specified key.
     *
     * @param keyUuid UUID of the parent key
     * @param keyItemUuid UUID of the item to edit
     * @param request requested item name, which replaces the current name
     * @return immutable model of the updated item
     * @throws NotFoundException if the item does not exist or belongs to another key
     */
    @Transactional(rollbackFor = Exception.class)
    public CryptographicKeyItemBasicModel editKeyItem(UUID keyUuid, UUID keyItemUuid, EditKeyItemDto request)
            throws NotFoundException {
        CryptographicKeyItem keyItem = cryptographicKeyItemRepository
                .findForUpdateByUuidAndKeyUuid(keyItemUuid, keyUuid)
                .orElseThrow(() -> new NotFoundException(
                        "Key Item has not been found for Key with UUID %s.".formatted(keyUuid)));
        keyItem.setName(request.getName());
        CryptographicKeyItem savedItem = cryptographicKeyItemRepository.save(keyItem);
        return CryptographicKeyItemBasicModel.from(savedItem);
    }

    /**
     * What brought a key item into the inventory: the history event and message it is recorded with, and the platform's
     * own reference for the private half of an imported key.
     */
    private record KeyItemOrigin(KeyEvent event, String historyMessage, UUID keyReference) {
    }
}
