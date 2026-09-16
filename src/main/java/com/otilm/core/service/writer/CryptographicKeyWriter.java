package com.otilm.core.service.writer;

import com.otilm.api.exception.AttributeException;
import com.otilm.api.exception.NotFoundException;
import com.otilm.api.model.client.cryptography.key.EditKeyItemDto;
import com.otilm.api.model.client.cryptography.key.EditKeyRequestDto;
import com.otilm.api.model.client.cryptography.key.KeyCompromiseReason;
import com.otilm.api.model.client.cryptography.key.KeyRequestDto;
import com.otilm.api.model.common.NameAndUuidDto;
import com.otilm.api.model.common.attribute.common.MetadataAttribute;
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
import com.otilm.core.model.crypto.ProviderKeyItem;
import com.otilm.core.model.crypto.RemoteKeyReference;
import com.otilm.core.model.crypto.TokenInstanceBasicModel;
import com.otilm.core.model.crypto.TokenProfileBasicModel;
import com.otilm.core.security.authz.SecurityResourceFilter;
import com.otilm.core.service.CertificateInternalService;
import com.otilm.core.service.CryptographicKeyEventHistoryService;
import com.otilm.core.service.ResourceObjectAssociationService;
import com.otilm.core.util.CryptographyUtil;
import jakarta.persistence.EntityManager;
import java.util.ArrayList;
import java.util.List;
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
        CryptographicKeyBasicModel savedKey = save(request, tokenProfileUuid, tokenInstance.uuid());
        for (ProviderKeyItem item : items) {
            createKeyContent(tokenProfile, tokenInstance, item, savedKey, isDiscovered, enabled);
        }
        return savedKey;
    }

    private void createKeyContent(TokenProfileBasicModel tokenProfile, TokenInstanceBasicModel tokenInstance,
            ProviderKeyItem item, CryptographicKeyBasicModel cryptographicKey, boolean isDiscovered, boolean enabled)
            throws AttributeException {
        logger.debug("Creating the Key Content for {}", cryptographicKey.toIdentifierString());
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
        keyItem.setState(KeyState.ACTIVE);
        keyItem.setEnabled(enabled);
        if (tokenProfile != null) {
            keyItem
                    .setUsage(tokenProfile
                            .usages()
                            .stream()
                            .filter(not(CryptographyUtil.getForbiddenUsages(item.type(), item.algorithm())::contains))
                            .toList());
        }

        cryptographicKeyItemRepository.save(keyItem);
        String message;
        if (isDiscovered) {
            message = "Key Discovered from Token Instance " + tokenInstance.name();
        } else {
            assert tokenProfile != null;
            message = "Key Created from Token Profile " + tokenProfile.name() + " on Token Instance "
                    + tokenInstance.name();
        }
        keyEventHistoryService
                .addEventHistory(KeyEvent.CREATE, KeyEventStatus.SUCCESS, message, null, keyItem.getUuid());

        attributeEngine
                .updateMetadataAttributes(item.metadata(),
                        ObjectAttributeContentInfo
                                .builder(Resource.CRYPTOGRAPHIC_KEY, keyItem.getUuid())
                                .connector(tokenInstance.connectorUuid())
                                .source(Resource.CRYPTOGRAPHIC_KEY, cryptographicKey.uuid())
                                .sourceName(cryptographicKey.name())
                                .build());
        if (item.type().equals(KeyType.PUBLIC_KEY)) {
            certificateService.updateCertificateKeys(cryptographicKey.uuid(), keyItem.getFingerprint());
        }
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
        UUID keyUuid = key.uuid();
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
     * @param parentKeyUuids parent UUIDs supplied for locking to serialize concurrent sibling deletions; must contain
     * the parent UUID of every selected item
     * @return number of existing items deleted, counting duplicate UUIDs only once
     */
    @Transactional
    public int deleteKeyItemsWithAssociations(List<UUID> keyItemUuids, List<UUID> parentKeyUuids) {
        if (keyItemUuids.isEmpty()) {
            return 0;
        }
        parentKeyUuids.stream().distinct().sorted().forEach(cryptographicKeyRepository::findForUpdateByUuid);
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
     * @param keyItemUuid UUID of the key item to delete
     * @return {@code true} if the item was deleted; {@code false} if it did not exist
     */
    @Transactional
    public boolean deleteKeyItem(UUID keyItemUuid) {
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
     * @param keyItemUuid non-null UUID of the key item to finalize
     * @throws NotFoundException if the item no longer exists
     */
    @Transactional(rollbackFor = NotFoundException.class)
    public void finalizeKeyItemDestruction(UUID keyItemUuid) throws NotFoundException {
        if (cryptographicKeyItemRepository.finalizeKeyItemDestruction(keyItemUuid) == 0) {
            throw new NotFoundException(CryptographicKeyItem.class, keyItemUuid);
        }
        keyEventHistoryService
                .addEventHistory(KeyEvent.DESTROY, KeyEventStatus.SUCCESS, "Key destroyed.", null, keyItemUuid);
    }

    /**
     * Creates a parent key record with the requested name, description, and token associations.
     *
     * @param request request supplying the key's name and description
     * @param tokenProfileUuid UUID of the associated token profile, or {@code null} if unassigned
     * @param tokenInstanceReferenceUuid UUID of the associated token instance, or {@code null} if unassigned
     * @return immutable basic model of the saved key
     */
    private CryptographicKeyBasicModel save(KeyRequestDto request, UUID tokenProfileUuid,
            UUID tokenInstanceReferenceUuid) {
        CryptographicKey key = new CryptographicKey();
        key.setName(request.getName());
        key.setDescription(request.getDescription());
        key.setTokenProfileUuid(tokenProfileUuid);
        key.setTokenInstanceReferenceUuid(tokenInstanceReferenceUuid);

        CryptographicKey savedKey = cryptographicKeyRepository.save(key);
        logger.debug("Cryptographic Key saved: {}", savedKey.toIdentifierString());
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
}
