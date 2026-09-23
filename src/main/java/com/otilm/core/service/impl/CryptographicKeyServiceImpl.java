package com.otilm.core.service.impl;

import com.otilm.api.exception.AlreadyExistException;
import com.otilm.api.exception.AttributeException;
import com.otilm.api.exception.ConnectorException;
import com.otilm.api.exception.NotFoundException;
import com.otilm.api.exception.NotSupportedException;
import com.otilm.api.exception.PlatformException;
import com.otilm.api.exception.ValidationError;
import com.otilm.api.exception.ValidationException;
import com.otilm.api.model.client.attribute.RequestAttribute;
import com.otilm.api.model.client.certificate.SearchFilterRequestDto;
import com.otilm.api.model.client.certificate.SearchRequestDto;
import com.otilm.api.model.client.cryptography.CryptographicKeyResponseDto;
import com.otilm.api.model.client.cryptography.key.BulkCompromiseKeyItemRequestDto;
import com.otilm.api.model.client.cryptography.key.BulkCompromiseKeyRequestDto;
import com.otilm.api.model.client.cryptography.key.BulkKeyItemUsageRequestDto;
import com.otilm.api.model.client.cryptography.key.BulkKeyUsageRequestDto;
import com.otilm.api.model.client.cryptography.key.CompromiseKeyRequestDto;
import com.otilm.api.model.client.cryptography.key.EditKeyItemDto;
import com.otilm.api.model.client.cryptography.key.EditKeyRequestDto;
import com.otilm.api.model.client.cryptography.key.KeyCompromiseReason;
import com.otilm.api.model.client.cryptography.key.KeyRequestDto;
import com.otilm.api.model.client.cryptography.key.KeyRequestType;
import com.otilm.api.model.client.cryptography.key.UpdateKeyUsageRequestDto;
import com.otilm.api.model.common.NameAndUuidDto;
import com.otilm.api.model.common.attribute.common.BaseAttribute;
import com.otilm.api.model.common.enums.cryptography.KeyAlgorithm;
import com.otilm.api.model.common.enums.cryptography.KeyFormat;
import com.otilm.api.model.common.enums.cryptography.KeyType;
import com.otilm.api.model.core.auth.Resource;
import com.otilm.api.model.core.auth.UserDto;
import com.otilm.api.model.core.cryptography.key.KeyDetailDto;
import com.otilm.api.model.core.cryptography.key.KeyDto;
import com.otilm.api.model.core.cryptography.key.KeyEvent;
import com.otilm.api.model.core.cryptography.key.KeyEventHistoryDto;
import com.otilm.api.model.core.cryptography.key.KeyEventStatus;
import com.otilm.api.model.core.cryptography.key.KeyItemDetailDto;
import com.otilm.api.model.core.cryptography.key.KeyItemDto;
import com.otilm.api.model.core.cryptography.key.KeyState;
import com.otilm.api.model.core.cryptography.key.KeyUsage;
import com.otilm.api.model.core.notification.RecipientType;
import com.otilm.api.model.core.scheduler.PaginationRequestDto;
import com.otilm.api.model.core.search.FilterFieldSource;
import com.otilm.api.model.core.search.SearchFieldDataByGroupDto;
import com.otilm.api.model.core.search.SearchFieldDataDto;
import com.otilm.core.attribute.engine.AttributeColumnProjector;
import com.otilm.core.attribute.engine.AttributeEngine;
import com.otilm.core.attribute.engine.AttributeEngine.CustomAttributeContentFilter;
import com.otilm.core.attribute.engine.ListingSortResolver;
import com.otilm.core.attribute.engine.records.ObjectAttributeContentInfo;
import com.otilm.core.comparator.SearchFieldDataComparator;
import com.otilm.core.config.cache.CacheConfig;
import com.otilm.core.config.cache.CacheEvictor;
import com.otilm.core.dao.entity.CryptographicKey;
import com.otilm.core.dao.entity.CryptographicKeyItem;
import com.otilm.core.dao.entity.CryptographicKeyItem_;
import com.otilm.core.dao.entity.CryptographicKey_;
import com.otilm.core.dao.entity.Group;
import com.otilm.core.dao.entity.TokenInstanceReference;
import com.otilm.core.dao.entity.TokenProfile;
import com.otilm.core.dao.repository.CryptographicKeyItemRepository;
import com.otilm.core.dao.repository.CryptographicKeyRepository;
import com.otilm.core.dao.repository.GroupRepository;
import com.otilm.core.dao.repository.TokenInstanceReferenceRepository;
import com.otilm.core.dao.repository.TokenProfileRepository;
import com.otilm.core.enums.FilterField;
import com.otilm.core.mapper.crypto.CryptographicKeyDtoMapper;
import com.otilm.core.messaging.jms.producers.NotificationProducer;
import com.otilm.core.messaging.model.NotificationRecipient;
import com.otilm.core.model.auth.ResourceAction;
import com.otilm.core.model.crypto.CryptographicKeyBasicModel;
import com.otilm.core.model.crypto.CryptographicKeyFullModel;
import com.otilm.core.model.crypto.CryptographicKeyItemBasicModel;
import com.otilm.core.model.crypto.CryptographicKeyItemOperationModel;
import com.otilm.core.model.crypto.CryptographicKeyItemOperationRow;
import com.otilm.core.model.crypto.ImmutableCryptographicKeyListModel;
import com.otilm.core.model.crypto.KeyMaterial;
import com.otilm.core.model.crypto.ProviderKeyItem;
import com.otilm.core.model.crypto.RemoteKeyReference;
import com.otilm.core.model.crypto.TokenInstanceFullModel;
import com.otilm.core.model.crypto.TokenProfileBasicModel;
import com.otilm.core.model.crypto.TokenProfileFullModel;
import com.otilm.core.security.authn.client.UserManagementApiClient;
import com.otilm.core.security.authz.AuthorizationEnforcer;
import com.otilm.core.security.authz.ExternalAuthorization;
import com.otilm.core.security.authz.ObjectFilterAspect;
import com.otilm.core.security.authz.SecuredParentUUID;
import com.otilm.core.security.authz.SecuredUUID;
import com.otilm.core.security.authz.SecurityFilter;
import com.otilm.core.security.authz.SecurityResourceFilter;
import com.otilm.core.service.CryptographicKeyEventHistoryService;
import com.otilm.core.service.CryptographicKeyExternalService;
import com.otilm.core.service.CryptographicKeyInternalService;
import com.otilm.core.service.ResourceObjectAssociationService;
import com.otilm.core.service.handler.key.KeyCreationValidationCapability;
import com.otilm.core.service.handler.key.KeyProviderAdapter;
import com.otilm.core.service.handler.key.KeyProviderAdapterFactory;
import com.otilm.core.service.writer.CertificateKeyWriter;
import com.otilm.core.service.writer.CryptographicKeyWriter;
import com.otilm.core.util.AuthHelper;
import com.otilm.core.util.CryptographyUtil;
import com.otilm.core.util.FilterPredicatesBuilder;
import com.otilm.core.util.RequestValidatorHelper;
import com.otilm.core.util.SearchHelper;
import com.otilm.core.util.SortOrderBuilder;
import jakarta.persistence.criteria.CriteriaBuilder;
import jakarta.persistence.criteria.CriteriaQuery;
import jakarta.persistence.criteria.Predicate;
import jakarta.persistence.criteria.Root;
import java.security.PublicKey;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.UUID;
import java.util.function.Supplier;
import java.util.stream.Collectors;
import org.apache.commons.lang3.function.TriFunction;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.cache.annotation.Cacheable;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageImpl;
import org.springframework.data.domain.PageRequest;
import org.springframework.data.domain.Pageable;
import org.springframework.lang.NonNull;
import org.springframework.lang.Nullable;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Propagation;
import org.springframework.transaction.annotation.Transactional;

import static java.util.function.Predicate.not;

@Service(Resource.Codes.CRYPTOGRAPHIC_KEY)
@Transactional(propagation = Propagation.NOT_SUPPORTED)
public class CryptographicKeyServiceImpl implements CryptographicKeyExternalService, CryptographicKeyInternalService {

    private static final Logger logger = LoggerFactory.getLogger(CryptographicKeyServiceImpl.class);
    private static final String ENABLE_OPERATION = "enable";
    private static final String ENABLED_STATE = "enabled";
    private static final String DISABLED_STATE = "disabled";

    @Value("${spring.jpa.properties.hibernate.jdbc.batch_size:500}")
    private int bulkDeleteBatchSize;
    private ObjectFilterAspect objectFilterAspect;
    // --------------------------------------------------------------------------------
    // Services & API Clients
    // --------------------------------------------------------------------------------
    private AttributeEngine attributeEngine;
    private AttributeColumnProjector attributeColumnProjector;
    private ListingSortResolver listingSortResolver;
    private CryptographicKeyEventHistoryService keyEventHistoryService;
    private AuthorizationEnforcer authorizationEnforcer;
    private ResourceObjectAssociationService objectAssociationService;
    private NotificationProducer notificationProducer;
    private KeyProviderAdapterFactory keyProviderAdapterFactory;
    private CryptographicKeyWriter cryptographicKeyWriter;
    private CertificateKeyWriter certificateKeyWriter;
    private UserManagementApiClient userManagementApiClient;
    private CacheEvictor cacheEvictor;
    // --------------------------------------------------------------------------------
    // Repositories
    // --------------------------------------------------------------------------------
    private CryptographicKeyRepository cryptographicKeyRepository;
    private CryptographicKeyItemRepository cryptographicKeyItemRepository;
    private TokenProfileRepository tokenProfileRepository;
    private TokenInstanceReferenceRepository tokenInstanceReferenceRepository;
    private GroupRepository groupRepository;

    private static TriFunction<Root<CryptographicKeyItem>, CriteriaBuilder, CriteriaQuery<?>, Predicate> createAdditionalWhereClauseForBulkDeleteBatch(
            List<UUID> batchUuids) {
        return ((root, cb, cr) -> {
            var in = cb.in(root.get(CryptographicKeyItem_.uuid.getName()));
            batchUuids.forEach(in::value);
            return in;
        });
    }

    @Autowired
    public void setObjectFilterAspect(ObjectFilterAspect objectFilterAspect) {
        this.objectFilterAspect = objectFilterAspect;
    }

    @Autowired
    public void setKeyProviderAdapterFactory(KeyProviderAdapterFactory keyProviderAdapterFactory) {
        this.keyProviderAdapterFactory = keyProviderAdapterFactory;
    }

    @Autowired
    public void setUserManagementApiClient(UserManagementApiClient userManagementApiClient) {
        this.userManagementApiClient = userManagementApiClient;
    }

    @Autowired
    public void setAttributeEngine(AttributeEngine attributeEngine) {
        this.attributeEngine = attributeEngine;
    }

    @Autowired
    public void setAttributeColumnProjector(AttributeColumnProjector attributeColumnProjector) {
        this.attributeColumnProjector = attributeColumnProjector;
    }

    @Autowired
    public void setListingSortResolver(ListingSortResolver listingSortResolver) {
        this.listingSortResolver = listingSortResolver;
    }

    @Autowired
    public void setObjectAssociationService(ResourceObjectAssociationService objectAssociationService) {
        this.objectAssociationService = objectAssociationService;
    }

    @Autowired
    public void setKeyEventHistoryService(CryptographicKeyEventHistoryService keyEventHistoryService) {
        this.keyEventHistoryService = keyEventHistoryService;
    }

    @Autowired
    public void setAuthorizationEnforcer(AuthorizationEnforcer authorizationEnforcer) {
        this.authorizationEnforcer = authorizationEnforcer;
    }

    @Autowired
    public void setNotificationProducer(NotificationProducer notificationProducer) {
        this.notificationProducer = notificationProducer;
    }

    @Autowired
    public void setCacheEvictor(CacheEvictor cacheEvictor) {
        this.cacheEvictor = cacheEvictor;
    }

    @Autowired
    public void setCryptographicKeyItemRepository(CryptographicKeyItemRepository cryptographicKeyItemRepository) {
        this.cryptographicKeyItemRepository = cryptographicKeyItemRepository;
    }

    @Autowired
    public void setCryptographicKeyRepository(CryptographicKeyRepository cryptographicKeyRepository) {
        this.cryptographicKeyRepository = cryptographicKeyRepository;
    }

    @Autowired
    public void setCryptographicKeyWriter(CryptographicKeyWriter cryptographicKeyWriter) {
        this.cryptographicKeyWriter = cryptographicKeyWriter;
    }

    @Autowired
    public void setCertificateKeyWriter(CertificateKeyWriter certificateKeyWriter) {
        this.certificateKeyWriter = certificateKeyWriter;
    }

    @Autowired
    public void setTokenProfileRepository(TokenProfileRepository tokenProfileRepository) {
        this.tokenProfileRepository = tokenProfileRepository;
    }

    @Autowired
    public void setGroupRepository(GroupRepository groupRepository) {
        this.groupRepository = groupRepository;
    }

    @Autowired
    public void setTokenInstanceReferenceRepository(TokenInstanceReferenceRepository tokenInstanceReferenceRepository) {
        this.tokenInstanceReferenceRepository = tokenInstanceReferenceRepository;
    }

    // ----------------------------------------------------------------------------------------------
    // Service Implementations
    // ----------------------------------------------------------------------------------------------

    @Override
    @ExternalAuthorization(resource = Resource.CRYPTOGRAPHIC_KEY, action = ResourceAction.LIST,
            parentResource = Resource.TOKEN, parentAction = ResourceAction.MEMBERS)
    public CryptographicKeyResponseDto listCryptographicKeys(SecurityFilter filter, SearchRequestDto request) {
        RequestValidatorHelper.revalidateSearchRequestDto(request);

        // Resolve attribute permissions lazily once, then share them across filtering, sorting, and projection.
        final Supplier<CustomAttributeContentFilter> contentFilter = attributeEngine.customAttributeContentFilterOnce();
        Page<CryptographicKeyItem> filteredPage = findAccessibleKeyItemsMatchingSearch(filter, request, contentFilter);
        List<UUID> filteredKeyUuids = filteredPage.getContent().stream().map(CryptographicKeyItem::getUuid).toList();

        // Fetch certificate-association counts for the whole page in one query, avoiding a query per item.
        Map<UUID, Integer> associationsCounts = cryptographicKeyItemRepository
                .getCountsOfAssociations(filteredKeyUuids)
                .stream()
                .collect(Collectors
                        .toMap(CryptographicKeyItemRepository.KeyItemAssociationCount::getUuid,
                                CryptographicKeyItemRepository.KeyItemAssociationCount::getAssociations));

        List<KeyItemDto> listedKeyDtos = filteredPage.getContent().stream().map(cki -> {
            KeyItemDto dto = cki.mapToSummaryDto();
            dto.setAssociations(associationsCounts.getOrDefault(cki.getUuid(), 0));
            return dto;
        }).toList();

        // Fill the requested attribute columns in each response DTO. Custom attributes belong to the parent
        // CryptographicKey, so look them up using keyWrapperUuid; metadata belongs to the individual
        // CryptographicKeyItem, so look it up using the item's uuid. Items with the same parent share custom
        // attribute values but can have different metadata. Apply contentFilter to respect attribute permissions.
        attributeColumnProjector
                .project(Resource.CRYPTOGRAPHIC_KEY, request.getColumns(), listedKeyDtos,
                        keyItem -> AttributeColumnProjector.parseUuid(keyItem.getKeyWrapperUuid()),
                        keyItem -> AttributeColumnProjector.parseUuid(keyItem.getUuid()), contentFilter);

        return CryptographicKeyDtoMapper.mapToResponseDto(filteredPage, listedKeyDtos);
    }

    @Override
    @ExternalAuthorization(resource = Resource.CRYPTOGRAPHIC_KEY, action = ResourceAction.LIST)
    public List<KeyDto> listKeyPairs(Optional<String> tokenProfileUuid, SecurityFilter filter) {
        logger.debug("Requesting key list for Token profile with UUID {}", tokenProfileUuid);
        filter.setParentRefProperty(CryptographicKey_.tokenInstanceReferenceUuid.getName());

        TriFunction<Root<CryptographicKey>, CriteriaBuilder, CriteriaQuery<?>, Predicate> additionalWhereClause = null;
        if (tokenProfileUuid.isPresent() && !tokenProfileUuid.get().isEmpty()) {
            additionalWhereClause = (root, cb, cr) -> cb
                    .equal(root.get(CryptographicKey_.tokenProfileUuid), UUID.fromString(tokenProfileUuid.get()));
        }

        List<CryptographicKey> keys = cryptographicKeyRepository
                .findUsingSecurityFilter(filter,
                        List.of("groups", "owner", "items", "tokenProfile", "tokenInstanceReference"),
                        additionalWhereClause, null, (root, cb) -> cb.desc(root.get("created")));
        Map<UUID, Long> certificateCounts = getKeyCertificateCounts(keys);
        List<KeyDto> response = keys
                .stream()
                .map(key -> ImmutableCryptographicKeyListModel
                        .from(key, certificateCounts.getOrDefault(key.getUuid(), 0L)))
                .map(CryptographicKeyDtoMapper::mapToDto)
                .toList();

        response = response
                .stream()
                .filter(e -> e.getItems().size() == 2)
                .filter(e -> e.getItems().stream().filter(i -> i.getState().equals(KeyState.ACTIVE)).count() == 2)
                .filter(e -> {
                    List<KeyType> keyTypes = e
                            .getItems()
                            .stream()
                            .map(KeyItemDto::getType)
                            .collect(Collectors.toList());
                    keyTypes.removeAll(List.of(KeyType.PUBLIC_KEY, KeyType.PRIVATE_KEY));
                    return keyTypes.isEmpty();
                })
                .toList();
        return response;
    }

    private Map<UUID, Long> getKeyCertificateCounts(List<CryptographicKey> keys) {
        List<UUID> uuids = keys.stream().map(CryptographicKey::getUuid).toList();
        Map<UUID, Long> counts = new HashMap<>();
        final int batchSize = 500;
        for (int start = 0; start < uuids.size(); start += batchSize) {
            List<UUID> batch = uuids.subList(start, Math.min(start + batchSize, uuids.size()));
            cryptographicKeyRepository
                    .getCertificateAssociationCounts(batch)
                    .forEach(count -> counts.put(count.getUuid(), count.getAssociations()));
        }
        return counts;
    }

    @Override
    @ExternalAuthorization(resource = Resource.CRYPTOGRAPHIC_KEY, action = ResourceAction.DETAIL)
    public KeyDetailDto getKey(SecuredUUID uuid) throws NotFoundException {
        CryptographicKeyFullModel key = getCryptographicKeyFullModel(uuid.getValue());
        verifyPermissionsForAssociatedToken(key, "get detail", ResourceAction.MEMBERS);
        KeyDetailDto dto = CryptographicKeyDtoMapper.mapToDetailDto(key);
        if (key.tokenInstance() != null) {
            dto
                    .setAttributes(attributeEngine
                            .getObjectDataAttributesContent(ObjectAttributeContentInfo
                                    .builder(Resource.CRYPTOGRAPHIC_KEY, key.uuid())
                                    .connector(key.tokenInstance().connectorUuid())
                                    .build()));
        }
        dto
                .setCustomAttributes(
                        attributeEngine.getObjectCustomAttributesContent(Resource.CRYPTOGRAPHIC_KEY, key.uuid()));
        dto
                .getItems()
                .forEach(k -> k
                        .setMetadata(attributeEngine
                                .getMappedMetadataContent(ObjectAttributeContentInfo
                                        .builder(Resource.CRYPTOGRAPHIC_KEY, UUID.fromString(k.getUuid()))
                                        .build())));
        logger.atDebug().addArgument(key::toIdentifierString).log("Key details retrieved: {}");
        return dto;
    }

    @Override
    @ExternalAuthorization(resource = Resource.CRYPTOGRAPHIC_KEY, action = ResourceAction.DETAIL)
    public KeyItemDetailDto getKeyItem(SecuredUUID uuid, String keyItemUuid) throws NotFoundException {
        CryptographicKeyBasicModel key = getCryptographicKeyBasicModel(uuid.getValue());
        verifyPermissionsForAssociatedToken(key, "get detail of key item %s".formatted(keyItemUuid),
                ResourceAction.MEMBERS);
        CryptographicKeyItem item = cryptographicKeyItemRepository
                .findByUuidAndKeyUuid(UUID.fromString(keyItemUuid), key.uuid())
                .orElseThrow(() -> new NotFoundException(CryptographicKeyItem.class, keyItemUuid));
        KeyItemDetailDto dto = item.mapToDto();
        logger.atDebug().addArgument(item::toIdentifierString).log("Key item retrieved: {}");
        dto
                .setMetadata(attributeEngine
                        .getMappedMetadataContent(ObjectAttributeContentInfo
                                .builder(Resource.CRYPTOGRAPHIC_KEY, item.getUuid())
                                .build()));
        logger.atDebug().addArgument(item::toIdentifierString).log("Key item attributes retrieved: {}");
        return dto;
    }

    @Override
    @ExternalAuthorization(resource = Resource.CRYPTOGRAPHIC_KEY, action = ResourceAction.CREATE,
            parentResource = Resource.TOKEN, parentAction = ResourceAction.DETAIL)
    public KeyDetailDto createKey(UUID tokenInstanceUuid, SecuredParentUUID tokenProfileUuid, KeyRequestType type,
            KeyRequestDto request) throws AlreadyExistException, ValidationException, ConnectorException,
            AttributeException, NotFoundException {
        logger.debug("Creating a new key for Token profile {}", tokenProfileUuid);

        if (cryptographicKeyRepository.findByName(request.getName()).isPresent()) {
            logger.error("Key with same name already exists");
            throw new AlreadyExistException("Existing Key with the same name already exists");
        }

        TokenProfileFullModel tokenProfile = getTokenProfile(tokenInstanceUuid, tokenProfileUuid);
        logger.atDebug().addArgument(tokenProfile::toIdentifierString).log("Token Profile: {}");
        throwIfTokenProfileNotEnabled(tokenProfile);

        attributeEngine.validateCustomAttributesContent(Resource.CRYPTOGRAPHIC_KEY, request.getCustomAttributes());
        mergeAndValidateAttributes(type, tokenProfile, request.getAttributes());

        List<ProviderKeyItem> remotelyCreatedKeyItems = keyProviderAdapterFactory
                .forToken(tokenProfile.tokenInstance())
                .createKey(tokenProfile, type, request.getAttributes(), request.getName());

        CryptographicKeyFullModel key = persistCreatedKey(tokenProfile, request, remotelyCreatedKeyItems);
        key = updateOwnerAndGroups(request, key);

        logger.atDebug().addArgument(key::toIdentifierString).log("Key creation is successful: {}");

        return assembleKeyDetailDto(request, key, tokenProfile);
    }

    @Override
    @ExternalAuthorization(resource = Resource.CRYPTOGRAPHIC_KEY, action = ResourceAction.UPDATE)
    public KeyDetailDto editKey(SecuredUUID uuid, EditKeyRequestDto request)
            throws NotFoundException, AttributeException {
        logger.debug("Updating the key with UUID {}", uuid);
        CryptographicKeyBasicModel key = getCryptographicKeyBasicModel(uuid.getValue());

        UUID tokenInstanceUuid = key.tokenInstanceReferenceUuid();
        if (tokenInstanceUuid != null) {
            authorizationEnforcer
                    .enforce(Resource.TOKEN, ResourceAction.MEMBERS, SecuredUUID.fromUUID(tokenInstanceUuid));
        }

        if (request.getTokenProfileUuid() != null) {
            TokenProfileBasicModel requestedTokenProfile = tokenProfileRepository
                    .findBasicModelByUuid(UUID.fromString(request.getTokenProfileUuid()))
                    .orElseThrow(() -> new NotFoundException(TokenProfile.class, request.getTokenProfileUuid()));
            if (!requestedTokenProfile.tokenInstanceReferenceUuid().equals(key.tokenInstanceReferenceUuid())) {
                throw new ValidationException(
                        ValidationError.create("Cannot assign Token Profile from different provider"));
            }
            throwIfTokenProfileNotEnabled(requestedTokenProfile);
        }

        NameAndUuidDto owner = request.getOwnerUuid() == null
                ? null
                : objectAssociationService
                        .getRecipientObjectInfo(RecipientType.USER, UUID.fromString(request.getOwnerUuid()));
        SecurityResourceFilter customAttributeResourceFilter = attributeEngine
                .loadCustomAttributesSecurityResourceFilter();

        CryptographicKeyFullModel updatedKey = cryptographicKeyWriter
                .update(key.uuid(), request, owner, customAttributeResourceFilter);
        updatedKey.items().forEach(item -> evictKeyItemCache(item.uuid()));

        logger.atDebug().addArgument(updatedKey::toIdentifierString).log("Key details updated. Key: {}");
        return getKey(uuid);
    }

    @Override
    @ExternalAuthorization(resource = Resource.CRYPTOGRAPHIC_KEY, action = ResourceAction.ENABLE)
    public void disableKey(UUID uuid, List<String> keyItemUuids) throws NotFoundException, ValidationException {
        CryptographicKeyFullModel key = getCryptographicKeyFullModel(uuid);
        verifyPermissionsForAssociatedToken(key, "disable", ResourceAction.DETAIL);
        List<CryptographicKeyItemBasicModel> items = resolveKeyItems(key, parseKeyItemUuids(keyItemUuids));
        setKeyItemsEnabled(itemUuidsAsStrings(items), false);
    }

    @Override
    @ExternalAuthorization(resource = Resource.CRYPTOGRAPHIC_KEY, action = ResourceAction.ENABLE)
    public void enableKey(UUID uuid, List<String> keyItemUuids) throws NotFoundException, ValidationException {
        CryptographicKeyFullModel key = getCryptographicKeyFullModel(uuid);
        verifyPermissionsForAssociatedToken(key, ENABLE_OPERATION, ResourceAction.DETAIL);
        List<CryptographicKeyItemBasicModel> items = resolveKeyItems(key, parseKeyItemUuids(keyItemUuids));
        setKeyItemsEnabled(itemUuidsAsStrings(items), true);
    }

    @Override
    @ExternalAuthorization(resource = Resource.CRYPTOGRAPHIC_KEY, action = ResourceAction.ENABLE,
            parentResource = Resource.TOKEN, parentAction = ResourceAction.DETAIL)
    public void disableKey(List<String> uuids) {
        logger.debug("Request to disable the keys with UUIDs {} ", uuids);
        for (String keyUuid : new LinkedHashSet<>(uuids)) {
            try {
                CryptographicKeyFullModel key = getCryptographicKeyFullModel(UUID.fromString(keyUuid));
                List<String> keyItemUuids = key.items().stream().map(keyItem -> keyItem.uuid().toString()).toList();
                verifyPermissionsForAssociatedToken(key, ENABLE_OPERATION, ResourceAction.DETAIL);
                setKeyItemsEnabled(keyItemUuids, false);
            } catch (NotFoundException e) {
                logger.error("Key items of the key '{}' could not be disabled.", keyUuid, e);
            }
        }
        logger.info("Keys with UUIDs {} have been disabled", uuids);
    }

    @Override
    @ExternalAuthorization(resource = Resource.CRYPTOGRAPHIC_KEY, action = ResourceAction.ENABLE,
            parentResource = Resource.TOKEN, parentAction = ResourceAction.DETAIL)
    public void enableKey(List<String> uuids) {
        logger.debug("Request to enable the keys with UUIDs {} ", uuids);
        for (String keyUuid : new LinkedHashSet<>(uuids)) {
            try {
                CryptographicKeyFullModel key = getCryptographicKeyFullModel(UUID.fromString(keyUuid));
                verifyPermissionsForAssociatedToken(key, ENABLE_OPERATION, ResourceAction.DETAIL);
                List<String> keyItemUuids = key.items().stream().map(keyItem -> keyItem.uuid().toString()).toList();
                setKeyItemsEnabled(keyItemUuids, true);
            } catch (NotFoundException e) {
                logger.error("Key items of the key '{}' could not be enabled.", keyUuid, e);
            }
        }
        logger.info("Keys with UUIDs {} have been enabled", uuids);
    }

    @Override
    @ExternalAuthorization(resource = Resource.CRYPTOGRAPHIC_KEY, action = ResourceAction.DELETE)
    public void deleteKey(UUID parentKeyUuid, List<String> keyItemUuids) throws ConnectorException, NotFoundException {
        CryptographicKeyFullModel key = getCryptographicKeyFullModel(parentKeyUuid);
        verifyPermissionsForAssociatedToken(key, "delete", ResourceAction.DETAIL);

        if (keyItemUuids == null || keyItemUuids.isEmpty()) {
            deleteKey(List.of(parentKeyUuid.toString()));
        } else {
            List<CryptographicKeyItemBasicModel> items = resolveKeyItems(key, parseKeyItemUuids(keyItemUuids));
            for (CryptographicKeyItemBasicModel item : items) {
                if (key.tokenInstance() != null) {
                    keyProviderAdapterFactory.forToken(key.tokenInstance()).destroyKeyItem(key, item.reference());
                }
                cryptographicKeyWriter.deleteKeyItem(item.uuid());
                evictKeyItemCache(item.uuid());
            }
            cryptographicKeyWriter.deleteKeyIfEmpty(key);
        }
        logger.atInfo().addArgument(key::toIdentifierString).log("Key deleted: {}");
    }

    @Override
    @ExternalAuthorization(resource = Resource.CRYPTOGRAPHIC_KEY, action = ResourceAction.DELETE,
            parentResource = Resource.TOKEN, parentAction = ResourceAction.DETAIL)
    public void deleteKey(List<String> uuids) throws ConnectorException {
        logger.debug("Request to deleted the keys with UUIDs {}", uuids);
        for (String uuid : uuids) {
            try {
                CryptographicKeyFullModel key = getCryptographicKeyFullModel(UUID.fromString(uuid));
                verifyPermissionsForAssociatedToken(key, "delete", ResourceAction.DETAIL);
                for (CryptographicKeyItemBasicModel keyItem : key.items()) {
                    if (key.tokenInstance() != null) {
                        keyProviderAdapterFactory
                                .forToken(key.tokenInstance())
                                .destroyKeyItem(key, keyItem.reference());
                    }
                    cryptographicKeyWriter.deleteKeyItem(keyItem.uuid());
                    evictKeyItemCache(keyItem.uuid());
                }
                cryptographicKeyWriter.deleteKeyWithAssociations(key);
            } catch (NotFoundException e) {
                logger.warn("Key with UUID '{}' could not be deleted because it was not found.", uuid);
            }
        }
        logger.info("Keys deleted: {}", uuids);
    }

    @Override
    @ExternalAuthorization(resource = Resource.CRYPTOGRAPHIC_KEY, action = ResourceAction.DELETE,
            parentResource = Resource.TOKEN, parentAction = ResourceAction.MEMBERS)
    public void deleteKeyItems(SecurityFilter filterForTokenInstance, List<String> keyItemUuids) {
        filterForTokenInstance.setParentRefProperty(CryptographicKey_.tokenInstanceReferenceUuid.getName());
        SecurityFilter filterForTokenProfile = createSecurityFilterFor(Resource.CRYPTOGRAPHIC_KEY,
                ResourceAction.DELETE, Resource.TOKEN_PROFILE, ResourceAction.MEMBERS,
                CryptographicKey_.tokenProfileUuid.getName());

        UUID loggedUserUuid = UUID.fromString(AuthHelper.getUserIdentification().getUuid());
        int totalToDelete = keyItemUuids.size();
        int deletedCount = 0;
        List<SecurityFilter> filters = List.of(filterForTokenInstance, filterForTokenProfile);

        for (int i = 0; i < totalToDelete; i += bulkDeleteBatchSize) {
            int end = Math.min(i + bulkDeleteBatchSize, totalToDelete);
            List<UUID> batchUuids = keyItemUuids.subList(i, end).stream().map(UUID::fromString).toList();

            try {
                deletedCount += deleteKeyItemsBatch(filters, batchUuids, loggedUserUuid);
            } catch (Exception e) {
                logger.error("Failed to process key item bulk deletion batch: {}", e.getMessage(), e);
                notificationProducer
                        .produceInternalNotificationMessage(Resource.CRYPTOGRAPHIC_KEY_ITEM, batchUuids.getFirst(),
                                NotificationRecipient.buildUserNotificationRecipient(loggedUserUuid),
                                "Batch key deletion failed for " + batchUuids.size() + " key items",
                                "Key item deletion failed. See server logs for details.");
            }
        }
        logger.debug("Bulk deleted {} of {} key items.", deletedCount, totalToDelete);
    }

    @Override
    @ExternalAuthorization(resource = Resource.CRYPTOGRAPHIC_KEY, action = ResourceAction.DELETE)
    public void destroyKey(UUID uuid, List<String> keyItemUuids) throws ConnectorException, NotFoundException {
        CryptographicKeyFullModel key = getCryptographicKeyFullModel(uuid);
        verifyPermissionsForAssociatedToken(key, "destroy", ResourceAction.DETAIL);

        List<CryptographicKeyItemBasicModel> items = resolveKeyItems(key, parseKeyItemUuids(keyItemUuids));
        KeyDestructionResult result = destroyKeyItemsInternal(key, items);
        result.throwIfFailed();
        logger.atInfo().addArgument(key::toIdentifierString).log("Key destroyed: {}");
    }

    @Override
    @ExternalAuthorization(resource = Resource.CRYPTOGRAPHIC_KEY, action = ResourceAction.DELETE,
            parentResource = Resource.TOKEN, parentAction = ResourceAction.DETAIL)
    public void destroyKey(List<String> uuids) throws ConnectorException, NotFoundException {
        logger.debug("Request to destroy the key with UUIDs {}", uuids);
        List<CryptographicKeyFullModel> keys = new ArrayList<>();
        Set<UUID> keyUuids = uuids.stream().map(UUID::fromString).collect(Collectors.toCollection(LinkedHashSet::new));
        for (UUID uuid : keyUuids) {
            CryptographicKeyFullModel key = getCryptographicKeyFullModel(uuid);
            verifyPermissionsForAssociatedToken(key, "destroy", ResourceAction.DETAIL);
            keys.add(key);
        }
        KeyDestructionResult result = new KeyDestructionResult();
        for (CryptographicKeyFullModel key : keys) {
            result.merge(destroyKeyItemsInternal(key, key.items()));
        }
        result.throwIfFailed();
        logger.info("Keys destroyed: {}", keys.stream().map(CryptographicKeyFullModel::toIdentifierString).toList());
    }

    @Override
    @ExternalAuthorization(resource = Resource.CRYPTOGRAPHIC_KEY, action = ResourceAction.ANY,
            parentResource = Resource.TOKEN_PROFILE, parentAction = ResourceAction.DETAIL)
    public List<BaseAttribute> listCreateKeyAttributes(UUID tokenInstanceUuid, SecuredParentUUID tokenProfileUuid,
            KeyRequestType type) throws ConnectorException, NotFoundException {
        logger.debug("Request to list the attributes for creating a new key on Token profile: {}", tokenProfileUuid);

        TokenProfileFullModel tokenProfile = getTokenProfile(tokenInstanceUuid, tokenProfileUuid);

        throwIfTokenProfileNotEnabled(tokenProfile);
        List<BaseAttribute> attributes = keyProviderAdapterFactory
                .forToken(tokenProfile.tokenInstance())
                .listCreateKeyAttributes(tokenProfile, type);

        logger
                .atDebug()
                .addArgument(tokenProfile::toIdentifierString)
                .log("Key creation attributes retrieved for Token profile: {}");
        return attributes;
    }

    @Override
    @ExternalAuthorization(resource = Resource.CRYPTOGRAPHIC_KEY, action = ResourceAction.UPDATE,
            parentResource = Resource.TOKEN, parentAction = ResourceAction.DETAIL)
    public void syncKeys(SecuredParentUUID tokenInstanceUuid)
            throws ConnectorException, AttributeException, NotFoundException {
        TokenInstanceFullModel tokenInstance = tokenInstanceReferenceRepository
                .findFullModelByUuid(tokenInstanceUuid.getValue())
                .orElseThrow(() -> new NotFoundException(TokenInstanceReference.class, tokenInstanceUuid.getValue()));

        if (tokenInstance.providerInterfaceVersion() != 1) {
            logger
                    .info("Skipping key synchronization: this operation is supported only for tokens connected to a "
                            + "Cryptography Provider of version 1.");
            return;
        }

        List<ProviderKeyItem> keys = keyProviderAdapterFactory.forToken(tokenInstance).listKeys(tokenInstance);

        // Create a map to hold the key and its objects. The association key will be used as the name for the parent key
        // object
        Map<String, List<ProviderKeyItem>> associations = new HashMap<>();

        // Iterate and add the keys with the same associations to the map
        for (ProviderKeyItem key : keys) {
            associations
                    .computeIfAbsent(
                            (key.association() == null || key.association().isEmpty()) ? "" : key.association(),
                            k -> new ArrayList<>())
                    .add(key);
        }
        logger.debug("Total number of keys from the connector: {}", keys.size());

        List<KeyMaterial> materials = getNewDiscoveredKeyMaterials(associations, tokenInstance.uuid());
        validateForDuplicateKeyFingerprints(materials);

        // Iterate through the created map and store the items in the database
        for (Map.Entry<String, List<ProviderKeyItem>> entry : associations.entrySet()) {
            // If the key is empty then it is individual entity. Probably only private or public key or Secret Key
            if (entry.getKey().isEmpty()) {
                for (ProviderKeyItem soleEntity : entry.getValue()) {
                    saveDiscoveredItems(tokenInstance, soleEntity.name(), List.of(soleEntity));
                }
            } else {
                saveDiscoveredItems(tokenInstance, entry.getKey(), entry.getValue());
            }
        }
        logger.info("Sync Key Completed");
    }

    @Override
    @ExternalAuthorization(resource = Resource.CRYPTOGRAPHIC_KEY, action = ResourceAction.UPDATE)
    public void compromiseKey(UUID uuid, CompromiseKeyRequestDto request) throws NotFoundException {
        CryptographicKeyFullModel key = getCryptographicKeyFullModel(uuid);
        verifyPermissionsForAssociatedToken(key, "compromise", ResourceAction.DETAIL);

        List<CryptographicKeyItemBasicModel> items = resolveKeyItems(key, request.getUuids());
        compromiseKeyItems(itemUuids(items), request.getReason());
        logger.atInfo().addArgument(key::toIdentifierString).log("Key marked as compromised: {}");
    }

    @Override
    @ExternalAuthorization(resource = Resource.CRYPTOGRAPHIC_KEY, action = ResourceAction.UPDATE,
            parentResource = Resource.TOKEN, parentAction = ResourceAction.DETAIL)
    public void compromiseKey(BulkCompromiseKeyRequestDto request) {
        List<UUID> uuids = request.getUuids();
        logger.debug("Request to mark the key as compromised with UUIDs {}", uuids);
        for (UUID uuid : uuids) {
            try {
                CryptographicKeyFullModel key = getCryptographicKeyFullModel(uuid);
                verifyPermissionsForAssociatedToken(key, "compromise", ResourceAction.DETAIL);
                List<UUID> keyItemUuids = key.items().stream().map(CryptographicKeyItemBasicModel::uuid).toList();
                compromiseKeyItems(keyItemUuids, request.getReason());
            } catch (NotFoundException e) {
                logger.warn(e.getMessage());
            }
        }
        logger.info("Keys marked as compromised: {}", uuids);
    }

    @Override
    @ExternalAuthorization(resource = Resource.CRYPTOGRAPHIC_KEY, action = ResourceAction.UPDATE,
            parentResource = Resource.TOKEN, parentAction = ResourceAction.DETAIL)
    public void updateKeyUsages(BulkKeyUsageRequestDto request) {
        logger.debug("Request to update the key usages with UUIDs {}", request.getUuids());
        for (UUID uuid : request.getUuids()) {
            try {
                CryptographicKeyFullModel key = getCryptographicKeyFullModel(uuid);
                verifyPermissionsForAssociatedToken(key, "update key usages", ResourceAction.DETAIL);
                List<UUID> keyItemsUuids = key.items().stream().map(CryptographicKeyItemBasicModel::uuid).toList();
                setKeyItemsUsages(keyItemsUuids, request.getUsage());
            } catch (NotFoundException e) {
                logger.warn(e.getMessage());
            }
        }
        logger.info("Key usages updated: {}", request.getUuids());
    }

    @Override
    @ExternalAuthorization(resource = Resource.CRYPTOGRAPHIC_KEY, action = ResourceAction.UPDATE)
    public void updateKeyUsages(UUID uuid, UpdateKeyUsageRequestDto request) throws NotFoundException {
        CryptographicKeyFullModel key = getCryptographicKeyFullModel(uuid);
        verifyPermissionsForAssociatedToken(key, "update key usages", ResourceAction.DETAIL);

        List<CryptographicKeyItemBasicModel> items = resolveKeyItems(key, request.getUuids());
        setKeyItemsUsages(itemUuids(items), request.getUsage());
        logger.atInfo().addArgument(key::toIdentifierString).log("Key usages updated: {}");
    }

    @Override
    @ExternalAuthorization(resource = Resource.CRYPTOGRAPHIC_KEY, action = ResourceAction.DETAIL)
    public List<KeyEventHistoryDto> getEventHistory(UUID uuid, UUID keyItemUuid) throws NotFoundException {
        logger.debug("Request to get the list of events for the key item");
        CryptographicKeyBasicModel key = getCryptographicKeyBasicModel(uuid);
        verifyPermissionsForAssociatedToken(key, "get key item history", ResourceAction.MEMBERS);
        cryptographicKeyItemRepository
                .findByUuidAndKeyUuid(keyItemUuid, uuid)
                .orElseThrow(() -> new NotFoundException(CryptographicKeyItem.class, keyItemUuid));
        return keyEventHistoryService.getKeyEventHistory(keyItemUuid);
    }

    @Override
    @ExternalAuthorization(resource = Resource.CRYPTOGRAPHIC_KEY, action = ResourceAction.UPDATE)
    public KeyItemDetailDto editKeyItem(SecuredUUID keyUuid, UUID keyItemUuid, EditKeyItemDto editKeyItemDto)
            throws NotFoundException {
        CryptographicKeyFullModel key = getCryptographicKeyFullModel(keyUuid.getValue());
        verifyPermissionsForAssociatedToken(key, "edit key item", ResourceAction.DETAIL);

        CryptographicKeyItemBasicModel updatedItem = cryptographicKeyWriter
                .editKeyItem(key.uuid(), keyItemUuid, editKeyItemDto);
        evictKeyItemCache(updatedItem.uuid());
        return CryptographicKeyDtoMapper.mapItemToDetailDto(updatedItem);
    }

    @Override
    @ExternalAuthorization(resource = Resource.CRYPTOGRAPHIC_KEY, action = ResourceAction.LIST)
    public List<SearchFieldDataByGroupDto> getSearchableFieldInformation() {
        return getSearchableFieldsMap();
    }

    @Override
    @ExternalAuthorization(resource = Resource.CRYPTOGRAPHIC_KEY, action = ResourceAction.ENABLE,
            parentResource = Resource.TOKEN, parentAction = ResourceAction.DETAIL)
    public void enableKeyItems(List<String> uuids) throws NotFoundException {
        List<CryptographicKeyItemBasicModel> keyItems = getRequestedKeyItems(parseKeyItemUuids(uuids));
        verifyPermissionsForKeyItemParents(keyItems, "enable key item");
        setKeyItemsEnabled(itemUuidsAsStrings(keyItems), true);
    }

    @Override
    @ExternalAuthorization(resource = Resource.CRYPTOGRAPHIC_KEY, action = ResourceAction.ENABLE,
            parentResource = Resource.TOKEN, parentAction = ResourceAction.DETAIL)
    public void disableKeyItems(List<String> uuids) throws NotFoundException {
        List<CryptographicKeyItemBasicModel> keyItems = getRequestedKeyItems(parseKeyItemUuids(uuids));
        verifyPermissionsForKeyItemParents(keyItems, "disable key item");
        setKeyItemsEnabled(itemUuidsAsStrings(keyItems), false);
    }

    @Override
    @ExternalAuthorization(resource = Resource.CRYPTOGRAPHIC_KEY, action = ResourceAction.DELETE,
            parentResource = Resource.TOKEN, parentAction = ResourceAction.DETAIL)
    public void destroyKeyItems(List<String> keyItemUuids) throws ConnectorException, NotFoundException {
        List<CryptographicKeyItemBasicModel> keyItems = getRequestedKeyItems(parseKeyItemUuids(keyItemUuids));
        Map<CryptographicKeyFullModel, List<CryptographicKeyItemBasicModel>> selections = new LinkedHashMap<>();
        for (UUID parentKeyUuid : keyItemParentUuids(keyItems)) {
            CryptographicKeyFullModel key = getCryptographicKeyFullModel(parentKeyUuid);
            verifyBulkKeyItemTokenPermission(key, "destroy key item");
            List<UUID> selectedUuids = keyItems
                    .stream()
                    .filter(item -> key.uuid().equals(item.parentKeyUuid()))
                    .map(CryptographicKeyItemBasicModel::uuid)
                    .toList();
            selections.put(key, resolveKeyItems(key, selectedUuids));
        }
        KeyDestructionResult result = new KeyDestructionResult();
        selections.forEach((key, selectedItems) -> result.merge(destroyKeyItemsInternal(key, selectedItems)));
        result.throwIfFailed();
        logger.info("Key items destroyed: {}", keyItemUuids);
    }

    @Override
    @ExternalAuthorization(resource = Resource.CRYPTOGRAPHIC_KEY, action = ResourceAction.UPDATE,
            parentResource = Resource.TOKEN, parentAction = ResourceAction.DETAIL)
    public void compromiseKeyItems(BulkCompromiseKeyItemRequestDto request) throws NotFoundException {
        List<CryptographicKeyItemBasicModel> keyItems = getRequestedKeyItems(request.getUuids());
        verifyPermissionsForKeyItemParents(keyItems, "compromise key item");
        compromiseKeyItems(itemUuids(keyItems), request.getReason());
    }

    @Override
    @ExternalAuthorization(resource = Resource.CRYPTOGRAPHIC_KEY, action = ResourceAction.UPDATE,
            parentResource = Resource.TOKEN, parentAction = ResourceAction.DETAIL)
    public void updateKeyItemUsages(BulkKeyItemUsageRequestDto request) throws NotFoundException {
        List<CryptographicKeyItemBasicModel> keyItems = getRequestedKeyItems(request.getUuids());
        verifyPermissionsForKeyItemParents(keyItems, "update key item usages");
        setKeyItemsUsages(itemUuids(keyItems), request.getUsage());
    }

    /**
     * Finds one ordered page of accessible key items matching a validated search request, with its total count.
     * Configures the supplied security filter's parent property for token-level authorization.
     *
     * @param contentFilter shared lazy attribute permissions, also used when projecting the response columns
     */
    private Page<CryptographicKeyItem> findAccessibleKeyItemsMatchingSearch(SecurityFilter filter,
            SearchRequestDto request, Supplier<CustomAttributeContentFilter> contentFilter) {
        // Convert the API's one-based page number to Spring's zero-based index and limit the page size.
        final Pageable page = PageRequest.of(request.getPageNumber() - 1, request.getItemsPerPage());

        // Defer translating search filters into a WHERE predicate until the repository supplies the query context.
        // root identifies the queried entity, cb builds conditions, and query supports constructs such as subqueries.
        final TriFunction<Root<CryptographicKeyItem>, CriteriaBuilder, CriteriaQuery<?>, Predicate> searchPredicate = (
                root, cb, query) -> FilterPredicatesBuilder
                        .getFiltersPredicate(cb, query, root, request.getFilters(), contentFilter);

        // Name the property linking keys to tokens so parent-level access restrictions can be applied.
        filter.setParentRefProperty(CryptographicKey_.tokenInstanceReferenceUuid.getName());

        // Page UUIDs first so fetching related collections cannot multiply rows and distort pagination.
        List<UUID> orderedUuids = cryptographicKeyItemRepository
                .findUuidsUsingSecurityFilter(filter, searchPredicate, page,
                        // Use newest-first ordering when the request does not specify a sort.
                        (root, cb) -> cb.desc(root.get("createdAt")),
                        // Resolve the requested sort, enforcing sortable-attribute rules and content permissions.
                        listingSortResolver.resolve(Resource.CRYPTOGRAPHIC_KEY, request.getSort(), contentFilter));

        // Fetch the selected entities together with the associations needed by summary mapping.
        List<CryptographicKeyItem> fetchedItems = cryptographicKeyItemRepository.findFullByUuidIn(orderedUuids);
        // An IN query does not preserve input order; match each entity's UUID to its position in the page.
        List<CryptographicKeyItem> orderedItems = SortOrderBuilder
                .rankBy(orderedUuids, fetchedItems, CryptographicKeyItem::getUuid);

        // Count without pagination, using the same authorization and search conditions as the UUID query.
        long totalItems = cryptographicKeyItemRepository.countUsingSecurityFilter(filter, searchPredicate);
        // Carry the ordered items and total together so the caller can construct the paginated response.
        return new PageImpl<>(orderedItems, page, totalItems);
    }

    private KeyDetailDto assembleKeyDetailDto(KeyRequestDto request, CryptographicKeyFullModel key,
            TokenProfileFullModel tokenProfile) throws NotFoundException, AttributeException {
        KeyDetailDto keyDetailDto = CryptographicKeyDtoMapper.mapToDetailDto(key);
        keyDetailDto
                .setCustomAttributes(attributeEngine
                        .updateObjectCustomAttributesContent(Resource.CRYPTOGRAPHIC_KEY, key.uuid(),
                                request.getCustomAttributes()));
        keyDetailDto
                .setAttributes(attributeEngine
                        .updateObjectDataAttributesContent(ObjectAttributeContentInfo
                                .builder(Resource.CRYPTOGRAPHIC_KEY, key.uuid())
                                .connector(tokenProfile.tokenInstance().connectorUuid())
                                .build(), request.getAttributes()));

        logger.atDebug().addArgument(key::toIdentifierString).log("Key details assembled: {}");
        return keyDetailDto;
    }

    private CryptographicKeyFullModel updateOwnerAndGroups(KeyRequestDto request, CryptographicKeyFullModel key)
            throws NotFoundException {
        Set<UUID> groupUuids = request.getGroupUuids() == null
                ? null
                : request.getGroupUuids().stream().map(UUID::fromString).collect(Collectors.toSet());
        return cryptographicKeyWriter.updateOwnerAndGroups(key, groupUuids);
    }

    private int deleteKeyItemsBatch(List<SecurityFilter> filters, List<UUID> batchUuids, UUID loggedUserUuid)
            throws ConnectorException, NotFoundException {
        List<UUID> permittedUuids = batchUuids;
        for (SecurityFilter filter : filters) {
            permittedUuids = filterKeyItemsBySecurityFilter(filter, permittedUuids, loggedUserUuid);
        }

        if (permittedUuids.isEmpty()) {
            return 0;
        }

        List<CryptographicKeyItemBasicModel> keyItems = cryptographicKeyItemRepository
                .findBasicModelsByUuidIn(permittedUuids);

        logger.debug("Going to delete key items with UUIDs {}", permittedUuids);
        Map<UUID, Optional<CryptographicKeyFullModel>> keys = new HashMap<>();
        int deletedCount = 0;
        for (CryptographicKeyItemBasicModel keyItem : keyItems) {
            UUID parentKeyUuid = keyItem.parentKeyUuid();
            CryptographicKeyFullModel key = keys
                    .computeIfAbsent(parentKeyUuid, cryptographicKeyRepository::findFullModelByUuid)
                    .orElseThrow(() -> new NotFoundException(CryptographicKey.class, parentKeyUuid));
            if (key.tokenInstance() != null) {
                keyProviderAdapterFactory.forToken(key.tokenInstance()).destroyKeyItem(key, keyItem.reference());
            }
            deletedCount += cryptographicKeyWriter
                    .deleteKeyItemsWithAssociations(List.of(keyItem.uuid()), List.of(parentKeyUuid));
            evictKeyItemCache(keyItem.uuid());
        }

        return deletedCount;
    }

    private List<UUID> filterKeyItemsBySecurityFilter(SecurityFilter filter, List<UUID> inputUuids,
            UUID loggedUserUuid) {
        TriFunction<Root<CryptographicKeyItem>, CriteriaBuilder, CriteriaQuery<?>, Predicate> additionalWhereClause = createAdditionalWhereClauseForBulkDeleteBatch(
                inputUuids);
        List<UUID> permittedUuids = cryptographicKeyItemRepository
                .findUuidsUsingSecurityFilter(filter, additionalWhereClause, null, null);
        List<UUID> nonPermittedUuids = new ArrayList<>(inputUuids);
        nonPermittedUuids.removeAll(permittedUuids);

        for (UUID nonPermittedUuid : nonPermittedUuids) {
            logger
                    .error("Unable to delete cryptographic key item {}. The cryptographic key item cannot be found or cannot be authorized for deletion.",
                            nonPermittedUuid);
            notificationProducer
                    .produceInternalNotificationMessage(Resource.CRYPTOGRAPHIC_KEY_ITEM, nonPermittedUuid,
                            NotificationRecipient.buildUserNotificationRecipient(loggedUserUuid),
                            "Unable to delete cryptographic key item " + nonPermittedUuid,
                            "The cryptographic key item cannot be found or cannot be authorized for deletion.");
        }
        return permittedUuids;
    }

    private SecurityFilter createSecurityFilterFor(@NonNull Resource resource, @NonNull ResourceAction action,
            @Nullable Resource parentResource, @Nullable ResourceAction parentAction,
            @Nullable String parentRefProperty) {
        SecurityFilter filter = SecurityFilter.create();
        objectFilterAspect.populateSecurityFilter(resource, action, parentResource, parentAction, filter);

        if (parentRefProperty != null) {
            filter.setParentRefProperty(parentRefProperty);
        }
        return filter;
    }

    private void throwIfTokenProfileNotEnabled(TokenProfileBasicModel tokenProfile) {
        if (!Boolean.TRUE.equals(tokenProfile.enabled())) {
            throw new ValidationException(ValidationError.create("Token Profile is disabled"));
        }
    }

    @Override
    public UUID findKeyByFingerprint(String fingerprint) {
        CryptographicKeyItem item = cryptographicKeyItemRepository.findByFingerprint(fingerprint).orElse(null);
        if (item != null) {
            return item.getKey().getUuid();
        }
        return null;
    }

    @Override
    public CryptographicKeyItem getKeyItemFromKey(CryptographicKey key, KeyType keyType) {
        for (CryptographicKeyItem item : key.getItems()) {
            if (item.getType().equals(keyType)) {
                return item;
            }
        }
        return null;
    }

    @Override
    @Cacheable(value = CacheConfig.CRYPTOGRAPHIC_KEY_ITEM_CACHE, key = "#keyItemUuid", sync = true)
    public CryptographicKeyItemOperationModel getKeyItemModel(UUID keyItemUuid) throws NotFoundException {
        CryptographicKeyItemOperationRow row = cryptographicKeyItemRepository
                .findOperationRowByUuid(keyItemUuid)
                .orElseThrow(() -> new NotFoundException(CryptographicKeyItem.class, keyItemUuid));
        if (row.connectorUuid() == null) {
            throw new NotFoundException("Connector associated to the Key is not found");
        }
        return row.toModel();
    }

    @Override
    @Transactional
    public UUID uploadCertificatePublicKey(String name, PublicKey publicKey, int keyLength, String fingerprint) {
        return certificateKeyWriter.uploadCertificatePublicKey(name, publicKey, keyLength, fingerprint);
    }

    private void evictKeyItemCache(UUID keyItemUuid) {
        cacheEvictor.evict(CacheConfig.CRYPTOGRAPHIC_KEY_ITEM_CACHE, keyItemUuid);
    }

    @Override
    public NameAndUuidDto getResourceObjectInternal(UUID objectUuid) throws NotFoundException {
        return cryptographicKeyRepository.findResourceObject(objectUuid, CryptographicKey_.name);
    }

    @Override
    @ExternalAuthorization(resource = Resource.CRYPTOGRAPHIC_KEY, action = ResourceAction.DETAIL)
    public NameAndUuidDto getResourceObjectExternal(SecuredUUID objectUuid) throws NotFoundException {
        CryptographicKeyFullModel key = getCryptographicKeyFullModel(objectUuid.getValue());
        verifyPermissionsForAssociatedToken(key, "get detail", ResourceAction.MEMBERS);
        return new NameAndUuidDto(key.uuid(), key.name());
    }

    @Override
    public List<NameAndUuidDto> listResourceObjects(SecurityFilter filter, List<SearchFilterRequestDto> filters,
            PaginationRequestDto pagination) {
        throw new NotSupportedException(
                "Listing of resource objects is not supported for resource cryptographic keys.");
    }

    @Override
    @ExternalAuthorization(resource = Resource.CRYPTOGRAPHIC_KEY, action = ResourceAction.UPDATE)
    public void evaluatePermissionChain(SecuredUUID uuid) throws NotFoundException {
        getCryptographicKeyBasicModel(uuid.getValue());
    }

    private @NonNull TokenProfileFullModel getTokenProfile(UUID tokenInstanceUuid, SecuredParentUUID tokenProfileUuid)
            throws NotFoundException {
        TokenProfileFullModel tokenProfile = tokenProfileRepository
                .findFullModelByUuidAndTokenInstanceReferenceUuid(tokenProfileUuid.getValue(), tokenInstanceUuid)
                .orElseThrow(() -> new NotFoundException("Token profile (" + tokenProfileUuid.getValue()
                        + ") connected to token instance (" + tokenInstanceUuid + ") was not found."));
        logger.atTrace().addArgument(tokenProfile::toIdentifierString).log("Token profile: {}");
        return tokenProfile;
    }

    private void saveDiscoveredItems(TokenInstanceFullModel tokenInstance, String key, List<ProviderKeyItem> items)
            throws AttributeException {
        // Iterate through the items for a specific key
        Set<UUID> existingReferenceUuids = cryptographicKeyItemRepository
                .findKeyReferenceUuidsByTokenInstanceUuid(tokenInstance.uuid());
        if (checkKeyAlreadyExists(existingReferenceUuids, items)) {
            return;
        }
        // Create the cryptographic Key
        KeyRequestDto request = new KeyRequestDto();
        request.setName(key);
        request.setDescription("Discovered from " + tokenInstance.name());
        // Create the items for each key
        CryptographicKeyBasicModel savedKey = cryptographicKeyWriter
                .createKeyWithItems(request, null, tokenInstance, items, true, false);
        cryptographicKeyItemRepository
                .findByKeyUuidIn(List.of(savedKey.uuid()))
                .forEach(item -> evictKeyItemCache(item.getUuid()));
    }

    private List<KeyMaterial> getNewDiscoveredKeyMaterials(Map<String, List<ProviderKeyItem>> associations,
            UUID tokenInstanceUuid) {
        List<KeyMaterial> materials = new ArrayList<>();
        for (Map.Entry<String, List<ProviderKeyItem>> association : associations.entrySet()) {
            List<List<ProviderKeyItem>> groups;
            if (association.getKey().isEmpty()) {
                groups = association.getValue().stream().map(List::of).toList();
            } else {
                groups = List.of(association.getValue());
            }
            Set<UUID> existingReferenceUuids = cryptographicKeyItemRepository
                    .findKeyReferenceUuidsByTokenInstanceUuid(tokenInstanceUuid);

            for (List<ProviderKeyItem> group : groups) {
                if (checkKeyAlreadyExists(existingReferenceUuids, group)) {
                    continue;
                }
                for (ProviderKeyItem response : group) {
                    KeyMaterial material = response.material();
                    materials.add(material);
                }
            }
        }
        return materials;
    }

    private boolean checkKeyAlreadyExists(Set<UUID> existingReferenceUuids, List<ProviderKeyItem> items) {
        // Iterate through the items for a specific key
        for (ProviderKeyItem item : items) {
            // check if the item with the reference uuid already exists in the database
            // Assumption - Content of the key from earlier does not change
            if (item.reference() instanceof RemoteKeyReference.UuidReference(UUID uuid)
                    && existingReferenceUuids.contains(uuid)) {
                return true;
            }
        }
        return false;
    }

    private void validateForDuplicateKeyFingerprints(List<KeyMaterial> materials) {
        Set<String> fingerprints = new HashSet<>();
        for (KeyMaterial material : materials) {
            String fingerprint = CryptographyUtil.calculateKeyFingerprint(material);
            if (fingerprint == null) {
                continue;
            }
            UUID existingKeyUuid = findKeyByFingerprint(fingerprint);
            if (existingKeyUuid != null) {
                throw new ValidationException(
                        "Key with the same fingerprint already exists. Existing key UUID: " + existingKeyUuid);
            }
            if (!fingerprints.add(fingerprint)) {
                throw new ValidationException("Multiple returned key items have the same fingerprint.");
            }
        }
    }

    private CryptographicKeyFullModel getCryptographicKeyFullModel(UUID uuid) throws NotFoundException {
        return cryptographicKeyRepository
                .findFullModelByUuid(uuid)
                .orElseThrow(() -> new NotFoundException(CryptographicKey.class, uuid));
    }

    private CryptographicKeyBasicModel getCryptographicKeyBasicModel(UUID uuid) throws NotFoundException {
        return cryptographicKeyRepository
                .findBasicModelByUuid(uuid)
                .orElseThrow(() -> new NotFoundException(CryptographicKey.class, uuid));
    }

    private void mergeAndValidateAttributes(KeyRequestType keyType, TokenProfileFullModel tokenProfile,
            List<RequestAttribute> attributes) throws ConnectorException, AttributeException, NotFoundException {
        TokenInstanceFullModel tokenInstance = tokenProfile.tokenInstance();
        logger
                .atDebug()
                .addArgument(tokenInstance::toIdentifierString)
                .log("Merging and validating attributes on token instance {}");
        if (tokenProfile.tokenInstance().connectorUuid() == null) {
            throw new ValidationException(ValidationError.create("Connector of the Token is not available / deleted"));
        }

        KeyProviderAdapter adapter = keyProviderAdapterFactory.forToken(tokenInstance);
        if (adapter instanceof KeyCreationValidationCapability validation) {
            validation.validateCreateKeyAttributes(tokenInstance, keyType, attributes);
        }
        List<BaseAttribute> definitions = adapter.listCreateKeyAttributes(tokenProfile, keyType);

        attributeEngine.validateUpdateDataAttributes(tokenInstance.connectorUuid(), null, definitions, attributes);
    }

    private CryptographicKeyFullModel persistCreatedKey(TokenProfileFullModel tokenProfile, KeyRequestDto request,
            List<ProviderKeyItem> remotelyCreatedItems) throws AttributeException, NotFoundException {

        CryptographicKeyBasicModel savedKey;
        try {
            List<KeyMaterial> keyMaterials = remotelyCreatedItems.stream().map(ProviderKeyItem::material).toList();
            validateForDuplicateKeyFingerprints(keyMaterials);
            savedKey = cryptographicKeyWriter
                    .createKeyWithItems(request, tokenProfile, tokenProfile.tokenInstance(), remotelyCreatedItems,
                            false, Boolean.TRUE.equals(request.getEnabled()));
        } catch (Exception e) {
            List<String> remoteKeyIdentifiers = remotelyCreatedItems
                    .stream()
                    .map(ProviderKeyItem::reference)
                    .map(RemoteKeyReference::toIdentifierString)
                    .toList();
            logger
                    .error("Provider created key for token {} and token profile {}, but Core validation or persistence failed. "
                            + "The remote key may be orphaned and requires manual reconciliation. Provider key references: {}",
                            tokenProfile.tokenInstance().toIdentifierString(), tokenProfile.toIdentifierString(),
                            remoteKeyIdentifiers, e);
            throw e;
        }

        CryptographicKeyFullModel createdKey = getCryptographicKeyFullModel(savedKey.uuid());
        createdKey.items().forEach(item -> evictKeyItemCache(item.uuid()));
        return createdKey;
    }

    private List<CryptographicKeyItemBasicModel> resolveKeyItems(CryptographicKeyFullModel key,
            List<UUID> keyItemUuids) {
        Map<UUID, CryptographicKeyItemBasicModel> belongingItems = key
                .items()
                .stream()
                .filter(item -> key.uuid().equals(item.parentKeyUuid()))
                .collect(Collectors
                        .toMap(CryptographicKeyItemBasicModel::uuid, item -> item, (first, duplicate) -> first,
                                LinkedHashMap::new));
        if (keyItemUuids == null || keyItemUuids.isEmpty()) {
            return List.copyOf(belongingItems.values());
        }
        List<UUID> requestedUuids = keyItemUuids.stream().distinct().toList();
        List<String> invalidUuids = requestedUuids
                .stream()
                .filter(not(belongingItems::containsKey))
                .map(String::valueOf)
                .toList();
        if (!invalidUuids.isEmpty()) {
            String message = "Key items do not belong to key %s or do not exist: %s. No key items were updated."
                    .formatted(key.uuid(), String.join(", ", invalidUuids));
            throw new ValidationException(ValidationError.create(message));
        }
        return requestedUuids.stream().map(belongingItems::get).toList();
    }

    private List<UUID> parseKeyItemUuids(List<String> keyItemUuids) {
        return keyItemUuids == null ? List.of() : keyItemUuids.stream().map(UUID::fromString).toList();
    }

    private List<CryptographicKeyItemBasicModel> getRequestedKeyItems(List<UUID> keyItemUuids) {
        if (keyItemUuids == null || keyItemUuids.isEmpty()) {
            return List.of();
        }
        List<UUID> requestedUuids = keyItemUuids.stream().distinct().toList();
        Map<UUID, CryptographicKeyItemBasicModel> items = cryptographicKeyItemRepository
                .findBasicModelsByUuidIn(requestedUuids)
                .stream()
                .collect(Collectors.toMap(CryptographicKeyItemBasicModel::uuid, item -> item));
        if (requestedUuids.stream().anyMatch(not(items::containsKey))) {
            throw bulkKeyItemSelectionFailure();
        }
        return requestedUuids.stream().map(items::get).toList();
    }

    private List<UUID> itemUuids(List<CryptographicKeyItemBasicModel> items) {
        return items.stream().map(CryptographicKeyItemBasicModel::uuid).toList();
    }

    private List<String> itemUuidsAsStrings(List<CryptographicKeyItemBasicModel> items) {
        return items.stream().map(item -> item.uuid().toString()).toList();
    }

    private Set<UUID> keyItemParentUuids(List<CryptographicKeyItemBasicModel> items) {
        return items
                .stream()
                .map(CryptographicKeyItemBasicModel::parentKeyUuid)
                .collect(Collectors.toCollection(LinkedHashSet::new));
    }

    private void verifyPermissionsForKeyItemParents(List<CryptographicKeyItemBasicModel> items, String operation)
            throws NotFoundException {
        for (UUID parentKeyUuid : keyItemParentUuids(items)) {
            CryptographicKeyBasicModel key = getCryptographicKeyBasicModel(parentKeyUuid);
            verifyBulkKeyItemTokenPermission(key, operation);
        }
    }

    private void verifyBulkKeyItemTokenPermission(CryptographicKeyBasicModel key, String operation) {
        try {
            verifyPermissionsForAssociatedToken(key, operation, ResourceAction.DETAIL);
        } catch (AccessDeniedException e) {
            throw bulkKeyItemSelectionFailure();
        }
    }

    private ValidationException bulkKeyItemSelectionFailure() {
        return new ValidationException(
                ValidationError.create("Key items were not found or are not authorized. No key items were updated."));
    }

    /**
     * Function to enable/disable the key
     *
     * @param keyItemsUuids UUIDs of the Key Items
     */
    private void setKeyItemsEnabled(List<String> keyItemsUuids, boolean enabled) {
        logger
                .debug("Request to set the key items with UUIDs {} {}", keyItemsUuids,
                        enabled ? ENABLED_STATE : DISABLED_STATE);
        if (keyItemsUuids != null && !keyItemsUuids.isEmpty()) {
            for (String keyItemUuid : new LinkedHashSet<>(keyItemsUuids)) {
                setKeyItemEnabled(UUID.fromString(keyItemUuid), enabled);
            }
        }
        logger.info("Key items {}: {}", enabled ? ENABLED_STATE : DISABLED_STATE, keyItemsUuids);
    }

    /**
     * Function to enable/disable the key
     *
     * @param uuid UUID of the Key Item
     */
    private void setKeyItemEnabled(UUID uuid, boolean enabled) {
        if (!cryptographicKeyWriter.setKeyItemEnabled(uuid, enabled)) {
            logger
                    .debug("Skipping update for key item {}: already {} or no longer exists", uuid,
                            enabled ? ENABLED_STATE : DISABLED_STATE);
            return;
        }
        evictKeyItemCache(uuid);
    }

    /**
     * Function to mark keys as compromised
     *
     * @param keyItemsUuids UUIDs of the Key Items
     */
    private void compromiseKeyItems(List<UUID> keyItemsUuids, KeyCompromiseReason reason) {
        logger.debug("Request to mark the key items as compromised with UUIDs {}", keyItemsUuids);
        List<String> errors = new ArrayList<>();
        int compromisedCount = 0;
        if (keyItemsUuids != null && !keyItemsUuids.isEmpty()) {
            for (UUID keyItemUuid : new LinkedHashSet<>(keyItemsUuids)) {
                try {
                    Optional<String> rejection = compromiseKeyItem(keyItemUuid, reason);
                    if (rejection.isPresent()) {
                        errors.add(rejection.get());
                    } else {
                        compromisedCount++;
                    }
                } catch (NotFoundException e) {
                    logger.warn("Key item {} could not be marked as compromised", keyItemUuid, e);
                    errors.add("Key item %s was not found.".formatted(keyItemUuid));
                }
            }
        }
        if (!errors.isEmpty()) {
            String message = "Some key items could not be marked as compromised. "
                    + "Compromise is allowed only in states %s, %s, or %s. %s "
                    + "Successfully compromised key items in this batch: %d.";
            String validationMessage = message
                    .formatted(KeyState.PRE_ACTIVE.getLabel(), KeyState.ACTIVE.getLabel(),
                            KeyState.DEACTIVATED.getLabel(), String.join(" ", errors), compromisedCount);
            throw new ValidationException(ValidationError.create(validationMessage));
        }
        logger.info("Key Items marked as compromised: {}", keyItemsUuids);
    }

    private Optional<String> compromiseKeyItem(UUID keyItemUuid, KeyCompromiseReason reason) throws NotFoundException {
        Optional<String> rejection = cryptographicKeyWriter.setKeyItemCompromised(keyItemUuid, reason);
        if (rejection.isEmpty()) {
            evictKeyItemCache(keyItemUuid);
        }
        return rejection;
    }

    private void setKeyItemsUsages(List<UUID> keyItemsUuids, List<KeyUsage> usages) {
        logger.debug("Request to update usages of key items with UUIDs {}", keyItemsUuids);
        List<String> errors = new ArrayList<>();
        int updatedCount = 0;
        if (keyItemsUuids != null && !keyItemsUuids.isEmpty()) {
            for (UUID keyItemUuid : new LinkedHashSet<>(keyItemsUuids)) {
                try {
                    Optional<String> rejection = setKeyItemUsages(keyItemUuid, usages);
                    if (rejection.isPresent()) {
                        errors.add(rejection.get());
                    } else {
                        updatedCount++;
                    }
                } catch (NotFoundException e) {
                    logger.warn("Usages of key item {} could not be updated", keyItemUuid, e);
                    errors.add("Key item %s was not found.".formatted(keyItemUuid));
                } catch (Exception e) {
                    logger.warn("Usages of key item {} could not be updated", keyItemUuid, e);
                    errors
                            .add("Usages of key item %s could not be updated due to an internal error."
                                    .formatted(keyItemUuid));
                }
            }
        }
        if (!errors.isEmpty()) {
            String message = "Usages of some key items could not be updated. %s "
                    + "Successfully updated key items in this batch: %d.";
            String validationMessage = message.formatted(String.join(" ", errors), updatedCount);
            throw new ValidationException(ValidationError.create(validationMessage));
        }
        logger.info("Key items usages updated: {}", keyItemsUuids);
    }

    private Optional<String> setKeyItemUsages(UUID keyItemUuid, List<KeyUsage> usages) throws NotFoundException {
        Optional<String> rejection = cryptographicKeyWriter.updateUsage(keyItemUuid, usages);
        if (rejection.isEmpty()) {
            evictKeyItemCache(keyItemUuid);
        }
        return rejection;
    }

    private KeyDestructionResult destroyKeyItemsInternal(CryptographicKeyFullModel key,
            List<CryptographicKeyItemBasicModel> keyItems) {
        KeyDestructionResult result = new KeyDestructionResult();
        for (CryptographicKeyItemBasicModel item : keyItems) {
            try {
                if (destroyKeyItem(key, item)) {
                    result.destroyedCount++;
                } else {
                    result.invalidStateItems.add("%s (%s)".formatted(item.uuid(), item.state().getLabel()));
                }
            } catch (Exception e) {
                logger
                        .warn("Key item {} destruction failed ({})", item.toIdentifierString(),
                                e.getClass().getSimpleName());
                logger.debug("Key item {} destruction failure details", item.toIdentifierString(), e);
                String failure = e instanceof KeyItemDestructionException
                        ? e.getMessage()
                        : "Destruction of key item %s failed before completion could be confirmed."
                                .formatted(item.uuid());
                result.failures.add(failure);
            }
        }
        return result;
    }

    private boolean destroyKeyItem(CryptographicKeyFullModel key, CryptographicKeyItemBasicModel keyItem)
            throws ConnectorException, NotFoundException {
        if (!keyItem.state().equals(KeyState.DEACTIVATED) && !keyItem.state().equals(KeyState.PRE_ACTIVE)
                && !keyItem.state().equals(KeyState.COMPROMISED)) {
            String message = "Invalid state of key " + keyItem.uuid() + ". Key is " + keyItem.state().getLabel()
                    + ", hence can't be set to " + KeyState.DESTROYED.getLabel() + ".";
            keyEventHistoryService
                    .addEventHistory(KeyEvent.DESTROY, KeyEventStatus.FAILED, message, null, keyItem.uuid());
            return false;
        }
        boolean remoteDestruction = keyItem.reference() != null && key.tokenInstance() != null;
        if (remoteDestruction) {
            keyProviderAdapterFactory.forToken(key.tokenInstance()).destroyKeyItem(key, keyItem.reference());
        }

        String failureMessage = remoteDestruction
                ? "Key item %s was destroyed remotely, but local finalization failed."
                : "Local destruction of key item %s could not be completed.";
        try {
            cryptographicKeyWriter.finalizeKeyItemDestruction(keyItem.uuid());
            failureMessage = "Key item %s was destroyed, but cache invalidation failed.";
            evictKeyItemCache(keyItem.uuid());
        } catch (Exception e) {
            throw new KeyItemDestructionException(failureMessage.formatted(keyItem.uuid()), e);
        }
        return true;
    }

    private List<SearchFieldDataByGroupDto> getSearchableFieldsMap() {
        final List<SearchFieldDataByGroupDto> searchFieldDataByGroupDtos = attributeEngine
                .getResourceSearchableFields(Resource.CRYPTOGRAPHIC_KEY, false);

        List<SearchFieldDataDto> fields = List
                .of(SearchHelper.prepareSearch(FilterField.CKI_NAME),
                        SearchHelper
                                .prepareSearch(FilterField.CK_GROUP,
                                        groupRepository.findAll().stream().map(Group::getName).toList()),
                        SearchHelper
                                .prepareSearch(FilterField.CK_OWNER,
                                        userManagementApiClient
                                                .getUsers()
                                                .getData()
                                                .stream()
                                                .map(UserDto::getUsername)
                                                .toList()),
                        SearchHelper
                                .prepareSearch(FilterField.CKI_USAGE,
                                        Arrays.stream(KeyUsage.values()).map(KeyUsage::getCode).toList()),
                        SearchHelper.prepareSearch(FilterField.CKI_LENGTH),
                        SearchHelper.prepareSearch(FilterField.CKI_ENABLED),
                        SearchHelper.prepareSearch(FilterField.CKI_CREATED),
                        SearchHelper
                                .prepareSearch(FilterField.CKI_STATE,
                                        Arrays.stream(KeyState.values()).map(KeyState::getCode).toList()),
                        SearchHelper
                                .prepareSearch(FilterField.CKI_FORMAT,
                                        Arrays.stream(KeyFormat.values()).map(KeyFormat::getCode).toList()),
                        SearchHelper
                                .prepareSearch(FilterField.CKI_TYPE,
                                        Arrays.stream(KeyType.values()).map(KeyType::getCode).toList()),
                        SearchHelper
                                .prepareSearch(FilterField.CKI_CRYPTOGRAPHIC_ALGORITHM,
                                        Arrays.stream(KeyAlgorithm.values()).map(KeyAlgorithm::getCode).toList()),
                        SearchHelper
                                .prepareSearch(FilterField.CK_TOKEN_PROFILE,
                                        tokenProfileRepository.findAll().stream().map(TokenProfile::getName).toList()),
                        SearchHelper
                                .prepareSearch(FilterField.CK_TOKEN_INSTANCE,
                                        tokenInstanceReferenceRepository
                                                .findAll()
                                                .stream()
                                                .map(TokenInstanceReference::getName)
                                                .toList())

                );
        fields = new ArrayList<>(fields);
        fields.sort(new SearchFieldDataComparator());
        searchFieldDataByGroupDtos.add(new SearchFieldDataByGroupDto(fields, FilterFieldSource.PROPERTY));

        logger.debug("Searchable CryptographicKey Fields groups: {}", searchFieldDataByGroupDtos);
        return searchFieldDataByGroupDtos;
    }

    private void verifyPermissionsForAssociatedToken(CryptographicKeyBasicModel key, String operation,
            ResourceAction requiredPermission) {
        String tokenInstanceMessage = "";
        if (key.tokenInstanceReferenceUuid() != null) {
            authorizationEnforcer
                    .enforce(Resource.TOKEN, requiredPermission,
                            SecuredUUID.fromUUID(key.tokenInstanceReferenceUuid()));
            tokenInstanceMessage = " in token instance " + key.tokenInstanceReferenceUuid();
        }
        logger
                .atDebug()
                .addArgument(operation)
                .addArgument(key::toIdentifierString)
                .addArgument(tokenInstanceMessage)
                .log("Allowed request to '{}' of key '{}'{}");
    }

    private static final class KeyDestructionResult {

        private final List<String> invalidStateItems = new ArrayList<>();
        private final List<String> failures = new ArrayList<>();
        private int destroyedCount;

        private void merge(KeyDestructionResult result) {
            destroyedCount += result.destroyedCount;
            invalidStateItems.addAll(result.invalidStateItems);
            failures.addAll(result.failures);
        }

        private void throwIfFailed() {
            if (invalidStateItems.isEmpty() && failures.isEmpty()) {
                return;
            }
            List<String> messages = new ArrayList<>();
            if (!invalidStateItems.isEmpty()) {
                String invalidStatesMessage = "Key items could not be destroyed because their current states do not allow destruction. "
                        + "Destruction is allowed only in states %s, %s, or %s. Affected key items (ID and state): %s.";
                messages
                        .add(invalidStatesMessage
                                .formatted(KeyState.PRE_ACTIVE.getLabel(), KeyState.DEACTIVATED.getLabel(),
                                        KeyState.COMPROMISED.getLabel(), String.join(", ", invalidStateItems)));
            }
            messages.addAll(failures);
            messages.add("Successfully destroyed key items in this batch: %d.".formatted(destroyedCount));
            throw new ValidationException(ValidationError.create(String.join(" ", messages)));
        }
    }

    private static final class KeyItemDestructionException extends RuntimeException implements PlatformException {

        private KeyItemDestructionException(String message, Exception cause) {
            super(message, cause);
        }
    }
}
