package com.czertainly.core.service.impl;

import com.czertainly.core.client.ConnectorApiFactory;
import com.czertainly.api.exception.*;
import com.czertainly.api.model.client.attribute.RequestAttribute;
import com.czertainly.api.model.client.certificate.SearchFilterRequestDto;
import com.czertainly.api.model.client.certificate.SearchRequestDto;
import com.czertainly.api.model.client.cryptography.CryptographicKeyResponseDto;
import com.czertainly.api.model.client.cryptography.key.*;
import com.czertainly.api.model.common.NameAndUuidDto;
import com.czertainly.api.model.common.attribute.common.BaseAttribute;
import com.czertainly.api.model.common.enums.cryptography.KeyAlgorithm;
import com.czertainly.api.model.common.enums.cryptography.KeyFormat;
import com.czertainly.api.model.common.enums.cryptography.KeyType;
import com.czertainly.api.model.connector.cryptography.enums.TokenInstanceStatus;
import com.czertainly.api.model.connector.cryptography.key.CreateKeyRequestDto;
import com.czertainly.api.model.connector.cryptography.key.KeyData;
import com.czertainly.api.model.connector.cryptography.key.KeyDataResponseDto;
import com.czertainly.api.model.connector.cryptography.key.KeyPairDataResponseDto;
import com.czertainly.api.model.core.auth.Resource;
import com.czertainly.api.model.core.auth.UserDto;
import com.czertainly.api.model.core.connector.ConnectorApiClientDto;
import com.czertainly.api.model.core.cryptography.key.*;
import com.czertainly.api.model.core.scheduler.PaginationRequestDto;
import com.czertainly.api.model.core.search.FilterFieldSource;
import com.czertainly.api.model.core.search.SearchFieldDataByGroupDto;
import com.czertainly.api.model.core.search.SearchFieldDataDto;
import com.czertainly.core.attribute.engine.AttributeEngine;
import com.czertainly.core.attribute.engine.records.ObjectAttributeContentInfo;
import com.czertainly.core.comparator.SearchFieldDataComparator;
import com.czertainly.core.dao.entity.*;
import com.czertainly.core.dao.repository.*;
import com.czertainly.core.enums.FilterField;
import com.czertainly.core.messaging.model.NotificationRecipient;
import com.czertainly.core.messaging.jms.producers.NotificationProducer;
import com.czertainly.core.model.auth.ResourceAction;
import com.czertainly.core.security.authn.client.UserManagementApiClient;
import com.czertainly.core.security.authz.ExternalAuthorization;
import com.czertainly.core.security.authz.ObjectFilterAspect;
import com.czertainly.core.security.authz.SecuredParentUUID;
import com.czertainly.core.security.authz.SecuredUUID;
import com.czertainly.core.security.authz.SecurityFilter;
import com.czertainly.core.service.*;
import com.czertainly.core.util.*;
import jakarta.persistence.criteria.CriteriaBuilder;
import jakarta.persistence.criteria.CriteriaQuery;
import jakarta.persistence.criteria.Predicate;
import jakarta.persistence.criteria.Root;
import org.apache.commons.lang3.function.TriFunction;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.data.domain.PageRequest;
import org.springframework.data.domain.Pageable;
import org.springframework.lang.NonNull;
import org.springframework.lang.Nullable;
import org.springframework.stereotype.Service;
import org.springframework.transaction.PlatformTransactionManager;
import org.springframework.transaction.TransactionStatus;
import org.springframework.transaction.annotation.Propagation;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.transaction.support.DefaultTransactionDefinition;

import java.nio.charset.StandardCharsets;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.time.LocalDateTime;
import java.util.*;
import java.util.stream.Collectors;
import java.util.stream.IntStream;

import static java.util.function.Predicate.not;

@Service(Resource.Codes.CRYPTOGRAPHIC_KEY)
@Transactional(noRollbackFor = ValidationException.class)
public class CryptographicKeyServiceImpl implements CryptographicKeyService {

    private static final Logger logger = LoggerFactory.getLogger(CryptographicKeyServiceImpl.class);

    // forbidden usages for the keys -- by key type and by key algorithm
    private static final Map<KeyType, List<KeyUsage>> FORBIDDEN_TYPE_USAGES = Map.of(
            KeyType.PRIVATE_KEY, List.of(KeyUsage.VERIFY, KeyUsage.ENCRYPT, KeyUsage.WRAP),
            KeyType.PUBLIC_KEY, List.of(KeyUsage.SIGN, KeyUsage.DECRYPT, KeyUsage.UNWRAP)
    );
    private static final Map<KeyAlgorithm, List<KeyUsage>> FORBIDDEN_ALGORITHM_USAGES = Map.of(
            KeyAlgorithm.ECDSA, List.of(KeyUsage.ENCRYPT, KeyUsage.DECRYPT)
    );

    private static List<KeyUsage> getForbiddenUsages(KeyType keyType, KeyAlgorithm keyAlgorithm) {
        Set<KeyUsage> result = new HashSet<>(Objects.requireNonNullElse(FORBIDDEN_TYPE_USAGES.get(keyType), Collections.emptyList()));
        result.addAll(Objects.requireNonNullElse(FORBIDDEN_ALGORITHM_USAGES.get(keyAlgorithm), Collections.emptyList()));
        return result.stream().toList();
    }

    @Value("${spring.jpa.properties.hibernate.jdbc.batch_size:500}")
    private int bulkDeleteBatchSize;

    private PlatformTransactionManager transactionManager;
    private ObjectFilterAspect objectFilterAspect;

    // --------------------------------------------------------------------------------
    // Services & API Clients
    // --------------------------------------------------------------------------------
    private AttributeEngine attributeEngine;
    private ConnectorApiFactory connectorApiFactory;
    private TokenInstanceService tokenInstanceService;
    private CryptographicKeyEventHistoryService keyEventHistoryService;
    private PermissionEvaluator permissionEvaluator;
    private CertificateService certificateService;
    private ResourceObjectAssociationService objectAssociationService;
    private NotificationProducer notificationProducer;

    private UserManagementApiClient userManagementApiClient;
    // --------------------------------------------------------------------------------
    // Repositories
    // --------------------------------------------------------------------------------
    private CryptographicKeyRepository cryptographicKeyRepository;
    private CryptographicKeyItemRepository cryptographicKeyItemRepository;
    private TokenProfileRepository tokenProfileRepository;
    private TokenInstanceReferenceRepository tokenInstanceReferenceRepository;
    private GroupRepository groupRepository;

    @Autowired
    public void setTransactionManager(PlatformTransactionManager transactionManager) {
        this.transactionManager = transactionManager;
    }

    @Autowired
    public void setObjectFilterAspect(ObjectFilterAspect objectFilterAspect) {
        this.objectFilterAspect = objectFilterAspect;
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
    public void setObjectAssociationService(ResourceObjectAssociationService objectAssociationService) {
        this.objectAssociationService = objectAssociationService;
    }

    @Autowired
    public void setConnectorApiFactory(ConnectorApiFactory connectorApiFactory) {
        this.connectorApiFactory = connectorApiFactory;
    }

    @Autowired
    public void setTokenInstanceService(TokenInstanceService tokenInstanceService) {
        this.tokenInstanceService = tokenInstanceService;
    }

    @Autowired
    public void setKeyEventHistoryService(CryptographicKeyEventHistoryService keyEventHistoryService) {
        this.keyEventHistoryService = keyEventHistoryService;
    }

    @Autowired
    public void setCertificateService(CertificateService certificateService) {
        this.certificateService = certificateService;
    }

    @Autowired
    public void setPermissionEvaluator(PermissionEvaluator permissionEvaluator) {
        this.permissionEvaluator = permissionEvaluator;
    }

    @Autowired
    public void setNotificationProducer(NotificationProducer notificationProducer) {
        this.notificationProducer = notificationProducer;
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
    @ExternalAuthorization(resource = Resource.CRYPTOGRAPHIC_KEY, action = ResourceAction.LIST, parentResource = Resource.TOKEN, parentAction = ResourceAction.MEMBERS)
    public CryptographicKeyResponseDto listCryptographicKeys(SecurityFilter filter, SearchRequestDto request) {
        filter.setParentRefProperty(CryptographicKey_.tokenInstanceReferenceUuid.getName());
        RequestValidatorHelper.revalidateSearchRequestDto(request);

        final Pageable p = PageRequest.of(request.getPageNumber() - 1, request.getItemsPerPage());
        final TriFunction<Root<CryptographicKeyItem>, CriteriaBuilder, CriteriaQuery<?>, Predicate> additionalWhereClause = (root, cb, cr) -> FilterPredicatesBuilder.getFiltersPredicate(cb, cr, root, request.getFilters());

        List<UUID> filteredKeyUuids = cryptographicKeyItemRepository.findUuidsUsingSecurityFilter(
                filter,
                additionalWhereClause,
                p,
                (root, cb) -> cb.desc(root.get("createdAt"))
        );

        List<CryptographicKeyItem> filteredKeys = cryptographicKeyItemRepository.findFullByUuidInOrderByCreatedAtDesc(filteredKeyUuids);

        List<Integer> associationsCounts = cryptographicKeyItemRepository.getCountsOfAssociations(filteredKeyUuids);

        List<KeyItemDto> listedKeyDtos = IntStream.range(0, filteredKeys.size())
                .mapToObj(i -> {
                    CryptographicKeyItem cki = filteredKeys.get(i);
                    KeyItemDto dto = cki.mapToSummaryDto();
                    dto.setAssociations(associationsCounts.get(i));
                    return dto;
                })
                .toList();


        final Long maxItems = cryptographicKeyItemRepository.countUsingSecurityFilter(filter, additionalWhereClause);
        final CryptographicKeyResponseDto responseDto = new CryptographicKeyResponseDto();
        responseDto.setCryptographicKeys(listedKeyDtos);
        responseDto.setItemsPerPage(request.getItemsPerPage());
        responseDto.setPageNumber(request.getPageNumber());
        responseDto.setTotalItems(maxItems);
        responseDto.setTotalPages((int) Math.ceil((double) maxItems / request.getItemsPerPage()));
        return responseDto;
    }

    @Override
    public List<SearchFieldDataByGroupDto> getSearchableFieldInformation() {
        return getSearchableFieldsMap();
    }


    @Override
    @ExternalAuthorization(resource = Resource.CRYPTOGRAPHIC_KEY, action = ResourceAction.LIST)
    public List<KeyDto> listKeyPairs(Optional<String> tokenProfileUuid, SecurityFilter filter) {
        logger.debug("Requesting key list for Token profile with UUID {}", tokenProfileUuid);
        filter.setParentRefProperty(CryptographicKey_.tokenInstanceReferenceUuid.getName());

        TriFunction<Root<CryptographicKey>, CriteriaBuilder, CriteriaQuery<?>, Predicate> additionalWhereClause = null;
        if (tokenProfileUuid.isPresent() && !tokenProfileUuid.get().isEmpty()) {
            additionalWhereClause = (root, cb, cr) -> cb.equal(root.get(CryptographicKey_.tokenProfileUuid), UUID.fromString(tokenProfileUuid.get()));
        }

        List<KeyDto> response = cryptographicKeyRepository.findUsingSecurityFilter(filter, List.of("groups", "owner"), additionalWhereClause, null, (root, cb) -> cb.desc(root.get("created")))
                .stream()
                .map(CryptographicKey::mapToDto)
                .toList();

        response = response
                .stream()
                .filter(
                        e -> e.getItems().size() == 2
                ).filter(
                        e -> e.getItems().stream().filter(i -> i.getState().equals(KeyState.ACTIVE)).count() == 2
                )
                .filter(
                        e -> {
                            List<KeyType> keyTypes = e.getItems().stream().map(KeyItemDto::getType).collect(Collectors.toList());
                            keyTypes.removeAll(List.of(KeyType.PUBLIC_KEY, KeyType.PRIVATE_KEY));
                            return keyTypes.isEmpty();
                        }
                ).toList();
        return response;
    }

    @Override
    @ExternalAuthorization(resource = Resource.CRYPTOGRAPHIC_KEY, action = ResourceAction.DETAIL)
    public KeyDetailDto getKey(SecuredUUID uuid) throws NotFoundException {
        CryptographicKey key = checkKeyRequestToken(uuid.getValue(), "get detail of", true, true);
        KeyDetailDto dto = key.mapToDetailDto();
        if (key.getTokenInstanceReferenceUuid() != null) {
            dto.setAttributes(attributeEngine.getObjectDataAttributesContent(ObjectAttributeContentInfo.builder(Resource.CRYPTOGRAPHIC_KEY, key.getUuid()).connector(key.getTokenInstanceReference().getConnectorUuid()).build()));
        }
        dto.setCustomAttributes(attributeEngine.getObjectCustomAttributesContent(Resource.CRYPTOGRAPHIC_KEY, key.getUuid()));
        dto.getItems().forEach(k -> k.setMetadata(attributeEngine.getMappedMetadataContent(ObjectAttributeContentInfo.builder(Resource.CRYPTOGRAPHIC_KEY, UUID.fromString(k.getUuid())).build())));
        logger.debug("Key details with attributes {}", dto);
        return dto;
    }


    @Override
    @ExternalAuthorization(resource = Resource.CRYPTOGRAPHIC_KEY, action = ResourceAction.DETAIL)
    public KeyItemDetailDto getKeyItem(SecuredUUID uuid, String keyItemUuid) throws NotFoundException {
        CryptographicKey key = checkKeyRequestToken(uuid.getValue(), "get detail of key item %s of".formatted(keyItemUuid), false, true);
        CryptographicKeyItem item = cryptographicKeyItemRepository.findByUuidAndKey(
                UUID.fromString(keyItemUuid),
                key
        ).orElseThrow(
                () -> new NotFoundException(CryptographicKeyItem.class, keyItemUuid)
        );
        KeyItemDetailDto dto = item.mapToDto();
        logger.debug("Key details: {}", dto);
        dto.setMetadata(attributeEngine.getMappedMetadataContent(ObjectAttributeContentInfo.builder(Resource.CRYPTOGRAPHIC_KEY, item.getUuid()).build()));
        logger.debug("Key details with attributes {}", dto);
        return dto;
    }

    @Override
    @ExternalAuthorization(resource = Resource.CRYPTOGRAPHIC_KEY, action = ResourceAction.CREATE, parentResource = Resource.TOKEN, parentAction = ResourceAction.DETAIL)
    public KeyDetailDto createKey(UUID tokenInstanceUuid, SecuredParentUUID tokenProfileUuid, KeyRequestType type, KeyRequestDto request) throws AlreadyExistException, ValidationException, ConnectorException, AttributeException, NotFoundException {
        logger.debug("Creating a new key for Token profile {}. Input: {}", tokenProfileUuid, request);
        if (cryptographicKeyRepository.findByName(request.getName()).isPresent()) {
            logger.error("Key with same name already exists");
            throw new AlreadyExistException("Existing Key with the same name already exists");
        }
        if (request.getName() == null) {
            logger.error("Name is empty. Cannot create key without name");
            throw new ValidationException(ValidationError.create("Name is required for creating a new Key"));
        }
        TokenInstanceReference tokenInstanceReference = tokenInstanceService.getTokenInstanceEntity(SecuredUUID.fromUUID(tokenInstanceUuid));
        TokenProfile tokenProfile = tokenProfileRepository.findByUuid(
                        tokenProfileUuid)
                .orElseThrow(
                        () -> new NotFoundException(
                                TokenInstanceReference.class,
                                tokenProfileUuid
                        )
                );

        attributeEngine.validateCustomAttributesContent(Resource.CRYPTOGRAPHIC_KEY, request.getCustomAttributes());
        mergeAndValidateAttributes(type, tokenInstanceReference, request.getAttributes());

        logger.debug("Token instance detail: {}", tokenInstanceReference);
        Connector connector = tokenInstanceReference.getConnector();
        logger.debug("Connector details: {}", connector);
        CreateKeyRequestDto createKeyRequestDto = new CreateKeyRequestDto();
        createKeyRequestDto.setCreateKeyAttributes(request.getAttributes());
        createKeyRequestDto.setTokenProfileAttributes(attributeEngine.getRequestObjectDataAttributesContent(ObjectAttributeContentInfo.builder(Resource.TOKEN_PROFILE, tokenProfile.getUuid()).connector(tokenProfile.getTokenInstanceReference().getConnectorUuid()).build()));

        CryptographicKey key;
        if (type.equals(KeyRequestType.KEY_PAIR)) {
            key = createKeyTypeOfKeyPair(
                    connector,
                    tokenProfile,
                    request,
                    createKeyRequestDto
            );
        } else {
            key = createKeyTypeOfSecret(
                    connector,
                    tokenProfile,
                    request,
                    createKeyRequestDto
            );
        }

        // set owner of certificate to logged user
        objectAssociationService.setOwnerFromProfile(Resource.CRYPTOGRAPHIC_KEY, key.getUuid());
        if (request.getGroupUuids() != null) {
            key.setGroups(objectAssociationService.setGroups(Resource.CRYPTOGRAPHIC_KEY, key.getUuid(), request.getGroupUuids().stream().map(UUID::fromString).collect(Collectors.toSet())));
        }

        logger.debug("Key creation is successful. UUID is {}", key.getUuid());
        KeyDetailDto keyDetailDto = key.mapToDetailDto();
        keyDetailDto.setCustomAttributes(attributeEngine.updateObjectCustomAttributesContent(Resource.CRYPTOGRAPHIC_KEY, key.getUuid(), request.getCustomAttributes()));
        keyDetailDto.setAttributes(attributeEngine.updateObjectDataAttributesContent(ObjectAttributeContentInfo.builder(Resource.CRYPTOGRAPHIC_KEY, key.getUuid()).connector(tokenInstanceReference.getConnectorUuid()).build(), request.getAttributes()));

        logger.debug("Key details: {}", keyDetailDto);
        return keyDetailDto;
    }

    @Override
    @ExternalAuthorization(resource = Resource.CRYPTOGRAPHIC_KEY, action = ResourceAction.UPDATE)
    public KeyDetailDto editKey(SecuredUUID uuid, EditKeyRequestDto request) throws NotFoundException, AttributeException {
        logger.debug("Updating the key with UUID {}. Request: {}", uuid, request);
        CryptographicKey key = getCryptographicKeyEntity(uuid.getValue());
        UUID tokenInstanceUuid = key.getTokenInstanceReferenceUuid();
        if (tokenInstanceUuid != null)
            permissionEvaluator.tokenInstanceMembers(SecuredUUID.fromUUID(tokenInstanceUuid));

        attributeEngine.validateCustomAttributesContent(Resource.CRYPTOGRAPHIC_KEY, request.getCustomAttributes());

        if (request.getName() != null && !request.getName().isEmpty()) key.setName(request.getName());
        if (request.getDescription() != null) key.setDescription(request.getDescription());
        if (request.getTokenProfileUuid() != null) {
            TokenProfile tokenProfile = tokenProfileRepository.findByUuid(
                            SecuredUUID.fromString(request.getTokenProfileUuid()))
                    .orElseThrow(
                            () -> new NotFoundException(
                                    TokenInstanceReference.class,
                                    request.getTokenProfileUuid()
                            )
                    );
            if (!tokenProfile.getTokenInstanceReferenceUuid().equals(key.getTokenInstanceReferenceUuid())) {
                throw new ValidationException(
                        ValidationError.create(
                                "Cannot assign Token Profile from different provider"
                        )
                );
            }
            key.setTokenProfile(tokenProfile);
        }
        key = cryptographicKeyRepository.save(key);

        if (request.getGroupUuids() != null) {
            objectAssociationService.setGroups(Resource.CRYPTOGRAPHIC_KEY, key.getUuid(), request.getGroupUuids().stream().map(UUID::fromString).collect(Collectors.toSet()));
        }
        if (request.getOwnerUuid() != null) {
            objectAssociationService.setOwner(Resource.CRYPTOGRAPHIC_KEY, key.getUuid(), UUID.fromString(request.getOwnerUuid()));
        }
        attributeEngine.updateObjectCustomAttributesContent(Resource.CRYPTOGRAPHIC_KEY, key.getUuid(), request.getCustomAttributes());

        logger.debug("Key details updated. Key: {}", key);
        return getKey(uuid);
    }

    @Override
    @ExternalAuthorization(resource = Resource.CRYPTOGRAPHIC_KEY, action = ResourceAction.ENABLE)
    public void disableKey(UUID uuid, List<String> keyUuids) throws NotFoundException, ValidationException {
        checkKeyRequestToken(uuid, "disable", false, false);

        if (keyUuids != null && !keyUuids.isEmpty()) {
            setKeyItemsEnabled(keyUuids, false, false);
        } else {
            disableKey(List.of(uuid.toString()));
        }
        logger.info("Key disabled: {}", uuid);
    }

    @Override
    @ExternalAuthorization(resource = Resource.CRYPTOGRAPHIC_KEY, action = ResourceAction.ENABLE)
    public void enableKey(UUID uuid, List<String> keyUuids) throws NotFoundException, ValidationException {
        checkKeyRequestToken(uuid, "enable", false, false);

        if (keyUuids != null && !keyUuids.isEmpty()) {
            setKeyItemsEnabled(keyUuids, false, true);
        } else {
            enableKey(List.of(uuid.toString()));
        }
        logger.info("Key enabled: {}", uuid);
    }

    @Override
    @ExternalAuthorization(resource = Resource.CRYPTOGRAPHIC_KEY, action = ResourceAction.ENABLE, parentResource = Resource.TOKEN, parentAction = ResourceAction.DETAIL)
    public void disableKey(List<String> uuids) {
        logger.debug("Request to disable the key with UUID {} ", uuids);
        for (String keyUuid : new LinkedHashSet<>(uuids)) {
            try {
                CryptographicKey key = getCryptographicKeyEntity(UUID.fromString(keyUuid));
                List<String> keyItemUuids = key.getItems().stream().map(keyItem -> keyItem.getUuid().toString()).toList();
                setKeyItemsEnabled(keyItemUuids, true, false);
            } catch (NotFoundException e) {
                logger.warn(e.getMessage());
            }
        }
        logger.info("Key disabled: {}", uuids);
    }

    @Override
    @ExternalAuthorization(resource = Resource.CRYPTOGRAPHIC_KEY, action = ResourceAction.ENABLE, parentResource = Resource.TOKEN, parentAction = ResourceAction.DETAIL)
    public void enableKey(List<String> uuids) {
        logger.debug("Request to enable the key with UUID {} ", uuids);
        for (String keyUuid : new LinkedHashSet<>(uuids)) {
            try {
                CryptographicKey key = getCryptographicKeyEntity(UUID.fromString(keyUuid));
                List<String> keyItemUuids = key.getItems().stream().map(keyItem -> keyItem.getUuid().toString()).toList();
                setKeyItemsEnabled(keyItemUuids, true, true);
            } catch (NotFoundException e) {
                logger.warn(e.getMessage());
            }
        }
        logger.info("Key enabled: {}", uuids);
    }

    @Override
    public void enableKeyItems(List<String> uuids) {
        setKeyItemsEnabled(uuids, true, true);
    }

    @Override
    public void disableKeyItems(List<String> uuids) {
        setKeyItemsEnabled(uuids, true, false);
    }

    @Override
    @ExternalAuthorization(resource = Resource.CRYPTOGRAPHIC_KEY, action = ResourceAction.DELETE)
    public void deleteKey(UUID uuid, List<String> keyItemUuids) throws ConnectorException, NotFoundException {
        CryptographicKey key = checkKeyRequestToken(uuid, "delete", false, false);

        if (keyItemUuids != null && !keyItemUuids.isEmpty()) {
            for (String keyUuid : new LinkedHashSet<>(keyItemUuids)) {
                CryptographicKeyItem keyItem = cryptographicKeyItemRepository
                        .findByUuid(UUID.fromString(keyUuid))
                        .orElseThrow(
                                () -> new NotFoundException(
                                        "Sub key with the UUID " + keyUuid + " is not found",
                                        CryptographicKeyItem.class
                                )
                        );
                if (key.getTokenInstanceReference() != null)
                    destroyKeyFromConnector(key.getTokenInstanceReference(), keyItem.getKeyReferenceUuid());
                key.getItems().remove(keyItem);
                attributeEngine.deleteObjectAttributeContent(Resource.CRYPTOGRAPHIC_KEY, keyItem.getUuid());
                cryptographicKeyItemRepository.delete(keyItem);
                cryptographicKeyRepository.save(key);
            }
            if (key.getItems().isEmpty()) {
                deleteKeyWithAssociations(key);
            }
        } else {
            deleteKey(List.of(uuid.toString()));
        }
        logger.info("Key deleted: {}", uuid);
    }

    private void destroyKeyFromConnector(TokenInstanceReference tokenInstanceReference, UUID keyReferenceUuid) throws ConnectorException {
        try {
            ConnectorApiClientDto connectorDto = tokenInstanceReference.getConnector().mapToApiClientDtoV1();
            connectorApiFactory.getKeyManagementApiClient(connectorDto).destroyKey(
                    connectorDto,
                    tokenInstanceReference.getTokenInstanceUuid(),
                    keyReferenceUuid.toString()
            );
            logger.info("Key item destroyed in the connector. Removing from the core now.");
        } catch (ConnectorEntityNotFoundException e) {
            logger.info("Key item already destroyed in the connector.");
        } catch (Exception e) {
            if (tokenInstanceReference.getStatus().equals(TokenInstanceStatus.DEACTIVATED)) {
                logger.info("Key cannot be accessed from the token. Key will not be destroyed in connector.");
            } else throw e;
        }
    }

    @Override
    @ExternalAuthorization(resource = Resource.CRYPTOGRAPHIC_KEY, action = ResourceAction.DELETE, parentResource = Resource.TOKEN, parentAction = ResourceAction.DETAIL)
    public void deleteKey(List<String> uuids) throws ConnectorException {
        logger.debug("Request to deleted the keys with UUIDs {}", uuids);
        for (String uuid : uuids) {
            try {
                CryptographicKey key = getCryptographicKeyEntity(UUID.fromString(uuid));
                if (key.getTokenProfile() != null) {
                    permissionEvaluator.tokenProfile(key.getTokenProfile().getSecuredUuid());
                }
                for (CryptographicKeyItem keyItem : key.getItems()) {
                    if (key.getTokenInstanceReference() != null) {
                        destroyKeyFromConnector(key.getTokenInstanceReference(), keyItem.getKeyReferenceUuid());
                    }
                    attributeEngine.deleteObjectAttributeContent(Resource.CRYPTOGRAPHIC_KEY, keyItem.getUuid());
                    cryptographicKeyItemRepository.delete(keyItem);
                }
                deleteKeyWithAssociations(key);
            } catch (NotFoundException e) {
                logger.warn(e.getMessage());
            }
        }
        logger.info("Keys deleted: {}", uuids);
    }

    @Override
    @ExternalAuthorization(resource = Resource.CRYPTOGRAPHIC_KEY, action = ResourceAction.DELETE, parentResource = Resource.TOKEN, parentAction = ResourceAction.MEMBERS)
    @Transactional(propagation = Propagation.NOT_SUPPORTED)
    public void deleteKeyItems(SecurityFilter filterForTokenInstance, List<String> keyItemUuids) throws ConnectorException {
        filterForTokenInstance.setParentRefProperty(CryptographicKey_.tokenInstanceReferenceUuid.getName());
        SecurityFilter filterForTokenProfile = createSecurityFilterFor(Resource.CRYPTOGRAPHIC_KEY, ResourceAction.DELETE, Resource.TOKEN_PROFILE, ResourceAction.MEMBERS,
                CryptographicKey_.tokenProfileUuid.getName());

        UUID loggedUserUuid = UUID.fromString(AuthHelper.getUserIdentification().getUuid());
        int totalToDelete = keyItemUuids.size();
        int deletedCount = 0;
        List<SecurityFilter> filters = List.of(filterForTokenInstance, filterForTokenProfile);

        // Process bulk deletion in batches. Every batch gets its own transaction.
        for (int i = 0; i < totalToDelete; i += bulkDeleteBatchSize) {
            int end = Math.min(i + bulkDeleteBatchSize, totalToDelete);
            List<UUID> batchUuids = keyItemUuids.subList(i, end).stream().map(UUID::fromString).toList();

            TransactionStatus txStatus = transactionManager.getTransaction(new DefaultTransactionDefinition());
            try {
                deletedCount += deleteKeyItemsBatch(filters, batchUuids, loggedUserUuid);
                transactionManager.commit(txStatus);
            } catch (Exception e) {
                transactionManager.rollback(txStatus);
                logger.error("Failed to process key item bulk deletion batch: {}", e.getMessage(), e);
                notificationProducer.produceInternalNotificationMessage(Resource.CRYPTOGRAPHIC_KEY_ITEM,
                        batchUuids.getFirst(),
                        NotificationRecipient.buildUserNotificationRecipient(loggedUserUuid),
                        "Batch key deletion failed for " + batchUuids.size() + " key items",
                        e.getMessage());

            }
        }
        logger.debug("Bulk deleted {} of {} key items.", deletedCount, totalToDelete);
    }

    private int deleteKeyItemsBatch(List<SecurityFilter> filters, List<UUID> batchUuids, UUID loggedUserUuid) throws ConnectorException {
        // 1. Check permissions for two parents: TokenInstance/MEMBERS and TokenProfile/MEMBERS
        List<UUID> permittedUuids = batchUuids;
        for (SecurityFilter filter : filters) {
            permittedUuids = filterKeyItemsBySecurityFilter(filter, permittedUuids, loggedUserUuid);
        }

        if (permittedUuids.isEmpty()) {
            return 0;
        }

        // 2. Fetch cryptographic key items and the associated keys.
        List<CryptographicKeyItem> keyItems = cryptographicKeyItemRepository.findWithKeyByUuidIn(permittedUuids);

        // 3. Destroy the keys from the connector.
        logger.debug("Going to delete key items with UUIDs {}", permittedUuids);
        for (CryptographicKeyItem keyItem : keyItems) {
            CryptographicKey key = keyItem.getKey();
            if (key.getTokenInstanceReferenceUuid() != null) {
                destroyKeyFromConnector(key.getTokenInstanceReference(), keyItem.getKeyReferenceUuid());
            }
        }

        // 4. First work on the cryptographic keys.
        List<CryptographicKey> keysToDelete = new ArrayList<>();
        for (CryptographicKeyItem keyItem : keyItems) {
            CryptographicKey key = keyItem.getKey();
            key.getItems().remove(keyItem);
            if (key.getItems().isEmpty()) {
                key.setOwner(null);
                key.getGroups().clear();
                keysToDelete.add(key);
            }
        }

        // 5. Get rid of cryptographic key items.
        attributeEngine.bulkDeleteObjectAttributeContent(Resource.CRYPTOGRAPHIC_KEY, permittedUuids);
        cryptographicKeyItemRepository.deleteAllById(permittedUuids);

        // 6. Finally, delete empty keys.
        if (!keysToDelete.isEmpty()) {
            List<UUID> keyUuidsToDelete = keysToDelete.stream().map(CryptographicKey::getUuid).toList();
            certificateService.bulkClearKeyAssociations(keyUuidsToDelete);
            attributeEngine.bulkDeleteObjectAttributeContent(Resource.CRYPTOGRAPHIC_KEY, keyUuidsToDelete);
            objectAssociationService.bulkRemoveObjectAssociations(Resource.CRYPTOGRAPHIC_KEY, keyUuidsToDelete);
            cryptographicKeyRepository.deleteAllById(keyUuidsToDelete);
        }

        return permittedUuids.size();
    }

    private static TriFunction<Root<CryptographicKeyItem>, CriteriaBuilder, CriteriaQuery<?>, Predicate> createAdditionalWhereClauseForBulkDeleteBatch(List<UUID> batchUuids) {
        return ((root, cb, cr) -> {
            var in = cb.in(root.get(CryptographicKeyItem_.uuid.getName()));
            batchUuids.forEach(in::value);
            return in;
        });
    }

    private List<UUID> filterKeyItemsBySecurityFilter(SecurityFilter filter, List<UUID> inputUuids, UUID loggedUserUuid) {
        TriFunction<Root<CryptographicKeyItem>, CriteriaBuilder, CriteriaQuery<?>, Predicate> additionalWhereClause = createAdditionalWhereClauseForBulkDeleteBatch(inputUuids);
        List<UUID> permittedUuids = cryptographicKeyItemRepository.findUuidsUsingSecurityFilter(filter, additionalWhereClause, null, null);
        List<UUID> nonPermittedUuids = new ArrayList<>(inputUuids);
        nonPermittedUuids.removeAll(permittedUuids);

        for (UUID nonPermittedUuid : nonPermittedUuids) {
            logger.error("Unable to delete cryptographic key item {}. The cryptographic key item cannot be found or cannot be authorized for deletion.", nonPermittedUuid);
            notificationProducer.produceInternalNotificationMessage(Resource.CRYPTOGRAPHIC_KEY_ITEM, nonPermittedUuid,
                    NotificationRecipient.buildUserNotificationRecipient(loggedUserUuid),
                    "Unable to delete cryptographic key item " + nonPermittedUuid,
                    "The cryptographic key item cannot be found or cannot be authorized for deletion.");
        }
        return permittedUuids;
    }


    private SecurityFilter createSecurityFilterFor(@NonNull Resource resource, @NonNull ResourceAction action,
                                                   @Nullable Resource parentResource, @Nullable ResourceAction parentAction, @Nullable String parentRefProperty) {
        SecurityFilter filter = SecurityFilter.create();
        Map<String, String> properties = new HashMap<>(Map.of(
                "name", resource.getCode(),
                "action", action.getCode(),
                "parentName", parentResource != null ? parentResource.getCode() : Resource.NONE.getCode(),
                "parentAction", parentAction != null ? parentAction.getCode() : ResourceAction.NONE.getCode()
        ));
        objectFilterAspect.populateSecurityFilter(properties, filter);

        if (parentRefProperty != null) {
            filter.setParentRefProperty(parentRefProperty);
        }
        return filter;
    }

    @Override
    @ExternalAuthorization(resource = Resource.CRYPTOGRAPHIC_KEY, action = ResourceAction.DELETE)
    public void destroyKey(UUID uuid, List<String> keyUuids) throws ConnectorException, NotFoundException {
        checkKeyRequestToken(uuid, "destroy", false, false);

        if (keyUuids != null && !keyUuids.isEmpty()) {
            destroyKeyItems(keyUuids, false);
        } else {
            destroyKey(List.of(uuid.toString()));
        }
        logger.info("Key destroyed: {}", uuid);
    }

    @Override
    @ExternalAuthorization(resource = Resource.CRYPTOGRAPHIC_KEY, action = ResourceAction.DELETE, parentResource = Resource.TOKEN, parentAction = ResourceAction.DETAIL)
    public void destroyKey(List<String> uuids) throws ConnectorException, NotFoundException {
        logger.debug("Request to destroy the key with UUIDs {}", uuids);
        for (String uuid : uuids) {
            CryptographicKey key = getCryptographicKeyEntity(UUID.fromString(uuid));
            List<String> keyItemUuids = key.getItems().stream().map(keyItem -> keyItem.getUuid().toString()).toList();
            destroyKeyItems(keyItemUuids, true);
        }
        logger.info("Key destroyed: {}", uuids);
    }

    @Override
    public void destroyKeyItems(List<String> keyItemUuids) throws ConnectorException {
        destroyKeyItems(keyItemUuids, true);
    }

    @Override
    @ExternalAuthorization(resource = Resource.CRYPTOGRAPHIC_KEY, action = ResourceAction.ANY, parentResource = Resource.TOKEN_PROFILE, parentAction = ResourceAction.DETAIL)
    public List<BaseAttribute> listCreateKeyAttributes(UUID tokenInstanceUuid, SecuredParentUUID tokenProfileUuid, KeyRequestType type) throws ConnectorException, NotFoundException {
        logger.debug("Request to list the attributes for creating a new key on Token profile: {}", tokenProfileUuid);
        TokenProfile tokenProfile = tokenProfileRepository.findByUuid(
                        tokenProfileUuid.getValue())
                .orElseThrow(
                        () -> new NotFoundException(
                                TokenProfile.class,
                                tokenProfileUuid
                        )
                );
        logger.debug("Token profile details: {}", tokenProfile);
        List<BaseAttribute> attributes;
        ConnectorApiClientDto connectorDto = tokenProfile.getTokenInstanceReference().getConnector().mapToApiClientDtoV1();
        if (type.equals(KeyRequestType.KEY_PAIR)) {
            attributes = connectorApiFactory.getKeyManagementApiClient(connectorDto).listCreateKeyPairAttributes(
                    connectorDto,
                    tokenProfile.getTokenInstanceReference().getTokenInstanceUuid()
            );
        } else {
            attributes = connectorApiFactory.getKeyManagementApiClient(connectorDto).listCreateSecretKeyAttributes(
                    connectorDto,
                    tokenProfile.getTokenInstanceReference().getTokenInstanceUuid()
            );
        }
        logger.debug("Attributes for the new creation: {}", attributes);
        return attributes;
    }

    @Override
    @ExternalAuthorization(resource = Resource.CRYPTOGRAPHIC_KEY, action = ResourceAction.UPDATE, parentResource = Resource.TOKEN, parentAction = ResourceAction.DETAIL)
    public void syncKeys(SecuredParentUUID tokenInstanceUuid) throws ConnectorException, AttributeException, NotFoundException {
        TokenInstanceReference tokenInstanceReference = tokenInstanceService.getTokenInstanceEntity(
                tokenInstanceUuid
        );
        //Create a map to hold the key and its objects. The association key will be used as the name for the parent key object
        Map<String, List<KeyDataResponseDto>> associations = new HashMap<>();
        // Get the list of keys from the connector
        ConnectorApiClientDto connectorDto = tokenInstanceReference.getConnector().mapToApiClientDtoV1();
        List<KeyDataResponseDto> keys = connectorApiFactory.getKeyManagementApiClient(connectorDto).listKeys(
                connectorDto,
                tokenInstanceReference.getTokenInstanceUuid()
        );

        // Iterate and add the keys with the same associations to the map
        for (KeyDataResponseDto key : keys) {
            associations.computeIfAbsent(
                    (key.getAssociation() == null || key.getAssociation().isEmpty()) ? "" : key.getAssociation(),
                    k -> new ArrayList<>()
            ).add(key);
        }
        logger.debug("Total number of keys from the connector: {}", keys.size());

        // Iterate through the created map and store the items in the database
        for (Map.Entry<String, List<KeyDataResponseDto>> entry : associations.entrySet()) {
            // If the key is empty then it is individual entity. Probably only private or public key or Secret Key
            if (entry.getKey().isEmpty()) {
                for (KeyDataResponseDto soleEntity : entry.getValue()) {
                    createKeyAndItems(
                            tokenInstanceReference.getConnectorUuid(),
                            tokenInstanceReference,
                            soleEntity.getName(),
                            List.of(soleEntity)
                    );
                }
            } else {
                createKeyAndItems(
                        tokenInstanceReference.getConnectorUuid(),
                        tokenInstanceReference,
                        entry.getKey(),
                        entry.getValue()
                );
            }
        }
        logger.info("Sync Key Completed");
    }

    @Override
    @ExternalAuthorization(resource = Resource.CRYPTOGRAPHIC_KEY, action = ResourceAction.UPDATE)
    public void compromiseKey(UUID uuid, CompromiseKeyRequestDto request) throws NotFoundException {
        checkKeyRequestToken(uuid, "compromise", false, false);

        List<UUID> keyUuids = request.getUuids();
        if (keyUuids != null && !keyUuids.isEmpty()) {
            compromiseKeyItems(keyUuids, false, request.getReason());
        } else {
            compromiseKey(new BulkCompromiseKeyRequestDto(request.getReason(), List.of(uuid)));
        }
        logger.info("Key marked as compromised: {}", uuid);
    }

    @Override
    @ExternalAuthorization(resource = Resource.CRYPTOGRAPHIC_KEY, action = ResourceAction.UPDATE, parentResource = Resource.TOKEN, parentAction = ResourceAction.DETAIL)
    public void compromiseKey(BulkCompromiseKeyRequestDto request) {
        List<UUID> uuids = request.getUuids();
        logger.debug("Request to mark the key as compromised with UUIDs {}", uuids);
        for (UUID uuid : uuids) {
            try {
                CryptographicKey key = getCryptographicKeyEntity(uuid);
                List<UUID> keyItemUuids = key.getItems().stream().map(UniquelyIdentified::getUuid).toList();
                compromiseKeyItems(keyItemUuids, true, request.getReason());
            } catch (NotFoundException e) {
                logger.warn(e.getMessage());
            }
        }
        logger.info("Key marked as compromised: {}", uuids);
    }

    @Override
    public void compromiseKeyItems(BulkCompromiseKeyItemRequestDto request) {
        compromiseKeyItems(request.getUuids(), true, request.getReason());
    }

    @Override
    @ExternalAuthorization(resource = Resource.CRYPTOGRAPHIC_KEY, action = ResourceAction.UPDATE, parentResource = Resource.TOKEN, parentAction = ResourceAction.DETAIL)
    public void updateKeyUsages(BulkKeyUsageRequestDto request) {
        logger.debug("Request to update the key usages with UUIDs {}", request.getUuids());
        for (UUID uuid : request.getUuids()) {
            try {
                CryptographicKey key = getCryptographicKeyEntity(uuid);
                List<UUID> keyItemsUuids = key.getItems().stream().map(UniquelyIdentified::getUuid).toList();
                setKeyItemsUsages(keyItemsUuids, request.getUsage(), false);
            } catch (Exception e) {
                logger.warn(e.getMessage());
            }
        }
        logger.info("Key usages updated: {}", request.getUuids());
    }

    @Override
    @ExternalAuthorization(resource = Resource.CRYPTOGRAPHIC_KEY, action = ResourceAction.UPDATE)
    public void updateKeyUsages(UUID uuid, UpdateKeyUsageRequestDto request) throws NotFoundException {
        checkKeyRequestToken(uuid, "update key usages of", false, false);

        if (request.getUuids() != null && !request.getUuids().isEmpty()) {
            setKeyItemsUsages(request.getUuids(), request.getUsage(), true);
        } else {
            BulkKeyUsageRequestDto requestDto = new BulkKeyUsageRequestDto();
            requestDto.setUsage(request.getUsage());
            requestDto.setUuids(List.of(uuid));
            updateKeyUsages(requestDto);
        }
        logger.info("Key usages updated: {}", uuid);
    }

    @Override
    public void updateKeyItemUsages(BulkKeyItemUsageRequestDto request) {
        setKeyItemsUsages(request.getUuids(), request.getUsage(), false);
    }

    @Override
    @ExternalAuthorization(resource = Resource.CRYPTOGRAPHIC_KEY, action = ResourceAction.DETAIL)
    public List<KeyEventHistoryDto> getEventHistory(UUID uuid, UUID keyItemUuid) throws NotFoundException {
        logger.debug("Request to get the list of events for the key item");
        return keyEventHistoryService.getKeyEventHistory(keyItemUuid);
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
    public UUID uploadCertificatePublicKey(String name, PublicKey publicKey, int keyLength, String fingerprint) {
        LocalDateTime now = LocalDateTime.now();
        CryptographicKey cryptographicKey = new CryptographicKey();
        cryptographicKey.setName(name);
        cryptographicKeyRepository.save(cryptographicKey);
        CryptographicKeyItem cryptographicKeyItem = new CryptographicKeyItem();
        cryptographicKeyItem.setUuid(UUID.randomUUID());
        cryptographicKeyItem.setName(name);
        cryptographicKeyItem.setType(KeyType.PUBLIC_KEY);
        cryptographicKeyItem.setKey(cryptographicKey);
        KeyAlgorithm keyAlgorithmEnumValue;
        try {
            keyAlgorithmEnumValue = CertificateUtil.getKeyAlgorithmEnumFromProviderName(publicKey.getAlgorithm());
        } catch (IllegalArgumentException e) {
            keyAlgorithmEnumValue = KeyAlgorithm.UNKNOWN;
        }
        cryptographicKeyItem.setKeyAlgorithm(keyAlgorithmEnumValue);
        cryptographicKeyItem.setKeyData(Base64.getEncoder().encodeToString(publicKey.getEncoded()));
        cryptographicKeyItem.setFormat(CryptographyUtil.getPublicKeyFormat(publicKey.getEncoded()));
        cryptographicKeyItem.setLength(keyLength);
        cryptographicKeyItem.setFingerprint(fingerprint);
        cryptographicKeyItem.setState(KeyState.ACTIVE);
        cryptographicKeyItem.setEnabled(true);
        cryptographicKeyItem.setCreatedAt(now);
        cryptographicKeyItem.setUpdatedAt(now);
        cryptographicKeyItemRepository.insertWithFingerprintConflictResolve(cryptographicKeyItem);
        return cryptographicKey.getUuid();
    }

    @Override
    public NameAndUuidDto getResourceObjectInternal(UUID objectUuid) throws NotFoundException {
        return cryptographicKeyRepository.findResourceObject(objectUuid, CryptographicKey_.name);
    }

    @Override
    @ExternalAuthorization(resource = Resource.CRYPTOGRAPHIC_KEY, action = ResourceAction.DETAIL)
    public NameAndUuidDto getResourceObjectExternal(SecuredUUID objectUuid) throws NotFoundException {
        CryptographicKey key = checkKeyRequestToken(objectUuid.getValue(), "get detail of", true, true);
        return new NameAndUuidDto(objectUuid.getValue(), key.getName());
    }

    @Override
    public List<NameAndUuidDto> listResourceObjects(SecurityFilter filter, List<SearchFilterRequestDto> filters, PaginationRequestDto pagination) {
        throw new NotSupportedException("Listing of resource objects is not supported for resource cryptographic keys.");
    }

    @Override
    @ExternalAuthorization(resource = Resource.CRYPTOGRAPHIC_KEY, action = ResourceAction.UPDATE)
    public void evaluatePermissionChain(SecuredUUID uuid) throws NotFoundException {
        getCryptographicKeyEntity(uuid.getValue());
    }

    @Override
    @ExternalAuthorization(resource = Resource.CRYPTOGRAPHIC_KEY, action = ResourceAction.DETAIL)
    public KeyItemDetailDto editKeyItem(SecuredUUID keyUuid, UUID keyItemUuid, EditKeyItemDto editKeyItemDto) throws NotFoundException {
        CryptographicKey key = getCryptographicKeyEntityWithAssociations(keyUuid.getValue());
        if (key.getTokenInstanceReferenceUuid() != null)
            permissionEvaluator.tokenInstance(key.getTokenInstanceReference().getSecuredUuid());
        Optional<CryptographicKeyItem> keyItem = key.getItems().stream().filter(cki -> cki.getUuid().equals(keyItemUuid)).findFirst();
        if (keyItem.isEmpty())
            throw new NotFoundException("Key Item has not been found for Key with UUID %s.".formatted(keyUuid));
        keyItem.get().setName(editKeyItemDto.getName());
        cryptographicKeyItemRepository.save(keyItem.get());
        return keyItem.get().mapToDto();
    }

    private void createKeyAndItems(UUID connectorUuid, TokenInstanceReference tokenInstanceReference, String key, List<KeyDataResponseDto> items) throws AttributeException {
        //Iterate through the items for a specific key
        if (checkKeyAlreadyExists(tokenInstanceReference.getUuid(), items)) {
            return;
        }
        // Create the cryptographic Key
        KeyRequestDto dto = new KeyRequestDto();
        dto.setName(key);
        dto.setDescription("Discovered from " + tokenInstanceReference.getName());
        CryptographicKey cryptographicKey = createKeyEntity(dto, null, tokenInstanceReference);
        // Create the items for each key
        Set<CryptographicKeyItem> children = new HashSet<>();
        for (KeyDataResponseDto item : items) {
            children.add(
                    createKeyContent(
                            item.getUuid(),
                            item.getName(),
                            item.getKeyData(),
                            cryptographicKey,
                            connectorUuid,
                            true,
                            false
                    )
            );
        }
        cryptographicKey.setItems(children);
        cryptographicKeyRepository.save(cryptographicKey);
    }

    private boolean checkKeyAlreadyExists(UUID tokenInstanceUuid, List<KeyDataResponseDto> items) {
        //Iterate through the items for a specific key
        for (KeyDataResponseDto item : items) {
            //check if the item with the reference uuid already exists in the database
            // Assumption - Content of the key from earlier does not change
            for (CryptographicKeyItem keyItem : cryptographicKeyItemRepository.findByKeyReferenceUuid(UUID.fromString(item.getUuid()))) {
                if (keyItem.getKey().getTokenInstanceReferenceUuid().equals(tokenInstanceUuid)) {
                    return true;
                }
            }
        }
        return false;
    }

    private CryptographicKey createKeyEntity(KeyRequestDto request, TokenProfile tokenProfile, TokenInstanceReference tokenInstanceReference) {
        CryptographicKey key = new CryptographicKey();
        key.setName(request.getName());
        key.setDescription(request.getDescription());
        key.setTokenProfile(tokenProfile);
        key.setTokenInstanceReference(tokenInstanceReference);

        logger.debug("Cryptographic Key: {}", key);
        return cryptographicKeyRepository.save(key);
    }

    private CryptographicKeyItem createKeyContent(String referenceUuid, String referenceName, KeyData keyData, CryptographicKey cryptographicKey, UUID connectorUuid, boolean isDiscovered, boolean enabled) throws AttributeException {
        logger.debug("Creating the Key Content for {}", cryptographicKey);
        CryptographicKeyItem keyItem = new CryptographicKeyItem();
        keyItem.setName(referenceName);
        keyItem.setKey(cryptographicKey);
        keyItem.setType(keyData.getType());
        keyItem.setKeyAlgorithm(keyData.getAlgorithm());
        keyItem.setKeyData(keyData.getFormat(), keyData.getValue());
        if (keyData.getFormat() != KeyFormat.CUSTOM) {
            try {
                String fingerprint = CertificateUtil.getThumbprint(keyItem.getKeyData().getBytes(StandardCharsets.UTF_8));
                UUID sameKeyUuid = findKeyByFingerprint(fingerprint);
                if (sameKeyUuid != null)
                    throw new ValidationException("Key with the same fingerprint as key item of key %s already exists. Existing key UUID: %s".formatted(cryptographicKey.getUuid(), sameKeyUuid));
                keyItem.setFingerprint(fingerprint);
            } catch (NoSuchAlgorithmException e) {
                throw new ValidationException("Failed to calculate fingerprint from key content: " + keyItem.getKeyData());
            }
        }
        keyItem.setFormat(keyData.getFormat());
        keyItem.setLength(keyData.getLength());
        keyItem.setKeyReferenceUuid(UUID.fromString(referenceUuid));
        keyItem.setState(KeyState.ACTIVE);
        keyItem.setEnabled(enabled);
        if (cryptographicKey.getTokenProfile() != null) {
            keyItem.setUsage(
                    cryptographicKey
                            .getTokenProfile()
                            .getUsage()
                            .stream()
                            .filter(
                                    not(getForbiddenUsages(keyData.getType(), keyData.getAlgorithm())::contains)
                            )
                            .toList()
            );
        }
        cryptographicKeyItemRepository.save(keyItem);
        String message;
        if (isDiscovered) {
            message = "Key Discovered from Token Instance "
                    + cryptographicKey.getTokenInstanceReference().getName();
        } else {
            message = "Key Created from Token Profile "
                    + cryptographicKey.getTokenProfile().getName()
                    + " on Token Instance "
                    + cryptographicKey.getTokenInstanceReference().getName();
        }
        keyEventHistoryService.addEventHistory(
                KeyEvent.CREATE,
                KeyEventStatus.SUCCESS,
                message,
                null,
                keyItem.getUuid()
        );

        attributeEngine.updateMetadataAttributes(keyData.getMetadata(), ObjectAttributeContentInfo.builder(Resource.CRYPTOGRAPHIC_KEY, UUID.fromString(keyItem.getUuid().toString())).connector(connectorUuid).source(Resource.CRYPTOGRAPHIC_KEY, cryptographicKey.getUuid()).sourceName(cryptographicKey.getName()).build());
        if (keyData.getType().equals(KeyType.PUBLIC_KEY)) {
            certificateService.updateCertificateKeys(cryptographicKey.getUuid(), keyItem.getFingerprint());
        }

        return keyItem;
    }

    private CryptographicKey getCryptographicKeyEntity(UUID uuid) throws NotFoundException {
        return cryptographicKeyRepository.findByUuid(uuid).orElseThrow(() -> new NotFoundException(CryptographicKey.class, uuid));
    }

    private CryptographicKey getCryptographicKeyEntityWithAssociations(UUID uuid) throws NotFoundException {
        return cryptographicKeyRepository.findWithAssociationsByUuid(uuid).orElseThrow(() -> new NotFoundException(CryptographicKey.class, uuid));
    }

    private void mergeAndValidateAttributes(KeyRequestType type, TokenInstanceReference tokenInstanceRef, List<RequestAttribute> attributes) throws ConnectorException, AttributeException {
        logger.debug("Merging and validating attributes on token instance {}. Request Attributes are: {}", tokenInstanceRef, attributes);
        if (tokenInstanceRef.getConnector() == null) {
            throw new ValidationException(ValidationError.create("Connector of the Token is not available / deleted"));
        }

        ConnectorApiClientDto connectorDto = tokenInstanceRef.getConnector().mapToApiClientDtoV1();

        // validate first by connector and list attributes definitions
        List<BaseAttribute> definitions;
        if (type.equals(KeyRequestType.KEY_PAIR)) {
            connectorApiFactory.getKeyManagementApiClient(connectorDto).validateCreateKeyPairAttributes(connectorDto, tokenInstanceRef.getTokenInstanceUuid(), attributes);
            definitions = connectorApiFactory.getKeyManagementApiClient(connectorDto).listCreateKeyPairAttributes(connectorDto, tokenInstanceRef.getTokenInstanceUuid());
        } else {
            connectorApiFactory.getKeyManagementApiClient(connectorDto).validateCreateSecretKeyAttributes(connectorDto, tokenInstanceRef.getTokenInstanceUuid(), attributes);
            definitions = connectorApiFactory.getKeyManagementApiClient(connectorDto).listCreateSecretKeyAttributes(connectorDto, tokenInstanceRef.getTokenInstanceUuid());
        }

        // validate and update definitions with attribute engine
        attributeEngine.validateUpdateDataAttributes(tokenInstanceRef.getConnectorUuid(), null, definitions, attributes);
    }

    private CryptographicKey createKeyTypeOfKeyPair(Connector connector, TokenProfile tokenProfile, KeyRequestDto request, CreateKeyRequestDto createKeyRequestDto) throws ConnectorException, AttributeException {
        boolean enabled = Boolean.TRUE.equals(request.getEnabled());
        ConnectorApiClientDto connectorDto = connector.mapToApiClientDtoV1();
        KeyPairDataResponseDto response = connectorApiFactory.getKeyManagementApiClient(connectorDto).createKeyPair(
                connectorDto,
                tokenProfile.getTokenInstanceReference().getTokenInstanceUuid(),
                createKeyRequestDto
        );

        logger.debug("Response from the connector for the new Key creation: {}", response);
        Set<CryptographicKeyItem> children = new HashSet<>();
        CryptographicKey key = createKeyEntity(request, tokenProfile, tokenProfile.getTokenInstanceReference());
        children.add(createKeyContent(
                response.getPrivateKeyData().getUuid(),
                response.getPrivateKeyData().getName(),
                response.getPrivateKeyData().getKeyData(),
                key,
                connector.getUuid(),
                false,
                enabled
        ));
        children.add(createKeyContent(
                response.getPublicKeyData().getUuid(),
                response.getPrivateKeyData().getName(),
                response.getPublicKeyData().getKeyData(),
                key,
                connector.getUuid(),
                false,
                enabled
        ));
        key.setItems(children);
        return cryptographicKeyRepository.save(key);
    }

    private CryptographicKey createKeyTypeOfSecret(Connector connector, TokenProfile tokenProfile, KeyRequestDto request, CreateKeyRequestDto createKeyRequestDto) throws ConnectorException, AttributeException {
        ConnectorApiClientDto connectorDto = connector.mapToApiClientDtoV1();
        KeyDataResponseDto response = connectorApiFactory.getKeyManagementApiClient(connectorDto).createSecretKey(
                connectorDto,
                tokenProfile.getTokenInstanceReference().getTokenInstanceUuid(),
                createKeyRequestDto
        );
        logger.debug("Response from the connector for the new Key creation: {}", response);
        CryptographicKey key = createKeyEntity(request, tokenProfile, tokenProfile.getTokenInstanceReference());

        Set<CryptographicKeyItem> items = new HashSet<>();
        items.add(createKeyContent(response.getUuid(), response.getName(), response.getKeyData(), key, connector.getUuid(), false, Boolean.TRUE.equals(request.getEnabled())));
        key.setItems(items);

        return cryptographicKeyRepository.save(key);
    }

    /**
     * Function to enable/disable the key
     *
     * @param keyItemsUuids UUIDs of the Key Items
     */
    private void setKeyItemsEnabled(List<String> keyItemsUuids, boolean evaluateTokenPermission, boolean enabled) {
        logger.debug("Request to set the key items with UUIDs {} {}", keyItemsUuids, enabled ? "enabled" : "disabled");
        List<String> errors = new ArrayList<>();
        if (keyItemsUuids != null && !keyItemsUuids.isEmpty()) {
            for (String keyItemUuid : new LinkedHashSet<>(keyItemsUuids)) {
                try {
                    if (!setKeyItemEnabled(UUID.fromString(keyItemUuid), evaluateTokenPermission, enabled)) {
                        errors.add(keyItemUuid);
                    }
                } catch (NotFoundException e) {
                    logger.warn(e.getMessage());
                }
            }
        }
        if (!errors.isEmpty()) {
            throw new ValidationException(errors.stream().map(ValidationError::create).toList());
        }
        logger.info("Key items {}: {}", enabled ? "enabled" : "disabled", keyItemsUuids);
    }

    /**
     * Function to enable/disable the key
     *
     * @param uuid UUID of the Key Item
     */
    private boolean setKeyItemEnabled(UUID uuid, boolean evaluateTokenPermission, boolean enabled) throws NotFoundException {
        CryptographicKeyItem keyItem = getKeyItem(uuid, evaluateTokenPermission);
        if (keyItem.isEnabled() == enabled) {
            String message = "Key " + uuid + " is already " + (enabled ? "enabled." : "disabled.");
            keyEventHistoryService.addEventHistory(KeyEvent.ENABLE, KeyEventStatus.FAILED, message, null, keyItem);
            return false;
        }
        keyItem.setEnabled(enabled);
        cryptographicKeyItemRepository.save(keyItem);
        keyEventHistoryService.addEventHistory(enabled ? KeyEvent.ENABLE : KeyEvent.DISABLE, KeyEventStatus.SUCCESS, "Key " + (enabled ? "enabled." : "disabled."), null, keyItem);
        return true;
    }

    /**
     * Function to mark keys as compromised
     *
     * @param keyItemsUuids UUIDs of the Key Items
     */
    private void compromiseKeyItems(List<UUID> keyItemsUuids, boolean evaluateTokenPermission, KeyCompromiseReason reason) {
        logger.debug("Request to mark the key items as compromised with UUIDs {}", keyItemsUuids);
        List<String> errors = new ArrayList<>();
        if (keyItemsUuids != null && !keyItemsUuids.isEmpty()) {
            for (UUID keyItemUuid : new LinkedHashSet<>(keyItemsUuids)) {
                try {
                    if (!compromiseKeyItem(keyItemUuid, reason, evaluateTokenPermission)) {
                        errors.add(keyItemUuid.toString());
                    }
                } catch (NotFoundException e) {
                    logger.warn(e.getMessage());
                }
            }
        }
        if (!errors.isEmpty()) {
            throw new ValidationException(errors.stream().map(ValidationError::create).toList());
        }
        logger.info("Key Items marked as compromised: {}", keyItemsUuids);
    }

    /**
     * Function to mark a key as compromised
     *
     * @param uuid UUID of the Key Item
     */
    private boolean compromiseKeyItem(UUID uuid, KeyCompromiseReason reason, boolean evaluateTokenPermission) throws NotFoundException {
        CryptographicKeyItem keyItem = getKeyItem(uuid, evaluateTokenPermission);
        if (!keyItem.getState().equals(KeyState.PRE_ACTIVE) && !keyItem.getState().equals(KeyState.ACTIVE) && !keyItem.getState().equals(KeyState.DEACTIVATED)) {
            String message = "Invalid state of key " + uuid + ". Key is " + keyItem.getState().getLabel() + ", hence can't be set to " + KeyState.COMPROMISED.getLabel() + ".";
            keyEventHistoryService.addEventHistory(KeyEvent.COMPROMISED, KeyEventStatus.FAILED,
                    message, null, keyItem);
            return false;
        }
        keyItem.setState(KeyState.COMPROMISED);
        keyItem.setReason(reason);
        cryptographicKeyItemRepository.save(keyItem);
        keyEventHistoryService.addEventHistory(KeyEvent.COMPROMISED, KeyEventStatus.SUCCESS, "Key compromised. Reason: " + reason + ".", null, keyItem);
        return true;
    }

    private void setKeyItemsUsages(List<UUID> keyItemsUuids, List<KeyUsage> usages, boolean evaluateTokenPermission) {
        logger.debug("Request to update usages of key items with UUIDs {}", keyItemsUuids);
        List<String> errors = new ArrayList<>();
        if (keyItemsUuids != null && !keyItemsUuids.isEmpty()) {
            for (UUID keyItemUuid : new LinkedHashSet<>(keyItemsUuids)) {
                try {
                    if (!setKeyItemUsages(keyItemUuid, usages, evaluateTokenPermission)) {
                        errors.add(keyItemUuid.toString());
                    }
                } catch (Exception e) {
                    logger.warn(e.getMessage());
                }
            }
        }
        if (!errors.isEmpty()) {
            throw new ValidationException(errors.stream().map(ValidationError::create).toList());
        }
        logger.info("Key items usages updated: {}", keyItemsUuids);
    }

    /**
     * Function to update the usage of the key
     *
     * @param uuid UUID of the Key Item
     */
    private boolean setKeyItemUsages(UUID uuid, List<KeyUsage> usages, boolean evaluateTokenPermission) throws NotFoundException {
        CryptographicKeyItem content = getKeyItem(uuid, evaluateTokenPermission);

        List<KeyUsage> forbiddenUsages = getForbiddenUsages(content.getType(), content.getKeyAlgorithm()).stream().filter(usages::contains).toList();
        if (!forbiddenUsages.isEmpty()) {
            String nonAllowedUsages = forbiddenUsages.stream().map(KeyUsage::getCode).collect(Collectors.joining(", "));
            String message = "Unsupported usages of key " + uuid + ": " + nonAllowedUsages + ".";
            keyEventHistoryService.addEventHistory(KeyEvent.UPDATE_USAGE, KeyEventStatus.FAILED, message, null, content);
            return false;
        }
        String oldUsage = content.getUsage().stream().map(KeyUsage::getCode).collect(Collectors.joining(", "));
        content.setUsage(usages);
        cryptographicKeyItemRepository.save(content);
        String newUsage = usages.stream().map(KeyUsage::getCode).collect(Collectors.joining(", "));
        keyEventHistoryService.addEventHistory(KeyEvent.UPDATE_USAGE, KeyEventStatus.SUCCESS,
                "Key usages updated from " + oldUsage + " to " + newUsage + ".", null, content);
        return true;
    }

    /**
     * Function to destroy the key items
     *
     * @param keyItemUuids UUIDs of the Key Items
     */
    private void destroyKeyItems(List<String> keyItemUuids, boolean evaluateTokenPermission) throws ConnectorException {
        logger.debug("Request to destroy the key items with UUIDs {}", keyItemUuids);
        List<String> errors = new ArrayList<>();
        if (keyItemUuids != null && !keyItemUuids.isEmpty()) {
            for (String uuid : new LinkedHashSet<>(keyItemUuids)) {
                try {
                    if (!destroyKeyItem(UUID.fromString(uuid), evaluateTokenPermission)) {
                        errors.add(uuid);
                    }
                } catch (Exception e) {
                    logger.warn(e.getLocalizedMessage());
                }
            }
        }
        if (!errors.isEmpty()) {
            throw new ValidationException(errors.stream().map(ValidationError::create).toList());
        }
        logger.info("Key Items destroyed: {}", keyItemUuids);
    }

    /**
     * Function to destroy the key
     *
     * @param uuid UUID of the Key Item
     */
    private boolean destroyKeyItem(UUID uuid, boolean evaluateTokenPermission) throws ConnectorException, NotFoundException {
        CryptographicKeyItem keyItem = getKeyItem(uuid, evaluateTokenPermission);
        KeyState finalState = keyItem.getState().equals(KeyState.COMPROMISED) ? KeyState.DESTROYED_COMPROMISED : KeyState.DESTROYED;
        if (!keyItem.getState().equals(KeyState.DEACTIVATED) && !keyItem.getState().equals(KeyState.PRE_ACTIVE) && !keyItem.getState().equals(KeyState.COMPROMISED)) {
            String message = "Invalid state of key " + uuid + ". Key is " + keyItem.getState().getLabel() + ", hence can't be set to " + finalState.getLabel() + ".";
            keyEventHistoryService.addEventHistory(KeyEvent.DESTROY, KeyEventStatus.FAILED,
                    message, null, keyItem);
            return false;
        }
        if (keyItem.getKey().getTokenInstanceReference() != null) {
            destroyKeyFromConnector(keyItem.getKey().getTokenInstanceReference(), keyItem.getKeyReferenceUuid());
        }
        keyItem.setKeyData(null);
        keyItem.setState(finalState);
        cryptographicKeyItemRepository.save(keyItem);
        keyEventHistoryService.addEventHistory(KeyEvent.DESTROY, KeyEventStatus.SUCCESS, "Key destroyed.", null, keyItem);
        return true;
    }

    private CryptographicKeyItem getKeyItem(UUID uuid, boolean evaluateTokenPermission) throws NotFoundException {
        CryptographicKeyItem keyItem = getCryptographicKeyItem(uuid);
        if (keyItem.getKey().getTokenProfileUuid() != null) {
            permissionEvaluator.tokenProfile(keyItem.getKey().getTokenProfile().getSecuredUuid());
        }
        if (evaluateTokenPermission && keyItem.getKey().getTokenInstanceReferenceUuid() != null) {
            permissionEvaluator.tokenInstance(keyItem.getKey().getTokenInstanceReference().getSecuredUuid());
        }
        return keyItem;
    }

    private CryptographicKeyItem getCryptographicKeyItem(UUID uuid) throws NotFoundException {
        return cryptographicKeyItemRepository
                .findByUuid(uuid)
                .orElseThrow(
                        () -> new NotFoundException(
                                CryptographicKeyItem.class,
                                uuid
                        )
                );
    }

    private void deleteKeyWithAssociations(CryptographicKey key) {
        certificateService.clearKeyAssociations(key.getUuid());
        attributeEngine.deleteObjectAttributeContent(Resource.CRYPTOGRAPHIC_KEY, key.getUuid());
        key.setOwner(null);
        key.getGroups().clear();
        objectAssociationService.removeObjectAssociations(Resource.CRYPTOGRAPHIC_KEY, key.getUuid());
        cryptographicKeyRepository.delete(key);
    }

    private List<SearchFieldDataByGroupDto> getSearchableFieldsMap() {
        final List<SearchFieldDataByGroupDto> searchFieldDataByGroupDtos = attributeEngine.getResourceSearchableFields(Resource.CRYPTOGRAPHIC_KEY, false);

        List<SearchFieldDataDto> fields = List.of(
                SearchHelper.prepareSearch(FilterField.CKI_NAME),
                SearchHelper.prepareSearch(FilterField.CK_GROUP, groupRepository.findAll().stream().map(Group::getName).toList()),
                SearchHelper.prepareSearch(FilterField.CK_OWNER, userManagementApiClient.getUsers().getData().stream().map(UserDto::getUsername).toList()),
                SearchHelper.prepareSearch(FilterField.CKI_USAGE, Arrays.stream(KeyUsage.values()).map(KeyUsage::getCode).toList()),
                SearchHelper.prepareSearch(FilterField.CKI_LENGTH),
                SearchHelper.prepareSearch(FilterField.CKI_STATE, Arrays.stream(KeyState.values()).map(KeyState::getCode).toList()),
                SearchHelper.prepareSearch(FilterField.CKI_FORMAT, Arrays.stream(KeyFormat.values()).map(KeyFormat::getCode).toList()),
                SearchHelper.prepareSearch(FilterField.CKI_TYPE, Arrays.stream(KeyType.values()).map(KeyType::getCode).toList()),
                SearchHelper.prepareSearch(FilterField.CKI_CRYPTOGRAPHIC_ALGORITHM, Arrays.stream(KeyAlgorithm.values()).map(KeyAlgorithm::getCode).toList()),
                SearchHelper.prepareSearch(FilterField.CK_TOKEN_PROFILE, tokenProfileRepository.findAll().stream().map(TokenProfile::getName).toList()),
                SearchHelper.prepareSearch(FilterField.CK_TOKEN_INSTANCE, tokenInstanceReferenceRepository.findAll().stream().map(TokenInstanceReference::getName).toList())

        );
        fields = new ArrayList<>(fields);
        fields.sort(new SearchFieldDataComparator());
        searchFieldDataByGroupDtos.add(new SearchFieldDataByGroupDto(fields, FilterFieldSource.PROPERTY));

        logger.debug("Searchable CryptographicKey Fields groups: {}", searchFieldDataByGroupDtos);
        return searchFieldDataByGroupDtos;
    }

    private CryptographicKey checkKeyRequestToken(UUID keyUuid, String operation, boolean withAssociations, boolean tokenMembersPermission) throws NotFoundException {
        CryptographicKey key = withAssociations ? getCryptographicKeyEntityWithAssociations(keyUuid) : getCryptographicKeyEntity(keyUuid);
        String tokenInstanceMessage = "";
        if (key.getTokenInstanceReferenceUuid() != null) {
            if (tokenMembersPermission) {
                permissionEvaluator.tokenInstanceMembers(key.getTokenInstanceReference().getSecuredUuid());
            } else {
                permissionEvaluator.tokenInstance(key.getTokenInstanceReference().getSecuredUuid());
            }
            tokenInstanceMessage = " in token instance " + key.getTokenInstanceReferenceUuid();
        }
        logger.debug("Request to {} the key with UUID {}{}", operation, keyUuid, tokenInstanceMessage);
        return key;
    }
}
