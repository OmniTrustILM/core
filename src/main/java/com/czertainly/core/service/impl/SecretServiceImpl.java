package com.czertainly.core.service.impl;

import com.czertainly.core.client.ConnectorApiFactory;
import com.czertainly.api.exception.*;
import com.czertainly.api.model.client.attribute.RequestAttribute;
import com.czertainly.api.model.client.certificate.SearchFilterRequestDto;
import com.czertainly.api.model.client.certificate.SearchRequestDto;
import com.czertainly.api.model.client.dashboard.StatisticsDto;
import com.czertainly.api.model.common.NameAndUuidDto;
import com.czertainly.api.model.common.PaginationResponseDto;
import com.czertainly.api.model.common.attribute.common.AttributeType;
import com.czertainly.api.model.common.attribute.common.BaseAttribute;
import com.czertainly.api.model.common.attribute.v3.content.data.ResourceObjectContentData;
import com.czertainly.api.model.common.attribute.v3.content.data.ResourceSecretContentData;
import com.czertainly.api.model.common.error.ErrorCode;
import com.czertainly.api.model.connector.secrets.*;
import com.czertainly.api.model.connector.secrets.content.*;
import com.czertainly.api.model.core.auth.Resource;
import com.czertainly.api.model.core.auth.UserDto;
import com.czertainly.api.model.core.connector.v2.ConnectorDetailDto;
import com.czertainly.api.model.core.scheduler.PaginationRequestDto;
import com.czertainly.api.model.core.search.FilterFieldSource;
import com.czertainly.api.model.core.search.SearchFieldDataByGroupDto;
import com.czertainly.api.model.core.search.SearchFieldDataDto;
import com.czertainly.api.model.core.compliance.ComplianceStatus;
import com.czertainly.api.model.core.secret.*;
import com.czertainly.api.model.core.secret.SecretRequestDto;
import com.czertainly.core.attribute.engine.AttributeEngine;
import com.czertainly.core.attribute.engine.ConnectorRequestAttributesBuilder;
import com.czertainly.core.attribute.engine.records.ObjectAttributeContentInfo;
import com.czertainly.core.comparator.SearchFieldDataComparator;
import com.czertainly.core.dao.entity.*;
import com.czertainly.core.dao.repository.*;
import com.czertainly.core.enums.FilterField;
import com.czertainly.core.messaging.model.ActionMessage;
import com.czertainly.core.messaging.model.SecretActionData;
import com.czertainly.core.messaging.jms.producers.ActionProducer;
import com.czertainly.core.model.auth.ResourceAction;
import com.czertainly.core.security.authn.client.UserManagementApiClient;
import com.czertainly.core.security.authz.ExternalAuthorization;
import com.czertainly.core.security.authz.SecuredParentUUID;
import com.czertainly.core.security.authz.SecuredUUID;
import com.czertainly.core.security.authz.SecurityFilter;
import com.czertainly.core.service.*;
import com.czertainly.core.service.v2.ConnectorService;
import com.czertainly.core.util.*;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.persistence.criteria.CriteriaBuilder;
import jakarta.persistence.criteria.CriteriaQuery;
import jakarta.persistence.criteria.Predicate;
import jakarta.persistence.criteria.Root;
import jakarta.transaction.Transactional;
import org.apache.commons.lang3.function.TriFunction;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.data.domain.PageRequest;
import org.springframework.data.domain.Pageable;
import org.springframework.security.concurrent.DelegatingSecurityContextExecutorService;
import org.springframework.stereotype.Service;

import java.security.NoSuchAlgorithmException;
import java.util.*;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.stream.Collectors;

@Service(value = Resource.Codes.SECRET)
@Transactional
public class SecretServiceImpl implements SecretService, AttributeResourceService {
    private static final Logger logger = LoggerFactory.getLogger(SecretServiceImpl.class);

    private static final ObjectMapper MAPPER = new ObjectMapper();

    private AttributeEngine attributeEngine;
    private ConnectorRequestAttributesBuilder connectorRequestAttributesBuilder;
    private PermissionEvaluator permissionEvaluator;

    private VaultProfileRepository vaultProfileRepository;
    private VaultInstanceRepository vaultInstanceRepository;
    private SecretRepository secretRepository;
    private SecretVersionRepository secretVersionRepository;
    private Secret2SyncVaultProfileRepository secret2SyncVaultProfileRepository;

    private GroupRepository groupRepository;
    private UserManagementApiClient userManagementApiClient;

    private ResourceObjectAssociationService objectAssociationService;
    private ConnectorService connectorService;
    private VaultInstanceService vaultInstanceService;

    private ConnectorApiFactory connectorApiFactory;

    private ActionProducer actionProducer;

    @Autowired
    public void setActionProducer(ActionProducer actionProducer) {
        this.actionProducer = actionProducer;
    }

    @Autowired
    public void setVaultInstanceService(VaultInstanceService vaultInstanceService) {
        this.vaultInstanceService = vaultInstanceService;
    }

    @Autowired
    public void setSecret2SyncVaultProfileRepository(Secret2SyncVaultProfileRepository secret2SyncVaultProfileRepository) {
        this.secret2SyncVaultProfileRepository = secret2SyncVaultProfileRepository;
    }

    @Autowired
    public void setConnectorRequestAttributesBuilder(ConnectorRequestAttributesBuilder connectorRequestAttributesBuilder) {
        this.connectorRequestAttributesBuilder = connectorRequestAttributesBuilder;
    }

    @Autowired
    public void setConnectorApiFactory(ConnectorApiFactory connectorApiFactory) {
        this.connectorApiFactory = connectorApiFactory;
    }

    @Autowired
    public void setConnectorService(ConnectorService connectorService) {
        this.connectorService = connectorService;
    }

    @Autowired
    public void setSecretVersionRepository(SecretVersionRepository secretVersionRepository) {
        this.secretVersionRepository = secretVersionRepository;
    }

    @Autowired
    public void setPermissionEvaluator(PermissionEvaluator permissionEvaluator) {
        this.permissionEvaluator = permissionEvaluator;
    }

    @Autowired
    public void setObjectAssociationService(ResourceObjectAssociationService objectAssociationService) {
        this.objectAssociationService = objectAssociationService;
    }

    @Autowired
    public void setSecretRepository(SecretRepository secretRepository) {
        this.secretRepository = secretRepository;
    }

    @Autowired
    public void setVaultProfileRepository(VaultProfileRepository vaultProfileRepository) {
        this.vaultProfileRepository = vaultProfileRepository;
    }

    @Autowired
    public void setAttributeEngine(AttributeEngine attributeEngine) {
        this.attributeEngine = attributeEngine;
    }

    @Autowired
    public void setVaultInstanceRepository(VaultInstanceRepository vaultInstanceRepository) {
        this.vaultInstanceRepository = vaultInstanceRepository;
    }

    @Autowired
    public void setUserManagementApiClient(UserManagementApiClient userManagementApiClient) {
        this.userManagementApiClient = userManagementApiClient;
    }

    @Autowired
    public void setGroupRepository(GroupRepository groupRepository) {
        this.groupRepository = groupRepository;
    }

    @Override
    public List<SearchFieldDataByGroupDto> getSearchableFieldInformation() {
        List<SearchFieldDataByGroupDto> searchFieldDataByGroupDtos = attributeEngine.getResourceSearchableFields(Resource.SECRET, false);
        List<SearchFieldDataDto> fieldDataDtos = new ArrayList<>(List.of(
                SearchHelper.prepareSearch(FilterField.SECRET_NAME),
                SearchHelper.prepareSearch(FilterField.SECRET_TYPE, Arrays.stream(com.czertainly.api.model.connector.secrets.SecretType.values()).map(com.czertainly.api.model.connector.secrets.SecretType::getCode).toList()),
                SearchHelper.prepareSearch(FilterField.SECRET_STATE, Arrays.stream(SecretState.values()).map(SecretState::getCode).toList()),
                SearchHelper.prepareSearch(FilterField.SECRET_ENABLED),
                SearchHelper.prepareSearch(FilterField.SECRET_COMPLIANCE_STATUS, Arrays.stream(ComplianceStatus.values()).map(ComplianceStatus::getCode).toList()),
                SearchHelper.prepareSearch(FilterField.SECRET_GROUP_NAME, groupRepository.findAll().stream().map(Group::getName).toList()),
                SearchHelper.prepareSearch(FilterField.SECRET_OWNER, userManagementApiClient.getUsers().getData().stream().map(UserDto::getUsername).toList()),
                SearchHelper.prepareSearch(FilterField.SECRET_SOURCE_VAULT_PROFILE, vaultProfileRepository.findAllNames()),
                SearchHelper.prepareSearch(FilterField.SECRET_SYNC_VAULT_PROFILE, vaultProfileRepository.findAllNames())
        ));

        fieldDataDtos.sort(new SearchFieldDataComparator());
        searchFieldDataByGroupDtos.add(new SearchFieldDataByGroupDto(fieldDataDtos, FilterFieldSource.PROPERTY));
        return searchFieldDataByGroupDtos;
    }

    @Override
    @ExternalAuthorization(resource = Resource.SECRET, action = ResourceAction.LIST, parentResource = Resource.VAULT_PROFILE, parentAction = ResourceAction.MEMBERS)
    public PaginationResponseDto<SecretDto> listSecrets(SearchRequestDto searchRequest, SecurityFilter securityFilter) {
        TriFunction<Root<Secret>, CriteriaBuilder, CriteriaQuery<?>, Predicate> additionalWhereClause = (root, cb, cq) -> FilterPredicatesBuilder.getFiltersPredicate(cb, cq, root, searchRequest.getFilters());
        Pageable p = PageRequest.of(searchRequest.getPageNumber() - 1, searchRequest.getItemsPerPage());
        List<Secret> secrets = getSecrets(securityFilter, p, additionalWhereClause);
        List<SecretDto> secretDtos = secrets.stream().map(Secret::mapToDto).toList();
        PaginationResponseDto<SecretDto> response = new PaginationResponseDto<>();
        response.setItems(secretDtos);
        response.setPageNumber(searchRequest.getPageNumber());
        response.setItemsPerPage(searchRequest.getItemsPerPage());
        response.setTotalItems(secretRepository.countUsingSecurityFilter(securityFilter, additionalWhereClause));
        response.setTotalPages((int) Math.ceil((double) response.getTotalItems() / searchRequest.getItemsPerPage()));
        return response;
    }

    private List<Secret> getSecrets(SecurityFilter securityFilter, Pageable p, TriFunction<Root<Secret>, CriteriaBuilder, CriteriaQuery<?>, Predicate> additionalWhereClause) {
        securityFilter.setParentRefProperty(Secret_.SOURCE_VAULT_PROFILE_UUID);
        return secretRepository.findUsingSecurityFilter(securityFilter, List.of(), additionalWhereClause, p, (root, cb) -> cb.desc(root.get(Audited_.CREATED))).stream().toList();
    }

    @Override
    @ExternalAuthorization(resource = Resource.SECRET, action = ResourceAction.CREATE, parentResource = Resource.VAULT, parentAction = ResourceAction.DETAIL)
    public SecretDetailDto createSecret(SecretRequestDto secretRequest, SecuredParentUUID sourceVaultProfileUuid, SecuredUUID vaultInstanceUuid) throws NotFoundException, AttributeException, AlreadyExistException {
        if (secretRepository.existsByName(secretRequest.getName())) {
            throw new AlreadyExistException("Secret with name '" + secretRequest.getName() + "' already exists");
        }

        VaultProfile vaultProfile = vaultProfileRepository.findByUuid(sourceVaultProfileUuid)
                .orElseThrow(() -> new NotFoundException(VaultProfile.class, sourceVaultProfileUuid.toString()));

        if (!vaultProfile.getVaultInstanceUuid().equals(vaultInstanceUuid.getValue())) {
            throw new ValidationException("Vault Profile with UUID %s is not a member of Vault Instance with UUID %s".formatted(vaultProfile.getUuid(), vaultInstanceUuid));
        }

        VaultInstance vaultInstance = vaultInstanceRepository.findByUuid(vaultInstanceUuid)
                .orElseThrow(() -> new NotFoundException(VaultInstance.class, vaultInstanceUuid.toString()));


        attributeEngine.validateCustomAttributesContent(Resource.SECRET, secretRequest.getCustomAttributes());

        Secret secret = new Secret();
        secret.setName(secretRequest.getName());
        secret.setDescription(secretRequest.getDescription());
        secret.setSourceVaultProfile(vaultProfile);
        secret.setState(SecretState.INACTIVE);
        secret.setType(secretRequest.getSecret().getType());
        SecretVersion secretVersion = new SecretVersion();
        secretVersion.setVersion(1);
        String fingerprint;
        try {
            fingerprint = SecretsUtil.calculateSecretContentFingerprint(secretRequest.getSecret());
        } catch (NoSuchAlgorithmException | JsonProcessingException e) {
            throw new ValidationException("Unable to calculate secret fingerprint: " + e.getMessage());
        }
        secretVersion.setFingerprint(fingerprint);
        secretVersionRepository.save(secretVersion);

        secret.setLatestVersion(secretVersion);
        secret.getVersions().add(secretVersion);
        secretRepository.save(secret);

        secretVersion.setSecret(secret);
        secretVersionRepository.save(secretVersion);

        objectAssociationService.setOwnerFromProfile(Resource.SECRET, secret.getUuid());

        SecretDetailDto secretDetailDto = secret.mapToDetailDto();
        secretDetailDto.setCustomAttributes(attributeEngine.updateObjectCustomAttributesContent(Resource.SECRET, secret.getUuid(), secretRequest.getCustomAttributes()));
        secretDetailDto.setAttributes(attributeEngine.updateObjectDataAttributesContent(ObjectAttributeContentInfo.builder(Resource.SECRET, secret.getUuid()).connector(vaultInstance.getConnectorUuid()).build(), secretRequest.getAttributes()));

        SecretActionData actionData;
        try {
            actionData = SecretActionData.builder()
                    .encryptedContent(SecretsUtil.encryptAndEncodeSecretString(MAPPER.writeValueAsString(secretRequest.getSecret()), SecretEncodingVersion.V1))
                    .name(secretRequest.getName())
                    .attributes(secretRequest.getAttributes())
                    .build();
        } catch (JsonProcessingException e) {
            throw new ValidationException("Unable to encrypt secret: " + e.getMessage());
        }
        produceActionMessage(actionData, vaultProfile, secret, ResourceAction.CREATE);
        return secretDetailDto;
    }

    @ExternalAuthorization(resource = Resource.SECRET, action = ResourceAction.CREATE, parentResource = Resource.VAULT, parentAction = ResourceAction.DETAIL)
    private void checkCreateSecretPermissions(SecuredParentUUID vaultInstanceUuid, SecuredUUID sourceVaultProfileUuid) {
        // empty to evaluate permissions
    }

    private void createSecretAction(UUID secretUuid, SecretRequestDto secretRequest, boolean isApproved) throws NotFoundException, AttributeException, SecretOperationException {
        Secret secret = getSecretEntity(secretUuid);
        VaultProfile vaultProfile = secret.getSourceVaultProfile();
        if (!isApproved) {
            checkCreateSecretPermissions(SecuredParentUUID.fromUUID(vaultProfile.getVaultInstanceUuid()), SecuredUUID.fromUUID(vaultProfile.getUuid()));
        }
        UUID connectorUuid = vaultProfile.getVaultInstance().getConnectorUuid();
        SecretResponseDto secretResponseDto;
        try {
            secretResponseDto = createSecretInVault(connectorUuid, vaultProfile.getVaultInstanceUuid(), secretRequest.getSecret().getType(), vaultProfile.getUuid(), secretRequest);
        } catch (Exception e) {
            secret.setState(SecretState.FAILED);
            throw new SecretOperationException("Failed to create secret in vault: " + e.getMessage());
        }
        SecretVersion secretVersion = secret.getLatestVersion();
        secretVersion.setVaultProfileUuid(vaultProfile.getUuid());
        secretVersion.setVaultVersion(secretResponseDto.getVersion());
        secretVersionRepository.save(secretVersion);
        secret.setState(SecretState.ACTIVE);
        attributeEngine.updateMetadataAttributes(secretResponseDto.getMetadata(), ObjectAttributeContentInfo.builder(Resource.SECRET, secret.getUuid()).connector(connectorUuid).source(Resource.VAULT_PROFILE, vaultProfile.getUuid()).sourceName(vaultProfile.getName()).build());
        secretRepository.save(secret);
    }

    @Override
    @ExternalAuthorization(resource = Resource.SECRET, action = ResourceAction.UPDATE)
    public SecretDetailDto updateSecret(UUID uuid, SecretUpdateRequestDto secretRequest) throws NotFoundException, AttributeException {
        Secret secret = getSecretEntity(uuid);

        attributeEngine.validateCustomAttributesContent(Resource.SECRET, secretRequest.getCustomAttributes());
        VaultProfile currentSourceVaultProfile = secret.getSourceVaultProfile();
        secret.setDescription(secretRequest.getDescription());


        SecretDetailDto secretDetailDto = secret.mapToDetailDto();
        secretDetailDto.setCustomAttributes(attributeEngine.updateObjectCustomAttributesContent(Resource.SECRET, secret.getUuid(), secretRequest.getCustomAttributes()));
        secretDetailDto.setAttributes(attributeEngine.getObjectDataAttributesContent(ObjectAttributeContentInfo.builder(Resource.SECRET, secret.getUuid()).connector(currentSourceVaultProfile.getVaultInstance().getConnectorUuid()).build()));
        secretDetailDto.setMetadata(attributeEngine.getMappedMetadataContent(ObjectAttributeContentInfo.builder(Resource.SECRET, secret.getUuid()).build()));

        if (secretRequest.getSecret() != null) {
            if (invalidSecretState(secret)) {
                throw new ValidationException("Secret %s is in state %s and cannot be updated".formatted(secret.getName(), secret.getState().getLabel()));
            }
            SecretVersion latestVersion = secret.getLatestVersion();
            String newFingerprint;
            try {
                newFingerprint = SecretsUtil.calculateSecretContentFingerprint(secretRequest.getSecret());
            } catch (NoSuchAlgorithmException | JsonProcessingException e) {
                throw new ValidationException("Unable to calculate secret fingerprint: " + e.getMessage());
            }

            boolean contentChanged = !newFingerprint.equals(latestVersion.getFingerprint());
            if (contentChanged) {
                SecretActionData actionData;
                try {
                    actionData = SecretActionData.builder()
                            .attributes(secretRequest.getAttributes())
                            .encryptedContent(SecretsUtil.encryptAndEncodeSecretString(MAPPER.writeValueAsString(secretRequest.getSecret()), SecretEncodingVersion.V1))
                            .originalState(secret.getState())
                            .build();
                } catch (JsonProcessingException e) {
                    throw new ValidationException("Unable to encrypt secret: " + e.getMessage());
                }
                produceActionMessage(actionData, currentSourceVaultProfile, secret, ResourceAction.UPDATE);
            }
        }

        return secretDetailDto;
    }

    private void produceActionMessage(SecretActionData secretActionData, VaultProfile currentSourceVaultProfile, Secret secret, ResourceAction resourceAction) {
        final ActionMessage actionMessage = new ActionMessage();
        actionMessage.setApprovalProfileResource(Resource.VAULT_PROFILE);
        actionMessage.setApprovalProfileResourceUuid(currentSourceVaultProfile.getUuid());
        actionMessage.setData(secretActionData);
        actionMessage.setUserUuid(UUID.fromString(AuthHelper.getUserIdentification().getUuid()));
        actionMessage.setResource(Resource.SECRET);
        actionMessage.setResourceAction(resourceAction);
        actionMessage.setResourceUuid(secret.getUuid());
        actionProducer.produceMessage(actionMessage);
    }

    @ExternalAuthorization(resource = Resource.SECRET, action = ResourceAction.UPDATE)
    private void checkUpdateSecretPermissions() {
        // empty to evaluate permissions
    }

    private void updateSecretAction(UUID secretUuid, SecretUpdateRequestDto secretRequest, boolean isApproved, SecretState originalState) throws NotFoundException, AttributeException, SecretOperationException {
        Secret secret = getSecretEntity(secretUuid);
        VaultProfile currentSourceVaultProfile = secret.getSourceVaultProfile();
        if (!isApproved) {
            checkUpdateSecretPermissions();
        }
        secret.setState(originalState);
        SecretVersion newVersion = new SecretVersion();
        newVersion.setSecret(secret);
        newVersion.setVersion(secret.getLatestVersion().getVersion() + 1);
        String newFingerprint;
        try {
            newFingerprint = SecretsUtil.calculateSecretContentFingerprint(secretRequest.getSecret());
        } catch (NoSuchAlgorithmException | JsonProcessingException e) {
            throw new ValidationException("Unable to calculate secret fingerprint: " + e.getMessage());
        }
        newVersion.setFingerprint(newFingerprint);
        newVersion.setVaultProfile(currentSourceVaultProfile);
        SecretResponseDto sourceVaultProfileResponse;
        try {
            sourceVaultProfileResponse = updateSecretInVault(secret, secret.getSourceVaultProfile(), secretRequest, secretRequest.getAttributes());
        } catch (Exception e) {
            throw new SecretOperationException(String.format("Failed to update secret %s for vault profile %s: %s", secret.getName(), secret.getSourceVaultProfile().getName(), e.getMessage()));
        }
        attributeEngine.updateMetadataAttributes(sourceVaultProfileResponse.getMetadata(), ObjectAttributeContentInfo.builder(Resource.SECRET, secret.getUuid()).connector(currentSourceVaultProfile.getVaultInstance().getConnectorUuid()).source(Resource.VAULT_PROFILE, currentSourceVaultProfile.getUuid()).sourceName(currentSourceVaultProfile.getName()).build());
        for (Secret2SyncVaultProfile profile : secret.getSyncVaultProfiles()) {
            VaultProfile syncVaultProfile = profile.getVaultProfile();
            SecretResponseDto syncResponse;
            try {
                syncResponse = updateSecretInVault(secret, syncVaultProfile, secretRequest, profile.getSecretAttributes());
            } catch (ConnectorException e) {
                throw new SecretOperationException(String.format("Failed to update secret %s for vault profile %s: %s", secret.getName(), profile.getVaultProfile().getName(), e.getMessage()));
            }
            attributeEngine.updateMetadataAttributes(syncResponse.getMetadata(), ObjectAttributeContentInfo.builder(Resource.SECRET, secret.getUuid()).connector(syncVaultProfile.getVaultInstance().getConnectorUuid()).source(Resource.VAULT_PROFILE, syncVaultProfile.getUuid()).sourceName(syncVaultProfile.getName()).build());
        }
        secretVersionRepository.save(newVersion);
        secret.setLatestVersion(newVersion);
        secret.getLatestVersion().setVaultVersion(sourceVaultProfileResponse.getVersion());
        secret.getVersions().add(newVersion);
        attributeEngine.updateObjectDataAttributesContent(ObjectAttributeContentInfo.builder(Resource.SECRET, secret.getUuid()).connector(currentSourceVaultProfile.getVaultInstance().getConnectorUuid()).build(), secretRequest.getAttributes());
    }

    @Override
    @ExternalAuthorization(resource = Resource.SECRET, action = ResourceAction.DELETE)
    public void deleteSecret(UUID uuid, boolean deleteInVaults) throws NotFoundException {
        Secret secret = secretRepository.findByUuid(SecuredUUID.fromUUID(uuid))
                .orElseThrow(() -> new NotFoundException(Secret.class, uuid));
        permissionEvaluator.vaultProfileMembers(SecuredUUID.fromUUID(secret.getSourceVaultProfile().getUuid()));
        SecretActionData actionData = SecretActionData.builder()
                .deleteInVault(deleteInVaults)
                .originalState(secret.getState())
                .build();
        produceActionMessage(actionData, secret.getSourceVaultProfile(), secret, ResourceAction.DELETE);
    }

    @ExternalAuthorization(resource = Resource.SECRET, action = ResourceAction.DELETE)
    private void checkDeleteSecretPermissions() {
        // empty to evaluate permissions
    }

    private void deleteSecretAction(UUID secretUuid, boolean isApproved, SecretState originalState, boolean deleteInVaults) throws NotFoundException, SecretOperationException {
        Secret secret = getSecretEntity(secretUuid);
        if (!isApproved) {
            checkDeleteSecretPermissions();
        }
        // Delete secret from vaults
        if (!invalidSecretState(secret) && deleteInVaults) {
            List<VaultProfile> vaultProfiles = new ArrayList<>(secret.getSyncVaultProfiles().stream().map(Secret2SyncVaultProfile::getVaultProfile).toList());
            vaultProfiles.add(secret.getSourceVaultProfile());
            for (VaultProfile vaultProfile : vaultProfiles) {
                try {
                    deleteSecretFromVault(vaultProfile, secret, attributeEngine.getRequestObjectDataAttributesContent(ObjectAttributeContentInfo.builder(Resource.SECRET, secret.getUuid()).connector(vaultProfile.getVaultInstance().getConnectorUuid()).build()));
                } catch (Exception e) {
                    secret.setState(originalState);
                    throw new SecretOperationException("Failed to delete secret %s from vault profile %s: %s".formatted(secret.getName(), vaultProfile.getVaultInstance().getName(), e.getMessage()));
                }
            }
        }
        Set<SecretVersion> secretVersions = new HashSet<>(secret.getVersions());
        secret.setOwner(null);
        secret.getGroups().clear();
        objectAssociationService.removeObjectAssociations(Resource.SECRET, secret.getUuid());
        secretRepository.delete(secret);
        secretVersionRepository.deleteAll(secretVersions);
    }

    private void deleteSecretFromVault(VaultProfile profile, Secret secret, List<RequestAttribute> secretAttributes) throws NotFoundException, ConnectorException, AttributeException {
        UUID connectorUuid = profile.getVaultInstance().getConnectorUuid();

        var secretRequestDto = new com.czertainly.api.model.connector.secrets.SecretRequestDto();
        ConnectorDetailDto connectorDetailDto = loadSecretRequestDto(connectorUuid, profile, secret, secretAttributes, secretRequestDto);
        try {
            connectorApiFactory.getSecretApiClient(connectorDetailDto).deleteSecret(connectorDetailDto, secretRequestDto);
        } catch (ConnectorProblemException e) {
            if (e.getProblemDetail().getErrorCode() == ErrorCode.RESOURCE_NOT_FOUND) {
                // If the secret is not found in the vault, we can consider it as already deleted and continue with the process
                logger.warn("Secret {} has already been removed in the vault {}", secret.getName(), profile.getVaultInstance().getName());
            } else {
                throw e;
            }
        }
    }

    @Override
    @ExternalAuthorization(resource = Resource.SECRET, action = ResourceAction.ENABLE)
    public void enableSecret(UUID uuid) throws NotFoundException {
        Secret secret = getSecretEntity(uuid);
        if (invalidSecretState(secret)) {
            throw new ValidationException("Secret %s is in state %s and cannot be enabled".formatted(secret.getName(), secret.getState().getLabel()));
        }
        secret.setEnabled(true);
        secretRepository.save(secret);
    }

    private static boolean invalidSecretState(Secret secret) {
        return secret.getState() == SecretState.FAILED || secret.getState() == SecretState.PENDING_APPROVAL || secret.getState() == SecretState.REJECTED;
    }

    @Override
    @ExternalAuthorization(resource = Resource.SECRET, action = ResourceAction.ENABLE)
    public void disableSecret(UUID uuid) throws NotFoundException {
        Secret secret = getSecretEntity(uuid);
        secret.setEnabled(false);
        secretRepository.save(secret);
    }

    @Override
    @ExternalAuthorization(resource = Resource.SECRET, action = ResourceAction.UPDATE)
    public void addVaultProfileToSecret(UUID uuid, UUID
            vaultProfileUuid, List<RequestAttribute> createSecretAttributes) throws
            NotFoundException, ConnectorException, AttributeException {
        Secret secret = getSecretEntity(uuid);
        if (secret.getSourceVaultProfile().getUuid().equals(vaultProfileUuid)) {
            throw new ValidationException("Vault Profile with UUID %s is the source vault profile for secret with UUID %s".formatted(vaultProfileUuid, uuid));
        }
        if (secret.getSyncVaultProfiles().stream().anyMatch(profile -> profile.getVaultProfile().getUuid().equals(vaultProfileUuid))) {
            throw new ValidationException("Vault Profile with UUID %s is already a sync vault profile for secret with UUID %s".formatted(vaultProfileUuid, uuid));
        }
        if (invalidSecretState(secret)) {
            throw new ValidationException("Secret %s is in state %s and sync profile cannot be added".formatted(secret.getName(), secret.getState().getLabel()));
        }

        VaultProfile addedVaultProfile = vaultProfileRepository.findByUuid(SecuredUUID.fromUUID(vaultProfileUuid))
                .orElseThrow(() -> new NotFoundException(VaultProfile.class, vaultProfileUuid));
        permissionEvaluator.vaultProfileMembers(SecuredUUID.fromUUID(addedVaultProfile.getUuid()));
        SecretRequestDto createSecretRequestDto = new SecretRequestDto();
        createSecretRequestDto.setName(secret.getName());
        createSecretRequestDto.setAttributes(createSecretAttributes);
        SecretContent secretContent = getSecretContent(uuid);
        createSecretRequestDto.setSecret(secretContent);
        SecretResponseDto secretResponseDto = null;
        try {
            secretResponseDto = createSecretInVault(addedVaultProfile.getVaultInstance().getConnectorUuid(), addedVaultProfile.getVaultInstanceUuid(), secret.getType(), addedVaultProfile.getUuid(), createSecretRequestDto);
        } catch (ConnectorProblemException e) {
            if (e.getProblemDetail().getErrorCode() == ErrorCode.RESOURCE_ALREADY_EXISTS) {
                logger.warn("Secret {} already exists in the vault {}", secret.getName(), addedVaultProfile.getVaultInstance().getName());
            } else {
                throw e;
            }
        }
        if (secretResponseDto != null) {
            attributeEngine.updateMetadataAttributes(secretResponseDto.getMetadata(), ObjectAttributeContentInfo.builder(Resource.SECRET, secret.getUuid()).connector(addedVaultProfile.getVaultInstance().getConnectorUuid()).source(Resource.VAULT_PROFILE, addedVaultProfile.getUuid()).sourceName(addedVaultProfile.getName()).build());
        }

        Secret2SyncVaultProfileId secret2SyncVaultProfileId = new Secret2SyncVaultProfileId(secret.getUuid(), addedVaultProfile.getUuid());
        Secret2SyncVaultProfile secret2SyncVaultProfile = new Secret2SyncVaultProfile();
        secret2SyncVaultProfile.setId(secret2SyncVaultProfileId);
        secret2SyncVaultProfile.setSecretAttributes(createSecretAttributes);
        secret2SyncVaultProfile.setVaultProfile(addedVaultProfile);
        secret2SyncVaultProfile.setSecret(secret);
        secret2SyncVaultProfileRepository.save(secret2SyncVaultProfile);
    }

    @Override
    @ExternalAuthorization(resource = Resource.SECRET, action = ResourceAction.UPDATE)
    public void removeVaultProfileFromSecret(UUID uuid, UUID vaultProfileUuid, boolean deleteInVault) throws
            NotFoundException, ConnectorException, AttributeException {
        Secret secret = getSecretEntity(uuid);
        if (secret.getSyncVaultProfiles().stream().noneMatch(profile -> profile.getVaultProfile().getUuid().equals(vaultProfileUuid))) {
            throw new ValidationException("Vault Profile with UUID %s is not a sync vault profile for secret with UUID %s".formatted(vaultProfileUuid, uuid));
        }
        VaultProfile removedVaultProfile = secret.getSyncVaultProfiles().stream().filter(profile -> profile.getVaultProfile().getUuid().equals(vaultProfileUuid)).findFirst().orElseThrow(
                () -> new NotFoundException(VaultProfile.class, vaultProfileUuid)
        ).getVaultProfile();
        Secret2SyncVaultProfile secret2SyncVaultProfile = secret2SyncVaultProfileRepository.getReferenceById(new Secret2SyncVaultProfileId(secret.getUuid(), removedVaultProfile.getUuid()));
        // Remove the secret from the vault
        if (deleteInVault) {
            deleteSecretFromVault(removedVaultProfile, secret, secret2SyncVaultProfile.getSecretAttributes());
        }

        secret.getSyncVaultProfiles().remove(secret2SyncVaultProfile);
        secretRepository.save(secret);
    }

    @Override
    @ExternalAuthorization(resource = Resource.SECRET, action = ResourceAction.DETAIL)
    public SecretDetailDto getSecretDetails(UUID uuid) throws NotFoundException {
        Secret secret = getSecretEntity(uuid);
        SecretDetailDto secretDetailDto = secret.mapToDetailDto();
        secretDetailDto.setCustomAttributes(attributeEngine.getObjectCustomAttributesContent(Resource.SECRET, secret.getUuid()));
        secretDetailDto.setAttributes(attributeEngine.getObjectDataAttributesContent(ObjectAttributeContentInfo.builder(Resource.SECRET, secret.getUuid()).connector(secret.getSourceVaultProfile().getVaultInstance().getConnectorUuid()).build()));
        secretDetailDto.setMetadata(attributeEngine.getMappedMetadataContent(ObjectAttributeContentInfo.builder(Resource.SECRET, secret.getUuid()).build()));
        return secretDetailDto;
    }

    private Secret getSecretEntity(UUID uuid) throws NotFoundException {
        Secret secret = secretRepository.findWithAssociationsByUuid(uuid)
                .orElseThrow(() -> new NotFoundException(Secret.class, uuid));
        permissionEvaluator.vaultProfileMembers(SecuredUUID.fromUUID(secret.getSourceVaultProfile().getUuid()));
        return secret;
    }

    @Override
    @ExternalAuthorization(resource = Resource.SECRET, action = ResourceAction.DETAIL)
    public List<SecretVersionDto> getSecretVersions(UUID uuid) throws NotFoundException {
        Secret secret = getSecretEntity(uuid);
        return secret.getVersions().stream().map(SecretVersion::mapToDto).toList();
    }

    @Override
    @ExternalAuthorization(resource = Resource.SECRET, action = ResourceAction.GET_SECRET_CONTENT)
    public SecretContent getSecretContent(UUID uuid) throws NotFoundException, ConnectorException, AttributeException {
        Secret secret = getSecretEntity(uuid);
        if (invalidSecretState(secret)) {
            throw new ValidationException("Secret %s is in state %s and cannot be retrieved".formatted(secret.getName(), secret.getState().getLabel()));
        }
        if (!secret.getSourceVaultProfile().isEnabled()) {
            throw new ValidationException("Source vault profile" + secret.getSourceVaultProfile().getName() + " is not enabled");
        }
        if (!secret.isEnabled()) {
            throw new ValidationException("Secret" + secret.getName() + " is not enabled");
        }
        SecretVersion latestVersion = secret.getLatestVersion();

        UUID connectorUuid = secret.getSourceVaultProfile().getVaultInstance().getConnectorUuid();

        var secretRequestDto = new com.czertainly.api.model.connector.secrets.SecretRequestDto();
        var secretAttributes = attributeEngine.getRequestObjectDataAttributesContent(ObjectAttributeContentInfo.builder(Resource.SECRET, secret.getUuid()).connector(connectorUuid).build());
        ConnectorDetailDto connectorDetailDto = loadSecretRequestDto(connectorUuid, secret.getSourceVaultProfile(), secret, secretAttributes, secretRequestDto);
        SecretContentResponseDto secretContent = connectorApiFactory.getSecretApiClient(connectorDetailDto).getSecretContent(connectorDetailDto, secretRequestDto, latestVersion.getVaultVersion());
        String secretContentFingerprint = null;
        try {
            secretContentFingerprint = SecretsUtil.calculateSecretContentFingerprint(secretContent.getContent());
        } catch (NoSuchAlgorithmException | JsonProcessingException e) {
            throw new ValidationException("Unable to calculate secret fingerprint: " + e.getMessage());
        }
        if (!secret.getLatestVersion().getFingerprint().equals(secretContentFingerprint)) {
            SecretVersion newVersion = new SecretVersion();
            newVersion.setSecret(secret);
            newVersion.setVersion(latestVersion.getVersion() + 1);
            newVersion.setFingerprint(secretContentFingerprint);
            newVersion.setVaultProfile(latestVersion.getVaultProfile());
            newVersion.setVaultVersion(secretContent.getVersion());
            secretVersionRepository.save(newVersion);
            secret.setLatestVersion(newVersion);
            secret.getVersions().add(newVersion);
            secretRepository.save(secret);
        }
        return secretContent.getContent();
    }

    @Override
    @ExternalAuthorization(resource = Resource.SECRET, action = ResourceAction.UPDATE)
    public void updateSecretObjects(UUID uuid, SecretUpdateObjectsDto request) throws NotFoundException {
        Secret secret = getSecretEntity(uuid);
        if (request.getGroupUuids() != null) {
            // check if there is change in groups compared to the current state
            Set<UUID> currentGroups = secret.getGroups().stream().map(Group::getUuid).collect(Collectors.toSet());
            if (currentGroups.equals(request.getGroupUuids())) {
                return;
            }
            objectAssociationService.setGroups(Resource.SECRET, secret.getUuid(), request.getGroupUuids());
        }
        if (request.getOwnerUuid() != null) {
            if (secret.getOwner() != null && request.getOwnerUuid().equals(secret.getOwner().getUuid().toString())) {
                return;
            }
            if (request.getOwnerUuid().isEmpty()) {
                secret.setOwner(null);
                secretRepository.save(secret);
            }
            objectAssociationService.setOwner(Resource.SECRET, secret.getUuid(), request.getOwnerUuid().isEmpty() ? null : UUID.fromString(request.getOwnerUuid()));
        }
        if (request.getSourceVaultProfileUuid() != null) {
            updateSourceVaultProfileAction(request, secret);
        }
    }

    private void updateSourceVaultProfileAction(SecretUpdateObjectsDto request, Secret secret) {
        if (invalidSecretState(secret)) {
            throw new ValidationException("Secret %s is in state %s and source vault profile cannot be updated".formatted(secret.getName(), secret.getState().getLabel()));
        }
        UUID currentSourceVaultProfileUuid = secret.getSourceVaultProfile().getUuid();
        // Evaluate vault profile membership for current source profile
        permissionEvaluator.vaultProfileMembers(SecuredUUID.fromUUID(currentSourceVaultProfileUuid));
        VaultProfile currentSourceVaultProfile = secret.getSourceVaultProfile();

        boolean sourceVaultProfileChanged = !request.getSourceVaultProfileUuid().equals(currentSourceVaultProfileUuid);
        SecretActionData secretActionData = SecretActionData.builder()
                .updatedSourceVaultProfileUuid(request.getSourceVaultProfileUuid())
                .attributes(request.getSecretAttributes())
                .originalState(secret.getState())
                .build();
        if (sourceVaultProfileChanged) {
            produceActionMessage(secretActionData, currentSourceVaultProfile, secret, ResourceAction.UPDATE_SOURCE_VAULT_PROFILE);
        }
    }

    private void updateSourceVaultProfile(SecretUpdateObjectsDto request, UUID secretUuid, boolean isApproved, SecretState originalState) throws NotFoundException, ConnectorException, AttributeException, SecretOperationException {
        Secret secret = getSecretEntity(secretUuid);
        if (!isApproved) {
            checkUpdateSecretPermissions();
        }
        secret.setState(originalState);
        VaultProfile currentSourceVaultProfile = secret.getSourceVaultProfile();
        VaultProfile updatedSourceVaultProfile = vaultProfileRepository.findByUuid(SecuredUUID.fromUUID(request.getSourceVaultProfileUuid()))
                .orElseThrow(() -> new NotFoundException(VaultProfile.class, request.getSourceVaultProfileUuid()));
        permissionEvaluator.vaultProfileMembers(SecuredUUID.fromUUID(request.getSourceVaultProfileUuid()));

        SecretVersion newVersion = new SecretVersion();
        newVersion.setSecret(secret);
        newVersion.setVaultProfile(updatedSourceVaultProfile);
        SecretRequestDto secretRequest = new SecretRequestDto();
        secretRequest.setName(secret.getName());
        secretRequest.setAttributes(request.getSecretAttributes());
        try {
            secretRequest.setSecret(getSecretContent(secret.getUuid()));
        } catch (Exception e) {
            secret.setState(originalState);
            throw new SecretOperationException("Could not retrieve secret content to create secret in vault: " + e.getMessage());
        }
        newVersion.setVersion(secret.getLatestVersion().getVersion() + 1);
        SecretResponseDto secretResponseDto = null;
        try {
            secretResponseDto = createSecretInVault(updatedSourceVaultProfile.getVaultInstance().getConnectorUuid(), updatedSourceVaultProfile.getVaultInstanceUuid(), secret.getType(), updatedSourceVaultProfile.getUuid(), secretRequest);
        } catch (ConnectorProblemException e) {
            if (e.getProblemDetail().getErrorCode() == ErrorCode.RESOURCE_ALREADY_EXISTS) {
                logger.warn("Secret {} already exists in the vault {}", secret.getName(), updatedSourceVaultProfile.getVaultInstance().getName());
                newVersion.setVaultVersion(secret.getLatestVersion().getVaultVersion());
            } else {
                secret.setState(originalState);
                throw new SecretOperationException("Failed to create secret in vault: " + e.getMessage());
            }
        }
        if (secretResponseDto != null) {
            attributeEngine.updateMetadataAttributes(secretResponseDto.getMetadata(), ObjectAttributeContentInfo.builder(Resource.SECRET, secret.getUuid()).connector(updatedSourceVaultProfile.getVaultInstance().getConnectorUuid()).source(Resource.VAULT_PROFILE, updatedSourceVaultProfile.getUuid()).sourceName(updatedSourceVaultProfile.getName()).build());
            newVersion.setVaultVersion(secretResponseDto.getVersion());
        }
        List<RequestAttribute> previousSourceVaultProfileAttributes = attributeEngine.getRequestObjectDataAttributesContent(ObjectAttributeContentInfo.builder(Resource.SECRET, secret.getUuid()).connector(currentSourceVaultProfile.getVaultInstance().getConnectorUuid()).build());
        attributeEngine.deleteObjectAttributesContent(AttributeType.DATA, ObjectAttributeContentInfo.builder(Resource.SECRET, secret.getUuid()).connector(currentSourceVaultProfile.getVaultInstance().getConnectorUuid()).build());
        attributeEngine.updateObjectDataAttributesContent(ObjectAttributeContentInfo.builder(Resource.SECRET, secret.getUuid()).connector(updatedSourceVaultProfile.getVaultInstance().getConnectorUuid()).build(), request.getSecretAttributes());
        newVersion.setFingerprint(secret.getLatestVersion().getFingerprint());
        secretVersionRepository.save(newVersion);
        secret.setLatestVersion(newVersion);
        secret.getVersions().add(newVersion);
        secretRepository.save(secret);

        // Move original source vault profile to sync vault profiles
        Secret2SyncVaultProfile secret2SyncVaultProfile = new Secret2SyncVaultProfile();
        secret2SyncVaultProfile.setSecretAttributes(previousSourceVaultProfileAttributes);
        secret2SyncVaultProfile.setId(new Secret2SyncVaultProfileId(secret.getUuid(), currentSourceVaultProfile.getUuid()));
        secret2SyncVaultProfile.setVaultProfile(currentSourceVaultProfile);
        secret2SyncVaultProfile.setSecret(secret);
        secret2SyncVaultProfileRepository.save(secret2SyncVaultProfile);

        // If new source vault profile was in sync vault profiles, remove association
        if (secret.getSyncVaultProfiles().stream().anyMatch(profile -> profile.getVaultProfile().getUuid().equals(updatedSourceVaultProfile.getUuid()))) {
            secret2SyncVaultProfileRepository.deleteById(new Secret2SyncVaultProfileId(secret.getUuid(), updatedSourceVaultProfile.getUuid()));
            secret.getSyncVaultProfiles().removeIf(profile -> profile.getVaultProfile().getUuid().equals(updatedSourceVaultProfile.getUuid()));
        }
        secret.setSourceVaultProfile(updatedSourceVaultProfile);
    }

    private void handleSecretRejected(UUID resourceUuid, ResourceAction action, SecretState originalState) throws NotFoundException {
        Secret secret = secretRepository.findByUuid(SecuredUUID.fromUUID(resourceUuid))
                .orElseThrow(() -> new NotFoundException(Secret.class, resourceUuid));
        if (action == ResourceAction.CREATE) {
            secret.setState(SecretState.REJECTED);
        } else {
            secret.setState(originalState);
        }
        secretRepository.save(secret);
    }

    @Override
    public void approvalCreatedAction(UUID resourceUuid) throws NotFoundException {
        Secret secret = secretRepository.findByUuid(SecuredUUID.fromUUID(resourceUuid))
                .orElseThrow(() -> new NotFoundException(Secret.class, resourceUuid));
        secret.setState(SecretState.PENDING_APPROVAL);
        secretRepository.save(secret);
    }

    @Override
    public void processSecretAction(ActionMessage actionMessage, boolean hasApproval, boolean isApproved) throws ConnectorException, NotFoundException, AttributeException, JsonProcessingException, SecretOperationException {
        SecretActionData secretActionData = MAPPER.convertValue(actionMessage.getData(), SecretActionData.class);

        // handle rejected actions
        if (hasApproval && !isApproved) {
            handleSecretRejected(actionMessage.getResourceUuid(), actionMessage.getResourceAction(), secretActionData.originalState());
            return;
        }

        switch (actionMessage.getResourceAction()) {
            case CREATE -> {
                SecretRequestDto secretRequestDto = new SecretRequestDto();
                secretRequestDto.setName(secretActionData.name());
                secretRequestDto.setSecret(MAPPER.readValue(SecretsUtil.decodeAndDecryptSecretString(secretActionData.encryptedContent(), SecretEncodingVersion.V1), SecretContent.class));
                secretRequestDto.setAttributes(secretActionData.attributes());
                createSecretAction(actionMessage.getResourceUuid(), secretRequestDto, isApproved);
            }
            case UPDATE -> {
                SecretUpdateRequestDto secretUpdateRequestDto = new SecretUpdateRequestDto();
                secretUpdateRequestDto.setSecret(MAPPER.readValue(SecretsUtil.decodeAndDecryptSecretString(secretActionData.encryptedContent(), SecretEncodingVersion.V1), SecretContent.class));
                secretUpdateRequestDto.setAttributes(secretActionData.attributes());
                updateSecretAction(actionMessage.getResourceUuid(), secretUpdateRequestDto, isApproved, secretActionData.originalState());
            }
            case DELETE ->
                    deleteSecretAction(actionMessage.getResourceUuid(), isApproved, secretActionData.originalState(), secretActionData.deleteInVault());
            case UPDATE_SOURCE_VAULT_PROFILE -> {
                SecretUpdateObjectsDto secretUpdateObjectsDto = new SecretUpdateObjectsDto();
                secretUpdateObjectsDto.setSourceVaultProfileUuid(secretActionData.updatedSourceVaultProfileUuid());
                secretUpdateObjectsDto.setSecretAttributes(secretActionData.attributes());
                updateSourceVaultProfile(secretUpdateObjectsDto, actionMessage.getResourceUuid(), isApproved, secretActionData.originalState());
            }
            default ->
                    logger.error("Action listener does not support action {} for resource {}", actionMessage.getResourceAction().getCode(), actionMessage.getResource().getLabel());
        }
    }

    @Override
    @ExternalAuthorization(resource = Resource.SECRET, action = ResourceAction.GET_SECRET_CONTENT)
    public ResourceObjectContentData getResourceObjectContent(UUID uuid) throws NotFoundException, ConnectorException, AttributeException {
        ResourceSecretContentData resourceSecretContentData = new ResourceSecretContentData();
        SecretContent contentDto = getSecretContent(uuid);
        resourceSecretContentData.setContent(contentDto);
        return resourceSecretContentData;
    }

    @Override
    @ExternalAuthorization(resource = Resource.SECRET, action = ResourceAction.DETAIL)
    public NameAndUuidDto getResourceObjectExternal(SecuredUUID objectUuid) throws NotFoundException {
        Secret secret = getSecretEntity(objectUuid.getValue());
        return new NameAndUuidDto(secret.getUuid(), secret.getName());
    }

    @Override
    public NameAndUuidDto getResourceObjectInternal(UUID objectUuid) throws NotFoundException {
        return secretRepository.findResourceObject(objectUuid, Secret_.name);
    }

    @Override
    @ExternalAuthorization(resource = Resource.SECRET, action = ResourceAction.LIST, parentResource = Resource.VAULT_PROFILE, parentAction = ResourceAction.MEMBERS)
    public List<NameAndUuidDto> listResourceObjects(SecurityFilter filter, List<SearchFilterRequestDto> filters, PaginationRequestDto pagination) {
        filter.setParentRefProperty(Secret_.SOURCE_VAULT_PROFILE_UUID);
        return secretRepository.listResourceObjects(filter, Secret_.name, (root, cb, cq) -> FilterPredicatesBuilder.getFiltersPredicate(cb, cq, root, filters), pagination);
    }

    @Override
    public void evaluatePermissionChain(SecuredUUID uuid) throws NotFoundException {
        getSecretEntity(uuid.getValue());
    }

    private SecretResponseDto createSecretInVault(UUID connectorUuid, UUID vaultUuid, SecretType type, UUID vaultProfileUuid, SecretRequestDto secretRequest) throws ConnectorException, NotFoundException, AttributeException {
        CreateSecretRequestDto createSecretRequestDto = new CreateSecretRequestDto();
        createSecretRequestDto.setName(secretRequest.getName());
        createSecretRequestDto.setSecret(secretRequest.getSecret());

        ConnectorDetailDto connectorDetailDto = loadSecretOperationRequest(connectorUuid, vaultUuid, vaultProfileUuid, type, secretRequest.getAttributes(), createSecretRequestDto);

        return connectorApiFactory.getSecretApiClient(connectorDetailDto).createSecret(connectorDetailDto, createSecretRequestDto);
    }

    private SecretResponseDto updateSecretInVault(Secret secret, VaultProfile vaultProfile, SecretUpdateRequestDto secretRequest, List<RequestAttribute> secretAttributes) throws
            NotFoundException, ConnectorException, AttributeException {
        UUID connectorUuid = vaultProfile.getVaultInstance().getConnectorUuid();

        // Ensure that the incoming secret content type (if specified) matches the persisted secret type
        if (secretRequest.getSecret().getType() != secret.getType()) {
            throw new ValidationException("Secret type cannot be changed during update.");
        }

        UpdateSecretRequestDto updateSecretRequestDto = new UpdateSecretRequestDto();
        updateSecretRequestDto.setName(secret.getName());
        updateSecretRequestDto.setSecret(secretRequest.getSecret());
        updateSecretRequestDto.setMetadata(attributeEngine.getMetadataAttributesDefinitionContent(ObjectAttributeContentInfo.builder(Resource.SECRET, secret.getUuid()).connector(connectorUuid).build()));

        ConnectorDetailDto connectorDetailDto = loadSecretOperationRequest(connectorUuid, vaultProfile.getVaultInstanceUuid(), vaultProfile.getUuid(), secret.getType(), secretAttributes, updateSecretRequestDto);

        return connectorApiFactory.getSecretApiClient(connectorDetailDto).updateSecret(connectorDetailDto, updateSecretRequestDto);
    }

    private ConnectorDetailDto loadSecretRequestDto(UUID connectorUuid, VaultProfile vaultProfile, Secret secret, List<RequestAttribute> secretAttributes, com.czertainly.api.model.connector.secrets.SecretRequestDto secretRequestDto) throws ConnectorException, NotFoundException, AttributeException {
        secretRequestDto.setName(secret.getName());
        secretRequestDto.setType(secret.getType());
        secretRequestDto.setMetadata(attributeEngine.getMetadataAttributesDefinitionContent(ObjectAttributeContentInfo.builder(Resource.SECRET, secret.getUuid()).connector(connectorUuid).build()));

        return loadSecretOperationRequest(connectorUuid, vaultProfile.getVaultInstanceUuid(), vaultProfile.getUuid(), secret.getType(), secretAttributes, secretRequestDto);
    }

    @Override
    @ExternalAuthorization(resource = Resource.SECRET, action = ResourceAction.LIST, parentResource = Resource.VAULT_PROFILE, parentAction = ResourceAction.MEMBERS)
    public Long statisticsSecretCount(SecurityFilter filter) {
        filter.setParentRefProperty(Secret_.SOURCE_VAULT_PROFILE_UUID);
        return secretRepository.countUsingSecurityFilter(filter, null);
    }

    @Override
    @ExternalAuthorization(resource = Resource.SECRET, action = ResourceAction.LIST, parentResource = Resource.VAULT_PROFILE, parentAction = ResourceAction.MEMBERS)
    public StatisticsDto addSecretStatistics(SecurityFilter filter, StatisticsDto dto) {
        filter.setParentRefProperty(Secret_.SOURCE_VAULT_PROFILE_UUID);
        long start = System.nanoTime();
        try (ExecutorService executor = new DelegatingSecurityContextExecutorService(Executors.newVirtualThreadPerTaskExecutor())) {
            List<Future<Void>> futures = executor.invokeAll(List.of(
                    () -> {
                        dto.setSecretStatByType(secretRepository.countGroupedUsingSecurityFilter(filter, null, Secret_.type, null, null));
                        return null;
                    },
                    () -> {
                        dto.setSecretStatByState(secretRepository.countGroupedUsingSecurityFilter(filter, null, Secret_.state, null, null));
                        return null;
                    },
                    () -> {
                        dto.setSecretStatByComplianceStatus(secretRepository.countGroupedUsingSecurityFilter(filter, null, Secret_.complianceStatus, null, null));
                        return null;
                    },
                    () -> {
                        dto.setSecretStatByVaultProfile(secretRepository.countGroupedUsingSecurityFilter(filter, Secret_.sourceVaultProfile, VaultProfile_.name, null, null));
                        return null;
                    },
                    () -> {
                        dto.setSecretStatByGroup(secretRepository.countGroupedUsingSecurityFilter(filter, Secret_.groups, Group_.name, null, null));
                        return null;
                    }
            ));
            processFutures(futures);
        } catch (InterruptedException e) {
            logger.error("An error occurred during calculation of secret statistics: {}", e.getMessage());
            Thread.currentThread().interrupt();
        }
        logger.debug("Secret statistics calculated in {} ms", (System.nanoTime() - start) / 1_000_000L);
        return dto;
    }

    private static void processFutures(List<Future<Void>> futures) throws InterruptedException {
        for (Future<Void> future : futures) {
            try {
                future.get();
            } catch (ExecutionException ex) {
                logger.error("An error occurred during calculation of secret statistics", ex.getCause());
            }
        }
    }

    private ConnectorDetailDto loadSecretOperationRequest(UUID connectorUuid, UUID vaultInstanceUuid, UUID vaultProfileUuid, SecretType type, List<RequestAttribute> secretAttributes, SecretOperationRequest secretOperationRequest) throws ConnectorException, NotFoundException, AttributeException {
        if (connectorUuid == null) {
            throw new ValidationException("Cannot load attributes for secret operation, when vault instance is not associated with connector");
        }

        ConnectorDetailDto connectorDetailDto = connectorService.getConnector(SecuredUUID.fromUUID(connectorUuid));

        vaultInstanceService.loadAttributesForSecretOperation(connectorDetailDto, vaultInstanceUuid, vaultProfileUuid, secretOperationRequest);

        List<BaseAttribute> secretAttributesDefinitions = connectorApiFactory.getSecretApiClient(connectorDetailDto).getSecretAttributes(connectorDetailDto, type);
        attributeEngine.updateAttributeDefinitionsWithCallback(connectorUuid, secretAttributesDefinitions);
        List<RequestAttribute> requestSecretAttributes = connectorRequestAttributesBuilder.prepareRequestAttributesForConnectorRequest(connectorUuid, secretAttributesDefinitions, secretAttributes);
        secretOperationRequest.setSecretAttributes(requestSecretAttributes);

        return connectorDetailDto;
    }
}
