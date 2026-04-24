package com.czertainly.core.service.impl;

import com.czertainly.api.exception.*;
import com.czertainly.api.model.client.certificate.SearchFilterRequestDto;
import com.czertainly.api.model.client.certificate.SearchRequestDto;
import com.czertainly.api.model.common.NameAndUuidDto;
import com.czertainly.api.model.common.PaginationResponseDto;
import com.czertainly.api.model.common.attribute.common.BaseAttribute;
import com.czertainly.api.model.connector.secrets.SecretType;
import com.czertainly.api.model.core.auth.Resource;
import com.czertainly.api.model.core.connector.v2.ConnectorDetailDto;
import com.czertainly.api.model.core.scheduler.PaginationRequestDto;
import com.czertainly.api.model.core.search.FilterFieldSource;
import com.czertainly.api.model.core.search.SearchFieldDataByGroupDto;
import com.czertainly.api.model.core.search.SearchFieldDataDto;
import com.czertainly.api.model.core.vaultprofile.*;
import com.czertainly.core.attribute.engine.AttributeEngine;
import com.czertainly.core.attribute.engine.records.ObjectAttributeContentInfo;
import com.czertainly.core.client.ConnectorApiFactory;
import com.czertainly.core.comparator.SearchFieldDataComparator;
import com.czertainly.core.dao.entity.*;
import com.czertainly.core.dao.repository.SecretRepository;
import com.czertainly.core.dao.repository.VaultInstanceRepository;
import com.czertainly.core.dao.repository.VaultProfileRepository;
import com.czertainly.core.enums.FilterField;
import com.czertainly.core.model.auth.ResourceAction;
import com.czertainly.core.security.authz.ExternalAuthorization;
import com.czertainly.core.security.authz.SecuredParentUUID;
import com.czertainly.core.security.authz.SecuredUUID;
import com.czertainly.core.security.authz.SecurityFilter;
import com.czertainly.core.service.PermissionEvaluator;
import com.czertainly.core.service.VaultProfileService;
import com.czertainly.core.service.v2.ConnectorService;
import com.czertainly.core.util.FilterPredicatesBuilder;
import com.czertainly.core.util.SearchHelper;
import jakarta.persistence.criteria.CriteriaBuilder;
import jakarta.persistence.criteria.CriteriaQuery;
import jakarta.persistence.criteria.Predicate;
import jakarta.persistence.criteria.Root;
import jakarta.transaction.Transactional;
import org.apache.commons.lang3.function.TriFunction;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.data.domain.PageRequest;
import org.springframework.data.domain.Pageable;
import org.springframework.stereotype.Service;

import java.util.ArrayList;
import java.util.List;
import java.util.UUID;

@Service(value = Resource.Codes.VAULT_PROFILE)
@Transactional
public class VaultProfileServiceImpl implements VaultProfileService {

    private VaultProfileRepository vaultProfileRepository;
    private VaultInstanceRepository vaultInstanceRepository;
    private SecretRepository secretRepository;

    private ConnectorService connectorService;
    private AttributeEngine attributeEngine;
    private PermissionEvaluator permissionEvaluator;

    private ConnectorApiFactory connectorApiFactory;

    @Autowired
    public void setPermissionEvaluator(PermissionEvaluator permissionEvaluator) {
        this.permissionEvaluator = permissionEvaluator;
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
    public void setSecretRepository(SecretRepository secretRepository) {
        this.secretRepository = secretRepository;
    }

    @Autowired
    public void setAttributeEngine(AttributeEngine attributeEngine) {
        this.attributeEngine = attributeEngine;
    }

    @Autowired
    public void setVaultProfileRepository(VaultProfileRepository vaultProfileRepository) {
        this.vaultProfileRepository = vaultProfileRepository;
    }

    @Autowired
    public void setVaultInstanceRepository(VaultInstanceRepository vaultInstanceRepository) {
        this.vaultInstanceRepository = vaultInstanceRepository;
    }

    @Override
    @ExternalAuthorization(resource = Resource.VAULT_PROFILE, action = ResourceAction.LIST, parentResource = Resource.VAULT, parentAction = ResourceAction.LIST)
    public PaginationResponseDto<VaultProfileDto> listVaultProfiles(SearchRequestDto request, SecurityFilter securityFilter) {
        securityFilter.setParentRefProperty(VaultProfile_.VAULT_INSTANCE_UUID);

        Pageable p = PageRequest.of(request.getPageNumber() - 1, request.getItemsPerPage());
        TriFunction<Root<VaultProfile>, CriteriaBuilder, CriteriaQuery<?>, Predicate> predicate = (root, cb, cq) -> FilterPredicatesBuilder.getFiltersPredicate(cb, cq, root, request.getFilters());
        List<VaultProfileDto> vaultProfiles = vaultProfileRepository.findUsingSecurityFilter(securityFilter, List.of(), predicate, p, (root, cb) -> cb.desc(root.get(Audited_.CREATED)))
                .stream()
                .map(VaultProfile::mapToDto)
                .toList();
        PaginationResponseDto<VaultProfileDto> response = new PaginationResponseDto<>();
        response.setItems(vaultProfiles);
        response.setPageNumber(request.getPageNumber());
        response.setItemsPerPage(request.getItemsPerPage());
        response.setTotalItems(vaultProfileRepository.countUsingSecurityFilter(securityFilter, predicate));
        response.setTotalPages((int) Math.ceil((double) response.getTotalItems() / request.getItemsPerPage()));
        return response;
    }

    @Override
    @ExternalAuthorization(resource = Resource.VAULT_PROFILE, action = ResourceAction.DETAIL, parentResource = Resource.VAULT, parentAction = ResourceAction.DETAIL)
    public VaultProfileDetailDto getVaultProfileDetails(SecuredParentUUID vaultUuid, SecuredUUID vaultProfileUuid) throws NotFoundException {
        VaultProfile vaultProfile = vaultProfileRepository.findByUuid(vaultProfileUuid).orElseThrow(() -> new NotFoundException(VaultProfile.class, vaultProfileUuid));
        VaultProfileDetailDto detailDto = vaultProfile.mapToDetailDto();
        if (vaultProfile.getVaultInstance().getConnectorUuid() != null) {
            detailDto.setAttributes(attributeEngine.getObjectDataAttributesContent(ObjectAttributeContentInfo.builder(Resource.VAULT_PROFILE, vaultProfile.getUuid()).connector(vaultProfile.getVaultInstance().getConnectorUuid()).build()));
        }
        detailDto.setCustomAttributes(attributeEngine.getObjectCustomAttributesContent(Resource.VAULT_PROFILE, vaultProfileUuid.getValue()));
        return detailDto;
    }

    @Override
    @ExternalAuthorization(resource = Resource.VAULT_PROFILE, action = ResourceAction.UPDATE, parentResource = Resource.VAULT, parentAction = ResourceAction.DETAIL)
    public VaultProfileDetailDto updateVaultProfile(SecuredParentUUID securedParentUUID, SecuredUUID securedUUID, VaultProfileUpdateRequestDto request) throws NotFoundException, AttributeException {
        VaultProfile vaultProfile = vaultProfileRepository.findByUuid(securedUUID).orElseThrow(() -> new NotFoundException(VaultProfile.class, securedUUID));
        if (vaultProfile.getVaultInstance().getConnectorUuid() == null) {
            throw new ValidationException("Cannot update vault profile for vault without associated connector");
        }

        // check that the vault profile is associated with the same vault instance?
        vaultProfile.setDescription(request.getDescription());
        attributeEngine.validateCustomAttributesContent(Resource.VAULT_PROFILE, request.getCustomAttributes());

        vaultProfileRepository.save(vaultProfile);
        VaultProfileDetailDto detailDto = vaultProfile.mapToDetailDto();
        detailDto.setAttributes(attributeEngine.updateObjectDataAttributesContent(ObjectAttributeContentInfo.builder(Resource.VAULT_PROFILE, vaultProfile.getUuid()).connector(vaultProfile.getVaultInstance().getConnectorUuid()).build(), request.getAttributes()));
        detailDto.setCustomAttributes(attributeEngine.updateObjectCustomAttributesContent(Resource.VAULT_PROFILE, vaultProfile.getUuid(), request.getCustomAttributes()));
        return detailDto;
    }

    @Override
    @ExternalAuthorization(resource = Resource.VAULT_PROFILE, action = ResourceAction.DELETE, parentResource = Resource.VAULT, parentAction = ResourceAction.DETAIL)
    public void deleteVaultProfile(SecuredParentUUID securedParentUUID, SecuredUUID securedUUID) throws NotFoundException {
        VaultProfile vaultProfile = vaultProfileRepository.findByUuid(securedUUID).orElseThrow(() -> new NotFoundException(VaultProfile.class, securedUUID));
        List<String> secretsSource = secretRepository.findAllNamesBySourceVaultProfileUuid(securedUUID.getValue());
        if (!secretsSource.isEmpty()) {
            throw new ValidationException("Cannot delete vault profile %s set as source for secrets %s.".formatted(vaultProfile.getName(), secretsSource));
        }
        List<String> secretsSync = secretRepository.findAllNamesBySyncVaultProfileUuid(securedUUID.getValue());
        if (!secretsSync.isEmpty()) {
            throw new ValidationException("Cannot delete vault profile %s set as sync for secrets %s.".formatted(vaultProfile.getName(), secretsSync));
        }
        attributeEngine.deleteObjectAttributeContent(Resource.VAULT_PROFILE, securedUUID.getValue());
        vaultProfileRepository.delete(vaultProfile);
    }

    @Override
    @ExternalAuthorization(resource = Resource.VAULT_PROFILE, action = ResourceAction.CREATE, parentResource = Resource.VAULT, parentAction = ResourceAction.DETAIL)
    public VaultProfileDetailDto createVaultProfile(SecuredParentUUID securedParentUUID, VaultProfileRequestDto request) throws NotFoundException, ValidationException, AttributeException, AlreadyExistException {
        if (vaultProfileRepository.existsByName(request.getName())) {
            throw new AlreadyExistException("Vault Profile with name " + request.getName() + " already exists");
        }
        VaultInstance vaultInstance = vaultInstanceRepository.findByUuid(securedParentUUID).orElseThrow(() -> new NotFoundException(VaultInstance.class, securedParentUUID));
        if (vaultInstance.getConnectorUuid() == null) {
            throw new ValidationException("Cannot create vault profile for vault without associated connector");
        }

        attributeEngine.validateCustomAttributesContent(Resource.VAULT_PROFILE, request.getCustomAttributes());

        VaultProfile vaultProfile = new VaultProfile();
        vaultProfile.setName(request.getName());
        vaultProfile.setDescription(request.getDescription());
        vaultProfile.setVaultInstance(vaultInstance);
        vaultProfileRepository.save(vaultProfile);

        VaultProfileDetailDto detailDto = vaultProfile.mapToDetailDto();
        // Store vault profile data and custom attributes
        detailDto.setAttributes(attributeEngine.updateObjectDataAttributesContent(ObjectAttributeContentInfo.builder(Resource.VAULT_PROFILE, vaultProfile.getUuid()).connector(vaultInstance.getConnectorUuid()).build(), request.getAttributes()));
        detailDto.setCustomAttributes(attributeEngine.updateObjectCustomAttributesContent(Resource.VAULT_PROFILE, vaultProfile.getUuid(), request.getCustomAttributes()));

        return detailDto;
    }

    @Override
    @ExternalAuthorization(resource = Resource.VAULT_PROFILE, action = ResourceAction.ENABLE, parentResource = Resource.VAULT, parentAction = ResourceAction.DETAIL)
    public void enableVaultProfile(SecuredParentUUID securedParentUUID, SecuredUUID securedUUID) throws NotFoundException {
        VaultProfile vaultProfile = vaultProfileRepository.findByUuid(securedUUID).orElseThrow(() -> new NotFoundException(VaultProfile.class, securedUUID));
        vaultProfile.setEnabled(true);
        vaultProfileRepository.save(vaultProfile);
    }

    @Override
    @ExternalAuthorization(resource = Resource.VAULT_PROFILE, action = ResourceAction.ENABLE, parentResource = Resource.VAULT, parentAction = ResourceAction.DETAIL)
    public void disableVaultProfile(SecuredParentUUID securedParentUUID, SecuredUUID securedUUID) throws NotFoundException {
        VaultProfile vaultProfile = vaultProfileRepository.findByUuid(securedUUID).orElseThrow(() -> new NotFoundException(VaultProfile.class, securedUUID));
        vaultProfile.setEnabled(false);
        vaultProfileRepository.save(vaultProfile);
    }

    @Override
    @ExternalAuthorization(resource = Resource.VAULT_PROFILE, action = ResourceAction.DETAIL, parentResource = Resource.VAULT, parentAction = ResourceAction.DETAIL)
    public List<BaseAttribute> listSecretAttributes(SecuredParentUUID vaultUUID, SecuredUUID vaultProfileUUID, SecretType secretType) throws NotFoundException, ConnectorException, AttributeException {
        VaultInstance vaultInstance = vaultInstanceRepository.findByUuid(vaultUUID).orElseThrow(() -> new NotFoundException(VaultInstance.class, vaultUUID));
        var connectorUuid = vaultInstance.getConnectorUuid();
        if (connectorUuid == null) {
            throw new ValidationException("Cannot list secret attributes for a vault without associated connector");
        }

        ConnectorDetailDto connectorDetailDto = connectorService.getConnector(SecuredUUID.fromUUID(connectorUuid));
        List<BaseAttribute> attributes = connectorApiFactory.getSecretApiClient(connectorDetailDto).getSecretAttributes(connectorDetailDto, secretType);
        // Save connector attributes definitions in attribute engine, so they can be used for validation and content preparation in other operations
        // TODO: This is a temporary solution, solution for this should be implemented in general
        attributeEngine.updateDataAttributeDefinitions(UUID.fromString(connectorDetailDto.getUuid()), null, attributes);
        return attributes;
    }

    @Override
    public List<SearchFieldDataByGroupDto> getSearchableFieldInformation() {
        List<SearchFieldDataByGroupDto> searchFieldDataByGroupDtos = attributeEngine.getResourceSearchableFields(Resource.VAULT_PROFILE, false);
        List<SearchFieldDataDto> fields = new ArrayList<>(List.of(
                SearchHelper.prepareSearch(FilterField.VAULT_PROFILE_NAME),
                SearchHelper.prepareSearch(FilterField.VAULT_PROFILE_VAULT_INSTANCE, vaultInstanceRepository.findAllNames())
        ));
        fields.sort(new SearchFieldDataComparator());
        searchFieldDataByGroupDtos.add(new SearchFieldDataByGroupDto(fields, FilterFieldSource.PROPERTY));
        return searchFieldDataByGroupDtos;
    }


    @Override
    public NameAndUuidDto getResourceObjectInternal(UUID objectUuid) throws NotFoundException {
        return vaultProfileRepository.findResourceObject(objectUuid, VaultProfile_.name);
    }

    @Override
    @ExternalAuthorization(resource = Resource.VAULT_PROFILE, action = ResourceAction.DETAIL)
    public NameAndUuidDto getResourceObjectExternal(SecuredUUID objectUuid) throws NotFoundException {
        VaultProfile vaultProfile = vaultProfileRepository.findByUuid(objectUuid).orElseThrow(() -> new NotFoundException(VaultProfile.class, objectUuid));
        permissionEvaluator.vaultInstance(vaultProfile.getVaultInstance().getSecuredUuid());
        return new NameAndUuidDto(objectUuid.getValue(), vaultProfile.getName());
    }

    @Override
    @ExternalAuthorization(resource = Resource.VAULT_PROFILE, action = ResourceAction.LIST)
    public List<NameAndUuidDto> listResourceObjects(SecurityFilter filter, List<SearchFilterRequestDto> filters, PaginationRequestDto pagination) {
        filter.setParentRefProperty(VaultProfile_.VAULT_INSTANCE_UUID);
        TriFunction<Root<VaultProfile>, CriteriaBuilder, CriteriaQuery<?>, Predicate> predicate = (root, cb, cq) -> FilterPredicatesBuilder.getFiltersPredicate(cb, cq, root, filters);
        return vaultProfileRepository.listResourceObjects(filter, VaultProfile_.name, predicate, pagination);
    }

    @Override
    @ExternalAuthorization(resource = Resource.VAULT_PROFILE, action = ResourceAction.UPDATE)
    public void evaluatePermissionChain(SecuredUUID uuid) throws NotFoundException {
        VaultProfile vaultProfile = vaultProfileRepository.findByUuid(uuid).orElseThrow(() -> new NotFoundException(VaultProfile.class, uuid));
        permissionEvaluator.vaultInstance(vaultProfile.getVaultInstance().getSecuredUuid());
    }

    @Override
    @ExternalAuthorization(resource = Resource.VAULT_PROFILE, action = ResourceAction.LIST, parentResource = Resource.VAULT, parentAction = ResourceAction.LIST)
    public Long statisticsVaultProfileCount(SecurityFilter filter) {
        filter.setParentRefProperty(VaultProfile_.VAULT_INSTANCE_UUID);
        return vaultProfileRepository.countUsingSecurityFilter(filter, null);
    }
}
