package com.czertainly.core.service.impl;

import com.czertainly.api.clients.ApiClientConnectorInfo;
import com.czertainly.core.client.ConnectorApiFactory;
import com.czertainly.api.exception.*;
import com.czertainly.api.model.client.attribute.RequestAttribute;
import com.czertainly.api.model.client.certificate.SearchRequestDto;
import com.czertainly.api.model.common.PaginationResponseDto;
import com.czertainly.api.model.common.attribute.common.BaseAttribute;
import com.czertainly.api.model.connector.secrets.SecretOperationRequest;
import com.czertainly.api.model.core.auth.Resource;
import com.czertainly.api.model.core.connector.v2.ConnectorDetailDto;
import com.czertainly.api.model.core.connector.v2.ConnectorInterfaceDto;
import com.czertainly.api.model.core.search.FilterFieldSource;
import com.czertainly.api.model.core.search.SearchFieldDataByGroupDto;
import com.czertainly.api.model.core.search.SearchFieldDataDto;
import com.czertainly.api.model.core.vault.*;
import com.czertainly.core.attribute.engine.AttributeEngine;
import com.czertainly.core.attribute.engine.ConnectorRequestAttributesBuilder;
import com.czertainly.core.attribute.engine.records.ObjectAttributeContentInfo;
import com.czertainly.core.comparator.SearchFieldDataComparator;
import com.czertainly.core.dao.entity.Audited_;
import com.czertainly.core.dao.entity.VaultInstance;
import com.czertainly.core.dao.entity.VaultInstance_;
import com.czertainly.core.dao.repository.VaultInstanceRepository;
import com.czertainly.core.dao.repository.VaultProfileRepository;
import com.czertainly.core.enums.FilterField;
import com.czertainly.core.model.auth.ResourceAction;
import com.czertainly.core.security.authz.ExternalAuthorization;
import com.czertainly.core.security.authz.SecuredUUID;
import com.czertainly.core.security.authz.SecurityFilter;
import com.czertainly.core.service.VaultInstanceService;
import com.czertainly.core.service.v2.ConnectorService;
import com.czertainly.core.util.FilterPredicatesBuilder;
import com.czertainly.core.util.SearchHelper;
import jakarta.persistence.criteria.CriteriaBuilder;
import jakarta.persistence.criteria.CriteriaQuery;
import jakarta.persistence.criteria.Predicate;
import jakarta.persistence.criteria.Root;
import org.apache.commons.lang3.function.TriFunction;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.data.domain.PageRequest;
import org.springframework.data.domain.Pageable;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.ArrayList;
import java.util.List;
import java.util.UUID;

@Service
@Transactional
public class VaultInstanceServiceImpl implements VaultInstanceService {


    private VaultProfileRepository vaultProfileRepository;
    private final VaultInstanceRepository vaultInstanceRepository;

    private ConnectorApiFactory connectorApiFactory;

    private ConnectorService connectorService;

    private AttributeEngine attributeEngine;
    private ConnectorRequestAttributesBuilder connectorRequestAttributesBuilder;

    @Autowired
    public void setConnectorRequestAttributesBuilder(ConnectorRequestAttributesBuilder connectorRequestAttributesBuilder) {
        this.connectorRequestAttributesBuilder = connectorRequestAttributesBuilder;
    }

    @Autowired
    public void setConnectorApiFactory(ConnectorApiFactory connectorApiFactory) {
        this.connectorApiFactory = connectorApiFactory;
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
    public void setConnectorService(ConnectorService connectorService) {
        this.connectorService = connectorService;
    }

    @Autowired
    public VaultInstanceServiceImpl(VaultInstanceRepository vaultInstanceRepository) {
        this.vaultInstanceRepository = vaultInstanceRepository;
    }

    @Override
    @ExternalAuthorization(resource = Resource.VAULT, action = ResourceAction.CREATE)
    public VaultInstanceDetailDto createVaultInstance(VaultInstanceRequestDto request) throws ConnectorException, NotFoundException, AttributeException, AlreadyExistException {

        if (vaultInstanceRepository.existsByName(request.getName())) {
            throw new AlreadyExistException("Vault Instance with the same name already exists");
        }

        ConnectorDetailDto connector = connectorService.getConnector(SecuredUUID.fromUUID(request.getConnectorUuid()));
        if (connector.getInterfaces().stream().map(ConnectorInterfaceDto::getUuid).noneMatch(request.getInterfaceUuid()::equals)) {
            throw new ValidationException("Connector does not have interface with UUID " + request.getInterfaceUuid());
        }
        checkConnectionToVaultInConnector(request.getConnectorUuid(), request.getAttributes(), connector);

        attributeEngine.validateCustomAttributesContent(Resource.VAULT, request.getCustomAttributes());

        VaultInstance vaultInstance = new VaultInstance();
        vaultInstance.setName(request.getName());
        vaultInstance.setConnectorUuid(request.getConnectorUuid());
        vaultInstance.setDescription(request.getDescription());
        vaultInstance.setConnectorInterfaceUuid(request.getInterfaceUuid());
        vaultInstanceRepository.save(vaultInstance);

        VaultInstanceDetailDto detailDto = vaultInstance.mapToDetailDto();
        detailDto.getConnector().setName(connector.getName());
        detailDto.setCustomAttributes(attributeEngine.updateObjectCustomAttributesContent(Resource.VAULT, vaultInstance.getUuid(), request.getCustomAttributes()));
        detailDto.setAttributes(attributeEngine.updateObjectDataAttributesContent(ObjectAttributeContentInfo.builder(Resource.VAULT, vaultInstance.getUuid()).connector(vaultInstance.getConnectorUuid()).build(), request.getAttributes()));

        return detailDto;
    }

    private void checkConnectionToVaultInConnector(UUID connectorUuid, List<RequestAttribute> requestAttributes, ConnectorDetailDto connector) throws ConnectorException, NotFoundException, AttributeException {
        List<BaseAttribute> attributes = listVaultInstanceAttributes(connectorUuid);
        List<RequestAttribute> connectorRequestAttributes = connectorRequestAttributesBuilder.prepareRequestAttributesForConnectorRequest(connectorUuid, attributes, requestAttributes);
        connectorApiFactory.getVaultApiClient(connector).checkVaultConnection(connector, connectorRequestAttributes);
    }

    @Override
    @ExternalAuthorization(resource = Resource.VAULT, action = ResourceAction.DETAIL)
    public VaultInstanceDetailDto getVaultInstance(UUID uuid) throws NotFoundException {
        VaultInstance vaultInstance = vaultInstanceRepository.findByUuid(SecuredUUID.fromUUID(uuid))
                .orElseThrow(() -> new NotFoundException(Resource.VAULT.getLabel(), uuid.toString()));
        VaultInstanceDetailDto detailDto = vaultInstance.mapToDetailDto();
        detailDto.setCustomAttributes(attributeEngine.getObjectCustomAttributesContent(Resource.VAULT, uuid));
        detailDto.setAttributes(attributeEngine.getObjectDataAttributesContent(ObjectAttributeContentInfo.builder(Resource.VAULT, vaultInstance.getUuid()).connector(vaultInstance.getConnectorUuid()).build()));
        return detailDto;
    }

    @Override
    @ExternalAuthorization(resource = Resource.VAULT, action = ResourceAction.LIST)
    public PaginationResponseDto<VaultInstanceDto> listVaultInstances(SearchRequestDto request, SecurityFilter securityFilter) {
        Pageable p = PageRequest.of(request.getPageNumber() - 1, request.getItemsPerPage());
        TriFunction<Root<VaultInstance>, CriteriaBuilder, CriteriaQuery<?>, Predicate> predicate = (root, cb, cq) -> FilterPredicatesBuilder.getFiltersPredicate(cb, cq, root, request.getFilters());
        List<VaultInstanceDto> vaultInstances = vaultInstanceRepository.findUsingSecurityFilter(securityFilter, List.of(VaultInstance_.CONNECTOR, VaultInstance_.CONNECTOR_INTERFACE), predicate, p, (root, cb) -> cb.desc(root.get(Audited_.CREATED)))
                .stream().map(VaultInstance::mapToDto).toList();
        PaginationResponseDto<VaultInstanceDto> response = new PaginationResponseDto<>();
        response.setItems(vaultInstances);
        response.setPageNumber(request.getPageNumber());
        response.setItemsPerPage(request.getItemsPerPage());
        Long totalItems = vaultInstanceRepository.countUsingSecurityFilter(securityFilter, predicate);
        response.setTotalPages((int) Math.ceil((double) totalItems / request.getItemsPerPage()));
        response.setTotalItems(totalItems);
        return response;
    }

    @Override
    @ExternalAuthorization(resource = Resource.VAULT, action = ResourceAction.DELETE)
    public void deleteVaultInstance(UUID uuid) throws NotFoundException {
        VaultInstance vaultInstance = vaultInstanceRepository.findByUuid(SecuredUUID.fromUUID(uuid))
                .orElseThrow(() -> new NotFoundException(Resource.VAULT.getLabel(), uuid.toString()));
        List<String> allByVaultInstanceUuid = vaultProfileRepository.findAllNamesByVaultInstanceUuid(vaultInstance.getUuid());
        if (!allByVaultInstanceUuid.isEmpty()) {
            throw new ValidationException("Vault Instance %s is used in Vault Profiles %s".formatted(uuid, allByVaultInstanceUuid));
        }
        vaultInstanceRepository.delete(vaultInstance);
    }

    @Override
    @ExternalAuthorization(resource = Resource.VAULT, action = ResourceAction.UPDATE)
    public VaultInstanceDetailDto updateVaultInstance(UUID uuid, VaultInstanceUpdateRequestDto request) throws NotFoundException, AttributeException, ConnectorException {
        VaultInstance vaultInstance = vaultInstanceRepository.findByUuid(SecuredUUID.fromUUID(uuid))
                .orElseThrow(() -> new NotFoundException(Resource.VAULT.getLabel(), uuid.toString()));
        vaultInstance.setDescription(request.getDescription());
        vaultInstanceRepository.save(vaultInstance);

        VaultInstanceDetailDto detailDto = vaultInstance.mapToDetailDto();
        attributeEngine.validateCustomAttributesContent(Resource.VAULT, request.getCustomAttributes());

        ConnectorDetailDto connector = connectorService.getConnector(SecuredUUID.fromUUID(vaultInstance.getConnectorUuid()));
        checkConnectionToVaultInConnector(vaultInstance.getConnectorUuid(), request.getAttributes(), connector);

        detailDto.setAttributes(attributeEngine.updateObjectDataAttributesContent(ObjectAttributeContentInfo.builder(Resource.VAULT, vaultInstance.getUuid()).connector(vaultInstance.getConnectorUuid()).build(), request.getAttributes()));
        detailDto.setCustomAttributes(attributeEngine.updateObjectCustomAttributesContent(Resource.VAULT, vaultInstance.getUuid(), request.getCustomAttributes()));

        return detailDto;
    }

    @Override
    public List<SearchFieldDataByGroupDto> getSearchableFieldInformation() {
        List<SearchFieldDataByGroupDto> searchFieldDataByGroupDtos = attributeEngine.getResourceSearchableFields(Resource.VAULT, false);

        List<SearchFieldDataDto> fields = List.of(
                SearchHelper.prepareSearch(FilterField.VAULT_INSTANCE_NAME),
                SearchHelper.prepareSearch(FilterField.VAULT_INSTANCE_CONNECTOR_NAME, vaultInstanceRepository.findAllConnectorNames())
        );
        fields = new ArrayList<>(fields);
        fields.sort(new SearchFieldDataComparator());

        searchFieldDataByGroupDtos.add(new SearchFieldDataByGroupDto(fields, FilterFieldSource.PROPERTY));

        return searchFieldDataByGroupDtos;
    }

    @Override
    @ExternalAuthorization(resource = Resource.VAULT, action = ResourceAction.ANY)
    public List<BaseAttribute> listVaultInstanceAttributes(UUID connectorUuid) throws ConnectorException, NotFoundException, AttributeException {
        ConnectorDetailDto connector = connectorService.getConnector(SecuredUUID.fromUUID(connectorUuid));
        List<BaseAttribute> attributes = connectorApiFactory.getVaultApiClient(connector).listVaultAttributes(connector);
        // Save connector attributes definitions in attribute engine, so they can be used for validation and content preparation in other operations
        // TODO: This is a temporary solution, solution for this should be implemented in general
        attributeEngine.updateDataAttributeDefinitions(connectorUuid, null, attributes);
        return attributes;
    }

    @Override
    @ExternalAuthorization(resource = Resource.VAULT, action = ResourceAction.ANY)
    public List<BaseAttribute> listVaultProfileAttributes(SecuredUUID vaultInstanceUuid) throws ConnectorException, NotFoundException, AttributeException {
        VaultInstance vaultInstance = vaultInstanceRepository.findByUuid(vaultInstanceUuid)
                .orElseThrow(() -> new NotFoundException(Resource.VAULT.getLabel(), vaultInstanceUuid.toString()));
        if (vaultInstance.getConnectorUuid() == null) {
            throw new ValidationException("Cannot list vault profile attributes for vault without associated connector");
        }

        ApiClientConnectorInfo connectorInfo = vaultInstance.getConnector().mapToApiClientDtoV2();
        List<BaseAttribute> vaultAttributes = connectorApiFactory.getVaultApiClient(connectorInfo).listVaultAttributes(connectorInfo);
        List<RequestAttribute> requestVaultAttributes = connectorRequestAttributesBuilder.prepareRequestAttributesForConnectorRequest(vaultInstance.getConnectorUuid(), vaultAttributes, attributeEngine.getRequestObjectDataAttributesContent(ObjectAttributeContentInfo.builder(Resource.VAULT, vaultInstance.getUuid()).connector(vaultInstance.getConnectorUuid()).build()));

        List<BaseAttribute> attributes = connectorApiFactory.getVaultApiClient(connectorInfo).listVaultProfileAttributes(connectorInfo, requestVaultAttributes);
        // TODO: This is a temporary solution, solution for this should be implemented in general
        // Save connector attributes definitions in attribute engine, so they can be used for validation and content preparation in other operations
        attributeEngine.updateDataAttributeDefinitions(vaultInstance.getConnectorUuid(), null, attributes);
        return attributes;
    }

    @Override
    public void loadAttributesForSecretOperation(ApiClientConnectorInfo connector, UUID vaultInstanceUuid, UUID vaultProfileUuid, SecretOperationRequest secretOperationRequest) throws NotFoundException, ConnectorException, AttributeException {
        UUID connectorUuid = UUID.fromString(connector.getUuid());

        // get and load vault attributes
        List<BaseAttribute> vaultAttributes = connectorApiFactory.getVaultApiClient(connector).listVaultAttributes(connector);
        attributeEngine.updateAttributeDefinitionsWithCallback(connectorUuid, vaultAttributes);
        List<RequestAttribute> requestVaultAttributes = connectorRequestAttributesBuilder.prepareRequestAttributesForConnectorRequest(connectorUuid, vaultAttributes, attributeEngine.getRequestObjectDataAttributesContent(ObjectAttributeContentInfo.builder(Resource.VAULT, vaultInstanceUuid).connector(connectorUuid).build()));

        // get and load vault profile attributes
        List<BaseAttribute> vaultProfileAttributes = connectorApiFactory.getVaultApiClient(connector).listVaultProfileAttributes(connector, requestVaultAttributes);
        attributeEngine.updateAttributeDefinitionsWithCallback(connectorUuid, vaultProfileAttributes);
        List<RequestAttribute> requestVaultProfileAttributes = connectorRequestAttributesBuilder.prepareRequestAttributesForConnectorRequest(connectorUuid, vaultProfileAttributes, attributeEngine.getRequestObjectDataAttributesContent(ObjectAttributeContentInfo.builder(Resource.VAULT_PROFILE, vaultProfileUuid).connector(connectorUuid).build()));

        secretOperationRequest.setVaultAttributes(requestVaultAttributes);
        secretOperationRequest.setVaultProfileAttributes(requestVaultProfileAttributes);
    }

    @Override
    @ExternalAuthorization(resource = Resource.VAULT, action = ResourceAction.LIST)
    public Long statisticsVaultInstanceCount(SecurityFilter filter) {
        return vaultInstanceRepository.countUsingSecurityFilter(filter, null);
    }

}
