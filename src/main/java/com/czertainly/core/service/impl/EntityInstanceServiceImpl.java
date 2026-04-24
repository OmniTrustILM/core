package com.czertainly.core.service.impl;

import com.czertainly.core.client.ConnectorApiFactory;
import com.czertainly.api.exception.*;
import com.czertainly.api.model.client.attribute.RequestAttribute;
import com.czertainly.api.model.client.attribute.ResponseAttribute;
import com.czertainly.api.model.client.certificate.EntityInstanceResponseDto;
import com.czertainly.api.model.client.certificate.SearchFilterRequestDto;
import com.czertainly.api.model.client.certificate.SearchRequestDto;
import com.czertainly.api.model.client.entity.EntityInstanceUpdateRequestDto;
import com.czertainly.api.model.common.NameAndUuidDto;
import com.czertainly.api.model.common.attribute.common.BaseAttribute;
import com.czertainly.api.model.connector.entity.EntityInstanceRequestDto;
import com.czertainly.api.model.core.auth.Resource;
import com.czertainly.api.model.core.connector.ConnectorApiClientDto;
import com.czertainly.api.model.core.connector.ConnectorDto;
import com.czertainly.api.model.core.connector.FunctionGroupCode;
import com.czertainly.api.model.core.entity.EntityInstanceDto;
import com.czertainly.api.model.core.scheduler.PaginationRequestDto;
import com.czertainly.api.model.core.search.FilterFieldSource;
import com.czertainly.api.model.core.search.SearchFieldDataByGroupDto;
import com.czertainly.api.model.core.search.SearchFieldDataDto;
import com.czertainly.core.attribute.engine.AttributeEngine;
import com.czertainly.core.attribute.engine.records.ObjectAttributeContentInfo;
import com.czertainly.core.comparator.SearchFieldDataComparator;
import com.czertainly.core.dao.entity.Connector;
import com.czertainly.core.dao.entity.EntityInstanceReference;
import com.czertainly.core.dao.entity.EntityInstanceReference_;
import com.czertainly.core.dao.repository.EntityInstanceReferenceRepository;
import com.czertainly.core.enums.FilterField;
import com.czertainly.core.model.auth.ResourceAction;
import com.czertainly.core.security.authz.ExternalAuthorization;
import com.czertainly.core.security.authz.SecuredUUID;
import com.czertainly.core.security.authz.SecurityFilter;
import com.czertainly.core.service.ConnectorService;
import com.czertainly.core.service.CredentialService;
import com.czertainly.core.service.EntityInstanceService;
import com.czertainly.core.service.ResourceService;
import com.czertainly.core.util.AttributeDefinitionUtils;
import com.czertainly.core.util.FilterPredicatesBuilder;
import com.czertainly.core.util.RequestValidatorHelper;
import com.czertainly.core.util.SearchHelper;
import jakarta.persistence.criteria.CriteriaBuilder;
import jakarta.persistence.criteria.CriteriaQuery;
import jakarta.persistence.criteria.Predicate;
import jakarta.persistence.criteria.Root;
import org.apache.commons.lang3.function.TriFunction;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.data.domain.PageRequest;
import org.springframework.data.domain.Pageable;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.ArrayList;
import java.util.List;
import java.util.UUID;

@Service(Resource.Codes.ENTITY)
@Transactional
public class EntityInstanceServiceImpl implements EntityInstanceService {

    private static final Logger logger = LoggerFactory.getLogger(EntityInstanceServiceImpl.class);
    private EntityInstanceReferenceRepository entityInstanceReferenceRepository;
    private ConnectorService connectorService;
    private CredentialService credentialService;
    private ConnectorApiFactory connectorApiFactory;
    private AttributeEngine attributeEngine;
    private ResourceService resourceService;

    @Autowired
    public void setResourceService(ResourceService resourceService) {
        this.resourceService = resourceService;
    }

    @Autowired
    public void setAttributeEngine(AttributeEngine attributeEngine) {
        this.attributeEngine = attributeEngine;
    }

    @Autowired
    public void setEntityInstanceReferenceRepository(EntityInstanceReferenceRepository entityInstanceReferenceRepository) {
        this.entityInstanceReferenceRepository = entityInstanceReferenceRepository;
    }

    @Autowired
    public void setConnectorService(ConnectorService connectorService) {
        this.connectorService = connectorService;
    }

    @Autowired
    public void setCredentialService(CredentialService credentialService) {
        this.credentialService = credentialService;
    }

    @Autowired
    public void setConnectorApiFactory(ConnectorApiFactory connectorApiFactory) {
        this.connectorApiFactory = connectorApiFactory;
    }

    @Override
    @ExternalAuthorization(resource = Resource.ENTITY, action = ResourceAction.LIST)
    public EntityInstanceResponseDto listEntityInstances(final SecurityFilter filter, final SearchRequestDto request) {
        RequestValidatorHelper.revalidateSearchRequestDto(request);
        final Pageable p = PageRequest.of(request.getPageNumber() - 1, request.getItemsPerPage());

        final TriFunction<Root<EntityInstanceReference>, CriteriaBuilder, CriteriaQuery<?>, Predicate> additionalWhereClause = (root, cb, cr) -> FilterPredicatesBuilder.getFiltersPredicate(cb, cr, root, request.getFilters());
        final List<EntityInstanceDto> listedKeyDTOs = entityInstanceReferenceRepository.findUsingSecurityFilter(filter, List.of(), additionalWhereClause, p, (root, cb) -> cb.desc(root.get("created")))
                .stream()
                .map(EntityInstanceReference::mapToDto).toList();
        final Long maxItems = entityInstanceReferenceRepository.countUsingSecurityFilter(filter, additionalWhereClause);

        final EntityInstanceResponseDto responseDto = new EntityInstanceResponseDto();
        responseDto.setEntities(listedKeyDTOs);
        responseDto.setItemsPerPage(request.getItemsPerPage());
        responseDto.setPageNumber(request.getPageNumber());
        responseDto.setTotalItems(maxItems);
        responseDto.setTotalPages((int) Math.ceil((double) maxItems / request.getItemsPerPage()));
        return responseDto;
    }

    @Override
    @ExternalAuthorization(resource = Resource.ENTITY, action = ResourceAction.DETAIL)
    public EntityInstanceDto getEntityInstance(SecuredUUID entityUuid) throws ConnectorException, NotFoundException {
        EntityInstanceReference entityInstanceReference = getEntityInstanceReferenceEntity(entityUuid);

        List<ResponseAttribute> attributes = attributeEngine.getObjectDataAttributesContent(ObjectAttributeContentInfo.builder(Resource.ENTITY, entityInstanceReference.getUuid()).connector(entityInstanceReference.getConnectorUuid()).build());

        EntityInstanceDto entityInstanceDto = entityInstanceReference.mapToDto();
        entityInstanceDto.setCustomAttributes(attributeEngine.getObjectCustomAttributesContent(Resource.ENTITY, entityUuid.getValue()));
        if (entityInstanceReference.getConnector() == null) {
            entityInstanceDto.setConnectorName(entityInstanceReference.getConnectorName() + " (Deleted)");
            entityInstanceDto.setConnectorUuid("");
            entityInstanceDto.setAttributes(attributes);
            logger.warn("Connector associated with the Entity: {} is not found. Unable to show details", entityInstanceReference.getName());
            return entityInstanceDto;
        }

        ConnectorApiClientDto connectorDto = entityInstanceReference.getConnector().mapToApiClientDtoV1();
        com.czertainly.api.model.connector.entity.EntityInstanceDto entityProviderInstanceDto = connectorApiFactory.getEntityInstanceApiClient(connectorDto).getEntityInstance(connectorDto,
                entityInstanceReference.getEntityInstanceUuid());

        if (attributes.isEmpty() && entityProviderInstanceDto.getAttributes() != null && !entityProviderInstanceDto.getAttributes().isEmpty()) {
            try {
                List<RequestAttribute> requestAttributes = AttributeDefinitionUtils.getClientAttributes(entityProviderInstanceDto.getAttributes());
                attributeEngine.updateDataAttributeDefinitions(entityInstanceReference.getConnectorUuid(), null, entityProviderInstanceDto.getAttributes());
                attributes = attributeEngine.updateObjectDataAttributesContent(ObjectAttributeContentInfo.builder(Resource.ENTITY, entityInstanceReference.getUuid()).connector(entityInstanceReference.getConnectorUuid()).build(), requestAttributes);
            } catch (AttributeException e) {
                logger.warn("Could not update data attributes for entity {} retrieved from connector", entityInstanceReference.getName());
            }
        }

        entityInstanceDto.setAttributes(attributes);
        return entityInstanceDto;
    }

    @Override
    @ExternalAuthorization(resource = Resource.ENTITY, action = ResourceAction.CREATE)
    public EntityInstanceDto createEntityInstance(com.czertainly.api.model.client.entity.EntityInstanceRequestDto request) throws AlreadyExistException, ConnectorException, AttributeException, NotFoundException {
        if (entityInstanceReferenceRepository.findByName(request.getName()).isPresent()) {
            throw new AlreadyExistException(EntityInstanceReference.class, request.getName());
        }

        if (request.getConnectorUuid() == null) {
            throw new ValidationException(ValidationError.create("Connector UUID is empty"));
        }

        UUID connectorUuid = UUID.fromString(request.getConnectorUuid());
        ConnectorDto connector = connectorService.getConnector(SecuredUUID.fromUUID(connectorUuid));


        FunctionGroupCode codeToSearch = FunctionGroupCode.ENTITY_PROVIDER;
        attributeEngine.validateCustomAttributesContent(Resource.ENTITY, request.getCustomAttributes());
        connectorService.mergeAndValidateAttributes(SecuredUUID.fromUUID(connectorUuid), codeToSearch, request.getAttributes(), request.getKind());

        // Load complete credential and resource data
        var dataAttributes = attributeEngine.getDataAttributesByContent(connectorUuid, request.getAttributes());
        credentialService.loadFullCredentialData(dataAttributes);
        resourceService.loadResourceObjectContentData(dataAttributes);

        EntityInstanceRequestDto entityInstanceDto = new EntityInstanceRequestDto();
        entityInstanceDto.setAttributes(AttributeDefinitionUtils.getClientAttributes(dataAttributes));
        entityInstanceDto.setKind(request.getKind());
        entityInstanceDto.setName(request.getName());

        com.czertainly.api.model.connector.entity.EntityInstanceDto response = connectorApiFactory.getEntityInstanceApiClient(connector).createEntityInstance(connector, entityInstanceDto);

        EntityInstanceReference entityInstanceRef = new EntityInstanceReference();
        entityInstanceRef.setEntityInstanceUuid((response.getUuid()));
        entityInstanceRef.setName(request.getName());
        //entityInstanceRef.setStatus("connected"); // TODO: status of the Entity
        entityInstanceRef.setConnectorUuid(connectorUuid);
        entityInstanceRef.setKind(request.getKind());
        entityInstanceRef.setConnectorName(connector.getName());
        entityInstanceReferenceRepository.save(entityInstanceRef);

        logger.info("Entity {} created with Kind {}", entityInstanceRef.getUuid(), entityInstanceRef.getKind());

        EntityInstanceDto dto = entityInstanceRef.mapToDto();
        dto.setCustomAttributes(attributeEngine.updateObjectCustomAttributesContent(Resource.ENTITY, entityInstanceRef.getUuid(), request.getCustomAttributes()));
        dto.setAttributes(attributeEngine.updateObjectDataAttributesContent(ObjectAttributeContentInfo.builder(Resource.ENTITY, entityInstanceRef.getUuid()).connector(entityInstanceRef.getConnectorUuid()).build(), request.getAttributes()));
        return dto;
    }

    @Override
    @ExternalAuthorization(resource = Resource.ENTITY, action = ResourceAction.UPDATE)
    public EntityInstanceDto editEntityInstance(SecuredUUID entityUuid, EntityInstanceUpdateRequestDto request) throws ConnectorException, AttributeException, NotFoundException {
        EntityInstanceReference entityInstanceRef = getEntityInstanceReferenceEntity(entityUuid);

        EntityInstanceDto ref = getEntityInstance(entityUuid);
        Connector connector = entityInstanceRef.getConnector();

        FunctionGroupCode codeToSearch = FunctionGroupCode.ENTITY_PROVIDER;
        attributeEngine.validateCustomAttributesContent(Resource.ENTITY, request.getCustomAttributes());
        connectorService.mergeAndValidateAttributes(connector.getSecuredUuid(), codeToSearch, request.getAttributes(), ref.getKind());

        // Load complete credential data
        var dataAttributes = attributeEngine.getDataAttributesByContent(connector.getUuid(), request.getAttributes());
        credentialService.loadFullCredentialData(dataAttributes);
        resourceService.loadResourceObjectContentData(dataAttributes);

        EntityInstanceRequestDto entityInstanceDto = new EntityInstanceRequestDto();
        entityInstanceDto.setAttributes(AttributeDefinitionUtils.getClientAttributes(dataAttributes));
        entityInstanceDto.setKind(entityInstanceRef.getKind());
        entityInstanceDto.setName(entityInstanceRef.getName());
        ConnectorApiClientDto connectorDto = connector.mapToApiClientDtoV1();
        connectorApiFactory.getEntityInstanceApiClient(connectorDto).updateEntityInstance(connectorDto, entityInstanceRef.getEntityInstanceUuid(), entityInstanceDto);
        entityInstanceReferenceRepository.save(entityInstanceRef);

        EntityInstanceDto dto = entityInstanceRef.mapToDto();
        dto.setCustomAttributes(attributeEngine.updateObjectCustomAttributesContent(Resource.ENTITY, entityInstanceRef.getUuid(), request.getCustomAttributes()));
        dto.setAttributes(attributeEngine.updateObjectDataAttributesContent(ObjectAttributeContentInfo.builder(Resource.ENTITY, entityInstanceRef.getUuid()).connector(entityInstanceRef.getConnectorUuid()).build(), request.getAttributes()));
        return dto;
    }

    @Override
    @ExternalAuthorization(resource = Resource.ENTITY, action = ResourceAction.DELETE)
    public void deleteEntityInstance(SecuredUUID entityUuid) throws ConnectorException, NotFoundException {
        EntityInstanceReference entityInstanceRef = getEntityInstanceReferenceEntity(entityUuid);

        List<ValidationError> errors = new ArrayList<>();
        if (!entityInstanceRef.getLocations().isEmpty()) {
            errors.add(ValidationError.create("Entity instance {} has {} dependent Locations", entityInstanceRef.getName(),
                    entityInstanceRef.getLocations().size()));
            entityInstanceRef.getLocations().forEach(c -> errors.add(ValidationError.create(c.getName())));
        }

        if (!errors.isEmpty()) {
            throw new ValidationException("Could not delete Entity instance", errors);
        }

        ConnectorApiClientDto connectorDto = entityInstanceRef.getConnector().mapToApiClientDtoV1();
        connectorApiFactory.getEntityInstanceApiClient(connectorDto).removeEntityInstance(connectorDto, entityInstanceRef.getEntityInstanceUuid());
        attributeEngine.deleteObjectAttributeContent(Resource.ENTITY, entityInstanceRef.getUuid());
        entityInstanceReferenceRepository.delete(entityInstanceRef);

        logger.info("Entity instance {} was deleted", entityInstanceRef.getName());
    }

    @Override
    @ExternalAuthorization(resource = Resource.ENTITY, action = ResourceAction.ANY)
    public List<BaseAttribute> listLocationAttributes(SecuredUUID entityUuid) throws ConnectorException, NotFoundException {
        final EntityInstanceReference entityInstance = getEntityInstanceReferenceEntity(entityUuid);
        final ConnectorApiClientDto connectorDto = entityInstance.getConnector().mapToApiClientDtoV1();
        return connectorApiFactory.getEntityInstanceApiClient(connectorDto).listLocationAttributes(connectorDto, entityInstance.getEntityInstanceUuid());
    }

    @Override
    @ExternalAuthorization(resource = Resource.ENTITY, action = ResourceAction.ANY)
    public void validateLocationAttributes(SecuredUUID entityUuid, List<RequestAttribute> attributes) throws ConnectorException, NotFoundException {
        EntityInstanceReference entityInstance = getEntityInstanceReferenceEntity(entityUuid);

        ConnectorApiClientDto connectorDto = entityInstance.getConnector().mapToApiClientDtoV1();

        connectorApiFactory.getEntityInstanceApiClient(connectorDto).validateLocationAttributes(connectorDto, entityInstance.getEntityInstanceUuid(),
                attributes);
    }

    @Override
    public NameAndUuidDto getResourceObjectInternal(UUID objectUuid) throws NotFoundException {
        return entityInstanceReferenceRepository.findResourceObject(objectUuid, EntityInstanceReference_.name);
    }

    @Override
    @ExternalAuthorization(resource = Resource.ENTITY, action = ResourceAction.DETAIL)
    public NameAndUuidDto getResourceObjectExternal(SecuredUUID objectUuid) throws NotFoundException {
        return entityInstanceReferenceRepository.findResourceObject(objectUuid.getValue(), EntityInstanceReference_.name);
    }

    @Override
    @ExternalAuthorization(resource = Resource.ENTITY, action = ResourceAction.LIST)
    public List<NameAndUuidDto> listResourceObjects(SecurityFilter filter, List<SearchFilterRequestDto> filters, PaginationRequestDto pagination) {
        final TriFunction<Root<EntityInstanceReference>, CriteriaBuilder, CriteriaQuery<?>, Predicate> additionalWhereClause = (root, cb, cr) -> FilterPredicatesBuilder.getFiltersPredicate(cb, cr, root, filters);
        return entityInstanceReferenceRepository.listResourceObjects(filter, EntityInstanceReference_.name, additionalWhereClause, pagination);
    }

    @Override
    @ExternalAuthorization(resource = Resource.ENTITY, action = ResourceAction.UPDATE)
    public void evaluatePermissionChain(SecuredUUID uuid) throws NotFoundException {
        getEntityInstanceReferenceEntity(uuid);
        // Since there are is no parent to the Entity, exclusive parent permission evaluation need not be done
    }

    private EntityInstanceReference getEntityInstanceReferenceEntity(SecuredUUID uuid) throws NotFoundException {
        return entityInstanceReferenceRepository.findByUuid(uuid)
                .orElseThrow(() -> new NotFoundException(EntityInstanceReference.class, uuid));
    }

    @Override
    public List<SearchFieldDataByGroupDto> getSearchableFieldInformationByGroup() {
        final List<SearchFieldDataByGroupDto> searchFieldDataByGroupDtos = attributeEngine.getResourceSearchableFields(Resource.ENTITY, false);

        List<SearchFieldDataDto> fields = List.of(
                SearchHelper.prepareSearch(FilterField.ENTITY_NAME),
                SearchHelper.prepareSearch(FilterField.ENTITY_CONNECTOR_NAME, entityInstanceReferenceRepository.findDistinctConnectorName()),
                SearchHelper.prepareSearch(FilterField.ENTITY_KIND, entityInstanceReferenceRepository.findDistinctKind())
        );

        fields = new ArrayList<>(fields);
        fields.sort(new SearchFieldDataComparator());

        searchFieldDataByGroupDtos.add(new SearchFieldDataByGroupDto(fields, FilterFieldSource.PROPERTY));

        logger.debug("Searchable Fields by Groups: {}", searchFieldDataByGroupDtos);
        return searchFieldDataByGroupDtos;
    }
}
