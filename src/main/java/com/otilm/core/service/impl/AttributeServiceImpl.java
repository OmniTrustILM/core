package com.otilm.core.service.impl;

import com.otilm.api.exception.AlreadyExistException;
import com.otilm.api.exception.AttributeException;
import com.otilm.api.exception.NotFoundException;
import com.otilm.api.model.client.attribute.AttributeDefinitionDto;
import com.otilm.api.model.client.attribute.custom.CustomAttributeCreateRequestDto;
import com.otilm.api.model.client.attribute.custom.CustomAttributeDefinitionDetailDto;
import com.otilm.api.model.client.attribute.custom.CustomAttributeDefinitionDto;
import com.otilm.api.model.client.attribute.custom.CustomAttributeUpdateRequestDto;
import com.otilm.api.model.client.attribute.metadata.ConnectorMetadataResponseDto;
import com.otilm.api.model.client.attribute.metadata.GlobalMetadataCreateRequestDto;
import com.otilm.api.model.client.attribute.metadata.GlobalMetadataDefinitionDetailDto;
import com.otilm.api.model.client.attribute.metadata.GlobalMetadataUpdateRequestDto;
import com.otilm.api.model.client.certificate.SearchFilterRequestDto;
import com.otilm.api.model.common.NameAndUuidDto;
import com.otilm.api.model.common.attribute.common.AttributeType;
import com.otilm.api.model.common.attribute.common.CustomAttribute;
import com.otilm.api.model.common.attribute.v2.MetadataAttributeV2;
import com.otilm.api.model.common.attribute.common.content.AttributeContentType;
import com.otilm.api.model.common.attribute.common.properties.CustomAttributeProperties;
import com.otilm.api.model.common.attribute.common.properties.MetadataAttributeProperties;
import com.otilm.api.model.common.attribute.v3.CustomAttributeV3;
import com.otilm.api.model.common.attribute.v3.content.BaseAttributeContentV3;
import com.otilm.api.model.core.auth.Resource;
import com.otilm.api.model.core.scheduler.PaginationRequestDto;
import com.otilm.core.attribute.engine.AttributeEngine;
import com.otilm.core.attribute.engine.AttributeVersionHelper;
import com.otilm.core.dao.entity.AttributeDefinition;
import com.otilm.core.dao.repository.AttributeDefinitionRepository;
import com.otilm.core.model.auth.ResourceAction;
import com.otilm.core.security.authz.ExternalAuthorization;
import com.otilm.core.security.authz.ExternalAuthorizationMissing;
import com.otilm.core.security.authz.SecuredUUID;
import com.otilm.core.security.authz.SecurityFilter;
import com.otilm.core.service.AttributeExternalService;
import com.otilm.core.service.AttributeInternalService;
import jakarta.transaction.Transactional;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.util.ArrayList;
import java.util.List;
import java.util.Optional;
import java.util.UUID;
import java.util.stream.Collectors;

@Service(Resource.Codes.ATTRIBUTE)
@Transactional
public class AttributeServiceImpl implements AttributeExternalService, AttributeInternalService {
    private static final Logger logger = LoggerFactory.getLogger(AttributeServiceImpl.class);

    private AttributeEngine attributeEngine;
    private AttributeDefinitionRepository attributeDefinitionRepository;

    @Autowired
    public void setAttributeEngine(AttributeEngine attributeEngine) {
        this.attributeEngine = attributeEngine;
    }

    @Autowired
    public void setAttributeDefinitionRepository(AttributeDefinitionRepository attributeDefinitionRepository) {
        this.attributeDefinitionRepository = attributeDefinitionRepository;
    }

    @Override
    @ExternalAuthorization(resource = Resource.ATTRIBUTE, action = ResourceAction.LIST)
    public List<CustomAttributeDefinitionDto> listCustomAttributes(SecurityFilter filter, AttributeContentType attributeContentType) {
        logger.debug("Fetching custom attributes");

        List<AttributeDefinition> customAttributes = attributeContentType == null
                ? attributeDefinitionRepository.findUsingSecurityFilter(filter, List.of("relations"), (root, cb, cr) -> cb.equal(root.get("type"), AttributeType.CUSTOM))
                : attributeDefinitionRepository.findUsingSecurityFilter(filter, List.of("relations"), (root, cb, cr) -> cb.and(cb.equal(root.get("type"), AttributeType.CUSTOM), cb.equal(root.get("contentType"), attributeContentType)));

        return customAttributes.stream().map(AttributeDefinition::mapToCustomAttributeDefinitionDto).toList();
    }

    @Override
    @ExternalAuthorization(resource = Resource.ATTRIBUTE, action = ResourceAction.LIST)
    public List<AttributeDefinitionDto> listGlobalMetadata() {
        logger.debug("Fetching global metadata");

        List<AttributeDefinition> metadataAttributes = attributeDefinitionRepository.findByTypeAndGlobal(AttributeType.META, true);
        return metadataAttributes.stream().map(AttributeDefinition::mapToGlobalMetadataDefinitionDto).toList();
    }

    @Override
    @ExternalAuthorization(resource = Resource.ATTRIBUTE, action = ResourceAction.DETAIL)
    public CustomAttributeDefinitionDetailDto getCustomAttribute(UUID uuid) throws NotFoundException {
        logger.debug("Fetching custom attribute with UUID: {}", uuid);
        AttributeDefinition definition = attributeDefinitionRepository.findByUuidAndType(uuid, AttributeType.CUSTOM).orElseThrow(() -> new NotFoundException(AttributeDefinition.class, uuid.toString()));
        return definition.mapToCustomAttributeDefinitionDetailDto();
    }

    @Override
    @ExternalAuthorization(resource = Resource.ATTRIBUTE, action = ResourceAction.DETAIL)
    public GlobalMetadataDefinitionDetailDto getGlobalMetadata(UUID uuid) throws NotFoundException {
        logger.debug("Fetching global metadata for UUID: {}", uuid);
        AttributeDefinition definition = attributeDefinitionRepository.findByUuidAndTypeAndGlobalTrue(uuid, AttributeType.META).orElseThrow(() -> new NotFoundException(AttributeDefinition.class, uuid.toString()));
        return definition.mapToGlobalMetadataDefinitionDetailDto();
    }

    @Override
    @ExternalAuthorization(resource = Resource.ATTRIBUTE, action = ResourceAction.CREATE)
    public CustomAttributeDefinitionDetailDto createCustomAttribute(CustomAttributeCreateRequestDto request) throws AlreadyExistException, AttributeException {
        logger.debug("Create custom attribute, request: {}", request);
        if (attributeDefinitionRepository.existsByTypeAndName(AttributeType.CUSTOM, request.getName())) {
            throw new AlreadyExistException("Custom Attribute with same name already exists");
        }

        if (request.getContentType() == AttributeContentType.RESOURCE) throw new AttributeException("Resource Object cannot be set as content type for custom attribute.");

        CustomAttributeV3 attribute = new CustomAttributeV3();
        attribute.setType(AttributeType.CUSTOM);
        attribute.setContentType(request.getContentType());
        attribute.setName(request.getName());
        attribute.setUuid(UUID.randomUUID().toString());
        attribute.setDescription(request.getDescription());
        if (request.getContent() != null) {
            attribute.setContent(request.getContent().stream().<BaseAttributeContentV3<?>>map(attributeContent -> AttributeVersionHelper.convertAttributeContentToV3(attributeContent, request.getContentType())).toList());
        }

        // Setting the attribute properties based on the information from the request
        CustomAttributeProperties properties = new CustomAttributeProperties();
        properties.setList(request.isList());
        properties.setGroup(request.getGroup());
        properties.setLabel(request.getLabel());
        properties.setVisible(request.isVisible());
        properties.setMultiSelect(request.isMultiSelect());
        properties.setReadOnly(request.isReadOnly());
        properties.setRequired(request.isRequired());
        properties.setProtectionLevel(request.getProtectionLevel());
        properties.setExtensibleList(request.isExtensibleList());
        attribute.setProperties(properties);

        return attributeEngine.updateCustomAttributeDefinition(attribute, request.getResources()).mapToCustomAttributeDefinitionDetailDto();
    }

    @Override
    @ExternalAuthorization(resource = Resource.ATTRIBUTE, action = ResourceAction.CREATE)
    public GlobalMetadataDefinitionDetailDto createGlobalMetadata(GlobalMetadataCreateRequestDto request) throws AlreadyExistException, AttributeException {
        logger.debug("Create global metadata, request: {}", request);
        if (attributeDefinitionRepository.existsByTypeAndNameAndGlobalTrue(AttributeType.META, request.getName())) {
            throw new AlreadyExistException("Global Metadata with same name already exists");
        }

        if (request.getContentType() == AttributeContentType.RESOURCE) throw new AttributeException("Resource Object cannot be set as content type for metadata attribute.");

        MetadataAttributeV2 attribute = new MetadataAttributeV2();
        attribute.setType(AttributeType.META);
        attribute.setContentType(request.getContentType());
        attribute.setName(request.getName());
        attribute.setUuid(UUID.randomUUID().toString());
        attribute.setDescription(request.getDescription());

        // Setting the attribute properties based on the information from the request
        MetadataAttributeProperties properties = new MetadataAttributeProperties();
        properties.setGroup(request.getGroup());
        properties.setLabel(request.getLabel());
        properties.setVisible(request.isVisible());
        properties.setGlobal(true);
        attribute.setProperties(properties);

        return attributeEngine.updateMetadataAttributeDefinition(attribute, null).mapToGlobalMetadataDefinitionDetailDto();
    }

    @Override
    @ExternalAuthorization(resource = Resource.ATTRIBUTE, action = ResourceAction.UPDATE)
    public CustomAttributeDefinitionDetailDto editCustomAttribute(UUID uuid, CustomAttributeUpdateRequestDto request) throws NotFoundException, AttributeException {
        logger.debug("Update custom attribute with uuid: {}, request: {}", uuid, request);
        AttributeDefinition definition = attributeDefinitionRepository.findByUuidAndType(uuid, AttributeType.CUSTOM).orElseThrow(() -> new NotFoundException(AttributeDefinition.class, uuid.toString()));

        CustomAttributeV3 attribute = new CustomAttributeV3();
        attribute.setUuid(definition.getUuid().toString());
        attribute.setName(definition.getName());
        attribute.setContentType(definition.getContentType());

        attribute.setDescription(request.getDescription());

        if (request.getContent() != null) {
            attribute.setContent(request.getContent().stream().<BaseAttributeContentV3<?>>map(attributeContent -> AttributeVersionHelper.convertAttributeContentToV3(attributeContent, definition.getContentType())).toList());
        }        attribute.setProperties(new CustomAttributeProperties());
        attribute.getProperties().setGroup(request.getGroup());
        attribute.getProperties().setLabel(request.getLabel());
        attribute.getProperties().setVisible(request.isVisible());
        attribute.getProperties().setList(request.isList());
        attribute.getProperties().setMultiSelect(request.isMultiSelect());
        attribute.getProperties().setReadOnly(request.isReadOnly());
        attribute.getProperties().setRequired(request.isRequired());
        attribute.getProperties().setProtectionLevel(request.getProtectionLevel());
        attribute.getProperties().setExtensibleList(request.isExtensibleList());

        return attributeEngine.updateCustomAttributeDefinition(attribute, request.getResources()).mapToCustomAttributeDefinitionDetailDto();
    }

    @Override
    @ExternalAuthorization(resource = Resource.ATTRIBUTE, action = ResourceAction.UPDATE)
    public GlobalMetadataDefinitionDetailDto editGlobalMetadata(UUID uuid, GlobalMetadataUpdateRequestDto request) throws NotFoundException, AttributeException {
        logger.debug("Update global metadata with uuid: {}, request: {}", uuid, request);
        AttributeDefinition definition = attributeDefinitionRepository.findByUuidAndTypeAndGlobalTrue(uuid, AttributeType.META).orElseThrow(() -> new NotFoundException(AttributeDefinition.class, uuid.toString()));

        MetadataAttributeV2 attribute = new MetadataAttributeV2();
        attribute.setUuid(definition.getAttributeUuid().toString());
        attribute.setName(definition.getName());
        attribute.setContentType(definition.getContentType());

        attribute.setDescription(request.getDescription());
        attribute.setProperties(new MetadataAttributeProperties());
        attribute.getProperties().setGroup(request.getGroup());
        attribute.getProperties().setLabel(request.getLabel());
        attribute.getProperties().setVisible(request.isVisible());
        attribute.getProperties().setGlobal(true);

        return attributeEngine.updateMetadataAttributeDefinition(attribute, null).mapToGlobalMetadataDefinitionDetailDto();
    }

    @Override
    @ExternalAuthorization(resource = Resource.ATTRIBUTE, action = ResourceAction.DELETE)
    public void deleteCustomAttribute(UUID uuid) throws NotFoundException {
        logger.debug("Deleting custom attribute with UUID: {}", uuid);
        attributeEngine.deleteAttributeDefinition(AttributeType.CUSTOM, uuid);
    }

    @Override
    @ExternalAuthorization(resource = Resource.ATTRIBUTE, action = ResourceAction.DELETE)
    public void bulkDeleteCustomAttributes(List<String> attributeUuids) {
        for (String uuid : attributeUuids) {
            try {
                deleteCustomAttribute(UUID.fromString(uuid));
            } catch (NotFoundException e) {
                logger.warn("Unable to find Attribute with UUID {} to be deleted", uuid);
            }
        }
    }

    @Override
    @ExternalAuthorization(resource = Resource.ATTRIBUTE, action = ResourceAction.ENABLE)
    public void enableCustomAttribute(UUID uuid, boolean enable) throws NotFoundException {
        logger.debug("{} custom attribute with UUID: {}", enable ? "Enabling" : "Disabling", uuid);
        AttributeDefinition definition = attributeDefinitionRepository.findByUuidAndType(uuid, AttributeType.CUSTOM).orElseThrow(() -> new NotFoundException(AttributeDefinition.class, uuid.toString()));
        definition.setEnabled(enable);
        attributeDefinitionRepository.save(definition);
    }

    @Override
    @ExternalAuthorization(resource = Resource.ATTRIBUTE, action = ResourceAction.ENABLE)
    public void bulkEnableCustomAttributes(List<String> attributeUuids, boolean enable) {
        for (String uuid : attributeUuids) {
            try {
                enableCustomAttribute(UUID.fromString(uuid), enable);
            } catch (NotFoundException e) {
                logger.warn("Unable to find Attribute with UUID {}", uuid);
            }
        }
    }

    @Override
    @ExternalAuthorization(resource = Resource.ATTRIBUTE, action = ResourceAction.LIST)
    public List<ConnectorMetadataResponseDto> getConnectorMetadata(Optional<String> connectorUuid) {
        List<AttributeDefinition> attributeDefinitions;
        List<ConnectorMetadataResponseDto> response = new ArrayList<>();
        if (connectorUuid.isPresent() && !connectorUuid.get().isEmpty()) {
            attributeDefinitions = attributeDefinitionRepository.findByConnectorUuidAndTypeAndGlobal(UUID.fromString(connectorUuid.get()), AttributeType.META, false);
        } else {
            attributeDefinitions = attributeDefinitionRepository.findByTypeAndGlobal(AttributeType.META, false);
        }

        for (AttributeDefinition definition : attributeDefinitions) {
            if (definition.getConnectorUuid() == null) {
                continue;
            }
            ConnectorMetadataResponseDto dto = new ConnectorMetadataResponseDto();
            dto.setName(definition.getName());
            dto.setUuid(definition.getAttributeUuid().toString());
            dto.setContentType(definition.getContentType());
            dto.setLabel(definition.getLabel());
            dto.setConnectorUuid(definition.getConnectorUuid().toString());
            response.add(dto);
        }
        return response;
    }

    @Override
    @ExternalAuthorization(resource = Resource.ATTRIBUTE, action = ResourceAction.UPDATE)
    public GlobalMetadataDefinitionDetailDto promoteConnectorMetadata(UUID uuid, UUID connectorUUid) throws NotFoundException {
        AttributeDefinition definition = attributeDefinitionRepository.findByConnectorUuidAndAttributeUuid(connectorUUid, uuid).orElseThrow(() -> new NotFoundException(AttributeDefinition.class, uuid.toString()));
        definition.setGlobal(true);
        attributeDefinitionRepository.save(definition);
        return getGlobalMetadata(definition.getUuid());
    }

    @Override
    @ExternalAuthorization(resource = Resource.ATTRIBUTE, action = ResourceAction.UPDATE)
    public void demoteConnectorMetadata(UUID uuid) throws NotFoundException {
        AttributeDefinition definition = attributeDefinitionRepository.findByUuidAndTypeAndGlobalTrue(uuid, AttributeType.META).orElseThrow(() -> new NotFoundException(AttributeDefinition.class, uuid.toString()));
        definition.setGlobal(false);
        attributeDefinitionRepository.save(definition);
    }

    @Override
    @ExternalAuthorization(resource = Resource.ATTRIBUTE, action = ResourceAction.UPDATE)
    public void bulkDemoteConnectorMetadata(List<String> attributeUuids) {
        for (String uuid : attributeUuids) {
            try {
                demoteConnectorMetadata(UUID.fromString(uuid));
            } catch (NotFoundException e) {
                logger.warn("Unable to find global metadata with UUID {}", uuid);
            }
        }
    }

    @Override
    @ExternalAuthorizationMissing
    public List<Resource> getResources() {
        return Resource.getCustomAttributesResources();
    }

    @Override
    @ExternalAuthorization(resource = Resource.ATTRIBUTE, action = ResourceAction.MEMBERS)
    public List<CustomAttribute> getResourceAttributes(SecurityFilter filter, Resource resource) {
        return attributeEngine.getCustomAttributesByResource(resource, filter.getResourceFilter());
    }

    @Override
    @ExternalAuthorization(resource = Resource.ATTRIBUTE, action = ResourceAction.UPDATE)
    public void updateResources(UUID uuid, List<Resource> resources) throws NotFoundException {
        attributeEngine.updateCustomAttributeResources(uuid, resources);
    }

    @Override
    public NameAndUuidDto getResourceObjectInternal(UUID objectUuid) throws NotFoundException {
        AttributeDefinition customAttribute = attributeDefinitionRepository.findByUuidAndType(objectUuid, AttributeType.CUSTOM).orElseThrow(() -> new NotFoundException(CustomAttribute.class, objectUuid));
        return customAttribute.mapToAccessControlObjects();
    }

    @Override
    @ExternalAuthorization(resource = Resource.ATTRIBUTE, action = ResourceAction.DETAIL)
    public NameAndUuidDto getResourceObjectExternal(SecuredUUID objectUuid) throws NotFoundException {
        return getResourceObjectInternal(objectUuid.getValue());
    }

    @Override
    @ExternalAuthorization(resource = Resource.ATTRIBUTE, action = ResourceAction.LIST)
    public List<NameAndUuidDto> listResourceObjects(SecurityFilter filter, List<SearchFilterRequestDto> filters, PaginationRequestDto pagination) {
        List<AttributeDefinition> customAttributes = attributeDefinitionRepository.findUsingSecurityFilter(
                filter, List.of(),
                (root, cb, cr) -> cb.equal(root.get("type"), AttributeType.CUSTOM));

        return customAttributes.stream().map(AttributeDefinition::mapToAccessControlObjects).collect(Collectors.toList());
    }

    @Override
    public void evaluatePermissionChain(SecuredUUID uuid) throws NotFoundException {
        // not necessary to evaluate permissions to update
    }
}
