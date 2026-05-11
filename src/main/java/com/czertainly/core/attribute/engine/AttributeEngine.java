package com.czertainly.core.attribute.engine;

import com.czertainly.api.exception.AttributeException;
import com.czertainly.api.exception.NotFoundException;
import com.czertainly.api.exception.ValidationError;
import com.czertainly.api.exception.ValidationException;
import com.czertainly.api.model.client.attribute.*;
import com.czertainly.api.model.client.metadata.MetadataResponseDto;
import com.czertainly.api.model.client.metadata.ResponseMetadata;
import com.czertainly.api.model.common.NameAndUuidDto;
import com.czertainly.api.model.common.attribute.common.*;
import com.czertainly.api.model.common.attribute.common.content.data.ProtectionLevel;
import com.czertainly.api.model.common.attribute.v2.*;
import com.czertainly.api.model.common.attribute.common.callback.AttributeCallback;
import com.czertainly.api.model.common.attribute.common.content.AttributeContentType;
import com.czertainly.api.model.common.attribute.v2.content.BaseAttributeContentV2;
import com.czertainly.api.model.common.attribute.common.content.data.AttributeContentData;
import com.czertainly.api.model.common.attribute.v3.CustomAttributeV3;
import com.czertainly.api.model.common.attribute.v3.DataAttributeV3;
import com.czertainly.api.model.common.attribute.v3.content.BaseAttributeContentV3;
import com.czertainly.api.model.core.auth.AttributeResource;
import com.czertainly.api.model.core.auth.Resource;
import com.czertainly.api.model.core.search.FilterFieldSource;
import com.czertainly.api.model.core.search.SearchFieldDataByGroupDto;
import com.czertainly.core.attribute.engine.records.*;
import com.czertainly.core.dao.entity.AttributeContent2Object;
import com.czertainly.core.dao.entity.AttributeContentItem;
import com.czertainly.core.dao.entity.AttributeDefinition;
import com.czertainly.core.dao.entity.AttributeRelation;
import com.czertainly.core.dao.repository.AttributeContent2ObjectRepository;
import com.czertainly.core.dao.repository.AttributeContentItemRepository;
import com.czertainly.core.dao.repository.AttributeDefinitionRepository;
import com.czertainly.core.dao.repository.AttributeRelationRepository;
import com.czertainly.core.model.SearchFieldObject;
import com.czertainly.core.model.auth.ResourceAction;
import com.czertainly.core.security.authz.SecurityResourceFilter;
import com.czertainly.core.util.*;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.DeserializationFeature;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.json.JsonMapper;
import jakarta.persistence.EntityManager;
import jakarta.persistence.PersistenceContext;
import org.apache.commons.lang3.StringUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;
import org.springframework.transaction.annotation.Transactional;

import java.util.*;
import java.util.regex.Pattern;
import java.util.stream.Collectors;
import java.util.stream.IntStream;

@Component
@Transactional
public class AttributeEngine {

    public static final String ATTRIBUTE_DEFINITION_FORCE_UPDATE_LABEL = "<UPDATE_NEEDED>";
    private static final Logger logger = LoggerFactory.getLogger(AttributeEngine.class);
    private static final Pattern UUID_REGEX = Pattern.compile("^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$");

    private static final ObjectMapper ATTRIBUTES_OBJECT_MAPPER = JsonMapper.builder()
            .findAndAddModules()
            .configure(DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES, false)
            .build();

    @PersistenceContext
    private EntityManager entityManager;
    private AttributeDefinitionRepository attributeDefinitionRepository;
    private AttributeRelationRepository attributeRelationRepository;
    private AttributeContentItemRepository attributeContentItemRepository;
    private AttributeContent2ObjectRepository attributeContent2ObjectRepository;

    private AuthHelper authHelper;

    @Autowired
    public void setAuthHelper(AuthHelper authHelper) {
        this.authHelper = authHelper;
    }

    @Autowired
    public void setAttributeDefinitionRepository(AttributeDefinitionRepository attributeDefinitionRepository) {
        this.attributeDefinitionRepository = attributeDefinitionRepository;
    }

    @Autowired
    public void setAttributeRelationRepository(AttributeRelationRepository attributeRelationRepository) {
        this.attributeRelationRepository = attributeRelationRepository;
    }

    @Autowired
    public void setAttributeContentRepository(AttributeContentItemRepository attributeContentItemRepository) {
        this.attributeContentItemRepository = attributeContentItemRepository;
    }

    @Autowired
    public void setAttributeContent2ObjectRepository(AttributeContent2ObjectRepository attributeContent2ObjectRepository) {
        this.attributeContent2ObjectRepository = attributeContent2ObjectRepository;
    }

    //region Search (Filtering) related methods

    public List<SearchFieldDataByGroupDto> getResourceSearchableFields(Resource resource, boolean settable) {
        final List<SearchFieldDataByGroupDto> searchFieldDataByGroupDtos = new ArrayList<>();

        // The following logic is driven by minimizing database operations. So we retrieve everything at once and then do client-side filtering.
        if (settable) {
            List<SearchFieldObject> settableAttributes = attributeDefinitionRepository.findDistinctAttributeSearchFieldsByResourceAndAttrTypeAndAttrContentType(
                    resource, List.of(AttributeType.CUSTOM), Arrays.stream(AttributeContentType.values()).filter(AttributeContentType::isFilterByData).toList());
            if (!settableAttributes.isEmpty()) {
                searchFieldDataByGroupDtos.add(new SearchFieldDataByGroupDto(SearchHelper.prepareSearchForJSON(settableAttributes), FilterFieldSource.CUSTOM));
            }
        } else {
            List<SearchFieldObject> searchableAttributes = attributeDefinitionRepository.findDistinctAttributeSearchFieldsByResourceAndAttrType(
                    resource, List.of(AttributeType.CUSTOM, AttributeType.DATA, AttributeType.META));
            var customAttributes = searchableAttributes.stream().filter(attr -> attr.getAttributeType().equals(AttributeType.CUSTOM)).toList();
            if (!customAttributes.isEmpty()) {
                searchFieldDataByGroupDtos.add(new SearchFieldDataByGroupDto(SearchHelper.prepareSearchForJSON(customAttributes), FilterFieldSource.CUSTOM));
            }

            var dataAttributes = searchableAttributes.stream().filter(attr -> attr.getAttributeType().equals(AttributeType.DATA)).toList();
            if (!dataAttributes.isEmpty()) {
                searchFieldDataByGroupDtos.add(new SearchFieldDataByGroupDto(SearchHelper.prepareSearchForJSON(dataAttributes), FilterFieldSource.DATA));
            }

            var metadataAttributes = searchableAttributes.stream().filter(attr -> attr.getAttributeType().equals(AttributeType.META)).toList();
            if (!metadataAttributes.isEmpty()) {
                searchFieldDataByGroupDtos.add(new SearchFieldDataByGroupDto(SearchHelper.prepareSearchForJSON(metadataAttributes), FilterFieldSource.META));
            }
        }

        return searchFieldDataByGroupDtos;
    }

    //endregion

    public static List<ResponseAttribute> getResponseAttributesFromBaseAttributes(List<BaseAttribute> attributes) {
        if (attributes == null || attributes.isEmpty()) return List.of();
        return attributes.stream().map(
                attribute ->
                        AttributeVersionHelper
                                .getResponseAttribute(UUID.fromString(attribute.getUuid()), attribute.getName(), getLabelFromAttributeProperties(attribute),
                                        attribute.getContent(), getAttributeContentType(attribute), attribute.getType(), attribute.getVersion())
        ).toList();
    }

    private static String getLabelFromAttributeProperties(BaseAttribute attribute) {
        if (attribute.getType() == AttributeType.DATA && ((DataAttribute) attribute).getProperties() != null)
            return ((DataAttribute) attribute).getProperties().getLabel();
        if (attribute.getType() == AttributeType.CUSTOM && ((CustomAttributeV3) attribute).getProperties() != null)
            return ((CustomAttributeV3) attribute).getProperties().getLabel();
        return attribute.getName();
    }

    private static AttributeContentType getAttributeContentType(BaseAttribute attribute) {
        if (attribute.getType() == AttributeType.DATA) return ((DataAttribute) attribute).getContentType();
        if (attribute.getType() == AttributeType.CUSTOM) return ((CustomAttributeV3) attribute).getContentType();
        return null;
    }

    public static List<ResponseAttribute> getResponseAttributesFromRequestAttributes(List<RequestAttribute> attributes) {
        if (attributes == null || attributes.isEmpty()) return List.of();
        return attributes.stream().map(
                attribute ->
                        AttributeVersionHelper.getResponseAttribute(attribute.getUuid(), attribute.getName(), attribute.getName(),
                                attribute.getContent(), attribute.getContentType(), AttributeType.DATA, attribute.getVersion().getVersion())
        ).toList();
    }


    public List<CustomAttribute> getCustomAttributesByResource(Resource resource, SecurityResourceFilter securityResourceFilter) {
        List<AttributeRelation> relations = attributeRelationRepository.findByResourceAndAttributeDefinitionTypeAndAttributeDefinitionEnabled(resource, AttributeType.CUSTOM, true);

        // filter definitions that are not allowed for user
        if (securityResourceFilter.areOnlySpecificObjectsAllowed()) {
            return relations.stream()
                    .filter(r -> securityResourceFilter.getAllowedObjects().contains(r.getAttributeDefinition().getUuid()))
                    .map(AttributeEngine::getCustomAttributeWithDecryptedContentFromRelation)
                    .toList();
        } else {
            return relations.stream().filter(r -> !securityResourceFilter.getForbiddenObjects().contains(r.getAttributeDefinition().getUuid())).map(AttributeEngine::getCustomAttributeWithDecryptedContentFromRelation).toList();
        }
    }

    private static CustomAttribute getCustomAttributeWithDecryptedContentFromRelation(AttributeRelation r) {
        CustomAttribute attribute = new CustomAttributeV3((CustomAttributeV3) r.getAttributeDefinition().getDefinition());
        if (attribute.getProperties().getProtectionLevel() == ProtectionLevel.ENCRYPTED && r.getAttributeDefinition().getEncryptedData() != null) {
            List<String> encryptedDataList = r.getAttributeDefinition().getEncryptedData();
            List<AttributeContent> content = attribute.getContent();
            List<AttributeContent> decryptedData = new ArrayList<>();
            for (int i = 0; i < content.size(); i++) {
                AttributeContent decryptedItem = i < encryptedDataList.size() ? AttributeVersionHelper.decryptContent(
                        content.get(i), 3, attribute.getContentType(), encryptedDataList.get(i)) : content.get(i);
                decryptedData.add(decryptedItem);
            }
            attribute.setContent(decryptedData);
        }
        return attribute;
    }

    public DataAttribute getDataAttributeDefinition(UUID connectorUuid, String name) {
        AttributeDefinition definition = attributeDefinitionRepository.findByTypeAndConnectorUuidAndName(AttributeType.DATA, connectorUuid, name).orElse(null);
        if (definition != null) {
            return (DataAttribute) definition.getDefinition();
        }
        return null;
    }

    public BaseAttribute getGroupAttributeDefinition(UUID connectorUuid, String name) {
        AttributeDefinition definition = attributeDefinitionRepository.findByTypeAndConnectorUuidAndName(AttributeType.GROUP, connectorUuid, name).orElse(null);
        if (definition != null) {
            return definition.getDefinition();
        }
        return null;
    }

    public List<MetadataAttribute> getMetadataAttributesDefinitionContent(ObjectAttributeContentInfo contentInfo) {
        // TODO: use also operation?
        List<ObjectAttributeDefinitionContent> objectDefinitionContents = attributeContent2ObjectRepository.getObjectAttributeDefinitionContent(AttributeType.META, contentInfo.connectorUuid(), null, contentInfo.objectType(), contentInfo.objectUuid(), contentInfo.sourceObjectType(), contentInfo.sourceObjectUuid(), contentInfo.objectVersion());

        Map<String, MetadataAttribute> mapping = new HashMap<>();

        for (ObjectAttributeDefinitionContent objectDefinitionContent : objectDefinitionContents) {

            if (objectDefinitionContent.contentItem().getData() == null) {
                continue;
            }

            String uuid = objectDefinitionContent.uuid().toString();

            MetadataAttribute attribute =
                    mapping.computeIfAbsent(uuid, k -> {
                        MetadataAttribute def =
                                (MetadataAttribute) objectDefinitionContent.definition();

                        def.setContent(new ArrayList<>());
                        return def;
                    });

            // Add content (requires raw cast because generics are invariant)
            ((List) attribute.getContent()).add(objectDefinitionContent.contentItem());
        }

        return mapping.values().stream().toList();

    }

    // TODO: make it generic to be used also for DATA attributes and update DTOs accordingly
    public List<MetadataResponseDto> getMappedMetadataContent(ObjectAttributeContentInfo contentInfo) {
        List<ObjectAttributeContentDetail> objectMetadataContents = attributeContent2ObjectRepository.getObjectAttributeContentDetail(AttributeType.META, contentInfo.connectorUuid(), null, contentInfo.objectType(), contentInfo.objectUuid(), contentInfo.sourceObjectType(), contentInfo.sourceObjectUuid(), contentInfo.objectVersion());

        Map<UUID, String> connectorMapping = new HashMap<>();
        Map<UUID, Map<Resource, Map<UUID, ResponseMetadata>>> mapping = new HashMap<>();
        for (ObjectAttributeContentDetail objectMetadataContent : objectMetadataContents) {
            // check in case data is null because of malformed data
            if (objectMetadataContent.contentItem().getData() == null) {
                continue;
            }

            ResponseMetadata metadataResponseAttributeDto;
            // do we need check for empty content?
            Map<Resource, Map<UUID, ResponseMetadata>> sourceAttributesContentsMapping;
            Map<UUID, ResponseMetadata> sourceAttributesContents;
            if (!connectorMapping.containsKey(objectMetadataContent.connectorUuid())) {
//                String connectorName = objectMetadataContent.connectorName() != null ? objectMetadataContent.connectorName() : "<No connector>";
                String connectorName = objectMetadataContent.connectorName();
                connectorMapping.put(objectMetadataContent.connectorUuid(), connectorName);
            }
            if ((sourceAttributesContentsMapping = mapping.get(objectMetadataContent.connectorUuid())) == null) {
                sourceAttributesContentsMapping = new HashMap<>();
                mapping.put(objectMetadataContent.connectorUuid(), sourceAttributesContentsMapping);
            }
            if ((sourceAttributesContents = sourceAttributesContentsMapping.get(objectMetadataContent.sourceObjectType())) == null) {
                sourceAttributesContents = new HashMap<>();
                sourceAttributesContentsMapping.put(objectMetadataContent.sourceObjectType(), sourceAttributesContents);
            }

            if ((metadataResponseAttributeDto = sourceAttributesContents.get(objectMetadataContent.uuid())) == null) {
                metadataResponseAttributeDto = AttributeVersionHelper.getResponseMetadata(objectMetadataContent.version(), new ArrayList<>(), objectMetadataContent.uuid(), objectMetadataContent.name(), objectMetadataContent.label(), objectMetadataContent.type(), objectMetadataContent.contentType(), new ArrayList<>());
                sourceAttributesContents.put(objectMetadataContent.uuid(), metadataResponseAttributeDto);
            }

            AttributeVersionHelper.addResponseMetadataContent(objectMetadataContent.version(), metadataResponseAttributeDto, objectMetadataContent.contentItem());

            if (objectMetadataContent.sourceObjectType() != null) {
                metadataResponseAttributeDto.getSourceObjects().add(new NameAndUuidDto(objectMetadataContent.sourceObjectUuid().toString(), objectMetadataContent.sourceObjectName()));
            }
        }

        List<MetadataResponseDto> metadataResponses = new ArrayList<>();
        for (var connectorSourceAttributes : mapping.entrySet()) {
            for (var sourceAttributes : connectorSourceAttributes.getValue().entrySet()) {
                var metadataResponseDto = new MetadataResponseDto();
                metadataResponseDto.setConnectorUuid(connectorSourceAttributes.getKey() != null ? connectorSourceAttributes.getKey().toString() : null);
                metadataResponseDto.setConnectorName(connectorMapping.get(connectorSourceAttributes.getKey()));
                metadataResponseDto.setSourceObjectType(sourceAttributes.getKey());
                metadataResponseDto.setItems(sourceAttributes.getValue().values().stream().toList());
                metadataResponses.add(metadataResponseDto);
            }
        }

        return metadataResponses;
    }

    public void updateCustomAttributeResources(UUID uuid, List<Resource> resources) throws NotFoundException {
        AttributeDefinition attributeDefinition = attributeDefinitionRepository.findByUuidAndType(uuid, AttributeType.CUSTOM).orElseThrow(() -> new NotFoundException(AttributeDefinition.class, uuid.toString()));
        attributeRelationRepository.deleteAll(attributeRelationRepository.findByAttributeDefinitionUuid(attributeDefinition.getUuid()));
        Set<String> differences = resources.stream().filter(e -> !Resource.getCustomAttributesResources().contains(e)).map(Resource::getCode).collect(Collectors.toSet());
        if (!differences.isEmpty()) {
            throw new ValidationException(ValidationError.create("Unsupported Resources for Custom Attribute binding: " + StringUtils.join(differences, ", ")));
        }

        for (Resource resource : new HashSet<>(resources)) {
            AttributeRelation attributeRelation = new AttributeRelation();
            attributeRelation.setAttributeDefinition(attributeDefinition);
            attributeRelation.setResource(resource);
            attributeRelationRepository.save(attributeRelation);
        }
    }

    public AttributeDefinition updateCustomAttributeDefinition(CustomAttributeV3 customAttribute, List<Resource> resources) throws AttributeException {
        validateAttributeDefinition(customAttribute, null);

        AttributeDefinition attributeDefinition = attributeDefinitionRepository.findByAttributeUuid(UUID.fromString(customAttribute.getUuid())).orElse(null);
        boolean newCustomAttribute = attributeDefinition == null;
        if (newCustomAttribute) {
            attributeDefinition = new AttributeDefinition();
            attributeDefinition.setUuid(UUID.fromString(customAttribute.getUuid()));
            attributeDefinition.setName(customAttribute.getName());
            attributeDefinition.setType(AttributeType.CUSTOM);
            attributeDefinition.setAttributeUuid(attributeDefinition.getUuid());
            attributeDefinition.setContentType(customAttribute.getContentType());
            // Default state of the attribute will always be enabled
            attributeDefinition.setEnabled(true);
        } else {
            if (attributeDefinition.getContentType() != customAttribute.getContentType()) {
                throw new AttributeException(String.format("Custom attribute content type changed to %s while stored attribute definition have content type %s", customAttribute.getContentType().getLabel(), attributeDefinition.getContentType().getLabel()), customAttribute.getUuid(), customAttribute.getName(), customAttribute.getType(), null);
            }
        }

        attributeDefinition.setLabel(customAttribute.getProperties().getLabel());
        attributeDefinition.setRequired(customAttribute.getProperties().isRequired());
        attributeDefinition.setReadOnly(customAttribute.getProperties().isReadOnly());
        attributeDefinition.setVersion(AttributeVersion.V3.getVersion());

        encryptOrDecryptExistingContent(attributeDefinition, customAttribute.getProperties().getProtectionLevel());
        customAttribute.setContent(encryptDefaultAttributeContent(customAttribute, attributeDefinition, customAttribute.getProperties().getProtectionLevel()));
        if (customAttribute.getProperties().getProtectionLevel() != ProtectionLevel.ENCRYPTED) {
            attributeDefinition.setEncryptedData(null);
        }

        attributeDefinition.setDefinition(customAttribute);
        attributeDefinition.setProtectionLevel(customAttribute.getProperties().getProtectionLevel());
        attributeDefinition = attributeDefinitionRepository.save(attributeDefinition);

        // save relations
        if (resources != null) {
            if (!newCustomAttribute) {
                attributeDefinition.getRelations().clear();
                attributeRelationRepository.deleteByAttributeDefinitionUuid(attributeDefinition.getUuid());
            }
            if (!resources.isEmpty()) {
                // check for invalid resources
                List<String> invalidResources = resources.stream().filter(r -> !r.hasCustomAttributes()).map(Resource::getLabel).toList();
                if (!invalidResources.isEmpty()) {
                    throw new AttributeException("Unsupported Resources for Custom Attribute: " + StringUtils.join(invalidResources, ", "), customAttribute.getUuid(), customAttribute.getName(), customAttribute.getType(), null);
                }

                for (Resource resource : new HashSet<>(resources)) {
                    AttributeRelation attributeRelation = new AttributeRelation();
                    attributeRelation.setAttributeDefinition(attributeDefinition);
                    attributeRelation.setResource(resource);
                    attributeRelationRepository.save(attributeRelation);
                    attributeDefinition.getRelations().add(attributeRelation);
                }
            }
        }

        return attributeDefinition;
    }

    private void encryptOrDecryptExistingContent(AttributeDefinition attributeDefinition, ProtectionLevel newProtectionLevel) throws AttributeException {
        if (attributeDefinition.getUuid() != null) {
            if (newProtectionLevel == ProtectionLevel.ENCRYPTED && attributeDefinition.getProtectionLevel() != ProtectionLevel.ENCRYPTED) {
                // if changing from NONE to ENCRYPTED, we need to encrypt existing content
                List<AttributeContentItem> contents = attributeContentItemRepository.findByAttributeDefinitionUuid(attributeDefinition.getUuid());
                for (AttributeContentItem contentItem : contents) {
                    String encryptedContent = encryptAttributeContent(attributeDefinition, contentItem.getJson());
                    contentItem.setEncryptedData(encryptedContent);
                    contentItem.setJson(AttributeVersionHelper.createEncryptedContent(contentItem.getUuid().toString(), attributeDefinition.getContentType(), AttributeVersion.V3.getVersion()));
                    attributeContentItemRepository.save(contentItem);
                }
            }
            if (newProtectionLevel != ProtectionLevel.ENCRYPTED && attributeDefinition.getProtectionLevel() == ProtectionLevel.ENCRYPTED) {
                // if changing from ENCRYPTED to NONE, we need to decrypt existing content
                List<AttributeContentItem> contents = attributeContentItemRepository.findByAttributeDefinitionUuid(attributeDefinition.getUuid());
                for (AttributeContentItem contentItem : contents) {
                    contentItem.setJson(AttributeVersionHelper.decryptContent(contentItem.getJson(), attributeDefinition.getVersion(), attributeDefinition.getContentType(), contentItem.getEncryptedData()));
                    contentItem.setEncryptedData(null);
                    attributeContentItemRepository.save(contentItem);
                }
            }
        }
    }

    private static List<AttributeContent> encryptDefaultAttributeContent(BaseAttribute baseAttribute, AttributeDefinition attributeDefinition, ProtectionLevel protectionLevel) throws AttributeException {
        if (protectionLevel == ProtectionLevel.ENCRYPTED && baseAttribute.getContent() != null) {
            List<String> encryptedContents = new ArrayList<>();
            List<AttributeContent> encryptedContentItems = new ArrayList<>();
            for (AttributeContent contentItem : (List<AttributeContent>) baseAttribute.getContent()) {
                encryptedContents.add(encryptAttributeContent(attributeDefinition, contentItem));
                encryptedContentItems.add(AttributeVersionHelper.createEncryptedContent(contentItem.getReference(), attributeDefinition.getContentType(), attributeDefinition.getVersion()));
            }
            attributeDefinition.setEncryptedData(encryptedContents);
            return encryptedContentItems;
        } else {
            return baseAttribute.getContent();
        }
    }

    public void validateUpdateDataAttributes(UUID connectorUuid, String operation, List<? extends BaseAttribute> attributes, List<RequestAttribute> requestAttributes) throws AttributeException {
        updateDataAttributeDefinitions(connectorUuid, operation, attributes);
        validateDataAttributesContent(connectorUuid, operation, attributes, requestAttributes);
    }

    private void validateDataAttributesContent(UUID connectorUuid, String operation, List<? extends BaseAttribute> attributes, List<RequestAttribute> requestAttributes) throws ValidationException {
        logger.debug("Validating data attributes: {}", attributes);
        if (attributes == null) {
            attributes = new ArrayList<>();
        }

        // alternative is to load all definitions by connector UUID and operation
        // TODO: what to do with orphaned (old) definitions from connector that were replaced and would be still validated and asked to be filled?
        List<UUID> attributeUuids = attributes.stream().filter(a -> a.getType() == AttributeType.DATA).map(a -> UUID.fromString(a.getUuid())).toList();
        List<String> attributeNames = attributes.stream().filter(a -> a.getType() == AttributeType.DATA).map(BaseAttribute::getName).toList();
        Map<String, AttributeDefinition> definitionsMapping = attributeDefinitionRepository.findByTypeAndConnectorUuidAndAttributeUuidInAndNameIn(AttributeType.DATA, connectorUuid, attributeUuids, attributeNames).stream().collect(Collectors.toMap(AttributeDefinition::getName, d -> d));

        // load missing data attributes definitions from DB
        for (RequestAttribute RequestAttribute : requestAttributes) {
            if (definitionsMapping.get(RequestAttribute.getName()) == null) {
                AttributeDefinition missingDefinition = attributeDefinitionRepository.findByTypeAndConnectorUuidAndAttributeUuidAndName(AttributeType.DATA, connectorUuid, UUID.fromString(String.valueOf(RequestAttribute.getUuid())), RequestAttribute.getName()).orElse(null);
                if (missingDefinition != null) {
                    // update operation - if attribute is retrieved by callback, we do not know its operation
                    if (!Objects.equals(missingDefinition.getOperation(), operation)) {
                        missingDefinition.setOperation(operation);
                        attributeDefinitionRepository.save(missingDefinition);
                    }
                    definitionsMapping.put(RequestAttribute.getName(), missingDefinition);
                }
            }
        }

        // no attributes to validate
        if (definitionsMapping.isEmpty() && requestAttributes.isEmpty()) {
            return;
        }

        // check for general attributes validation
        List<ValidationError> errors = validateAttributesContent(definitionsMapping, requestAttributes);
        if (!errors.isEmpty()) {
            throw new ValidationException(errors);
        }
    }

    public void updateDataAttributeDefinitions(UUID connectorUuid, String operation, List<? extends BaseAttribute> attributes) throws AttributeException {
        if (attributes == null) {
            return;
        }
        for (BaseAttribute attribute : attributes) {
            if (attribute.getType() == AttributeType.DATA) {
                updateDataAttributeDefinition(connectorUuid, operation, (DataAttribute) attribute);
            }
            if (attribute.getType() == AttributeType.GROUP) {
                updateGroupAttributeDefinition(connectorUuid, attribute);
            }
        }
    }

    public void updateAttributeDefinitionsWithCallback(UUID connectorUuid, List<? extends BaseAttribute> attributes) throws AttributeException {
        for (BaseAttribute attribute : attributes) {
            if (attribute.getType() == AttributeType.GROUP) {
                updateGroupAttributeDefinition(connectorUuid, attribute);
            }
            if (attribute.getType() == AttributeType.DATA && ((DataAttribute) attribute).getAttributeCallback() != null) {
                updateDataAttributeDefinition(connectorUuid, null, (DataAttribute) attribute);
            }
        }
    }

    private void updateGroupAttributeDefinition(UUID connectorUuid, BaseAttribute attribute) throws AttributeException {
        validateAttributeDefinition(attribute, connectorUuid);
        AttributeDefinition attributeDefinition = attributeDefinitionRepository.findByTypeAndConnectorUuidAndAttributeUuidAndName(AttributeType.GROUP, connectorUuid, UUID.fromString(attribute.getUuid()), attribute.getName()).orElse(null);
        if (attributeDefinition == null) {
            attributeDefinition = new AttributeDefinition();
            attributeDefinition.setConnectorUuid(connectorUuid);
            attributeDefinition.setAttributeUuid(UUID.fromString(attribute.getUuid()));
            attributeDefinition.setName(attribute.getName());
            attributeDefinition.setType(AttributeType.GROUP);
            attributeDefinition.setVersion(attribute.getVersion());
            attributeDefinition.setLabel(attribute.getName());
        }
        attributeDefinition.setDefinition(attribute);
        attributeDefinitionRepository.save(attributeDefinition);
    }

    private void updateDataAttributeDefinition(UUID connectorUuid, String operation, DataAttribute dataAttribute) throws AttributeException {
        validateAttributeDefinition(dataAttribute, connectorUuid);

        // find by connector uuid and name only because attribute uuid could be generated when data attribute was migrated from RequestAttribute
        AttributeDefinition attributeDefinition = attributeDefinitionRepository.findByTypeAndConnectorUuidAndAttributeUuidAndName(AttributeType.DATA, connectorUuid, UUID.fromString(dataAttribute.getUuid()), dataAttribute.getName()).orElse(null);
        if (attributeDefinition != null) {
            // update definition when it was migrated from RequestAttribute
            if (attributeDefinition.getLabel().isEmpty() && attributeDefinition.getDefinition().getDescription().equals(ATTRIBUTE_DEFINITION_FORCE_UPDATE_LABEL)) {
                attributeDefinition.setContentType(dataAttribute.getContentType());
                attributeDefinition.setAttributeUuid(UUID.fromString(dataAttribute.getUuid()));
            }
            // check for change of content type
            else if (attributeDefinition.getContentType() != dataAttribute.getContentType()) {
                throw new AttributeException(String.format("Connector attribute content type changed to %s while stored attribute definition have content type %s", dataAttribute.getContentType().getLabel(), attributeDefinition.getContentType().getLabel()), dataAttribute.getUuid(), dataAttribute.getName(), dataAttribute.getType(), connectorUuid.toString());
            }
        } else {
            logger.debug("Registering new data attribute with UUID {} and name {} for connector {}", dataAttribute.getUuid(), dataAttribute.getName(), connectorUuid);
            attributeDefinition = new AttributeDefinition();
            attributeDefinition.setConnectorUuid(connectorUuid);
            attributeDefinition.setAttributeUuid(UUID.fromString(dataAttribute.getUuid()));
            attributeDefinition.setName(dataAttribute.getName());
            attributeDefinition.setType(AttributeType.DATA);
            attributeDefinition.setContentType(dataAttribute.getContentType());
            attributeDefinition.setOperation(operation);
            attributeDefinition.setVersion(dataAttribute.getVersion());
        }
        attributeDefinition.setLabel(dataAttribute.getProperties().getLabel());
        attributeDefinition.setRequired(dataAttribute.getProperties().isRequired());
        attributeDefinition.setReadOnly(dataAttribute.getProperties().isReadOnly());

        encryptOrDecryptExistingContent(attributeDefinition, dataAttribute.getProperties().getProtectionLevel());
        attributeDefinition.setProtectionLevel(dataAttribute.getProperties().getProtectionLevel());

        // we need content only for readonly attribute
        if (!Boolean.TRUE.equals(attributeDefinition.isReadOnly()) && dataAttribute.getProperties().isExtensibleList()) {
            dataAttribute.setContent(null);
        } else
            dataAttribute.setContent(encryptDefaultAttributeContent(dataAttribute, attributeDefinition, dataAttribute.getProperties().getProtectionLevel()));
        attributeDefinition.setDefinition(dataAttribute);
        attributeDefinitionRepository.save(attributeDefinition);
    }

    public AttributeDefinition updateMetadataAttributeDefinition(MetadataAttribute metadataAttribute, UUID connectorUuid) throws AttributeException {
        var isGlobal = metadataAttribute.getProperties().isGlobal();
        if (connectorUuid == null && !isGlobal) {
            throw new AttributeException("Cannot update metadata without specifying connector UUID.", metadataAttribute.getUuid(), metadataAttribute.getName(), metadataAttribute.getType(), null);
        }
        validateAttributeDefinition(metadataAttribute, connectorUuid);

        AttributeDefinition attributeDefinition = null;
        if (isGlobal) {
            attributeDefinition = attributeDefinitionRepository.findByTypeAndNameAndGlobal(AttributeType.META, metadataAttribute.getName(), true).orElse(null);
        }
        if (attributeDefinition == null) {
            attributeDefinition = attributeDefinitionRepository.findByTypeAndConnectorUuidAndAttributeUuidAndName(AttributeType.META, connectorUuid, UUID.fromString(metadataAttribute.getUuid()), metadataAttribute.getName()).orElse(null);
        }
        if (attributeDefinition != null) {
            // check for change of content type
            if (attributeDefinition.getContentType() != metadataAttribute.getContentType()) {
                throw new AttributeException(String.format("Metadata attribute content type changed to %s while stored attribute definition have content type %s", metadataAttribute.getContentType().getLabel(), attributeDefinition.getContentType().getLabel()), metadataAttribute.getUuid(), metadataAttribute.getName(), metadataAttribute.getType(), connectorUuid == null ? null : connectorUuid.toString());
            }
        } else {
            logger.debug("Registering new {} metadata attribute with UUID {} and name {} for connector {}", isGlobal ? "global" : "connector", metadataAttribute.getUuid(), metadataAttribute.getName(), connectorUuid);
            attributeDefinition = new AttributeDefinition();
            attributeDefinition.setConnectorUuid(connectorUuid);
            attributeDefinition.setAttributeUuid(UUID.fromString(metadataAttribute.getUuid()));
            attributeDefinition.setName(metadataAttribute.getName());
            attributeDefinition.setType(AttributeType.META);
            attributeDefinition.setContentType(metadataAttribute.getContentType());
            attributeDefinition.setVersion(metadataAttribute.getVersion());
            attributeDefinition.setGlobal(isGlobal);
        }
        attributeDefinition.setLabel(metadataAttribute.getProperties().getLabel());

        // we don't need content in definition
        metadataAttribute.setContent(List.of());
        attributeDefinition.setDefinition(metadataAttribute);
        attributeDefinitionRepository.save(attributeDefinition);

        return attributeDefinition;
    }

    public void updateMetadataAttributes(List<MetadataAttribute> attributes, ObjectAttributeContentInfo objectAttributeContentInfo) throws AttributeException {
        if (objectAttributeContentInfo.connectorUuid() == null) {
            throw new AttributeException("Cannot update metadata without specifying connector UUID.");
        }
        if (attributes == null) {
            return;
        }

        for (MetadataAttribute metadataAttribute : attributes) {
            if (metadataAttribute.getType() != AttributeType.META) {
                continue;
            }

            updateMetadataAttribute(metadataAttribute, objectAttributeContentInfo);
        }
    }

    public void updateMetadataAttribute(MetadataAttribute metadataAttribute, ObjectAttributeContentInfo objectAttributeContentInfo) throws AttributeException {
        UUID connectorUuid = objectAttributeContentInfo.connectorUuid();
        List<AttributeContent> contentItems = metadataAttribute.getContent();
        AttributeDefinition attributeDefinition = updateMetadataAttributeDefinition(metadataAttribute, connectorUuid);

        if (objectAttributeContentInfo.connectorUuid() == null) {
            throw new AttributeException("Cannot update metadata content without specifying connector UUID.");
        }

        // delete content of metadata for this object as its content should be replaced;
        if (metadataAttribute.getProperties().isOverwrite()) {
            deleteObjectAttributeDefinitionContent(attributeDefinition.getUuid(), objectAttributeContentInfo.objectType(), objectAttributeContentInfo.objectUuid(), objectAttributeContentInfo.objectVersion());
        }
        createObjectAttributeContent(attributeDefinition, objectAttributeContentInfo, contentItems);
    }

    public List<DataAttribute> getDefinitionObjectAttributeContent(AttributeType attributeType, UUID connectorUuid, String operation, Resource objectType, UUID objectUuid) {
        logger.debug("Getting the {} attributes for {} with UUID: {}", attributeType.getLabel(), objectType.getLabel(), objectUuid);
        List<ObjectAttributeDefinitionContent> objectDefinitionContents = attributeContent2ObjectRepository.getObjectAttributeDefinitionContent(attributeType, connectorUuid, operation, objectType, objectUuid, null, null, null);

        Map<String, DataAttribute> mapping = new HashMap<>();
        for (ObjectAttributeDefinitionContent objectDefinitionContent : objectDefinitionContents) {
            String uuid = objectDefinitionContent.uuid().toString();
            if (objectDefinitionContent.definition().getVersion() == 2) {
                DataAttributeV2 attribute;
                if ((attribute = (DataAttributeV2) mapping.get(uuid)) == null) {
                    attribute = (DataAttributeV2) objectDefinitionContent.definition();
                    attribute.setContent(new ArrayList<>());
                    mapping.put(uuid, attribute);
                }
                attribute.getContent().add((BaseAttributeContentV2<?>) objectDefinitionContent.contentItem());
            }
            if (objectDefinitionContent.definition().getVersion() == 3) {
                DataAttributeV3 attribute;
                if ((attribute = (DataAttributeV3) mapping.get(uuid)) == null) {
                    attribute = (DataAttributeV3) objectDefinitionContent.definition();
                    attribute.setContent(new ArrayList<>());
                    mapping.put(uuid, attribute);
                }
                attribute.getContent().add((BaseAttributeContentV3<?>) objectDefinitionContent.contentItem());
            }
        }

        return mapping.values().stream().toList();
    }

    public void registerAttributeContentItems(UUID attributeDefinitionUuid, Collection<AttributeContent> attributeContentItems) {
        for (AttributeContent attributeContentItem : attributeContentItems) {
            AttributeContentItem contentItemEntity = attributeContentItemRepository.findByJsonAndAttributeDefinitionUuid(attributeContentItem, attributeDefinitionUuid);

            // check if content item for this attribute definition exists to don't create duplicate items
            if (contentItemEntity == null) {
                contentItemEntity = new AttributeContentItem();
                contentItemEntity.setJson(attributeContentItem);
                contentItemEntity.setAttributeDefinitionUuid(attributeDefinitionUuid);
                attributeContentItemRepository.save(contentItemEntity);
            }
        }
    }

    public List<ResponseAttribute> loadResponseAttributes(AttributeType attributeType, UUID connectorUuid, List<RequestAttribute> requestAttributes) {
        List<UUID> attributeUuids = new ArrayList<>();
        List<String> attributeNames = new ArrayList<>();
        for (RequestAttribute requestAttribute : requestAttributes) {
            attributeUuids.add(requestAttribute.getUuid());
            attributeNames.add(requestAttribute.getName());
        }

        Map<UUID, AttributeDefinition> definitionsMapping = attributeDefinitionRepository.findByTypeAndConnectorUuidAndAttributeUuidInAndNameIn(attributeType, connectorUuid, attributeUuids, attributeNames).stream().collect(Collectors.toMap(AttributeDefinition::getAttributeUuid, d -> d));

        List<ResponseAttribute> responseAttributes = new ArrayList<>();
        for (RequestAttribute requestAttribute : requestAttributes) {
            AttributeDefinition attributeDefinition = definitionsMapping.get(requestAttribute.getUuid());
            if (attributeDefinition == null) {
                continue;
            }

            if (requestAttribute.getVersion() == AttributeVersion.V2) {
                ResponseAttributeV2 responseAttribute = getResponseAttributeV2(attributeType, requestAttribute, attributeDefinition);
                responseAttributes.add(responseAttribute);
            } else if (requestAttribute.getVersion() == AttributeVersion.V3) {
                ResponseAttributeV3 responseAttribute = getResponseAttributeV3(attributeType, requestAttribute, attributeDefinition);
                responseAttributes.add(responseAttribute);
            }
        }

        return responseAttributes;
    }

    private static ResponseAttributeV2 getResponseAttributeV2(AttributeType attributeType, RequestAttribute requestAttribute, AttributeDefinition attributeDefinition) {
        ResponseAttributeV2 responseAttribute = new ResponseAttributeV2();
        responseAttribute.setUuid(requestAttribute.getUuid());
        responseAttribute.setName(requestAttribute.getName());
        responseAttribute.setContentType(requestAttribute.getContentType());
        responseAttribute.setContent(((RequestAttributeV2) requestAttribute).getContent());
        responseAttribute.setLabel(attributeDefinition.getLabel());
        responseAttribute.setType(attributeType);
        return responseAttribute;
    }

    private static ResponseAttributeV3 getResponseAttributeV3(AttributeType attributeType, RequestAttribute requestAttribute, AttributeDefinition attributeDefinition) {
        ResponseAttributeV3 responseAttribute = new ResponseAttributeV3();
        responseAttribute.setUuid(requestAttribute.getUuid());
        responseAttribute.setName(requestAttribute.getName());
        responseAttribute.setContentType(requestAttribute.getContentType());
        responseAttribute.setContent(((RequestAttributeV3) requestAttribute).getContent());
        responseAttribute.setLabel(attributeDefinition.getLabel());
        responseAttribute.setType(attributeType);
        return responseAttribute;
    }

    public List<ResponseAttribute> getObjectCustomAttributesContent(Resource objectType, UUID objectUuid) {
        logger.debug("Getting the custom attributes for {} with UUID: {}", objectType.getLabel(), objectUuid);
        SecurityResourceFilter securityResourceFilter = loadCustomAttributesSecurityResourceFilter();

        return getObjectCustomAttributesContent(objectType, objectUuid, securityResourceFilter);
    }

    private List<ResponseAttribute> getObjectCustomAttributesContent(Resource objectType, UUID objectUuid, SecurityResourceFilter securityResourceFilter) {
        List<UUID> allowedAttributes = null;
        List<UUID> forbiddenAttributes = null;
        if (securityResourceFilter != null) {
            if (securityResourceFilter.areOnlySpecificObjectsAllowed()) {
                allowedAttributes = securityResourceFilter.getAllowedObjects();
                if (allowedAttributes.isEmpty()) allowedAttributes.add(null);
            } else if (!securityResourceFilter.getForbiddenObjects().isEmpty()) {
                forbiddenAttributes = securityResourceFilter.getForbiddenObjects();
            }
        }

        List<ObjectAttributeContent> objectContents = attributeContent2ObjectRepository.getObjectCustomAttributesContent(AttributeType.CUSTOM, objectType, objectUuid, allowedAttributes, forbiddenAttributes);
        return getResponseAttributes(objectContents);
    }

    public List<ResponseAttribute> getObjectDataAttributesContentUnversioned(Resource objectType, UUID objectUuid) {
        List<ObjectAttributeContent> objectContents = attributeContent2ObjectRepository.getObjectDataAttributesContentUnversioned(objectType, objectUuid);
        return getResponseAttributes(objectContents);
    }

    public List<ResponseAttribute> getObjectDataAttributesContent(ObjectAttributeContentInfo info) {
        logger.debug("Getting the data attributes for {} with UUID {} from connector {} and operation {} for purpose {} version {}.",
                info.objectType().getLabel(), info.objectUuid(), info.connectorUuid(), info.operation(), info.purpose(), info.objectVersion());
        List<ObjectAttributeContent> objectContents = loadDataAttributesContent(info);
        return getResponseAttributes(objectContents);
    }

    public List<RequestAttribute> getRequestObjectDataAttributesContent(ObjectAttributeContentInfo info) {
        logger.debug("Getting the request data attributes for {} with UUID {} from connector {} and operation {} version {}.",
                info.objectType().getLabel(), info.objectUuid(), info.connectorUuid(), info.operation(), info.objectVersion());
        List<ObjectAttributeContent> objectContents = loadDataAttributesContent(info);
        return getRequestAttributes(objectContents);
    }

    public List<DataAttribute> getDataAttributesByContent(UUID connectorUuid, List<RequestAttribute> requestAttributes) throws AttributeException {
        List<DataAttribute> dataAttributes = new ArrayList<>();
        String connectorUuidStr = connectorUuid == null ? null : connectorUuid.toString();
        for (RequestAttribute requestAttribute : requestAttributes) {
            AttributeDefinition definition = attributeDefinitionRepository.findByTypeAndConnectorUuidAndAttributeUuidAndName(AttributeType.DATA, connectorUuid, requestAttribute.getUuid(), requestAttribute.getName())
                    .orElseThrow(() -> new AttributeException("Missing data attribute definition", requestAttribute.getUuid() == null ? null : String.valueOf(requestAttribute.getUuid()), requestAttribute.getName(), AttributeType.DATA, connectorUuidStr));
            validateAttributeContent(definition, requestAttribute.getContent());
            DataAttribute dataAttribute = AttributeVersionHelper.copyDataAttribute((DataAttribute) definition.getDefinition());
            dataAttribute.setContent(requestAttribute.getContent());
            dataAttributes.add(dataAttribute);
        }

        return dataAttributes;
    }

    private List<ObjectAttributeContent> loadDataAttributesContent(ObjectAttributeContentInfo info) {
        List<ObjectAttributeContent> objectContents;
        if (info.operation() != null && info.connectorUuid() != null) {
            objectContents = attributeContent2ObjectRepository.getObjectDataAttributesContent(AttributeType.DATA, info.connectorUuid(), info.operation(), info.purpose(), info.objectType(), info.objectUuid(), info.objectVersion());
        } else if (info.operation() != null) {
            objectContents = attributeContent2ObjectRepository.getObjectDataAttributesContentNoConnector(AttributeType.DATA, info.operation(), info.purpose(), info.objectType(), info.objectUuid(), info.objectVersion());
        } else if (info.connectorUuid() != null) {
            objectContents = attributeContent2ObjectRepository.getObjectDataAttributesContentNoOperation(AttributeType.DATA, info.connectorUuid(), info.objectType(), info.objectUuid(), info.objectVersion());
        } else {
            objectContents = attributeContent2ObjectRepository.getObjectDataAttributesContentNoConnectorNoOperation(AttributeType.DATA, info.objectType(), info.objectUuid(), info.objectVersion());
        }

        return objectContents;
    }

    private List<RequestAttribute> getRequestAttributes(List<ObjectAttributeContent> objectContents) {
        Map<String, RequestAttribute> mapping = new HashMap<>();
        for (ObjectAttributeContent objectContent : objectContents) {
            String uuid = objectContent.uuid().toString();
            RequestAttribute requestAttribute;

            if ((requestAttribute = mapping.get(uuid)) == null) {
                requestAttribute = AttributeVersionHelper.getRequestAttribute(objectContent.uuid(), objectContent.name(), new ArrayList<>(), objectContent.contentType(), objectContent.version());
                mapping.put(uuid, requestAttribute);
            }
            AttributeVersionHelper.addRequestAttributeContent(requestAttribute, objectContent);
        }

        return mapping.values().stream().toList();
    }

    private List<ResponseAttribute> getResponseAttributes(List<ObjectAttributeContent> objectContents) {
        Map<String, ResponseAttribute> mapping = new HashMap<>();
        for (ObjectAttributeContent objectContent : objectContents) {
            String uuid = objectContent.uuid().toString();
            ResponseAttribute responseAttribute;
            if ((mapping.get(uuid)) == null) {
                responseAttribute = AttributeVersionHelper.getResponseAttribute(objectContent.uuid(), objectContent.name(), objectContent.label(), new ArrayList<>(), objectContent.contentType(), objectContent.type(), objectContent.version());
                mapping.put(uuid, responseAttribute);
            } else {
                responseAttribute = mapping.get(uuid);
            }
            AttributeVersionHelper.addResponseAttributeContent(responseAttribute, objectContent);
        }

        return mapping.values().stream().toList();
    }

    public List<ResponseAttribute> updateObjectDataAttributesContent(ObjectAttributeContentInfo info, List<RequestAttribute> requestAttributes) throws ValidationException, NotFoundException, AttributeException {
        logger.debug("Updating the content of data attributes for resource {} with UUID: {} version: {}", info.objectType().getLabel(), info.objectUuid(), info.objectVersion());
        if (requestAttributes == null) {
            requestAttributes = new ArrayList<>();
        }

        deleteOperationObjectAttributesContent(AttributeType.DATA, info);
        for (RequestAttribute requestAttribute : requestAttributes) {
            AttributeDefinition attributeDefinition = attributeDefinitionRepository.findByTypeAndConnectorUuidAndAttributeUuidAndName(AttributeType.DATA, info.connectorUuid(), requestAttribute.getUuid(), requestAttribute.getName()).orElseThrow(() -> new NotFoundException(AttributeDefinition.class, requestAttribute.getName()));
            createObjectAttributeContent(attributeDefinition, info, requestAttribute.getContent());
        }

        return getObjectDataAttributesContent(info);
    }

    /**
     * Atomically replaces attribute content for the given versioned object, operation, and purpose,
     * regardless of which connector originally stored the rows.
     *
     * <p>Use this method instead of {@link #updateObjectDataAttributesContent} when <em>both</em>
     * of the following conditions hold:
     * <ol>
     *   <li>{@code info.objectVersion()} is non-null (versioned objects only).</li>
     *   <li>The connector contributing attributes for the operation may have changed since the version was last written
     *   — for example, when a versioned resource is updated in-place (no version bump) and the resource can also change
     *   from connector A to connector B.</li>
     * </ol>
     *
     * <p>Callers where the connector is guaranteed not to change between writes (e.g. first-time
     * creation of a resource version) may continue to use {@link #updateObjectDataAttributesContent}.
     */
    public List<ResponseAttribute> replaceObjectDataAttributesContent(
            ObjectAttributeContentInfo info, List<RequestAttribute> requestAttributes)
            throws ValidationException, NotFoundException, AttributeException {
        if (info.objectVersion() == null) {
            throw new IllegalArgumentException(
                    "replaceObjectDataAttributesContent requires a non-null objectVersion; " +
                            "use updateObjectDataAttributesContent for unversioned objects");
        }
        if (info.operation() == null) {
            throw new IllegalArgumentException(
                    "replaceObjectDataAttributesContent requires a non-null operation");
        }
        logger.debug("Replacing object data attribute content for resource {} UUID {} version {} operation {}.",
                info.objectType().getLabel(), info.objectUuid(), info.objectVersion(), info.operation());

        if (requestAttributes == null) {
            requestAttributes = new ArrayList<>();
        }

        // Wide pre-delete: removes every row for this (objectType, objectUuid, objectVersion, operation, purpose)
        // tuple irrespective of connectorUuid, preventing stale rows when the connector changes between in-place overwrites
        // of the same version.
        Long deleted = attributeContent2ObjectRepository.deleteAllOperationAttributesByVersion(
                AttributeType.DATA, info.operation(), info.purpose(),
                info.objectType(), info.objectUuid(), info.objectVersion());
        logger.debug("Removed {} stale attribute row(s) before replace for resource {} UUID {} version {} operation {} purpose {}.",
                deleted, info.objectType().getLabel(), info.objectUuid(), info.objectVersion(), info.operation(), info.purpose());

        for (RequestAttribute requestAttribute : requestAttributes) {
            AttributeDefinition attributeDefinition = attributeDefinitionRepository
                    .findByTypeAndConnectorUuidAndAttributeUuidAndName(
                            AttributeType.DATA, info.connectorUuid(),
                            requestAttribute.getUuid(), requestAttribute.getName())
                    .orElseThrow(() -> new NotFoundException(AttributeDefinition.class, requestAttribute.getName()));
            createObjectAttributeContent(attributeDefinition, info, requestAttribute.getContent());
        }

        return getObjectDataAttributesContent(info);
    }

    public List<ResponseAttribute> updateObjectCustomAttributesContent(Resource objectType, UUID objectUuid, List<RequestAttribute> requestAttributes) throws ValidationException, NotFoundException, AttributeException {
        logger.debug("Updating the content of custom attributes for resource {} with UUID: {}", objectType.getLabel(), objectUuid);
        if (requestAttributes == null) {
            requestAttributes = new ArrayList<>();
        }

        SecurityResourceFilter securityResourceFilter = loadCustomAttributesSecurityResourceFilter();
        validateCustomAttributesContent(objectType, requestAttributes, securityResourceFilter);

        // if protocol user or has all permissions for attributes
        if (securityResourceFilter == null || (!securityResourceFilter.areOnlySpecificObjectsAllowed() && securityResourceFilter.getForbiddenObjects().isEmpty())) {
            // custom attributes content is automatically replaced
            deleteObjectAttributeContentByType(AttributeType.CUSTOM, objectType, objectUuid);
            for (RequestAttribute requestAttribute : requestAttributes) {
                AttributeDefinition attributeDefinition = attributeDefinitionRepository.findByTypeAndName(AttributeType.CUSTOM, requestAttribute.getName()).orElseThrow(() -> new NotFoundException(AttributeDefinition.class, requestAttribute.getName()));
                List<? extends AttributeContent> attributeContent = requestAttribute.getVersion() == AttributeVersion.V3 ? ((RequestAttributeV3) requestAttribute).getContent() : ((RequestAttributeV2) requestAttribute).getContent().stream().map(ac -> AttributeVersionHelper.convertAttributeContentToV3(ac, requestAttribute.getContentType())).toList();
                createObjectAttributeContent(attributeDefinition, ObjectAttributeContentInfo.builder(objectType, objectUuid).build(), attributeContent);
            }
        } else {
            // delete only content of allowed attributes
            deleteObjectAllowedCustomAttributeContent(securityResourceFilter, objectType, objectUuid);

            for (RequestAttribute requestAttribute : requestAttributes) {
                AttributeDefinition attributeDefinition = attributeDefinitionRepository.findByTypeAndName(AttributeType.CUSTOM, requestAttribute.getName()).orElseThrow(() -> new NotFoundException(AttributeDefinition.class, requestAttribute.getName()));
                checkCustomAttributeUpdatePermissions(securityResourceFilter, attributeDefinition);

                createObjectAttributeContent(attributeDefinition, ObjectAttributeContentInfo.builder(objectType, objectUuid).build(), requestAttribute.getContent());
            }
        }

        return getObjectCustomAttributesContent(objectType, objectUuid, securityResourceFilter);
    }

    private static void checkCustomAttributeUpdatePermissions(SecurityResourceFilter securityResourceFilter, AttributeDefinition attributeDefinition) throws AttributeException {
        if ((securityResourceFilter.areOnlySpecificObjectsAllowed())) {
            if (!securityResourceFilter.getAllowedObjects().contains(attributeDefinition.getUuid())) {
                throw new AttributeException(String.format("Updating custom attribute `%s` is not allowed", attributeDefinition.getName()));
            }
        } else {
            if (securityResourceFilter.getForbiddenObjects().contains(attributeDefinition.getUuid())) {
                throw new AttributeException(String.format("Updating custom attribute `%s` is not allowed", attributeDefinition.getName()));
            }
        }
    }

    public void updateObjectCustomAttributeContent(Resource objectType, UUID objectUuid, UUID definitionUuid, String attributeName, List<? extends AttributeContent> attributeContentItems) throws NotFoundException, AttributeException {
        AttributeDefinition attributeDefinition;
        if (definitionUuid != null) {
            attributeDefinition = attributeDefinitionRepository.findByUuid(definitionUuid).orElseThrow(() -> new NotFoundException(AttributeDefinition.class, definitionUuid.toString()));
        } else {
            attributeDefinition = attributeDefinitionRepository.findByTypeAndName(AttributeType.CUSTOM, attributeName).orElseThrow(() -> new NotFoundException(AttributeDefinition.class, attributeName));
        }
        if (attributeDefinition.getType() != AttributeType.CUSTOM) {
            throw new AttributeException("Cannot update content of attribute. Only custom attributes are allowed to be updated directly.", attributeDefinition.getUuid().toString(), attributeDefinition.getName(), attributeDefinition.getType(), null);
        }
        if (!Boolean.TRUE.equals(attributeDefinition.isEnabled())) {
            throw new AttributeException("Cannot update content of disabled attribute.", attributeDefinition.getUuid().toString(), attributeDefinition.getName(), attributeDefinition.getType(), null);
        }

        // Check if attribute is associated with a resource
        attributeRelationRepository.findByResourceAndAttributeDefinitionUuidAndAttributeDefinitionTypeAndAttributeDefinitionEnabled(objectType, attributeDefinition.getUuid(), AttributeType.CUSTOM, true)
                .orElseThrow(() -> new AttributeException("Cannot update content of attribute since it is not associated with resource " + objectType.getLabel(), attributeDefinition.getUuid().toString(), attributeDefinition.getName(), attributeDefinition.getType(), null));

        // filter out updating
        processSecurityFilter(definitionUuid, attributeDefinition);

        // custom attributes content is automatically replaced
        deleteObjectAttributeDefinitionContent(attributeDefinition.getUuid(), objectType, objectUuid);
        if (attributeContentItems != null && !attributeContentItems.isEmpty()) {
            List<BaseAttributeContentV3<?>> contentV3s = AttributeVersionHelper.getBaseAttributeContentV3s(attributeContentItems, attributeDefinition);
            validateAttributeContent(attributeDefinition, contentV3s);
            createObjectAttributeContent(attributeDefinition, ObjectAttributeContentInfo.builder(objectType, objectUuid).build(), contentV3s);
        }
    }

    private void processSecurityFilter(UUID definitionUuid, AttributeDefinition attributeDefinition) throws AttributeException {
        SecurityResourceFilter securityResourceFilter = loadCustomAttributesSecurityResourceFilter();
        if (securityResourceFilter != null) {
            if ((securityResourceFilter.areOnlySpecificObjectsAllowed())) {
                if (!securityResourceFilter.getAllowedObjects().contains(definitionUuid)) {
                    throw new AttributeException(String.format("Updating custom attribute `%s` is not allowed", attributeDefinition.getName()));
                }
            } else {
                if (securityResourceFilter.getForbiddenObjects().contains(definitionUuid)) {
                    throw new AttributeException(String.format("Updating custom attribute `%s` is not allowed", attributeDefinition.getName()));
                }
            }
        }
    }

    private void validateAttributeDefinition(BaseAttribute attribute, UUID connectorUuid) throws AttributeException {
        String connectorUuidStr = connectorUuid == null ? null : connectorUuid.toString();
        if (attribute.getUuid() == null || !UUID_REGEX.matcher(attribute.getUuid()).matches()) {
            throw new AttributeException("Attribute does not have valid UUID", attribute.getUuid(), attribute.getName(), attribute.getType(), connectorUuidStr);
        }
        if (attribute.getName() == null || attribute.getName().isBlank()) {
            throw new AttributeException("Attribute does not have valid name", attribute.getUuid(), attribute.getName(), attribute.getType(), connectorUuidStr);
        }

        if (attribute.getType() == AttributeType.GROUP) {
            AttributeCallback callback = AttributeVersionHelper.getGroupAttributeCallback(attribute);
            if (callback == null) {
                throw new AttributeException("Group attribute does not have callback", attribute.getUuid(), attribute.getName(), attribute.getType(), connectorUuidStr);
            }
        } else if (attribute.getType() == AttributeType.CUSTOM || attribute.getType() == AttributeType.DATA) {
            validateAttributeProperties(attribute, connectorUuidStr);
        }
    }

    private static void validateAttributeProperties(BaseAttribute attribute, String connectorUuidStr) throws AttributeException {
        String label;
        boolean readOnly;
        boolean list;
        boolean multiSelect;
        boolean hasCallback;
        boolean hasContent;
        boolean extensibleList;
        AttributeResource attributeResource = null;
        if (attribute.getType() == AttributeType.CUSTOM) {
            CustomAttributeV3 customAttribute = (CustomAttributeV3) attribute;

            label = customAttribute.getProperties().getLabel();
            readOnly = customAttribute.getProperties().isReadOnly();
            list = customAttribute.getProperties().isList();
            multiSelect = customAttribute.getProperties().isMultiSelect();
            hasCallback = false;
            hasContent = customAttribute.getContent() != null && !customAttribute.getContent().isEmpty();
            extensibleList = customAttribute.getProperties().isExtensibleList();
        } else {
            DataAttribute dataAttribute = (DataAttribute) attribute;

            label = dataAttribute.getProperties().getLabel();
            readOnly = dataAttribute.getProperties().isReadOnly();
            list = dataAttribute.getProperties().isList();
            multiSelect = dataAttribute.getProperties().isMultiSelect();
            hasCallback = dataAttribute.getAttributeCallback() != null;
            hasContent = dataAttribute.getContent() != null && !((List<? extends AttributeContent>) dataAttribute.getContent()).isEmpty();
            attributeResource = dataAttribute.getProperties().getResource();
            extensibleList = dataAttribute.getProperties().isExtensibleList();
        }

        if (label == null || label.isBlank()) {
            throw new AttributeException("Attribute does not have label", attribute.getUuid(), attribute.getName(), attribute.getType(), connectorUuidStr);
        }

        if (multiSelect && !list) {
            throw new AttributeException("Attribute has to be defined as list to be multiselect", attribute.getUuid(), attribute.getName(), attribute.getType(), connectorUuidStr);
        }

        if (extensibleList && !list) {
            throw new AttributeException("Attribute has to be defined as list to be extensible list", attribute.getUuid(), attribute.getName(), attribute.getType(), connectorUuidStr);
        }
        validateResourceAttributeProperties(attribute, connectorUuidStr, attributeResource, hasCallback);

        if (readOnly) {
            if (hasCallback) {
                throw new AttributeException("Read only attribute cannot have callback", attribute.getUuid(), attribute.getName(), attribute.getType(), connectorUuidStr);
            }
            if (!hasContent) {
                throw new AttributeException("Read only attribute must define its content", attribute.getUuid(), attribute.getName(), attribute.getType(), connectorUuidStr);
            }
            if (list) {
                throw new AttributeException("Read only attribute cannot be list", attribute.getUuid(), attribute.getName(), attribute.getType(), connectorUuidStr);
            }
        }


    }

    private static void validateResourceAttributeProperties(BaseAttribute attribute, String connectorUuidStr, AttributeResource attributeResource, boolean hasCallback) throws AttributeException {
        if (attribute instanceof DataAttribute dataAttribute && dataAttribute.getContentType() == AttributeContentType.RESOURCE) {
            if (attributeResource == null)
                throw new AttributeException("Attribute with Resource Content Type is missing resource type in properties", attribute.getUuid(), attribute.getName(), attribute.getType(), connectorUuidStr);
            if (!hasCallback)
                throw new AttributeException("Attribute with Resource Content Type is missing callback", attribute.getUuid(), attribute.getName(), attribute.getType(), connectorUuidStr);
        }
    }

    public static void validateRequestDataAttributes(List<? extends BaseAttribute> definitions, List<? extends RequestAttribute> requestAttributes, boolean strict) throws ValidationException {
        if (definitions == null) {
            definitions = new ArrayList<>();
        }
        if (requestAttributes == null) {
            requestAttributes = new ArrayList<>();
        }

        Map<UUID, DataAttributeV2> mappedDefinitions = definitions.stream().filter(d -> d.getType() == AttributeType.DATA).collect(Collectors.toMap(baseAttribute -> UUID.fromString(baseAttribute.getUuid()), a -> (DataAttributeV2) a));
        Map<String, RequestAttribute> mappedRequestAttributes = requestAttributes.stream().collect(Collectors.toMap(requestAttribute -> requestAttribute.getUuid().toString(), a -> a));

        if (strict) {
            for (RequestAttribute requestAttribute : requestAttributes) {
                if (mappedDefinitions.get(requestAttribute.getUuid()) == null) {
                    throw new ValidationException("Request attribute '%s' does not have definition".formatted(requestAttribute.getName()));
                }
            }
        }

        for (DataAttributeV2 definition : mappedDefinitions.values()) {
            RequestAttribute requestAttribute = mappedRequestAttributes.get(definition.getUuid());
            if (requestAttribute == null) {
                if (definition.getProperties().isRequired()) {
                    throw new ValidationException("Missing Request attribute for required attribute '%s'".formatted(definition.getName()));
                }
                continue;
            }

            // compare name and content type
            if (!definition.getName().equals(requestAttribute.getName())) {
                throw new ValidationException("Data attribute with UUID '%s' and name '%s' has different name in request attribute: '%s'".formatted(definition.getUuid(), definition.getName(), requestAttribute.getName()));
            }
            if (!definition.getContentType().equals(requestAttribute.getContentType())) {
                throw new ValidationException("Data attribute '%s' of content type '%s' has different content type in request attribute: '%s'".formatted(definition.getName(), definition.getContentType().getLabel(), requestAttribute.getContentType().getLabel()));
            }
        }
    }

    public List<ResponseAttribute> getRequestDataAttributesContent(List<BaseAttribute> definitions, List<? extends RequestAttribute> requestAttributes) throws ValidationException {
        if (definitions == null) {
            definitions = new ArrayList<>();
        }
        if (requestAttributes == null) {
            requestAttributes = new ArrayList<>();
        }

        List<ResponseAttribute> responseAttributes = new ArrayList<>();
        Map<String, DataAttribute> mappedDefinitions = definitions.stream().filter(d -> d.getType() == AttributeType.DATA).collect(Collectors.toMap(BaseAttribute::getUuid, a -> (DataAttribute) a));
        for (RequestAttribute requestAttribute : requestAttributes) {
            DataAttribute definition = mappedDefinitions.get(requestAttribute.getUuid().toString());
            if (definition == null) {
                continue;
            }
            responseAttributes.add(AttributeVersionHelper
                    .getResponseAttribute(requestAttribute.getUuid(), requestAttribute.getName(), definition.getProperties().getLabel(), requestAttribute.getContent(), requestAttribute.getContentType(), definition.getType(), requestAttribute.getVersion().getVersion()));
        }
        return responseAttributes;
    }

    public void validateCustomAttributesContent(Resource resource, List<RequestAttribute> attributes) throws ValidationException {
        logger.debug("Validating custom attributes: {}", attributes);
        SecurityResourceFilter securityResourceFilter = loadCustomAttributesSecurityResourceFilter();
        validateCustomAttributesContent(resource, attributes, securityResourceFilter);
    }

    private void validateCustomAttributesContent(Resource resource, List<RequestAttribute> attributes, SecurityResourceFilter securityResourceFilter) throws ValidationException {
        if (attributes == null) {
            attributes = new ArrayList<>();
        }

        List<AttributeRelation> relations = attributeRelationRepository.findByResourceAndAttributeDefinitionType(resource, AttributeType.CUSTOM);

        // filter definitions that are not allowed for user
        Map<String, AttributeDefinition> definitionsMapping;
        if (securityResourceFilter != null) {
            if (securityResourceFilter.areOnlySpecificObjectsAllowed()) {
                definitionsMapping = relations.stream().filter(r -> securityResourceFilter.getAllowedObjects().contains(r.getAttributeDefinition().getUuid())).collect(Collectors.toMap(r -> r.getAttributeDefinition().getName(), AttributeRelation::getAttributeDefinition));
                attributes = attributes.stream().filter(a -> securityResourceFilter.getAllowedObjects().contains(a.getUuid())).toList();
            } else {
                definitionsMapping = relations.stream().filter(r -> !securityResourceFilter.getForbiddenObjects().contains(r.getAttributeDefinition().getUuid())).collect(Collectors.toMap(r -> r.getAttributeDefinition().getName(), AttributeRelation::getAttributeDefinition));
                attributes = attributes.stream().filter(a -> !securityResourceFilter.getForbiddenObjects().contains(a.getUuid())).toList();
            }
        } else {
            definitionsMapping = relations.stream().collect(Collectors.toMap(r -> r.getAttributeDefinition().getName(), AttributeRelation::getAttributeDefinition));
        }

        // no attributes to validate
        if (definitionsMapping.isEmpty() && attributes.isEmpty()) {
            return;
        }

        // check for custom attributes specific validation
        List<ValidationError> errors = new ArrayList<>();
        for (RequestAttribute attribute : attributes) {
            AttributeDefinition definition = definitionsMapping.get(attribute.getName());
            if (definition == null) {
                errors.add(ValidationError.create("Content for custom attribute {} is provided but resource {} is not associated with it", attribute.getName(), resource.getLabel()));
                continue;
            }
            if (!Boolean.TRUE.equals(definition.isEnabled())) {
                errors.add(ValidationError.create("Content for custom attribute {} is provided but attribute is disabled", attribute.getName(), resource.getLabel()));
            }
        }

        // check for general attributes validation
        if (errors.isEmpty()) {
            errors = validateAttributesContent(definitionsMapping, attributes);
        }
        if (!errors.isEmpty()) {
            throw new ValidationException(errors);
        }
    }

    public void deleteConnectorAttributeDefinitionsContent(UUID connectorUuid) {
        // delete data attributes with content
        logger.debug("Deleting data attribute definitions for connector with UUID {}", connectorUuid);
        attributeContent2ObjectRepository.deleteByAttributeContentItemAttributeDefinitionTypeAndConnectorUuid(AttributeType.DATA, connectorUuid);
        attributeContentItemRepository.deleteByAttributeDefinitionTypeAndAttributeDefinitionConnectorUuid(AttributeType.DATA, connectorUuid);
        Long deletedDefinitions = attributeDefinitionRepository.deleteByTypeAndConnectorUuid(AttributeType.DATA, connectorUuid);
        logger.debug("Deleted {} data attribute definitions for connector with UUID {}", deletedDefinitions, connectorUuid);

        // remove connector reference from metadata definitions and content
        // WARNING: connector uuid is removed from all content disregarding attribute type since connector data attributes content was already removed in step before and custom attributes are not linked to connector so it is safe
        attributeDefinitionRepository.removeConnectorByTypeAndConnectorUuid(AttributeType.META, connectorUuid);
        attributeContent2ObjectRepository.removeConnectorByConnectorUuid(connectorUuid);
    }

    public void deleteAttributeDefinition(AttributeType attributeType, UUID definitionUuid) throws NotFoundException {
        AttributeDefinition definition = attributeDefinitionRepository.findByUuidAndType(definitionUuid, attributeType).orElseThrow(() -> new NotFoundException(AttributeDefinition.class, definitionUuid.toString()));
        deleteAllAttributeDefinitionContent(definitionUuid);
        attributeDefinitionRepository.delete(definition);
    }

    public void deleteAttributeDefinition(AttributeType attributeType, UUID connectorUuid, UUID attributeUuid, String name) throws NotFoundException {
        AttributeDefinition definition = attributeDefinitionRepository.findByTypeAndConnectorUuidAndAttributeUuidAndName(attributeType, connectorUuid, attributeUuid, name).orElseThrow(() -> new NotFoundException(AttributeDefinition.class, attributeUuid));
        deleteAllAttributeDefinitionContent(definition.getUuid());
        attributeDefinitionRepository.delete(definition);
    }

    /**
     * Deletes <em>all</em> attribute content rows for the given object across every version, including unversioned rows.
     *
     * <p>This is the correct method when the owning entity is being permanently removed and its entire attribute history
     * should be purged. To delete only the attribute content that belongs to one specific version (e.g. when pruning old version history),
     * use {@link #deleteObjectAttributeContentForVersion} instead.
     */
    public void deleteObjectAttributeContent(Resource objectType, UUID objectUuid) {
        logger.debug("Deleting the attribute content for resource {} with UUID: {}", objectType.getLabel(), objectUuid);
        Long deletedCount = attributeContent2ObjectRepository.deleteByObjectTypeAndObjectUuid(objectType, objectUuid);
        logger.debug("Deleted {} attribute content items for {} with UUID {}", deletedCount, objectType.getLabel(), objectUuid);
    }

    /**
     * Deletes all attribute content rows that belong to a single version of a versioned object, leaving every other
     * version (and any unversioned rows) untouched.
     *
     * <p>This is the version-scoped complement of {@link #deleteObjectAttributeContent}. Use it when you want to
     * prune attribute data for one specific version without affecting the rest of the object's attribute history
     * — for example, when rolling back or expiring an old resource version.
     *
     * <p>{@link #deleteObjectAttributeContent} remains the correct choice for full
     * object deletion, because it removes every attribute row regardless of version.
     */
    public void deleteObjectAttributeContentForVersion(Resource objectType, UUID objectUuid, Integer version) {
        if (version == null) {
            throw new IllegalArgumentException(
                    "deleteObjectAttributeContentForVersion requires a non-null version; " +
                            "use deleteObjectAttributeContent to remove content across all versions");
        }
        logger.debug("Deleting attribute content for resource {} with UUID: {} version: {}",
                objectType.getLabel(), objectUuid, version);
        Long deletedCount = attributeContent2ObjectRepository
                .deleteByObjectTypeAndObjectUuidAndObjectVersion(objectType, objectUuid, version);
        logger.debug("Deleted {} attribute content items for {} with UUID {} version {}",
                deletedCount, objectType.getLabel(), objectUuid, version);
    }

    public void bulkDeleteObjectAttributeContent(Resource objectType, List<UUID> objectUuids) {
        logger.debug("Deleting the attribute content for resource {} with UUIDs: {}", objectType.getLabel(), objectUuids);
        Long deletedCount = attributeContent2ObjectRepository.deleteByObjectTypeAndObjectUuidIn(objectType, objectUuids);
        logger.debug("Deleted {} attribute content items for {} with UUIDs {}", deletedCount, objectType.getLabel(), objectUuids);
    }

    public void deleteObjectAttributesContent(AttributeType attributeType, ObjectAttributeContentInfo contentInfo) {
        logger.debug("Deleting the {} attribute content for resource {} with UUID {}. Info: {}", attributeType.getLabel(), contentInfo.objectType().getLabel(), contentInfo.objectUuid(), contentInfo);
        Long deletedCount = attributeContent2ObjectRepository.deleteByAttributeContentItemAttributeDefinitionTypeAndConnectorUuidAndObjectTypeAndObjectUuidAndSourceObjectTypeAndSourceObjectUuid(attributeType, contentInfo.connectorUuid(), contentInfo.objectType(), contentInfo.objectUuid(), contentInfo.sourceObjectType(), contentInfo.sourceObjectUuid());
        logger.debug("Deleted {} attribute content items for {} with UUID {}", deletedCount, contentInfo.objectType().getLabel(), contentInfo.objectUuid());
    }

    public void deleteObjectAttributesContentBySource(AttributeType attributeType, UUID connectorUuid, Resource objectType, Resource sourceObjectType, UUID sourceObjectUuid) {
        logger.debug("Deleting {} attribute content for all {} objects with source {} {}", attributeType.getLabel(), objectType.getLabel(), sourceObjectType.getLabel(), sourceObjectUuid);
        Long deletedCount = attributeContent2ObjectRepository.deleteByAttributeContentItemAttributeDefinitionTypeAndConnectorUuidAndObjectTypeAndSourceObjectTypeAndSourceObjectUuid(attributeType, connectorUuid, objectType, sourceObjectType, sourceObjectUuid);
        logger.debug("Deleted {} attribute content items for {} objects with source {} {}", deletedCount, objectType.getLabel(), sourceObjectType.getLabel(), sourceObjectUuid);
    }

    public void deleteOperationObjectAttributesContent(AttributeType attributeType, ObjectAttributeContentInfo contentInfo) {
        logger.debug("Deleting the {} attribute content of operation {} for resource {} with UUID {} version {}. Info: {}", attributeType.getLabel(), contentInfo.operation(), contentInfo.objectType().getLabel(), contentInfo.objectUuid(), contentInfo.objectVersion(), contentInfo);
        Long deletedCount;
        if (contentInfo.objectVersion() != null) {
            // Versioned: target only the specified version's rows via the @Modifying @Query.
            deletedCount = attributeContent2ObjectRepository.deleteOperationObjectAttributesByVersion(
                    attributeType, contentInfo.operation(), contentInfo.purpose(),
                    contentInfo.connectorUuid(), contentInfo.objectType(), contentInfo.objectUuid(),
                    contentInfo.objectVersion(),
                    contentInfo.sourceObjectType(), contentInfo.sourceObjectUuid());
        } else {
            // Unversioned (with or without purpose): use the explicit @Modifying @Query that
            // (a) handles null operation via IS NULL matching instead of equality,
            // (b) is scoped to objectVersion IS NULL so it cannot accidentally remove versioned rows.
            deletedCount = attributeContent2ObjectRepository.deleteOperationObjectAttributesUnversioned(
                    attributeType, contentInfo.operation(), contentInfo.purpose(),
                    contentInfo.connectorUuid(), contentInfo.objectType(), contentInfo.objectUuid(),
                    contentInfo.sourceObjectType(), contentInfo.sourceObjectUuid());
        }
        logger.debug("Deleted {} attribute content items for {} with UUID {} version {}", deletedCount, contentInfo.objectType().getLabel(), contentInfo.objectUuid(), contentInfo.objectVersion());
    }

    private void createObjectAttributeContent(AttributeDefinition attributeDefinition, ObjectAttributeContentInfo objectAttributeContentInfo, List<? extends AttributeContent> attributeContentItems) throws AttributeException {
        logger.debug("Creating the attribute content for attribute {} of type {}. Info: {}", attributeDefinition.getName(), attributeDefinition.getType().getLabel(), objectAttributeContentInfo);

        validateAttributeContent(attributeDefinition, attributeContentItems);

        // validateAttributeContent treats null and empty content equivalently for non-required
        // attributes; mirror that contract here. Without this guard the iteration below NPEs on
        // attributeContentItems.size() and surfaces as a 500 with framework-internal message,
        // instead of a clean no-op for an optional attribute the connector left unset.
        if (attributeContentItems == null || attributeContentItems.isEmpty()) {
            return;
        }

        for (int i = 0; i < attributeContentItems.size(); i++) {
            AttributeContent attributeContentItem = attributeContentItems.get(i);
            AttributeContentItem contentItemEntity = null;
            String encryptedData = null;
            // If attribute is encrypted, set data to null before searching for existing content item, since json for encrypted attribute content will always be the same
            if (attributeDefinition.getProtectionLevel() == ProtectionLevel.ENCRYPTED) {
                encryptedData = encryptAttributeContent(attributeDefinition, attributeContentItem);
                attributeContentItem = AttributeVersionHelper.createEncryptedContent(attributeContentItem.getReference(), attributeDefinition.getContentType(), attributeDefinition.getVersion());
            } else {
                // For non-encrypted attributes, try to find existing content item, since json will be different for different content
                contentItemEntity = attributeContentItemRepository.findByJsonAndAttributeDefinitionUuid(attributeContentItem, attributeDefinition.getUuid());
            }

            // check if content item for this attribute definition exists to don't create duplicate items
            if (contentItemEntity != null) {
                // check if that content item is not already assigned to same object+version for meta attribute
                // TODO: do we need to allow duplicate content items for one attribute definition? Maybe if attribute is list or do this check just for META attributes?
                var aco = attributeContent2ObjectRepository.findExistingContentMapping(
                        objectAttributeContentInfo.connectorUuid(), contentItemEntity.getUuid(),
                        objectAttributeContentInfo.objectType(), objectAttributeContentInfo.objectUuid(),
                        objectAttributeContentInfo.objectVersion(),
                        objectAttributeContentInfo.sourceObjectType(), objectAttributeContentInfo.sourceObjectUuid(),
                        objectAttributeContentInfo.purpose());
                if (!aco.isEmpty()) {
                    continue;
                }
            } else {
                contentItemEntity = new AttributeContentItem();
                contentItemEntity.setJson(attributeContentItem);
                contentItemEntity.setAttributeDefinitionUuid(attributeDefinition.getUuid());
                contentItemEntity.setEncryptedData(encryptedData);
                contentItemEntity = attributeContentItemRepository.save(contentItemEntity);
            }

            final AttributeContent2Object objectContentItem = new AttributeContent2Object();
            objectContentItem.setObjectUuid(objectAttributeContentInfo.objectUuid());
            objectContentItem.setObjectType(objectAttributeContentInfo.objectType());
            objectContentItem.setConnectorUuid(objectAttributeContentInfo.connectorUuid());
            objectContentItem.setSourceObjectUuid(objectAttributeContentInfo.sourceObjectUuid());
            objectContentItem.setSourceObjectType(objectAttributeContentInfo.sourceObjectType());
            objectContentItem.setSourceObjectName(objectAttributeContentInfo.sourceObjectName());
            objectContentItem.setPurpose(objectAttributeContentInfo.purpose());
            objectContentItem.setObjectVersion(objectAttributeContentInfo.objectVersion());
            objectContentItem.setOrder(i);
            objectContentItem.setAttributeContentItem(contentItemEntity);
            attributeContent2ObjectRepository.save(objectContentItem);
        }
    }

    public static String encryptAttributeContent(AttributeDefinition attributeDefinition, AttributeContent attributeContentItem) throws AttributeException {
        String encryptedData;
        if ((AttributeContentData.class.isAssignableFrom(attributeDefinition.getContentType().getContentDataClass()))) {
            try {
                encryptedData = SecretsUtil.encryptAndEncodeSecretString(ATTRIBUTES_OBJECT_MAPPER.writeValueAsString(attributeContentItem.getData()), SecretEncodingVersion.V1);
            } catch (JsonProcessingException e) {
                throw new AttributeException("Error encrypting attribute content data: " + e.getMessage(), Objects.toString(attributeDefinition.getUuid(), null), attributeDefinition.getName(), attributeDefinition.getType(), attributeDefinition.getConnectorUuid() == null ? null : attributeDefinition.getConnectorUuid().toString());
            }

        } else {
            encryptedData = SecretsUtil.encryptAndEncodeSecretString(attributeContentItem.getData().toString(), SecretEncodingVersion.V1);
        }
        return encryptedData;
    }

    private List<ValidationError> validateAttributesContent(Map<String, AttributeDefinition> definitionsMapping, List<RequestAttribute> attributes) {
        List<ValidationError> errors = new ArrayList<>();
        for (RequestAttribute attribute : attributes) {
            AttributeDefinition definition = definitionsMapping.get(attribute.getName());
            if (definition == null) {
                errors.add(ValidationError.create("Content for attribute {} is provided but definition is not found", attribute.getName()));
                continue;
            }
            try {
                validateAttributeContent(definition, attribute.getContent());
            } catch (AttributeException e) {
                errors.add(ValidationError.create(e.getMessage()));
            }

            definitionsMapping.remove(attribute.getName());
        }

        // check if there are remaining required attribute definitions that are required but not set
        for (AttributeDefinition definition : definitionsMapping.values()) {
            if (Boolean.TRUE.equals(definition.isRequired())) {
                errors.add(ValidationError.create("Content for required {} attribute {} is not provided.", definition.getType().getLabel(), definition.getName()));
            }
        }

        return errors;
    }

    private void validateAttributeContent(AttributeDefinition attributeDefinition, List<? extends AttributeContent> attributeContent) throws AttributeException {
        String connectorUuidStr = attributeDefinition.getConnectorUuid() == null ? null : attributeDefinition.getConnectorUuid().toString();
        boolean noContent = attributeContent == null || attributeContent.isEmpty();

        if (Boolean.TRUE.equals(attributeDefinition.isRequired()) && noContent) {
            throw new AttributeException("Attribute is required and no content is sent", attributeDefinition.getUuid().toString(), attributeDefinition.getName(), attributeDefinition.getType(), connectorUuidStr);
        }

        // validate read only content to equal to definition content
        validateReadOnlyContent(attributeDefinition, attributeContent, connectorUuidStr);

        if (!noContent) {
            // check for malformed content
            for (AttributeContent contentItem : attributeContent) {
                if (contentItem.getData() == null) {
                    throw new AttributeException("Attribute content is malformed and does not contain data", attributeDefinition.getUuid().toString(), attributeDefinition.getName(), attributeDefinition.getType(), connectorUuidStr);
                }

                validateExtensibleList(attributeDefinition, contentItem, connectorUuidStr);
                validateContentData(attributeDefinition, contentItem, connectorUuidStr);

                List<ValidationError> constraintsValidationErrors = AttributeDefinitionUtils.validateConstraints(attributeDefinition.getDefinition(), attributeContent);
                if (!constraintsValidationErrors.isEmpty()) {
                    throw new AttributeException(constraintsValidationErrors.stream()
                            .map(ValidationError::getErrorDescription)
                            .collect(Collectors.joining(" \n")), attributeDefinition.getUuid().toString(), attributeDefinition.getName(), attributeDefinition.getType(), connectorUuidStr);
                }

                // convert content items to its respective content classes
                validateConvertingContentItemsToClasses(attributeDefinition, contentItem, connectorUuidStr);
            }
        }
    }

    private static void validateExtensibleList(AttributeDefinition attributeDefinition, AttributeContent contentItem, String connectorUuidStr) throws AttributeException {
        boolean extensibleList;
        ProtectionLevel protectionLevel;
        List<AttributeContent> defaultContentItems = attributeDefinition.getDefinition().getContent();
        if (defaultContentItems == null || defaultContentItems.isEmpty()) {
            return;
        }
        if (attributeDefinition.getDefinition() instanceof CustomAttribute customAttribute) {
            if (!customAttribute.getProperties().isList()) {
                return;
            }
            extensibleList = customAttribute.getProperties().isExtensibleList();
            protectionLevel = customAttribute.getProperties().getProtectionLevel();
        } else if (attributeDefinition.getDefinition() instanceof DataAttribute dataAttribute) {
            if (!dataAttribute.getProperties().isList()) {
                return;
            }
            extensibleList = dataAttribute.getProperties().isExtensibleList();
            protectionLevel = dataAttribute.getProperties().getProtectionLevel();
        } else {
            // Other attribute types are not supported for extensible list
            return;
        }

        if (!extensibleList) {
            List<AttributeContent> decryptedContentItems;
            if (protectionLevel == ProtectionLevel.ENCRYPTED) {
                decryptedContentItems = IntStream.range(0, defaultContentItems.size())
                        .mapToObj(i -> AttributeVersionHelper.decryptContent(
                                defaultContentItems.get(i),
                                attributeDefinition.getVersion(),
                                attributeDefinition.getContentType(),
                                attributeDefinition.getEncryptedData().get(i))).toList();
            } else {
                decryptedContentItems = new ArrayList<>(defaultContentItems);
            }
            if (decryptedContentItems.stream().noneMatch(aci -> attributeContentEquals(aci, contentItem))) {
                throw new AttributeException("Attribute content item is not part of predefined list", attributeDefinition.getUuid().toString(), attributeDefinition.getName(), attributeDefinition.getType(), connectorUuidStr);
            }
        }
    }

    private static boolean attributeContentEquals(AttributeContent content1, AttributeContent content2) {
        return Objects.equals(content1.getReference(), content2.getReference()) && Objects.equals(content1.getData(), content2.getData()) && Objects.equals(content1.getContentType(), content2.getContentType());
    }

    private static void validateConvertingContentItemsToClasses(AttributeDefinition attributeDefinition, AttributeContent contentItem, String connectorUuidStr) throws AttributeException {
        try {
            Class<?> contentTypeClass = attributeDefinition.getVersion() == 3 ? contentItem.getClass() : attributeDefinition.getContentType().getContentV2Class();
            ATTRIBUTES_OBJECT_MAPPER.convertValue(contentItem, contentTypeClass);
        } catch (IllegalArgumentException e) {
            throw new AttributeException("Wrong content for attribute of content type " + attributeDefinition.getContentType().getLabel(), attributeDefinition.getUuid().toString(), attributeDefinition.getName(), attributeDefinition.getType(), connectorUuidStr);
        }
    }

    private static void validateContentData(AttributeDefinition attributeDefinition, AttributeContent contentItem, String connectorUuidStr) throws AttributeException {
        if (AttributeContentData.class.isAssignableFrom(attributeDefinition.getContentType().getContentDataClass())) {
            try {
                AttributeContentData data = (AttributeContentData) ATTRIBUTES_OBJECT_MAPPER.convertValue(contentItem.getData(), attributeDefinition.getContentType().getContentDataClass());
                data.validate();
            } catch (ValidationException e) {
                throw new AttributeException(e.getMessage(), attributeDefinition.getUuid().toString(), attributeDefinition.getName(), attributeDefinition.getType(), connectorUuidStr);
            } catch (IllegalArgumentException e) {
                throw new AttributeException("Malformed attribute content data: " + e.getMessage(), attributeDefinition.getUuid().toString(), attributeDefinition.getName(), attributeDefinition.getType(), connectorUuidStr);
            }
        }
    }

    private static void validateReadOnlyContent(AttributeDefinition attributeDefinition, List<? extends AttributeContent> attributeContent, String connectorUuidStr) throws AttributeException {
        if (Boolean.TRUE.equals(attributeDefinition.isReadOnly())) {
            Object definitionContent = attributeDefinition.getDefinition().getContent();
            if (attributeContent == null || !attributeContent.equals(definitionContent)) {
                throw new AttributeException("Wrong value of read only attribute " + attributeDefinition.getLabel(), attributeDefinition.getUuid().toString(), attributeDefinition.getName(), attributeDefinition.getType(), connectorUuidStr);
            }
        }
    }

    public void deleteObjectAttributeContentByType(AttributeType attributeType, Resource objectType, UUID objectUuid) {
        logger.debug("Deleting the {} attributes content for {} with UUID: {}", attributeType.getLabel(), objectType.getLabel(), objectUuid);
        Long deletedCount = attributeContent2ObjectRepository.deleteByAttributeContentItemAttributeDefinitionTypeAndObjectTypeAndObjectUuid(attributeType, objectType, objectUuid);
        logger.debug("Deleted {} attribute content items for {} with UUID {}", deletedCount, objectType.getLabel(), objectUuid);
    }

    public void deleteObjectAllowedCustomAttributeContent(SecurityResourceFilter securityResourceFilter, Resource objectType, UUID objectUuid) {
        Long deletedCount;
        if ((securityResourceFilter.areOnlySpecificObjectsAllowed())) {
            logger.debug("Deleting allowed custom attributes content for {} with UUID: {}", objectType.getLabel(), objectUuid);
            deletedCount = attributeContent2ObjectRepository.deleteByAttributeContentItemAttributeDefinitionTypeAndAttributeContentItemAttributeDefinitionUuidInAndObjectTypeAndObjectUuid(AttributeType.CUSTOM, securityResourceFilter.getAllowedObjects(), objectType, objectUuid);
        } else {
            logger.debug("Deleting not forbidden custom attributes content for {} with UUID: {}", objectType.getLabel(), objectUuid);
            deletedCount = attributeContent2ObjectRepository.deleteByAttributeContentItemAttributeDefinitionTypeAndAttributeContentItemAttributeDefinitionUuidNotInAndObjectTypeAndObjectUuid(AttributeType.CUSTOM, securityResourceFilter.getForbiddenObjects(), objectType, objectUuid);
        }
        logger.debug("Deleted {} attribute content items for {} with UUID {}", deletedCount, objectType.getLabel(), objectUuid);
    }

    private void deleteAllAttributeDefinitionContent(UUID definitionUuid) {
        Long deletedCount = attributeContent2ObjectRepository.deleteByAttributeContentItemAttributeDefinitionUuid(definitionUuid);
        attributeRelationRepository.deleteByAttributeDefinitionUuid(definitionUuid);
        attributeContentItemRepository.deleteByAttributeDefinitionUuid(definitionUuid);
        logger.debug("Deleted {} attribute content items for attribute with UUID {}", deletedCount, definitionUuid);
    }

    private void deleteObjectAttributeDefinitionContent(UUID definitionUuid, Resource objectType, UUID objectUuid) {
        Long deletedCount = attributeContent2ObjectRepository.deleteByObjectTypeAndObjectUuidAndAttributeContentItemAttributeDefinitionUuid(objectType, objectUuid, definitionUuid);
        logger.debug("Deleted {} attribute content items for {} with UUID {} for attribute {}", deletedCount, objectType.getLabel(), objectUuid, definitionUuid);
    }

    /**
     * Version-scoped variant: when {@code objectVersion} is non-null, deletes only the rows belonging to that specific version.
     * Falls back to the unversioned (all-versions) delete when {@code objectVersion} is null.
     */
    private void deleteObjectAttributeDefinitionContent(UUID definitionUuid, Resource objectType, UUID objectUuid, Integer objectVersion) {
        Long deletedCount;
        if (objectVersion != null) {
            deletedCount = attributeContent2ObjectRepository
                    .deleteByObjectTypeAndObjectUuidAndObjectVersionAndAttributeContentItemAttributeDefinitionUuid(
                            objectType, objectUuid, objectVersion, definitionUuid);
            logger.debug("Deleted {} attribute content items for {} with UUID {} version {} for attribute {}",
                    deletedCount, objectType.getLabel(), objectUuid, objectVersion, definitionUuid);
        } else {
            deletedCount = attributeContent2ObjectRepository
                    .deleteByObjectTypeAndObjectUuidAndAttributeContentItemAttributeDefinitionUuid(
                            objectType, objectUuid, definitionUuid);
            logger.debug("Deleted {} attribute content items for {} with UUID {} for attribute {}", deletedCount, objectType.getLabel(), objectUuid, definitionUuid);
        }
    }

    private SecurityResourceFilter loadCustomAttributesSecurityResourceFilter() {
        // if user is anonymous or protocol user, allow all custom attribute content for sake of system processes and protocol operations
        boolean loadAllContent;
        try {
            loadAllContent = AuthHelper.isLoggedProtocolUser();
        } catch (ValidationException ex) {
            // anonymous user
            // NOTE: subject to change in case of anonymous user needs custom attributes content
            loadAllContent = false;
        }

        return loadAllContent ? null : authHelper.loadObjectPermissions(Resource.ATTRIBUTE, ResourceAction.MEMBERS);
    }
}
