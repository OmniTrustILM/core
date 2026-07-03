package com.otilm.core.service;

import com.otilm.api.exception.AlreadyExistException;
import com.otilm.api.exception.AttributeException;
import com.otilm.api.exception.NotFoundException;
import com.otilm.api.exception.ValidationException;
import com.otilm.api.model.client.attribute.custom.CustomAttributeCreateRequestDto;
import com.otilm.api.model.client.attribute.custom.CustomAttributeDefinitionDetailDto;
import com.otilm.api.model.client.attribute.custom.CustomAttributeDefinitionDto;
import com.otilm.api.model.client.attribute.custom.CustomAttributeUpdateRequestDto;
import com.otilm.api.model.common.NameAndUuidDto;
import com.otilm.api.model.common.attribute.common.AttributeType;
import com.otilm.api.model.common.attribute.common.CustomAttribute;
import com.otilm.api.model.common.attribute.common.content.data.ProtectionLevel;
import com.otilm.api.model.common.attribute.v2.*;
import com.otilm.api.model.common.attribute.common.content.AttributeContentType;
import com.otilm.api.model.common.attribute.common.properties.CustomAttributeProperties;
import com.otilm.api.model.common.attribute.common.properties.MetadataAttributeProperties;
import com.otilm.api.model.common.attribute.v3.CustomAttributeV3;
import com.otilm.api.model.common.attribute.v3.content.BaseAttributeContentV3;
import com.otilm.api.model.common.attribute.v3.content.StringAttributeContentV3;
import com.otilm.api.model.core.auth.Resource;
import com.otilm.core.dao.entity.AttributeContentItem;
import com.otilm.core.dao.entity.AttributeDefinition;
import com.otilm.core.dao.repository.AttributeContentItemRepository;
import com.otilm.core.dao.repository.AttributeDefinitionRepository;
import com.otilm.core.security.authz.SecurityFilter;
import com.otilm.core.util.BaseSpringBootTest;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;

import java.util.List;
import java.util.UUID;

class CustomAttributeServiceTest extends BaseSpringBootTest {

    @Autowired
    private AttributeExternalService attributeService;

    @Autowired
    private AttributeInternalService attributeInternalService;

    @Autowired
    private AttributeDefinitionRepository attributeDefinitionRepository;

    private AttributeDefinition definition;
    private CustomAttributeV3 attribute;
    private AttributeDefinition metaDefinition;

    @Autowired
    private AttributeContentItemRepository attributeContentItemRepository;

    @BeforeEach
    void setUp() {
        attribute = new CustomAttributeV3();
        attribute.setUuid("87e968ca-9404-4128-8b58-3ab5db2ba06e");
        attribute.setName("attribute");
        attribute.setDescription("Attribute");
        attribute.setType(AttributeType.CUSTOM);
        attribute.setContentType(AttributeContentType.STRING);
        CustomAttributeProperties urlProperties = new CustomAttributeProperties();
        urlProperties.setLabel("Attribute");
        urlProperties.setRequired(true);
        urlProperties.setReadOnly(false);
        urlProperties.setVisible(true);
        urlProperties.setList(false);
        urlProperties.setMultiSelect(false);
        attribute.setProperties(urlProperties);

        MetadataAttributeV2 metaAttribute = new MetadataAttributeV2();
        metaAttribute.setUuid("87e968ca-9404-4128-8b58-3ab5db2ba07e");
        metaAttribute.setName("attribute1");
        metaAttribute.setDescription("Attribute1");
        metaAttribute.setType(AttributeType.META);
        metaAttribute.setContentType(AttributeContentType.STRING);
        MetadataAttributeProperties properties = new MetadataAttributeProperties();
        properties.setLabel("Attribute1");
        properties.setVisible(true);
        metaAttribute.setProperties(properties);

        definition = new AttributeDefinition();
        definition.setDefinition(attribute);
        definition.setName(attribute.getName());
        definition.setAttributeUuid(UUID.fromString(attribute.getUuid()));
        definition.setContentType(attribute.getContentType());
        definition.setType(AttributeType.CUSTOM);
        definition.setEnabled(true);
        definition.setLabel(attribute.getProperties().getLabel());
        definition.setRequired(attribute.getProperties().isRequired());
        definition.setReadOnly(attribute.getProperties().isReadOnly());
        attributeDefinitionRepository.save(definition);

        metaDefinition = new AttributeDefinition();
        metaDefinition.setDefinition(metaAttribute);
        metaDefinition.setName(metaAttribute.getName());
        metaDefinition.setAttributeUuid(UUID.fromString(metaAttribute.getUuid()));
        metaDefinition.setContentType(metaAttribute.getContentType());
        metaDefinition.setType(AttributeType.META);
        metaDefinition.setEnabled(true);
        metaDefinition.setLabel(metaAttribute.getProperties().getLabel());
        attributeDefinitionRepository.save(metaDefinition);
    }

    @Test
    void testListAttributes() {
        List<CustomAttributeDefinitionDto> attributes = attributeService.listCustomAttributes(SecurityFilter.create(), null);
        Assertions.assertNotNull(attributes);
        Assertions.assertFalse(attributes.isEmpty());
        Assertions.assertEquals(1, attributes.size());
        Assertions.assertEquals(attribute.getUuid(), attributes.getFirst().getUuid());
        Assertions.assertEquals(attribute.getName(), attributes.getFirst().getName());
        Assertions.assertEquals(attribute.getProperties().getLabel(), attributes.getFirst().getLabel());
    }

    @Test
    void testGetAttribute() throws NotFoundException {
        CustomAttributeDefinitionDetailDto dto = attributeService.getCustomAttribute(definition.getUuid());
        Assertions.assertNotNull(dto);
        Assertions.assertFalse(dto.getUuid().isEmpty());
        Assertions.assertEquals(attribute.getUuid(), dto.getUuid());
        Assertions.assertEquals(attribute.getName(), dto.getName());
        Assertions.assertEquals(AttributeType.CUSTOM, attribute.getType());
        Assertions.assertEquals(AttributeContentType.STRING, attribute.getContentType());
    }

    @Test
    void testGetAttributeNotFound() {
        Assertions.assertThrows(NotFoundException.class, () -> attributeService.getCustomAttribute(metaDefinition.getUuid()));
    }

    @Test
    void testCreateAttribute() throws ValidationException, AlreadyExistException, AttributeException {
        CustomAttributeCreateRequestDto request = new CustomAttributeCreateRequestDto();
        request.setName("testAttribute");
        request.setDescription("Sample description");
        request.setLabel("TestAttribute");
        request.setContentType(AttributeContentType.RESOURCE);
        request.setRequired(true);
        request.setVisible(true);
        request.setResources(List.of(Resource.USER, Resource.ROLE));
        Assertions.assertThrows(AttributeException.class, () -> attributeService.createCustomAttribute(request));


        request.setContentType(AttributeContentType.STRING);
        CustomAttributeDefinitionDetailDto response = attributeService.createCustomAttribute(request);
        Assertions.assertNotNull(response);
        Assertions.assertFalse(response.getUuid().isEmpty());
        Assertions.assertEquals(request.getName(), response.getName());
        Assertions.assertEquals(AttributeType.CUSTOM, response.getType());
        Assertions.assertEquals(AttributeContentType.STRING, request.getContentType());
        Assertions.assertEquals(2, request.getResources().size());


        request.setName("testAttribute2");
        request.setLabel("TestAttribute2");
        request.setContent(List.of(new StringAttributeContentV3("content")));
        response = attributeService.createCustomAttribute(request);
        Assertions.assertEquals(request.getContent().getFirst().getData().toString(), response.getContent().getFirst().getData().toString());

        request.setName("encryptedAttribute");
        request.setLabel("EncryptedAttribute");
        request.setProtectionLevel(ProtectionLevel.ENCRYPTED);
        request.setContent(List.of(new StringAttributeContentV3("content"), new StringAttributeContentV3("content2")));
        response = attributeService.createCustomAttribute(request);

        AttributeDefinition encryptedDefinition = attributeDefinitionRepository.findByUuid(UUID.fromString(response.getUuid())).orElseThrow();
        Assertions.assertEquals(ProtectionLevel.ENCRYPTED, encryptedDefinition.getProtectionLevel());
        Assertions.assertNotNull(response.getContent().getFirst().getData());
        Assertions.assertEquals("content", response.getContent().getFirst().getData().toString());
        Assertions.assertEquals("content2", response.getContent().getLast().getData().toString());
        Assertions.assertNull(((List<StringAttributeContentV3>) encryptedDefinition.getDefinition().getContent()).getFirst().getData());
        Assertions.assertNotNull(encryptedDefinition.getEncryptedData());
    }

    @Test
    void testCreateAttributeAlreadyExistsException() throws ValidationException {
        CustomAttributeCreateRequestDto request = new CustomAttributeCreateRequestDto();
        request.setName("attribute");
        request.setDescription("Attribute");
        request.setLabel("Attribute");
        request.setContentType(AttributeContentType.STRING);
        request.setRequired(true);
        request.setVisible(true);

        Assertions.assertThrows(AlreadyExistException.class, () -> attributeService.createCustomAttribute(request));
    }

    @Test
    void testCreateAttributeValidationException() throws ValidationException {
        CustomAttributeCreateRequestDto request = new CustomAttributeCreateRequestDto();

        Assertions.assertThrows(AttributeException.class, () -> attributeService.createCustomAttribute(request));
    }

    @Test
    void testEditAttribute() throws NotFoundException, AttributeException {
        CustomAttributeUpdateRequestDto request = new CustomAttributeUpdateRequestDto();
        request.setLabel("Updated Attribute");
        request.setDescription("Desc");
        request.setResources(List.of(Resource.RA_PROFILE));

        CustomAttributeDefinitionDetailDto response = attributeService.editCustomAttribute(definition.getUuid(), request);
        Assertions.assertEquals(request.getDescription(), response.getDescription());
        Assertions.assertEquals(request.getLabel(), response.getLabel());
        Assertions.assertEquals(1, response.getResources().size());

        request.setContent(List.of(new StringAttributeContentV3("new")));
        response = attributeService.editCustomAttribute(definition.getUuid(), request);
        Assertions.assertEquals("new", response.getContent().getFirst().getData());

        AttributeContentItem contentItem = new AttributeContentItem();
        contentItem.setJson(new StringAttributeContentV3("encrypted"));
        contentItem.setAttributeDefinitionUuid(UUID.fromString(response.getUuid()));
        attributeContentItemRepository.save(contentItem);

        request.setProtectionLevel(ProtectionLevel.ENCRYPTED);
        response = attributeService.editCustomAttribute(definition.getUuid(), request);
        AttributeDefinition encryptedDefinition = attributeDefinitionRepository.findByUuid(UUID.fromString(response.getUuid())).orElseThrow();
        Assertions.assertEquals(ProtectionLevel.ENCRYPTED, encryptedDefinition.getProtectionLevel());
        Assertions.assertNotNull(response.getContent().getFirst().getData());
        Assertions.assertNull(((List<StringAttributeContentV3>) encryptedDefinition.getDefinition().getContent()).getFirst().getData());
        Assertions.assertNotNull(encryptedDefinition.getEncryptedData());

        contentItem = attributeContentItemRepository.findByAttributeDefinitionUuid(UUID.fromString(response.getUuid())).getFirst();
        Assertions.assertNull(contentItem.getJson().getData());
        Assertions.assertNotNull(contentItem.getEncryptedData());

        request.setProtectionLevel(ProtectionLevel.NONE);
        response = attributeService.editCustomAttribute(definition.getUuid(), request);
        encryptedDefinition = attributeDefinitionRepository.findByUuid(UUID.fromString(response.getUuid())).orElseThrow();
        Assertions.assertEquals(ProtectionLevel.NONE, encryptedDefinition.getProtectionLevel());
        Assertions.assertEquals("new", response.getContent().getFirst().getData());
        Assertions.assertNotNull(((List<StringAttributeContentV3>) encryptedDefinition.getDefinition().getContent()).getFirst().getData());
        Assertions.assertNull(encryptedDefinition.getEncryptedData());

        contentItem = attributeContentItemRepository.findByAttributeDefinitionUuid(UUID.fromString(response.getUuid())).getFirst();
        Assertions.assertEquals("encrypted", contentItem.getJson().getData());
        Assertions.assertNull(contentItem.getEncryptedData());
    }

    @Test
    void testEditAttributeNotFoundException() {
        CustomAttributeUpdateRequestDto request = new CustomAttributeUpdateRequestDto();
        request.setLabel("Updated Attribute");
        request.setDescription("Desc");

        Assertions.assertThrows(NotFoundException.class, () -> attributeService.editCustomAttribute(metaDefinition.getUuid(), request));
    }

    @Test
    void testEnableAttribute() throws NotFoundException {
        attributeService.enableCustomAttribute(definition.getUuid(), true);
        CustomAttributeDefinitionDetailDto dto = attributeService.getCustomAttribute(definition.getUuid());
        Assertions.assertEquals(true, dto.isEnabled());
    }

    @Test
    void testEnableAttributeNotFoundException() {
        Assertions.assertThrows(NotFoundException.class, () -> attributeService.enableCustomAttribute(metaDefinition.getUuid(), true));
    }

    @Test
    void testDisableAttribute() throws NotFoundException {
        attributeService.enableCustomAttribute(definition.getUuid(), false);
        CustomAttributeDefinitionDetailDto dto = attributeService.getCustomAttribute(definition.getUuid());
        Assertions.assertEquals(false, dto.isEnabled());
    }

    @Test
    void testDisableAttributeNotFoundException() {
        Assertions.assertThrows(NotFoundException.class, () -> attributeService.enableCustomAttribute(metaDefinition.getUuid(), false));
    }

    @Test
    void testDeleteAttribute() throws NotFoundException {
        attributeService.deleteCustomAttribute(definition.getUuid());
        Assertions.assertThrows(NotFoundException.class, () -> attributeService.getCustomAttribute(definition.getUuid()));
    }

    @Test
    void testDeleteAttributeNotFoundException() {
        Assertions.assertThrows(NotFoundException.class, () -> attributeService.deleteCustomAttribute(metaDefinition.getUuid()));
    }

    @Test
    void testBulkEnableAttribute() throws NotFoundException {
        attributeService.bulkEnableCustomAttributes(List.of(definition.getUuid().toString()), true);
        CustomAttributeDefinitionDetailDto dto = attributeService.getCustomAttribute(definition.getUuid());
        Assertions.assertEquals(true, dto.isEnabled());
    }

    @Test
    void testBulkDisableAttribute() throws NotFoundException {
        attributeService.bulkEnableCustomAttributes(List.of(definition.getUuid().toString()), false);
        CustomAttributeDefinitionDetailDto dto = attributeService.getCustomAttribute(definition.getUuid());
        Assertions.assertEquals(false, dto.isEnabled());
    }

    @Test
    void testBulkDeleteAttribute() {
        attributeService.bulkDeleteCustomAttributes(List.of(definition.getUuid().toString()));
        Assertions.assertThrows(NotFoundException.class, () -> attributeService.getCustomAttribute(definition.getUuid()));
    }

    @Test
    void testUpdateResource() throws NotFoundException {
        attributeService.updateResources(definition.getUuid(), List.of(Resource.ROLE, Resource.CREDENTIAL));
        List<CustomAttribute> attributes = attributeService.getResourceAttributes(SecurityFilter.create(), Resource.ROLE);
        Assertions.assertEquals(1, attributes.size());
        Assertions.assertEquals(attribute.getUuid(), attributes.getFirst().getUuid());
    }

    @Test
    void testUpdateResourceFailure() throws ValidationException {
        UUID uuid = definition.getUuid();
        List<Resource> auditLog = List.of(Resource.AUDIT_LOG);
        Assertions.assertThrows(ValidationException.class, () -> attributeService.updateResources(uuid, auditLog));
    }

    @Test
    void testGetResourceAttributesWithValue() throws NotFoundException, AttributeException {
        attributeService.updateResources(definition.getUuid(), List.of(Resource.ROLE, Resource.CREDENTIAL));
        List<CustomAttribute> attributes = attributeService.getResourceAttributes(SecurityFilter.create(), Resource.ROLE);
        Assertions.assertEquals(1, attributes.size());
        CustomAttributeUpdateRequestDto request = new CustomAttributeUpdateRequestDto();
        request.setLabel(definition.getLabel());
        request.setProtectionLevel(ProtectionLevel.ENCRYPTED);
        request.setContent(List.of(new StringAttributeContentV3("value")));
        attributeService.editCustomAttribute(definition.getUuid(), request);
        attributes = attributeService.getResourceAttributes(SecurityFilter.create(), Resource.ROLE);
        Assertions.assertNotNull(((List<BaseAttributeContentV3<?>>)attributes.getFirst().getContent()).getFirst().getData());
    }

    @Test
    void testGetResourceObject() throws NotFoundException {
        Assertions.assertThrows(NotFoundException.class, () -> attributeInternalService.getResourceObjectInternal(UUID.randomUUID()));
        NameAndUuidDto nameAndUuidDto = attributeInternalService.getResourceObjectInternal(definition.getUuid());
        Assertions.assertEquals(definition.getUuid().toString(), nameAndUuidDto.getUuid());
        Assertions.assertEquals(definition.getName(), nameAndUuidDto.getName());

        nameAndUuidDto = attributeInternalService.getResourceObjectExternal(definition.getSecuredUuid());
        Assertions.assertEquals(definition.getUuid().toString(), nameAndUuidDto.getUuid());
        Assertions.assertEquals(definition.getName(), nameAndUuidDto.getName());

    }
}
