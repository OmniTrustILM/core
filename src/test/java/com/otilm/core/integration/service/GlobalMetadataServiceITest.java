package com.otilm.core.integration.service;

import com.otilm.api.exception.AlreadyExistException;
import com.otilm.api.exception.AttributeException;
import com.otilm.api.exception.NotFoundException;
import com.otilm.api.exception.ValidationException;
import com.otilm.api.model.client.attribute.AttributeDefinitionDto;
import com.otilm.api.model.client.attribute.metadata.ConnectorMetadataResponseDto;
import com.otilm.api.model.client.attribute.metadata.GlobalMetadataCreateRequestDto;
import com.otilm.api.model.client.attribute.metadata.GlobalMetadataDefinitionDetailDto;
import com.otilm.api.model.client.attribute.metadata.GlobalMetadataUpdateRequestDto;
import com.otilm.api.model.client.connector.v2.ConnectorVersion;
import com.otilm.api.model.common.attribute.common.AttributeType;
import com.otilm.api.model.common.attribute.v2.DataAttributeV2;
import com.otilm.api.model.common.attribute.v2.MetadataAttributeV2;
import com.otilm.api.model.common.attribute.common.content.AttributeContentType;
import com.otilm.api.model.common.attribute.common.properties.DataAttributeProperties;
import com.otilm.api.model.common.attribute.common.properties.MetadataAttributeProperties;
import com.otilm.api.model.core.connector.ConnectorStatus;
import com.otilm.core.dao.entity.AttributeDefinition;
import com.otilm.core.dao.entity.Connector;
import com.otilm.core.dao.repository.*;
import com.otilm.core.dao.repository.AttributeDefinitionRepository;
import com.otilm.core.dao.repository.ConnectorRepository;
import com.otilm.core.service.AttributeExternalService;
import com.otilm.core.util.BaseSpringBootTest;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;

import java.util.List;
import java.util.Optional;
import java.util.UUID;

class GlobalMetadataServiceITest extends BaseSpringBootTest {

    @Autowired
    private AttributeExternalService attributeService;

    @Autowired
    private AttributeDefinitionRepository attributeDefinitionRepository;

    @Autowired
    private ConnectorRepository connectorRepository;

    private Connector connector;
    private AttributeDefinition definition;
    private DataAttributeV2 attribute;
    private MetadataAttributeV2 metaAttribute;
    private MetadataAttributeV2 connectorMetaAttribute;
    private AttributeDefinition metaDefinition;
    private AttributeDefinition connectorMetaDefinition;

    @BeforeEach
    void setUp() {
        connector = new Connector();
        connector.setName("test");
        connector.setUrl("http://localhost:3665");
        connector.setVersion(ConnectorVersion.V1);
        connector.setStatus(ConnectorStatus.CONNECTED);
        connector = connectorRepository.save(connector);

        attribute = new DataAttributeV2();
        attribute.setUuid("87e968ca-9404-4128-8b58-3ab5db2ba06e");
        attribute.setName("attribute");
        attribute.setDescription("Attribute");
        attribute.setType(AttributeType.DATA);
        attribute.setContentType(AttributeContentType.STRING);
        DataAttributeProperties urlProperties = new DataAttributeProperties();
        urlProperties.setLabel("Attribute");
        urlProperties.setRequired(true);
        urlProperties.setReadOnly(false);
        urlProperties.setVisible(true);
        urlProperties.setList(false);
        urlProperties.setMultiSelect(false);
        attribute.setProperties(urlProperties);

        metaAttribute = new MetadataAttributeV2();
        metaAttribute.setUuid("87e968ca-9404-4128-8b58-3ab5db2ba07e");
        metaAttribute.setName("attribute1");
        metaAttribute.setDescription("Attribute1");
        metaAttribute.setType(AttributeType.META);
        metaAttribute.setContentType(AttributeContentType.STRING);
        MetadataAttributeProperties properties = new MetadataAttributeProperties();
        properties.setLabel("Attribute1");
        properties.setVisible(true);
        properties.setGlobal(true);
        metaAttribute.setProperties(properties);

        connectorMetaAttribute = new MetadataAttributeV2();
        connectorMetaAttribute.setUuid("87e968ca-9404-4128-8b58-3ab5db2ba08e");
        connectorMetaAttribute.setName("connectorAttribute");
        connectorMetaAttribute.setDescription("Connector Attribute");
        connectorMetaAttribute.setType(AttributeType.META);
        connectorMetaAttribute.setContentType(AttributeContentType.STRING);
        MetadataAttributeProperties connectorProperties = new MetadataAttributeProperties();
        connectorProperties.setLabel("Connector Attribute");
        connectorProperties.setVisible(true);
        connectorMetaAttribute.setProperties(connectorProperties);

        definition = new AttributeDefinition();
        definition.setDefinition(attribute);
        definition.setName(attribute.getName());
        definition.setAttributeUuid(UUID.fromString(attribute.getUuid()));
        definition.setContentType(attribute.getContentType());
        definition.setType(AttributeType.DATA);
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
        metaDefinition.setGlobal(true);
        metaDefinition.setLabel(metaAttribute.getProperties().getLabel());
        attributeDefinitionRepository.save(metaDefinition);

        connectorMetaDefinition = new AttributeDefinition();
        connectorMetaDefinition.setDefinition(connectorMetaAttribute);
        connectorMetaDefinition.setName(connectorMetaAttribute.getName());
        connectorMetaDefinition.setAttributeUuid(UUID.fromString(connectorMetaAttribute.getUuid()));
        connectorMetaDefinition.setContentType(connectorMetaAttribute.getContentType());
        connectorMetaDefinition.setType(AttributeType.META);
        connectorMetaDefinition.setConnectorUuid(connector.getUuid());
        connectorMetaDefinition.setGlobal(false);
        connectorMetaDefinition.setLabel(connectorMetaAttribute.getProperties().getLabel());
        attributeDefinitionRepository.save(connectorMetaDefinition);
    }

    @Test
    void testListGlobalMetadata() {
        List<AttributeDefinitionDto> metadata = attributeService.listGlobalMetadata();
        Assertions.assertNotNull(metadata);
        Assertions.assertFalse(metadata.isEmpty());
        Assertions.assertEquals(1, metadata.size());
        Assertions.assertEquals(metaDefinition.getUuid().toString(), metadata.get(0).getUuid());
        Assertions.assertEquals(((MetadataAttributeV2) metaDefinition.getDefinition()).getProperties().getLabel(), metadata.getFirst().getLabel());
    }

    @Test
    void testGetGlobalMetadata() throws NotFoundException {
        GlobalMetadataDefinitionDetailDto dto = attributeService.getGlobalMetadata(metaDefinition.getUuid());
        Assertions.assertNotNull(dto);
        Assertions.assertFalse(dto.getUuid().isEmpty());
        Assertions.assertEquals(metaDefinition.getUuid().toString(), dto.getUuid());
        Assertions.assertEquals(metaAttribute.getName(), dto.getName());
        Assertions.assertEquals(AttributeType.META, metaAttribute.getType());
        Assertions.assertEquals(AttributeContentType.STRING, metaAttribute.getContentType());
    }

    @Test
    void testGlobalAttributeNotFound() {
        Assertions.assertThrows(NotFoundException.class, () -> attributeService.getGlobalMetadata(UUID.fromString(attribute.getUuid())));
    }

    @Test
    void testCreateGlobalMetadata() throws ValidationException, AlreadyExistException, AttributeException {
        GlobalMetadataCreateRequestDto request = new GlobalMetadataCreateRequestDto();
        request.setName("testAttribute");
        request.setDescription("Sample description");
        request.setLabel("TestAttribute");
        request.setContentType(AttributeContentType.RESOURCE);
        request.setVisible(true);
        Assertions.assertThrows(AttributeException.class, () -> attributeService.createGlobalMetadata(request));

        request.setContentType(AttributeContentType.STRING);
        GlobalMetadataDefinitionDetailDto response = attributeService.createGlobalMetadata(request);
        Assertions.assertNotNull(response);
        Assertions.assertFalse(response.getUuid().isEmpty());
        Assertions.assertEquals(request.getName(), response.getName());
        Assertions.assertEquals(AttributeType.META, response.getType());
        Assertions.assertEquals(AttributeContentType.STRING, request.getContentType());
    }

    @Test
    void testCreateGlobalMetadataAlreadyExistsException() throws ValidationException {
        GlobalMetadataCreateRequestDto request = new GlobalMetadataCreateRequestDto();
        request.setName("attribute1");
        request.setDescription("Attribute");
        request.setLabel("Attribute");
        request.setContentType(AttributeContentType.STRING);
        request.setVisible(true);

        Assertions.assertThrows(AlreadyExistException.class, () -> attributeService.createGlobalMetadata(request));
    }

    @Test
    void testCreateGlobalMetadataValidationException() throws ValidationException {
        GlobalMetadataCreateRequestDto request = new GlobalMetadataCreateRequestDto();

        Assertions.assertThrows(AttributeException.class, () -> attributeService.createGlobalMetadata(request));
    }

    @Test
    void testEditGlobalMetadata() throws NotFoundException, AttributeException {
        GlobalMetadataUpdateRequestDto request = new GlobalMetadataUpdateRequestDto();
        request.setLabel("Updated Attribute");
        request.setDescription("Desc");

        GlobalMetadataDefinitionDetailDto response = attributeService.editGlobalMetadata(metaDefinition.getUuid(), request);
        Assertions.assertEquals(request.getDescription(), response.getDescription());
        Assertions.assertEquals(request.getLabel(), response.getLabel());
    }

    @Test
    void testEditGlobalMetadataNotFoundException() {
        GlobalMetadataUpdateRequestDto request = new GlobalMetadataUpdateRequestDto();
        request.setLabel("Updated Attribute");
        request.setDescription("Desc");

        Assertions.assertThrows(NotFoundException.class, () -> attributeService.editGlobalMetadata(UUID.fromString(attribute.getUuid()), request));
    }

    @Test
    void testGlobalMetadataAttribute() throws NotFoundException {
        attributeService.demoteConnectorMetadata(metaDefinition.getUuid());
        Assertions.assertThrows(NotFoundException.class, () -> attributeService.getGlobalMetadata(metaDefinition.getUuid()));
    }

    @Test
    void testDeleteGlobalMetadataNotFoundException() {
        Assertions.assertThrows(NotFoundException.class, () -> attributeService.demoteConnectorMetadata(UUID.fromString(attribute.getUuid())));
    }

    @Test
    void testBulkDeleteGlobalMetadata() {
        attributeService.bulkDeleteCustomAttributes(List.of(metaDefinition.getUuid().toString()));
        Assertions.assertThrows(NotFoundException.class, () -> attributeService.getCustomAttribute(metaDefinition.getUuid()));
    }

    @Test
    void getConnectorMetadata() {
        List<ConnectorMetadataResponseDto> metadata = attributeService.getConnectorMetadata(Optional.empty());
        Assertions.assertEquals(1, metadata.size());
        Assertions.assertEquals(metadata.get(0).getUuid(), connectorMetaAttribute.getUuid());
        Assertions.assertEquals(metadata.get(0).getName(), connectorMetaAttribute.getName());
    }

    @Test
    void getConnectorMetadata_ItemNotFound() {
        connectorMetaDefinition.setConnectorUuid(null);
        attributeDefinitionRepository.save(connectorMetaDefinition);
        List<ConnectorMetadataResponseDto> metadata = attributeService.getConnectorMetadata(Optional.empty());
        Assertions.assertTrue(metadata.isEmpty());
    }

    @Test
    void promoteConnectorMetadata() throws NotFoundException {
        attributeService.promoteConnectorMetadata(UUID.fromString(connectorMetaAttribute.getUuid()), connector.getUuid());
        List<AttributeDefinitionDto> dto = attributeService.listGlobalMetadata();
        Assertions.assertEquals(2, dto.size());
    }
}
