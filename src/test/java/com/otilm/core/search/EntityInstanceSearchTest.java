package com.otilm.core.search;

import com.otilm.api.exception.AttributeException;
import com.otilm.api.exception.NotFoundException;
import com.otilm.api.model.client.attribute.RequestAttributeV3;
import com.otilm.api.model.client.certificate.EntityInstanceResponseDto;
import com.otilm.api.model.client.certificate.SearchFilterRequestDto;
import com.otilm.api.model.client.certificate.SearchRequestDto;
import com.otilm.api.model.client.connector.v2.ConnectorVersion;
import com.otilm.api.model.common.attribute.common.AttributeType;
import com.otilm.api.model.common.attribute.v2.MetadataAttributeV2;
import com.otilm.api.model.common.attribute.common.content.AttributeContentType;
import com.otilm.api.model.common.attribute.v2.content.TextAttributeContentV2;
import com.otilm.api.model.common.attribute.common.properties.CustomAttributeProperties;
import com.otilm.api.model.common.attribute.common.properties.MetadataAttributeProperties;
import com.otilm.api.model.common.attribute.v3.CustomAttributeV3;
import com.otilm.api.model.common.attribute.v3.content.BaseAttributeContentV3;
import com.otilm.api.model.common.attribute.v3.content.TextAttributeContentV3;
import com.otilm.api.model.core.auth.Resource;
import com.otilm.api.model.core.connector.ConnectorStatus;
import com.otilm.api.model.core.search.FilterConditionOperator;
import com.otilm.api.model.core.search.FilterFieldSource;
import com.otilm.core.attribute.engine.AttributeEngine;
import com.otilm.core.attribute.engine.records.ObjectAttributeContentInfo;
import com.otilm.core.dao.entity.Connector;
import com.otilm.core.dao.entity.EntityInstanceReference;
import com.otilm.core.dao.entity.Location;
import com.otilm.core.dao.repository.ConnectorRepository;
import com.otilm.core.dao.repository.EntityInstanceReferenceRepository;
import com.otilm.core.dao.repository.LocationRepository;
import com.otilm.core.enums.FilterField;
import com.otilm.core.security.authz.SecurityFilter;
import com.otilm.core.service.EntityInstanceService;
import com.otilm.core.util.BaseSpringBootTest;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;

import java.time.OffsetDateTime;
import java.util.ArrayList;
import java.util.List;
import java.util.UUID;

class EntityInstanceSearchTest extends BaseSpringBootTest {

    @Autowired
    private EntityInstanceReferenceRepository entityInstanceReferenceRepository;
    @Autowired
    private ConnectorRepository connectorRepository;
    @Autowired
    private LocationRepository locationRepository;
    @Autowired
    private EntityInstanceService entityInstanceService;
    private AttributeEngine attributeEngine;

    @Autowired
    public void setAttributeEngine(AttributeEngine attributeEngine) {
        this.attributeEngine = attributeEngine;
    }

    private EntityInstanceReference entityInstanceReference;


    private Connector connector;

    private boolean isLoadedData = false;

    @BeforeEach
    public void loadData() throws AttributeException, NotFoundException {

        if (isLoadedData) {
            return;
        }

        connector = new Connector();
        connector.setName("testProviderConnector");
        connector.setUrl("http://localhost:3665");
        connector.setVersion(ConnectorVersion.V1);
        connector.setStatus(ConnectorStatus.CONNECTED);
        connector = connectorRepository.save(connector);

        entityInstanceReference = new EntityInstanceReference();
        entityInstanceReference.setConnector(connector);
        entityInstanceReference.setConnectorName("testConnector1");
        entityInstanceReference.setCreated(OffsetDateTime.now());
        entityInstanceReference.setKind("test-kind1");
        entityInstanceReference.setName("entity-ref-1");
        entityInstanceReference = entityInstanceReferenceRepository.save(entityInstanceReference);

        final Location location = new Location();
        location.setEntityInstanceReference(entityInstanceReference);
        location.setEntityInstanceName("test-instance-name-1");
        location.setName("location1");
        location.setSupportMultipleEntries(true);
        location.setSupportKeyManagement(false);
        location.setEnabled(true);
        locationRepository.save(location);

        loadMetaData();
        loadCustomAttributesData();

        entityInstanceReference = new EntityInstanceReference();
        entityInstanceReference.setConnector(connector);
        entityInstanceReference.setConnectorName("testConnector2");
        entityInstanceReference.setCreated(OffsetDateTime.now());
        entityInstanceReference.setKind("test-kind2");
        entityInstanceReference.setName("entity-ref-2");
        entityInstanceReference = entityInstanceReferenceRepository.save(entityInstanceReference);

        final Location location2 = new Location();
        location2.setEntityInstanceReference(entityInstanceReference);
        location2.setEntityInstanceName("test-instance-name-1");
        location2.setName("location1");
        location2.setSupportMultipleEntries(true);
        location2.setSupportKeyManagement(true);
        location2.setEnabled(false);
        locationRepository.save(location2);

        entityInstanceReference = new EntityInstanceReference();
        entityInstanceReference.setConnector(connector);
        entityInstanceReference.setConnectorName("testConnector3");
        entityInstanceReference.setCreated(OffsetDateTime.now());
        entityInstanceReference.setKind("test3-kind");
        entityInstanceReference.setName("entity3-ref");
        entityInstanceReference = entityInstanceReferenceRepository.save(entityInstanceReference);

        final Location location3 = new Location();
        location3.setEntityInstanceReference(entityInstanceReference);
        location3.setEntityInstanceName("test-instance-name-3");
        location3.setName("location3");
        location3.setSupportMultipleEntries(false);
        location3.setSupportKeyManagement(true);
        location3.setEnabled(false);
        locationRepository.save(location3);

        isLoadedData = true;
    }

    @Test
    void testInsertedData() {
        final List<SearchFilterRequestDto> filters = new ArrayList<>();
        final EntityInstanceResponseDto responseDto = retrieveTheEntitiesBySearch(filters);
        Assertions.assertEquals(3, responseDto.getEntities().size());
    }

    @Test
    void testEntityByName() {
        final List<SearchFilterRequestDto> filters = new ArrayList<>();
        filters.add(new SearchFilterRequestDtoDummy(FilterFieldSource.PROPERTY, FilterField.ENTITY_NAME.name(), FilterConditionOperator.EQUALS, "entity-ref-2"));
        final EntityInstanceResponseDto responseDto = retrieveTheEntitiesBySearch(filters);
        Assertions.assertEquals(1, responseDto.getEntities().size());
    }

    @Test
    void testEntityByConnectorName() {
        final List<SearchFilterRequestDto> filters = new ArrayList<>();
        filters.add(new SearchFilterRequestDtoDummy(FilterFieldSource.PROPERTY, FilterField.ENTITY_CONNECTOR_NAME.name(), FilterConditionOperator.CONTAINS, "Connector"));
        final EntityInstanceResponseDto responseDto = retrieveTheEntitiesBySearch(filters);
        Assertions.assertEquals(3, responseDto.getEntities().size());
    }

    @Test
    void testEntityByKind() {
        final List<SearchFilterRequestDto> filters = new ArrayList<>();
        filters.add(new SearchFilterRequestDtoDummy(FilterFieldSource.PROPERTY, FilterField.ENTITY_KIND.name(), FilterConditionOperator.CONTAINS, "test-kind"));
        final EntityInstanceResponseDto responseDto = retrieveTheEntitiesBySearch(filters);
        Assertions.assertEquals(2, responseDto.getEntities().size());
    }

    @Test
    void testFilterDataByMetadata() {
        final List<SearchFilterRequestDto> filters = new ArrayList<>();
        filters.add(new SearchFilterRequestDtoDummy(FilterFieldSource.META, "attributeMeta1|TEXT", FilterConditionOperator.CONTAINS, "-meta-"));
        final EntityInstanceResponseDto responseDto = retrieveTheEntitiesBySearch(filters);
        Assertions.assertEquals(1, responseDto.getEntities().size());
    }

    @Test
    void testFilterDataByCustomAttr() {
        final List<SearchFilterRequestDto> filters = new ArrayList<>();
        filters.add(new SearchFilterRequestDtoDummy(FilterFieldSource.CUSTOM, "attributeCustom1|TEXT", FilterConditionOperator.CONTAINS, "-custom-"));
        final EntityInstanceResponseDto responseDto = retrieveTheEntitiesBySearch(filters);
        Assertions.assertEquals(1, responseDto.getEntities().size());
    }

    private EntityInstanceResponseDto retrieveTheEntitiesBySearch(final List<SearchFilterRequestDto> filters) {
        final SearchRequestDto searchRequestDto = new SearchRequestDto();
        searchRequestDto.setFilters(filters);
        return entityInstanceService.listEntityInstances(SecurityFilter.create(), searchRequestDto);
    }

    private void loadMetaData() throws AttributeException {
        MetadataAttributeV2 metadataAttribute = new MetadataAttributeV2();
        metadataAttribute.setUuid(UUID.randomUUID().toString());
        metadataAttribute.setName("attributeMeta1");
        metadataAttribute.setType(AttributeType.META);
        metadataAttribute.setContentType(AttributeContentType.TEXT);
        MetadataAttributeProperties metadataAttributeProperties = new MetadataAttributeProperties();
        metadataAttributeProperties.setLabel("Test meta");
        metadataAttribute.setProperties(metadataAttributeProperties);        metadataAttribute.setContent(List.of(new TextAttributeContentV2("reference-test-1", "data-meta-test-1")));

        attributeEngine.updateMetadataAttribute(metadataAttribute, ObjectAttributeContentInfo.builder(Resource.ENTITY, entityInstanceReference.getUuid()).connector(connector.getUuid()).build());
    }

    private void loadCustomAttributesData() throws AttributeException, NotFoundException {
        CustomAttributeV3 customAttribute = new CustomAttributeV3();
        customAttribute.setUuid(UUID.randomUUID().toString());
        customAttribute.setName("attributeCustom1");
        customAttribute.setType(AttributeType.CUSTOM);
        customAttribute.setContentType(AttributeContentType.TEXT);
        CustomAttributeProperties properties = new CustomAttributeProperties();
        properties.setLabel("Test custom");
        customAttribute.setProperties(properties);
        List<BaseAttributeContentV3<?>> contentItems = List.of(new TextAttributeContentV3("reference-test-1", "data-custom-test-1"));
        RequestAttributeV3 requestAttribute = new RequestAttributeV3();
        requestAttribute.setUuid(UUID.fromString(customAttribute.getUuid()));
        requestAttribute.setName(customAttribute.getName());
        requestAttribute.setContent(contentItems);

        attributeEngine.updateCustomAttributeDefinition(customAttribute, List.of(Resource.ENTITY));
        attributeEngine.updateObjectCustomAttributesContent(Resource.ENTITY, entityInstanceReference.getUuid(), List.of(requestAttribute));
    }









}
