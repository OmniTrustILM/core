package com.czertainly.core.search;

import com.czertainly.api.exception.AttributeException;
import com.czertainly.api.exception.NotFoundException;
import com.czertainly.api.exception.ValidationException;
import com.czertainly.api.model.client.attribute.RequestAttributeV3;
import com.czertainly.api.model.client.certificate.DiscoveryResponseDto;
import com.czertainly.api.model.client.certificate.SearchFilterRequestDto;
import com.czertainly.api.model.client.certificate.SearchRequestDto;
import com.czertainly.api.model.client.connector.v2.ConnectorVersion;
import com.czertainly.api.model.common.attribute.common.AttributeType;
import com.czertainly.api.model.common.attribute.v2.MetadataAttributeV2;
import com.czertainly.api.model.common.attribute.common.content.AttributeContentType;
import com.czertainly.api.model.common.attribute.v2.content.TextAttributeContentV2;
import com.czertainly.api.model.common.attribute.common.properties.CustomAttributeProperties;
import com.czertainly.api.model.common.attribute.common.properties.MetadataAttributeProperties;
import com.czertainly.api.model.common.attribute.v3.CustomAttributeV3;
import com.czertainly.api.model.common.attribute.v3.content.BaseAttributeContentV3;
import com.czertainly.api.model.common.attribute.v3.content.TextAttributeContentV3;
import com.czertainly.api.model.core.auth.Resource;
import com.czertainly.api.model.core.connector.ConnectorStatus;
import com.czertainly.api.model.core.connector.FunctionGroupCode;
import com.czertainly.api.model.core.discovery.DiscoveryStatus;
import com.czertainly.api.model.core.search.FilterConditionOperator;
import com.czertainly.api.model.core.search.FilterFieldSource;
import com.czertainly.core.attribute.engine.AttributeEngine;
import com.czertainly.core.attribute.engine.records.ObjectAttributeContentInfo;
import com.czertainly.core.dao.entity.*;
import com.czertainly.core.dao.repository.*;
import com.czertainly.core.enums.FilterField;
import com.czertainly.core.security.authz.SecurityFilter;
import com.czertainly.core.service.DiscoveryService;
import com.czertainly.core.util.BaseSpringBootTest;
import com.czertainly.core.util.MetaDefinitions;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;

import java.text.DateFormat;
import java.text.ParseException;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.List;
import java.util.UUID;

class DiscoveryHistorySearchTest extends BaseSpringBootTest {

    @Autowired
    private DiscoveryRepository discoveryRepository;
    @Autowired
    private ConnectorRepository connectorRepository;
    @Autowired
    private FunctionGroupRepository functionGroupRepository;
    @Autowired
    private Connector2FunctionGroupRepository connector2FunctionGroupRepository;
    @Autowired
    private DiscoveryService discoveryService;
    private AttributeEngine attributeEngine;

    @Autowired
    void setAttributeEngine(AttributeEngine attributeEngine) {
        this.attributeEngine = attributeEngine;
    }

    private static final DateFormat DATE_FORMAT = new SimpleDateFormat("yyyy-MM-dd'T'HH:mm:ss");

    private boolean isLoadedData = false;

    private Connector connector;
    private DiscoveryHistory discoveryHistory;

    @BeforeEach
    void loadData() {
        try {
            if (isLoadedData) {
                return;
            }

            connector = new Connector();
            connector.setName("discoveryProviderConnector");
            connector.setUrl("http://localhost:3665");
            connector.setVersion(ConnectorVersion.V1);
            connector.setStatus(ConnectorStatus.CONNECTED);
            connector = connectorRepository.save(connector);

            FunctionGroup functionGroup = new FunctionGroup();
            functionGroup.setCode(FunctionGroupCode.DISCOVERY_PROVIDER);
            functionGroup.setName(FunctionGroupCode.DISCOVERY_PROVIDER.getCode());
            functionGroupRepository.save(functionGroup);

            Connector2FunctionGroup c2fg = new Connector2FunctionGroup();
            c2fg.setConnector(connector);
            c2fg.setFunctionGroup(functionGroup);
            c2fg.setKinds(MetaDefinitions.serializeArrayString(List.of("IpAndPort")));
            connector2FunctionGroupRepository.save(c2fg);

            connector.getFunctionGroups().add(c2fg);
            connectorRepository.save(connector);

            final DiscoveryHistory discovery1 = new DiscoveryHistory();
            discovery1.setName("test_discovery1");
            discovery1.setConnectorUuid(connector.getUuid());
            discovery1.setConnectorName("connector1");
            discovery1.setStatus(DiscoveryStatus.FAILED);
            discovery1.setConnectorStatus(DiscoveryStatus.FAILED);
            discovery1.setKind("kindTEST1");
            discovery1.setStartTime(DATE_FORMAT.parse("2020-01-01T10:10:10"));
            discovery1.setEndTime(DATE_FORMAT.parse("2020-02-01T10:10:10"));
            discovery1.setTotalCertificatesDiscovered(15);
            discovery1.setConnectorTotalCertificatesDiscovered(15);
            discoveryHistory = discoveryRepository.save(discovery1);

            final DiscoveryHistory discovery2 = new DiscoveryHistory();
            discovery2.setName("test_discovery2");
            discovery2.setConnectorUuid(connector.getUuid());
            discovery2.setConnectorName("connector1");
            discovery2.setStatus(DiscoveryStatus.COMPLETED);
            discovery2.setConnectorStatus(DiscoveryStatus.COMPLETED);
            discovery2.setKind("kindTEST3");
            discovery2.setStartTime(DATE_FORMAT.parse("2020-05-05T10:10:10"));
            discovery2.setEndTime(DATE_FORMAT.parse("2021-02-01T10:10:10"));
            discovery2.setTotalCertificatesDiscovered(11);
            discovery2.setConnectorTotalCertificatesDiscovered(11);
            discoveryRepository.save(discovery2);

            final DiscoveryHistory discovery3 = new DiscoveryHistory();
            discovery3.setName("test_discovery3");
            discovery3.setConnectorUuid(connector.getUuid());
            discovery3.setConnectorName("connector5");
            discovery3.setStatus(DiscoveryStatus.COMPLETED);
            discovery3.setConnectorStatus(DiscoveryStatus.COMPLETED);
            discovery3.setKind("kindTEST3");
            discovery3.setStartTime(DATE_FORMAT.parse("2022-10-01T10:10:10"));
            discovery3.setEndTime(DATE_FORMAT.parse("2023-02-01T10:10:10"));
            discovery3.setTotalCertificatesDiscovered(20);
            discovery3.setConnectorTotalCertificatesDiscovered(20);
            discoveryRepository.save(discovery3);

            final DiscoveryHistory discovery4 = new DiscoveryHistory();
            discovery4.setName("test_discovery4");
            discovery4.setConnectorUuid(connector.getUuid());
            discovery4.setConnectorName("connector1");
            discovery4.setStatus(DiscoveryStatus.IN_PROGRESS);
            discovery4.setConnectorStatus(DiscoveryStatus.IN_PROGRESS);
            discovery4.setKind("kindTEST4");
            discovery4.setStartTime(DATE_FORMAT.parse("2020-06-01T10:10:10"));
            discovery4.setEndTime(DATE_FORMAT.parse("2020-10-01T10:10:10"));
            discovery4.setTotalCertificatesDiscovered(5);
            discovery4.setConnectorTotalCertificatesDiscovered(5);
            discoveryRepository.save(discovery4);

            loadMetaData();
            loadCustomAttributesData();
            isLoadedData = true;
        } catch (ParseException | NotFoundException | AttributeException e) {
            isLoadedData = false;
        }
    }

    private void loadMetaData() throws AttributeException {
        MetadataAttributeV2 metadataAttribute = new MetadataAttributeV2();
        metadataAttribute.setUuid(UUID.randomUUID().toString());
        metadataAttribute.setName("attributeMeta1");
        metadataAttribute.setType(AttributeType.META);
        metadataAttribute.setContentType(AttributeContentType.TEXT);
        MetadataAttributeProperties metadataAttributeProperties = new MetadataAttributeProperties();
        metadataAttributeProperties.setLabel("Test meta");
        metadataAttribute.setProperties(metadataAttributeProperties);
        metadataAttribute.setContent(List.of(new TextAttributeContentV2("reference-test-1", "data-meta-test-1")));

        attributeEngine.updateMetadataAttribute(metadataAttribute, ObjectAttributeContentInfo.builder(Resource.DISCOVERY, discoveryHistory.getUuid()).connector(connector.getUuid()).build());
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

        attributeEngine.updateCustomAttributeDefinition(customAttribute, List.of(Resource.DISCOVERY));
        attributeEngine.updateObjectCustomAttributesContent(Resource.DISCOVERY, discoveryHistory.getUuid(), List.of(requestAttribute));
    }


    @Test
    void testInsertedData() {
        final List<DiscoveryHistory> discoveryHistoryList = discoveryRepository.findAll();
        Assertions.assertEquals(4, discoveryHistoryList.size());
    }

    @Test
    void testInsertedData2() {
        final SearchRequestDto searchRequestDto = new SearchRequestDto();
        final DiscoveryResponseDto responseDto = discoveryService.listDiscoveries(SecurityFilter.create(), searchRequestDto);
        Assertions.assertEquals(4, responseDto.getDiscoveries().size());
    }

    @Test
    void testInsertedAttributes() {
        var customAttrs = attributeEngine.getObjectCustomAttributesContent(Resource.DISCOVERY, discoveryHistory.getUuid());
        var metaAttrs = attributeEngine.getMetadataAttributesDefinitionContent(ObjectAttributeContentInfo.builder(Resource.DISCOVERY, discoveryHistory.getUuid()).build());
        Assertions.assertEquals(1, customAttrs.size());
        Assertions.assertEquals(1, metaAttrs.size());
    }

    @Test
    void testFilterDataByNameContains() {
        final List<SearchFilterRequestDto> filters = new ArrayList<>();
        filters.add(new SearchFilterRequestDtoDummy(FilterFieldSource.PROPERTY, FilterField.DISCOVERY_NAME.name(), FilterConditionOperator.CONTAINS, "test_discovery"));
        final DiscoveryResponseDto responseDto = retrieveTheDiscoveriesBySearch(filters);
        Assertions.assertEquals(4, responseDto.getDiscoveries().size());
    }

    @Test
    void testFilterDataByNameEquals() {
        final List<SearchFilterRequestDto> filters = new ArrayList<>();
        filters.add(new SearchFilterRequestDtoDummy(FilterFieldSource.PROPERTY, FilterField.DISCOVERY_NAME.name(), FilterConditionOperator.EQUALS, "test_discovery2"));
        final DiscoveryResponseDto responseDto = retrieveTheDiscoveriesBySearch(filters);
        Assertions.assertEquals(1, responseDto.getDiscoveries().size());
    }

    @Test
    void testFilterDataByStartTime() {
        final List<SearchFilterRequestDto> filters = new ArrayList<>();
        filters.add(new SearchFilterRequestDtoDummy(FilterFieldSource.PROPERTY, FilterField.DISCOVERY_START_TIME.name(), FilterConditionOperator.GREATER, "2020-05-06T10:10:10.000Z"));
        final DiscoveryResponseDto responseDto = retrieveTheDiscoveriesBySearch(filters);
        Assertions.assertEquals(2, responseDto.getDiscoveries().size());
    }

    @Test
    void testFilterDataByEndTime() {
        final List<SearchFilterRequestDto> filters = new ArrayList<>();
        filters.add(new SearchFilterRequestDtoDummy(FilterFieldSource.PROPERTY, FilterField.DISCOVERY_END_TIME.name(), FilterConditionOperator.LESSER, "2020-02-02T10:10:10.000Z"));
        final DiscoveryResponseDto responseDto = retrieveTheDiscoveriesBySearch(filters);
        Assertions.assertEquals(1, responseDto.getDiscoveries().size());
    }

    @Test
    void testFilterDataByStatus() {
        final List<SearchFilterRequestDto> filters = new ArrayList<>();
        filters.add(new SearchFilterRequestDtoDummy(FilterFieldSource.PROPERTY, FilterField.DISCOVERY_STATUS.name(), FilterConditionOperator.NOT_EQUALS, DiscoveryStatus.COMPLETED.getCode()));
        final DiscoveryResponseDto responseDto = retrieveTheDiscoveriesBySearch(filters);
        Assertions.assertEquals(2, responseDto.getDiscoveries().size());
    }

    @Test
    void testFilterDataByTotalCertificateDiscovered() {
        final List<SearchFilterRequestDto> filters = new ArrayList<>();
        filters.add(new SearchFilterRequestDtoDummy(FilterFieldSource.PROPERTY, FilterField.DISCOVERY_TOTAL_CERT_DISCOVERED.name(), FilterConditionOperator.GREATER, 10));
        final SearchRequestDto searchRequestDto = new SearchRequestDto();
        searchRequestDto.setFilters(filters);
        final DiscoveryResponseDto responseDto = discoveryService.listDiscoveries(SecurityFilter.create(), searchRequestDto);
        Assertions.assertEquals(3, responseDto.getDiscoveries().size());
    }

    @Test
    void testFilterDataByKind() {
        final List<SearchFilterRequestDto> filters = new ArrayList<>();
        filters.add(new SearchFilterRequestDtoDummy(FilterFieldSource.PROPERTY, FilterField.DISCOVERY_KIND.name(), FilterConditionOperator.NOT_CONTAINS, "TEST3"));
        final DiscoveryResponseDto responseDto = retrieveTheDiscoveriesBySearch(filters);
        Assertions.assertEquals(2, responseDto.getDiscoveries().size());
    }

    @Test
    void testFilterDataByConnectorName() {
        final List<SearchFilterRequestDto> filters = new ArrayList<>();
        filters.add(new SearchFilterRequestDtoDummy(FilterFieldSource.PROPERTY, FilterField.DISCOVERY_CONNECTOR_NAME.name(), FilterConditionOperator.EQUALS, "connector1"));
        final DiscoveryResponseDto responseDto = retrieveTheDiscoveriesBySearch(filters);
        Assertions.assertEquals(3, responseDto.getDiscoveries().size());
    }

    @Test
    void testFilterDataByConnectorNameAndStatus() {
        final List<SearchFilterRequestDto> filters = new ArrayList<>();
        filters.add(new SearchFilterRequestDtoDummy(FilterFieldSource.PROPERTY, FilterField.DISCOVERY_CONNECTOR_NAME.name(), FilterConditionOperator.EQUALS, "connector1"));
        filters.add(new SearchFilterRequestDtoDummy(FilterFieldSource.PROPERTY, FilterField.DISCOVERY_STATUS.name(), FilterConditionOperator.EQUALS, DiscoveryStatus.COMPLETED.getCode()));
        final DiscoveryResponseDto responseDto = retrieveTheDiscoveriesBySearch(filters);
        Assertions.assertEquals(1, responseDto.getDiscoveries().size());
    }

    @Test
    void testFilterDataByConnectorNameAndKind() {
        final List<SearchFilterRequestDto> filters = new ArrayList<>();
        filters.add(new SearchFilterRequestDtoDummy(FilterFieldSource.PROPERTY, FilterField.DISCOVERY_CONNECTOR_NAME.name(), FilterConditionOperator.EQUALS, "connector1"));
        filters.add(new SearchFilterRequestDtoDummy(FilterFieldSource.PROPERTY, FilterField.DISCOVERY_KIND.name(), FilterConditionOperator.STARTS_WITH, "kindTEST"));
        filters.add(new SearchFilterRequestDtoDummy(FilterFieldSource.PROPERTY, FilterField.DISCOVERY_START_TIME.name(), FilterConditionOperator.LESSER, "2020-02-01T10:10:10.000Z"));
        final DiscoveryResponseDto responseDto = retrieveTheDiscoveriesBySearch(filters);
        Assertions.assertEquals(1, responseDto.getDiscoveries().size());
    }

    @Test
    void testFilterDataByMetadata() {
        final List<SearchFilterRequestDto> filters = new ArrayList<>();
        filters.add(new SearchFilterRequestDtoDummy(FilterFieldSource.META, "attributeMeta1|TEXT", FilterConditionOperator.CONTAINS, "-meta-"));
        final DiscoveryResponseDto responseDto = retrieveTheDiscoveriesBySearch(filters);
        Assertions.assertEquals(1, responseDto.getDiscoveries().size());
    }

    @Test
    void testFilterDataByCustomAttr() {
        final List<SearchFilterRequestDto> filters = new ArrayList<>();
        filters.add(new SearchFilterRequestDtoDummy(FilterFieldSource.CUSTOM, "attributeCustom1|TEXT", FilterConditionOperator.CONTAINS, "-custom-"));
        final DiscoveryResponseDto responseDto = retrieveTheDiscoveriesBySearch(filters);
        Assertions.assertEquals(1, responseDto.getDiscoveries().size());
    }

    // ─────────────────────────────────────────────────────────────────────────
    // NumberFormatException → ValidationException on NUMBER property filters
    // ─────────────────────────────────────────────────────────────────────────

    @Test
    void filterByTotalCertDiscovered_invalidStringValue_throwsValidationException() {
        List<SearchFilterRequestDto> filters = List.of(
                new SearchFilterRequestDtoDummy(FilterFieldSource.PROPERTY,
                        FilterField.DISCOVERY_TOTAL_CERT_DISCOVERED.name(),
                        FilterConditionOperator.EQUALS, "not-a-number"));
        Assertions.assertThrows(ValidationException.class,
                () -> retrieveTheDiscoveriesBySearch(filters),
                "Non-numeric value for a NUMBER filter field must throw ValidationException, not NumberFormatException");
    }

    @Test
    void filterByTotalCertDiscovered_invalidStringValue_forGreaterThanOperator_throwsValidationException() {
        List<SearchFilterRequestDto> filters = List.of(
                new SearchFilterRequestDtoDummy(FilterFieldSource.PROPERTY,
                        FilterField.DISCOVERY_TOTAL_CERT_DISCOVERED.name(),
                        FilterConditionOperator.GREATER, "xyz"));
        Assertions.assertThrows(ValidationException.class,
                () -> retrieveTheDiscoveriesBySearch(filters),
                "Non-numeric value for GREATER on a NUMBER field must throw ValidationException");
    }

    private DiscoveryResponseDto retrieveTheDiscoveriesBySearch(final List<SearchFilterRequestDto> filters) {
        final SearchRequestDto searchRequestDto = new SearchRequestDto();
        searchRequestDto.setFilters(filters);
        return discoveryService.listDiscoveries(SecurityFilter.create(), searchRequestDto);
    }

}
