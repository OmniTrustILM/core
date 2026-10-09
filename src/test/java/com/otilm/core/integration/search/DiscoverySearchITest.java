package com.otilm.core.integration.search;

import com.otilm.api.exception.AttributeException;
import com.otilm.api.exception.NotFoundException;
import com.otilm.api.exception.ValidationException;
import com.otilm.api.model.client.attribute.RequestAttributeV3;
import com.otilm.api.model.client.certificate.DiscoveryResponseDto;
import com.otilm.api.model.client.certificate.SearchFilterRequestDto;
import com.otilm.api.model.client.certificate.SearchRequestDto;
import com.otilm.api.model.client.certificate.SearchSortRequestDto;
import com.otilm.api.model.client.connector.v2.ConnectorVersion;
import com.otilm.api.model.client.discovery.DiscoveryListDto;
import com.otilm.api.model.common.attribute.common.AttributeType;
import com.otilm.api.model.common.attribute.common.content.AttributeContentType;
import com.otilm.api.model.common.attribute.common.properties.CustomAttributeProperties;
import com.otilm.api.model.common.attribute.common.properties.MetadataAttributeProperties;
import com.otilm.api.model.common.attribute.v2.MetadataAttributeV2;
import com.otilm.api.model.common.attribute.v2.content.TextAttributeContentV2;
import com.otilm.api.model.common.attribute.v3.CustomAttributeV3;
import com.otilm.api.model.common.attribute.v3.content.BaseAttributeContentV3;
import com.otilm.api.model.common.attribute.v3.content.TextAttributeContentV3;
import com.otilm.api.model.core.auth.Resource;
import com.otilm.api.model.core.connector.ConnectorStatus;
import com.otilm.api.model.core.connector.FunctionGroupCode;
import com.otilm.api.model.core.discovery.DiscoveryStatus;
import com.otilm.api.model.core.search.FilterConditionOperator;
import com.otilm.api.model.core.search.FilterFieldSource;
import com.otilm.api.model.core.search.SearchFieldDataByGroupDto;
import com.otilm.api.model.core.search.SearchFieldDataDto;
import com.otilm.api.model.core.search.SortDirection;
import com.otilm.core.attribute.engine.AttributeEngine;
import com.otilm.core.attribute.engine.records.ObjectAttributeContentInfo;
import com.otilm.core.dao.entity.Connector;
import com.otilm.core.dao.entity.Connector2FunctionGroup;
import com.otilm.core.dao.entity.Discovery;
import com.otilm.core.dao.entity.FunctionGroup;
import com.otilm.core.dao.repository.Connector2FunctionGroupRepository;
import com.otilm.core.dao.repository.ConnectorRepository;
import com.otilm.core.dao.repository.DiscoveryRepository;
import com.otilm.core.dao.repository.FunctionGroupRepository;
import com.otilm.core.enums.FilterField;
import com.otilm.core.security.authz.SecurityFilter;
import com.otilm.core.service.DiscoveryExternalService;
import com.otilm.core.util.BaseSpringBootTest;
import com.otilm.core.util.MetaDefinitions;
import java.time.LocalDateTime;
import java.time.OffsetDateTime;
import java.time.ZoneId;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.UUID;
import java.util.function.Function;
import java.util.stream.Collectors;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;

import static com.otilm.core.util.builders.SearchFilterRequestDtoBuilder.aCustomAttributeFilter;
import static com.otilm.core.util.builders.SearchFilterRequestDtoBuilder.aMetaAttributeFilter;
import static com.otilm.core.util.builders.SearchFilterRequestDtoBuilder.aPropertyEqualsFilter;
import static com.otilm.core.util.builders.SearchFilterRequestDtoBuilder.aPropertyFilter;
import static com.otilm.core.util.builders.SearchFilterRequestDtoBuilder.aPropertyNotEqualsFilter;

class DiscoverySearchITest extends BaseSpringBootTest {

    @Autowired
    private DiscoveryRepository discoveryRepository;
    @Autowired
    private ConnectorRepository connectorRepository;
    @Autowired
    private FunctionGroupRepository functionGroupRepository;
    @Autowired
    private Connector2FunctionGroupRepository connector2FunctionGroupRepository;
    @Autowired
    private DiscoveryExternalService discoveryService;
    private AttributeEngine attributeEngine;

    @Autowired
    void setAttributeEngine(AttributeEngine attributeEngine) {
        this.attributeEngine = attributeEngine;
    }

    /** Interprets local fixture timestamps in the system zone, preserving their intended instants. */
    private static OffsetDateTime localDateTime(String value) {
        return LocalDateTime.parse(value).atZone(ZoneId.systemDefault()).toOffsetDateTime();
    }

    private boolean isLoadedData = false;

    private Connector connector;
    private Discovery discovery;

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

            final Discovery discovery1 = new Discovery();
            discovery1.setName("test_discovery1");
            discovery1.setConnectorUuid(connector.getUuid());
            discovery1.setConnectorName("connector1");
            discovery1.setStatus(DiscoveryStatus.FAILED);
            discovery1.setConnectorStatus(DiscoveryStatus.FAILED);
            discovery1.setKind("kindTEST1");
            discovery1.setStartTime(localDateTime("2020-01-01T10:10:10"));
            discovery1.setEndTime(localDateTime("2020-02-01T10:10:10"));
            discovery1.setTotalCertificatesDiscovered(15);
            discovery1.setConnectorTotalCertificatesDiscovered(15);
            discovery = discoveryRepository.save(discovery1);

            final Discovery discovery2 = new Discovery();
            discovery2.setName("test_discovery2");
            discovery2.setConnectorUuid(connector.getUuid());
            discovery2.setConnectorName("connector1");
            discovery2.setStatus(DiscoveryStatus.COMPLETED);
            discovery2.setConnectorStatus(DiscoveryStatus.COMPLETED);
            discovery2.setKind("kindTEST3");
            discovery2.setStartTime(localDateTime("2020-05-05T10:10:10"));
            discovery2.setEndTime(localDateTime("2021-02-01T10:10:10"));
            discovery2.setTotalCertificatesDiscovered(11);
            discovery2.setConnectorTotalCertificatesDiscovered(11);
            discoveryRepository.save(discovery2);

            final Discovery discovery3 = new Discovery();
            discovery3.setName("test_discovery3");
            discovery3.setConnectorUuid(connector.getUuid());
            discovery3.setConnectorName("connector5");
            discovery3.setStatus(DiscoveryStatus.COMPLETED);
            discovery3.setConnectorStatus(DiscoveryStatus.COMPLETED);
            discovery3.setKind("kindTEST3");
            discovery3.setStartTime(localDateTime("2022-10-01T10:10:10"));
            discovery3.setEndTime(localDateTime("2023-02-01T10:10:10"));
            discovery3.setTotalCertificatesDiscovered(20);
            discovery3.setConnectorTotalCertificatesDiscovered(20);
            discoveryRepository.save(discovery3);

            final Discovery discovery4 = new Discovery();
            discovery4.setName("test_discovery4");
            discovery4.setConnectorUuid(connector.getUuid());
            discovery4.setConnectorName("connector1");
            discovery4.setStatus(DiscoveryStatus.IN_PROGRESS);
            discovery4.setConnectorStatus(DiscoveryStatus.IN_PROGRESS);
            discovery4.setKind("kindTEST4");
            discovery4.setStartTime(localDateTime("2020-06-01T10:10:10"));
            discovery4.setEndTime(localDateTime("2020-10-01T10:10:10"));
            discovery4.setTotalCertificatesDiscovered(5);
            discovery4.setConnectorTotalCertificatesDiscovered(5);
            // Targets keys as well, and received far more items than certificates.
            discovery4.setLastAppliedSequence(40);
            discovery4.setResources(new ArrayList<>(List.of(Resource.CERTIFICATE, Resource.CRYPTOGRAPHIC_KEY)));
            discoveryRepository.save(discovery4);

            loadMetaData();
            loadCustomAttributesData();
            isLoadedData = true;
        } catch (NotFoundException | AttributeException e) {
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

        attributeEngine
                .updateMetadataAttribute(metadataAttribute,
                        ObjectAttributeContentInfo
                                .builder(Resource.DISCOVERY, discovery.getUuid())
                                .connector(connector.getUuid())
                                .build());
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

        List<BaseAttributeContentV3<?>> contentItems = List
                .of(new TextAttributeContentV3("reference-test-1", "data-custom-test-1"));
        RequestAttributeV3 requestAttribute = new RequestAttributeV3();
        requestAttribute.setUuid(UUID.fromString(customAttribute.getUuid()));
        requestAttribute.setName(customAttribute.getName());
        requestAttribute.setContent(contentItems);

        attributeEngine.updateCustomAttributeDefinition(customAttribute, List.of(Resource.DISCOVERY));
        attributeEngine
                .updateObjectCustomAttributesContent(Resource.DISCOVERY, discovery.getUuid(),
                        List.of(requestAttribute));
    }

    @Test
    void testInsertedData() {
        final List<Discovery> discoveryList = discoveryRepository.findAll();
        Assertions.assertEquals(4, discoveryList.size());
    }

    @Test
    void testInsertedData2() {
        final SearchRequestDto searchRequestDto = new SearchRequestDto();
        final DiscoveryResponseDto responseDto = discoveryService
                .listDiscoveries(SecurityFilter.create(), searchRequestDto);
        Assertions.assertEquals(4, responseDto.getDiscoveries().size());
    }

    @Test
    void testInsertedAttributes() {
        var customAttrs = attributeEngine.getObjectCustomAttributesContent(Resource.DISCOVERY, discovery.getUuid());
        var metaAttrs = attributeEngine
                .getMetadataAttributesDefinitionContent(
                        ObjectAttributeContentInfo.builder(Resource.DISCOVERY, discovery.getUuid()).build());
        Assertions.assertEquals(1, customAttrs.size());
        Assertions.assertEquals(1, metaAttrs.size());
    }

    @Test
    void testFilterDataByNameContains() {
        final List<SearchFilterRequestDto> filters = new ArrayList<>();
        filters.add(aPropertyFilter(FilterField.DISCOVERY_NAME, FilterConditionOperator.CONTAINS, "test_discovery"));
        final DiscoveryResponseDto responseDto = retrieveTheDiscoveriesBySearch(filters);
        Assertions.assertEquals(4, responseDto.getDiscoveries().size());
    }

    @Test
    void testFilterDataByNameEquals() {
        final List<SearchFilterRequestDto> filters = new ArrayList<>();
        filters.add(aPropertyEqualsFilter(FilterField.DISCOVERY_NAME, "test_discovery2"));
        final DiscoveryResponseDto responseDto = retrieveTheDiscoveriesBySearch(filters);
        Assertions.assertEquals(1, responseDto.getDiscoveries().size());
    }

    @Test
    void testFilterDataByStartTime() {
        final List<SearchFilterRequestDto> filters = new ArrayList<>();
        filters
                .add(aPropertyFilter(FilterField.DISCOVERY_START_TIME, FilterConditionOperator.GREATER,
                        "2020-05-06T10:10:10.000Z"));
        final DiscoveryResponseDto responseDto = retrieveTheDiscoveriesBySearch(filters);
        Assertions.assertEquals(2, responseDto.getDiscoveries().size());
    }

    @Test
    void testFilterDataByEndTime() {
        final List<SearchFilterRequestDto> filters = new ArrayList<>();
        filters
                .add(aPropertyFilter(FilterField.DISCOVERY_END_TIME, FilterConditionOperator.LESSER,
                        "2020-02-02T10:10:10.000Z"));
        final DiscoveryResponseDto responseDto = retrieveTheDiscoveriesBySearch(filters);
        Assertions.assertEquals(1, responseDto.getDiscoveries().size());
    }

    @Test
    void testFilterDataByStatus() {
        final List<SearchFilterRequestDto> filters = new ArrayList<>();
        filters.add(aPropertyNotEqualsFilter(FilterField.DISCOVERY_STATUS, DiscoveryStatus.COMPLETED.getCode()));
        final DiscoveryResponseDto responseDto = retrieveTheDiscoveriesBySearch(filters);
        Assertions.assertEquals(2, responseDto.getDiscoveries().size());
    }

    @Test
    void testFilterDataByTotalCertificateDiscovered() {
        final List<SearchFilterRequestDto> filters = new ArrayList<>();
        filters.add(aPropertyFilter(FilterField.DISCOVERY_TOTAL_CERT_DISCOVERED, FilterConditionOperator.GREATER, 10));
        final SearchRequestDto searchRequestDto = new SearchRequestDto();
        searchRequestDto.setFilters(filters);
        final DiscoveryResponseDto responseDto = discoveryService
                .listDiscoveries(SecurityFilter.create(), searchRequestDto);
        Assertions.assertEquals(3, responseDto.getDiscoveries().size());
    }

    @Test
    void testFilterDataByKind() {
        final List<SearchFilterRequestDto> filters = new ArrayList<>();
        filters.add(aPropertyFilter(FilterField.DISCOVERY_KIND, FilterConditionOperator.NOT_CONTAINS, "TEST3"));
        final DiscoveryResponseDto responseDto = retrieveTheDiscoveriesBySearch(filters);
        Assertions.assertEquals(2, responseDto.getDiscoveries().size());
    }

    @Test
    void testFilterDataByConnectorName() {
        final List<SearchFilterRequestDto> filters = new ArrayList<>();
        filters.add(aPropertyEqualsFilter(FilterField.DISCOVERY_CONNECTOR_NAME, "connector1"));
        final DiscoveryResponseDto responseDto = retrieveTheDiscoveriesBySearch(filters);
        Assertions.assertEquals(3, responseDto.getDiscoveries().size());
    }

    @Test
    void testFilterDataByConnectorNameAndStatus() {
        final List<SearchFilterRequestDto> filters = new ArrayList<>();
        filters.add(aPropertyEqualsFilter(FilterField.DISCOVERY_CONNECTOR_NAME, "connector1"));
        filters.add(aPropertyEqualsFilter(FilterField.DISCOVERY_STATUS, DiscoveryStatus.COMPLETED.getCode()));
        final DiscoveryResponseDto responseDto = retrieveTheDiscoveriesBySearch(filters);
        Assertions.assertEquals(1, responseDto.getDiscoveries().size());
    }

    @Test
    void testFilterDataByConnectorNameAndKind() {
        final List<SearchFilterRequestDto> filters = new ArrayList<>();
        filters.add(aPropertyEqualsFilter(FilterField.DISCOVERY_CONNECTOR_NAME, "connector1"));
        filters.add(aPropertyFilter(FilterField.DISCOVERY_KIND, FilterConditionOperator.STARTS_WITH, "kindTEST"));
        filters
                .add(aPropertyFilter(FilterField.DISCOVERY_START_TIME, FilterConditionOperator.LESSER,
                        "2020-02-01T10:10:10.000Z"));
        final DiscoveryResponseDto responseDto = retrieveTheDiscoveriesBySearch(filters);
        Assertions.assertEquals(1, responseDto.getDiscoveries().size());
    }

    @Test
    void testFilterDataByMetadata() {
        final List<SearchFilterRequestDto> filters = new ArrayList<>();
        filters
                .add(aMetaAttributeFilter("attributeMeta1", AttributeContentType.TEXT, FilterConditionOperator.CONTAINS,
                        "-meta-"));
        final DiscoveryResponseDto responseDto = retrieveTheDiscoveriesBySearch(filters);
        Assertions.assertEquals(1, responseDto.getDiscoveries().size());
    }

    @Test
    void testFilterDataByCustomAttr() {
        final List<SearchFilterRequestDto> filters = new ArrayList<>();
        filters
                .add(aCustomAttributeFilter("attributeCustom1", AttributeContentType.TEXT,
                        FilterConditionOperator.CONTAINS, "-custom-"));
        final DiscoveryResponseDto responseDto = retrieveTheDiscoveriesBySearch(filters);
        Assertions.assertEquals(1, responseDto.getDiscoveries().size());
    }

    // ─────────────────────────────────────────────────────────────────────────
    // NumberFormatException → ValidationException on NUMBER property filters
    // ─────────────────────────────────────────────────────────────────────────

    @Test
    void filterByTotalCertDiscovered_invalidStringValue_throwsValidationException() {
        List<SearchFilterRequestDto> filters = List
                .of(aPropertyEqualsFilter(FilterField.DISCOVERY_TOTAL_CERT_DISCOVERED, "not-a-number"));
        Assertions
                .assertThrows(ValidationException.class, () -> retrieveTheDiscoveriesBySearch(filters),
                        "Non-numeric value for a NUMBER filter field must throw ValidationException, not NumberFormatException");
    }

    @Test
    void filterByTotalCertDiscovered_invalidStringValue_forGreaterThanOperator_throwsValidationException() {
        List<SearchFilterRequestDto> filters = List
                .of(aPropertyFilter(FilterField.DISCOVERY_TOTAL_CERT_DISCOVERED, FilterConditionOperator.GREATER,
                        "xyz"));
        Assertions
                .assertThrows(ValidationException.class, () -> retrieveTheDiscoveriesBySearch(filters),
                        "Non-numeric value for GREATER on a NUMBER field must throw ValidationException");
    }

    @Test
    void testFilterDataByTotalItemsDiscovered() {
        final List<SearchFilterRequestDto> filters = new ArrayList<>();
        // test_discovery4 found only 5 certificates; the item total counts its keys too.
        filters.add(aPropertyFilter(FilterField.DISCOVERY_TOTAL_ITEMS_DISCOVERED, FilterConditionOperator.GREATER, 15));
        Assertions
                .assertEquals(Set.of("test_discovery3", "test_discovery4"),
                        namesOf(retrieveTheDiscoveriesBySearch(filters)));
    }

    @Test
    void testFilterDataByTotalItemsDiscovered_pastTheIntegerRange() {
        // Nothing bounds a connector's sequence, so the cursor, and the total read off it, can outgrow an integer.
        final Discovery outsized = new Discovery();
        outsized.setName("test_discovery_outsized");
        outsized.setConnectorUuid(discovery.getConnectorUuid());
        outsized.setConnectorName("connector1");
        outsized.setStatus(DiscoveryStatus.IN_PROGRESS);
        outsized.setConnectorStatus(DiscoveryStatus.IN_PROGRESS);
        outsized.setLastAppliedSequence(3_000_000_000L);
        discoveryRepository.save(outsized);

        final List<SearchFilterRequestDto> filters = List
                .of(aPropertyFilter(FilterField.DISCOVERY_TOTAL_ITEMS_DISCOVERED, FilterConditionOperator.GREATER, 15));
        Assertions
                .assertEquals(Set.of("test_discovery3", "test_discovery4", "test_discovery_outsized"),
                        namesOf(retrieveTheDiscoveriesBySearch(filters)));
    }

    @Test
    void testFilterDataByResources() {
        Assertions
                .assertEquals(Set.of("test_discovery4"),
                        namesOf(retrieveTheDiscoveriesByResources(FilterConditionOperator.CONTAINS,
                                Resource.CRYPTOGRAPHIC_KEY.getCode())));
        Assertions
                .assertEquals(Set.of("test_discovery1", "test_discovery2", "test_discovery3"),
                        namesOf(retrieveTheDiscoveriesByResources(FilterConditionOperator.NOT_CONTAINS,
                                Resource.CRYPTOGRAPHIC_KEY.getCode())));
    }

    @Test
    void testFilterDataByResources_findsV1RunsByTheCertificatesTheyTarget() {
        Assertions
                .assertEquals(Set.of("test_discovery1", "test_discovery2", "test_discovery3", "test_discovery4"),
                        namesOf(retrieveTheDiscoveriesByResources(FilterConditionOperator.CONTAINS,
                                Resource.CERTIFICATE.getCode())));
    }

    @Test
    void theListingSortsByTheItemTotal() {
        final SearchRequestDto searchRequestDto = new SearchRequestDto();
        searchRequestDto
                .setSort(new SearchSortRequestDto(FilterFieldSource.PROPERTY,
                        FilterField.DISCOVERY_TOTAL_ITEMS_DISCOVERED.name(), SortDirection.DESC));

        List<String> names = discoveryService
                .listDiscoveries(SecurityFilter.create(), searchRequestDto)
                .getDiscoveries()
                .stream()
                .map(DiscoveryListDto::getName)
                .toList();

        Assertions
                .assertEquals(List.of("test_discovery4", "test_discovery3", "test_discovery1", "test_discovery2"),
                        names);
    }

    @Test
    void theListingCarriesEachRunsItemTotalAndResources() {
        Map<String, DiscoveryListDto> byName = discoveryService
                .listDiscoveries(SecurityFilter.create(), new SearchRequestDto())
                .getDiscoveries()
                .stream()
                .collect(Collectors.toMap(DiscoveryListDto::getName, Function.identity()));

        Assertions.assertEquals(40, byName.get("test_discovery4").getTotalItemsDiscovered());
        Assertions
                .assertEquals(List.of(Resource.CERTIFICATE, Resource.CRYPTOGRAPHIC_KEY),
                        byName.get("test_discovery4").getResources());
        Assertions.assertEquals(15, byName.get("test_discovery1").getTotalItemsDiscovered());
        Assertions.assertEquals(List.of(Resource.CERTIFICATE), byName.get("test_discovery1").getResources());
    }

    @Test
    void theCatalogueOffersTheItemTotalAndTheResourcesADiscoveryCanTarget() {
        Map<String, SearchFieldDataDto> fields = discoveryService
                .getSearchableFieldInformationByGroup()
                .stream()
                .filter(group -> group.getFilterFieldSource() == FilterFieldSource.PROPERTY)
                .map(SearchFieldDataByGroupDto::getSearchFieldData)
                .flatMap(List::stream)
                .collect(Collectors.toMap(SearchFieldDataDto::getFieldIdentifier, Function.identity()));

        SearchFieldDataDto items = fields.get(FilterField.DISCOVERY_TOTAL_ITEMS_DISCOVERED.name());
        Assertions.assertNotNull(items);
        Assertions.assertEquals(true, items.getSortable());

        SearchFieldDataDto resources = fields.get(FilterField.DISCOVERY_RESOURCES.name());
        Assertions.assertNotNull(resources);
        Assertions
                .assertEquals(List.of(Resource.CERTIFICATE.getCode(), Resource.CRYPTOGRAPHIC_KEY.getCode()),
                        resources.getValue());
        // A run holds several resources, so there is no one value to order by.
        Assertions.assertEquals(false, resources.getSortable());
    }

    private DiscoveryResponseDto retrieveTheDiscoveriesByResources(FilterConditionOperator operator, String code) {
        return retrieveTheDiscoveriesBySearch(
                List.of(aPropertyFilter(FilterField.DISCOVERY_RESOURCES, operator, code)));
    }

    private static Set<String> namesOf(DiscoveryResponseDto responseDto) {
        return responseDto.getDiscoveries().stream().map(DiscoveryListDto::getName).collect(Collectors.toSet());
    }

    private DiscoveryResponseDto retrieveTheDiscoveriesBySearch(final List<SearchFilterRequestDto> filters) {
        final SearchRequestDto searchRequestDto = new SearchRequestDto();
        searchRequestDto.setFilters(filters);
        return discoveryService.listDiscoveries(SecurityFilter.create(), searchRequestDto);
    }

}
