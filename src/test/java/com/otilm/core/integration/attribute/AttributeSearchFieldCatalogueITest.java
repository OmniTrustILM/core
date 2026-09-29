package com.otilm.core.integration.attribute;

import com.github.benmanes.caffeine.cache.Cache;
import com.otilm.api.model.client.attribute.custom.CustomAttributeCreateRequestDto;
import com.otilm.api.model.client.attribute.custom.CustomAttributeDefinitionDetailDto;
import com.otilm.api.model.client.attribute.metadata.GlobalMetadataCreateRequestDto;
import com.otilm.api.model.client.attribute.metadata.GlobalMetadataDefinitionDetailDto;
import com.otilm.api.model.client.attribute.metadata.GlobalMetadataUpdateRequestDto;
import com.otilm.api.model.client.certificate.SearchFilterRequestDto;
import com.otilm.api.model.client.certificate.SearchRequestDto;
import com.otilm.api.model.client.certificate.SearchSortRequestDto;
import com.otilm.api.model.client.connector.v2.ConnectorVersion;
import com.otilm.api.model.common.attribute.common.AttributeType;
import com.otilm.api.model.common.attribute.common.content.AttributeContentType;
import com.otilm.api.model.common.attribute.common.properties.MetadataAttributeProperties;
import com.otilm.api.model.common.attribute.v2.MetadataAttributeV2;
import com.otilm.api.model.common.attribute.v2.content.StringAttributeContentV2;
import com.otilm.api.model.core.auth.Resource;
import com.otilm.api.model.core.connector.ConnectorStatus;
import com.otilm.api.model.core.listview.ListViewColumnDto;
import com.otilm.api.model.core.listview.ListViewRequestDto;
import com.otilm.api.model.core.search.FilterConditionOperator;
import com.otilm.api.model.core.search.FilterFieldSource;
import com.otilm.api.model.core.search.SortDirection;
import com.otilm.core.attribute.engine.AttributeEngine;
import com.otilm.core.attribute.engine.AttributeSearchFieldCatalogue;
import com.otilm.core.attribute.engine.NamedField;
import com.otilm.core.attribute.engine.records.ObjectAttributeContentInfo;
import com.otilm.core.config.cache.CacheConfig;
import com.otilm.core.dao.entity.Connector;
import com.otilm.core.dao.repository.ConnectorRepository;
import com.otilm.core.model.SearchFieldObject;
import com.otilm.core.security.authz.SecurityFilter;
import com.otilm.core.service.AttributeExternalService;
import com.otilm.core.service.DiscoveryExternalService;
import com.otilm.core.service.ListViewExternalService;
import com.otilm.core.util.BaseSpringBootTest;
import com.otilm.core.util.SqlCapture;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.UUID;
import java.util.concurrent.Callable;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.cache.CacheManager;
import org.springframework.transaction.support.TransactionTemplate;

import static org.assertj.core.api.Assertions.assertThat;

class AttributeSearchFieldCatalogueITest extends BaseSpringBootTest {

    @Autowired
    private AttributeSearchFieldCatalogue catalogue;

    @Autowired
    private AttributeExternalService attributeService;

    @Autowired
    private CacheManager cacheManager;

    @Autowired
    private TransactionTemplate transactionTemplate;

    @Autowired
    private ListViewExternalService listViewService;

    @Autowired
    private DiscoveryExternalService discoveryService;

    @Autowired
    private AttributeEngine attributeEngine;

    @Autowired
    private ConnectorRepository connectorRepository;

    @Test
    void aSecondReadRunsNoCatalogueQuery() throws Exception {
        catalogue.fields(Resource.CERTIFICATE, false);

        assertThat(catalogueQueriesDuring(() -> catalogue.fields(Resource.CERTIFICATE, false))).isEmpty();
    }

    @Test
    void aReaderChangingItsCopyDoesNotChangeTheNextRead() throws Exception {
        createCustomAttribute("environment");
        List<SearchFieldObject> first = catalogue.fields(Resource.CERTIFICATE, false);
        environmentRow(first).setVisible(false);
        first.clear();

        List<SearchFieldObject> second = catalogue.fields(Resource.CERTIFICATE, false);

        assertThat(environmentRow(second).isVisible()).isTrue();
    }

    private static SearchFieldObject environmentRow(List<SearchFieldObject> rows) {
        return rows
                .stream()
                .filter(row -> row.getAttributeName().equals("environment"))
                .findFirst()
                .orElseThrow(() -> new AssertionError("no environment row in " + rows));
    }

    @Test
    void aCustomAttributeCreatedHereShowsOnTheNextRead() throws Exception {
        catalogue.fields(Resource.CERTIFICATE, false);

        createCustomAttribute("created-later");

        assertThat(catalogue.fields(Resource.CERTIFICATE, false))
                .anyMatch(row -> row.getAttributeName().equals("created-later"));
    }

    /** A replica that did not make the change keeps its entry, until a request names the new field. */
    @Test
    void aFieldCreatedElsewhereIsReadOnceARequestNamesIt() throws Exception {
        catalogue.fields(Resource.CERTIFICATE, false);
        onAnotherReplica(() -> createCustomAttribute("created-elsewhere"));
        NamedField named = NamedField
                .of(FilterFieldSource.CUSTOM, "created-elsewhere|" + AttributeContentType.TEXT.name());

        assertThat(catalogue.fields(Resource.CERTIFICATE, false)).noneMatch(named::names);
        assertThat(catalogue.fieldsNaming(Resource.CERTIFICATE, false, List.of(named))).anyMatch(named::names);
        assertThat(catalogue.fields(Resource.CERTIFICATE, false)).anyMatch(named::names);
    }

    @Test
    void aPropertyFieldNamedByARequestNeverForcesARebuild() throws Exception {
        catalogue.fields(Resource.CERTIFICATE, false);

        List<String> statements = SqlCapture
                .during(() -> catalogue
                        .fieldsNaming(Resource.CERTIFICATE, false,
                                List.of(NamedField.of(FilterFieldSource.PROPERTY, "COMMON_NAME"))))
                .statements();

        assertThat(statements).isEmpty();
    }

    @Test
    void aCustomAttributeMovedOffTheResourceLeavesItsCatalogue() throws Exception {
        CustomAttributeDefinitionDetailDto created = createCustomAttribute("moved");
        catalogue.fields(Resource.CERTIFICATE, false);

        attributeService.updateResources(UUID.fromString(created.getUuid()), List.of(Resource.CRYPTOGRAPHIC_KEY));

        assertThat(catalogue.fields(Resource.CERTIFICATE, false))
                .noneMatch(row -> row.getAttributeName().equals("moved"));
    }

    @Test
    void aDeletedCustomAttributeLeavesTheCatalogue() throws Exception {
        CustomAttributeDefinitionDetailDto created = createCustomAttribute("deleted");
        catalogue.fields(Resource.CERTIFICATE, false);

        attributeService.deleteCustomAttribute(UUID.fromString(created.getUuid()));

        assertThat(catalogue.fields(Resource.CERTIFICATE, false))
                .noneMatch(row -> row.getAttributeName().equals("deleted"));
    }

    /** The same write drops the cached entry once it commits, and leaves it when it rolls back. */
    @Test
    void onlyACommittedChangeDropsTheCachedEntry() throws Exception {
        catalogue.fields(Resource.CERTIFICATE, false);

        transactionTemplate.executeWithoutResult(status -> {
            try {
                createCustomAttribute("rolled-back");
            } catch (Exception e) {
                throw new IllegalStateException(e);
            }
            status.setRollbackOnly();
        });
        assertThat(catalogueQueriesDuring(() -> catalogue.fields(Resource.CERTIFICATE, false))).isEmpty();

        createCustomAttribute("committed");
        assertThat(catalogueQueriesDuring(() -> catalogue.fields(Resource.CERTIFICATE, false))).isNotEmpty();
    }

    /** An operator's rename of a global metadata attribute shows at once on the replica that made it. */
    @Test
    void aGlobalMetadataRenamedHereShowsOnTheNextRead() throws Exception {
        GlobalMetadataDefinitionDetailDto owner = createGlobalMetadataOnACertificate("owner", "Owner");
        assertThat(metadataRow(catalogue.fields(Resource.CERTIFICATE, false), "owner").getLabel()).isEqualTo("Owner");

        GlobalMetadataUpdateRequestDto rename = new GlobalMetadataUpdateRequestDto();
        rename.setLabel("Owner team");
        rename.setVisible(true);
        attributeService.editGlobalMetadata(UUID.fromString(owner.getUuid()), rename);

        assertThat(metadataRow(catalogue.fields(Resource.CERTIFICATE, false), "owner").getLabel())
                .isEqualTo("Owner team");
    }

    /** Another replica registered the field after this one cached the catalogue: saving a view with it still works. */
    @Test
    void aViewNamingAFieldCreatedElsewhereIsSaved() throws Exception {
        catalogue.fields(Resource.CERTIFICATE, false);
        onAnotherReplica(() -> createCustomAttribute("late-column"));
        String identifier = "late-column|" + AttributeContentType.TEXT.name();

        ListViewRequestDto request = certificateView("late view", identifier);
        SearchFilterRequestDto filter = new SearchFilterRequestDto();
        filter.setFieldSource(FilterFieldSource.CUSTOM);
        filter.setFieldIdentifier(identifier);
        filter.setCondition(FilterConditionOperator.EQUALS);
        filter.setValue("production");
        request.setFilters(List.of(filter));

        assertThat(listViewService.createView(request).getColumns()).hasSize(1);
    }

    /** A view saved through another replica keeps its column when this one reads it back. */
    @Test
    void aViewSavedElsewhereKeepsItsColumnHere() throws Exception {
        catalogue.fields(Resource.CERTIFICATE, false);
        String identifier = "late-read|" + AttributeContentType.TEXT.name();
        onAnotherReplica(() -> {
            createCustomAttribute("late-read");
            return listViewService.createView(certificateView("read view", identifier));
        });

        assertThat(listViewService.listViews(Resource.CERTIFICATE))
                .singleElement()
                .satisfies(view -> assertThat(view.getColumns()).hasSize(1));
    }

    /** The same holds for ordering a listing by the new field. */
    @Test
    void aSortOnAFieldCreatedElsewhereIsAccepted() throws Exception {
        catalogue.fields(Resource.DISCOVERY, false);
        onAnotherReplica(() -> createCustomAttribute("late-sort", Resource.DISCOVERY));

        SearchRequestDto request = new SearchRequestDto();
        request.setPageNumber(1);
        request.setItemsPerPage(10);
        request.setSort(new SearchSortRequestDto(FilterFieldSource.CUSTOM, "late-sort|TEXT", SortDirection.ASC));

        assertThat(discoveryService.listDiscoveries(SecurityFilter.create(), request).getDiscoveries()).isEmpty();
    }

    /** A global metadata attribute is in a resource's catalogue once a connector has written it to an object. */
    private GlobalMetadataDefinitionDetailDto createGlobalMetadataOnACertificate(String name, String label)
            throws Exception {
        GlobalMetadataCreateRequestDto request = new GlobalMetadataCreateRequestDto();
        request.setName(name);
        request.setLabel(label);
        request.setContentType(AttributeContentType.STRING);
        request.setVisible(true);
        GlobalMetadataDefinitionDetailDto created = attributeService.createGlobalMetadata(request);

        Connector connector = new Connector();
        connector.setName("metadata-writer");
        connector.setUrl("http://localhost:3665");
        connector.setVersion(ConnectorVersion.V1);
        connector.setStatus(ConnectorStatus.CONNECTED);
        connector = connectorRepository.save(connector);

        MetadataAttributeProperties properties = new MetadataAttributeProperties();
        properties.setLabel(label);
        properties.setVisible(true);
        properties.setGlobal(true);
        MetadataAttributeV2 written = new MetadataAttributeV2();
        written.setUuid(created.getUuid());
        written.setName(name);
        written.setType(AttributeType.META);
        written.setContentType(AttributeContentType.STRING);
        written.setProperties(properties);
        written.setContent(List.of(new StringAttributeContentV2("alice")));
        attributeEngine
                .updateMetadataAttribute(written,
                        ObjectAttributeContentInfo
                                .builder(Resource.CERTIFICATE, UUID.randomUUID())
                                .connector(connector.getUuid())
                                .build());
        return created;
    }

    private static SearchFieldObject metadataRow(List<SearchFieldObject> rows, String name) {
        return rows
                .stream()
                .filter(row -> row.getAttributeType() == AttributeType.META && row.getAttributeName().equals(name))
                .findFirst()
                .orElseThrow(() -> new AssertionError("no metadata row " + name + " in " + rows));
    }

    private static ListViewRequestDto certificateView(String name, String customFieldIdentifier) {
        ListViewRequestDto request = new ListViewRequestDto();
        request.setResource(Resource.CERTIFICATE);
        request.setName(name);
        request.setColumns(List.of(new ListViewColumnDto(FilterFieldSource.CUSTOM, customFieldIdentifier, null)));
        return request;
    }

    private static List<String> catalogueQueriesDuring(Callable<?> read) throws Exception {
        return SqlCapture
                .during(read)
                .statements()
                .stream()
                .filter(sql -> sql.contains("attribute_definition"))
                .toList();
    }

    private CustomAttributeDefinitionDetailDto createCustomAttribute(String name) throws Exception {
        return createCustomAttribute(name, Resource.CERTIFICATE);
    }

    private CustomAttributeDefinitionDetailDto createCustomAttribute(String name, Resource resource) throws Exception {
        CustomAttributeCreateRequestDto request = new CustomAttributeCreateRequestDto();
        request.setName(name);
        request.setLabel(name);
        request.setResources(List.of(resource));
        request.setContentType(AttributeContentType.TEXT);
        return attributeService.createCustomAttribute(request);
    }

    /** Makes a change as another replica would: afterwards this one holds exactly the entries it held before. */
    private void onAnotherReplica(Callable<?> change) throws Exception {
        Map<Object, Object> entriesBeforeTheChange = Map.copyOf(nativeCache().asMap());
        change.call();
        nativeCache().invalidateAll();
        nativeCache().putAll(entriesBeforeTheChange);
    }

    @SuppressWarnings("unchecked")
    private Cache<Object, Object> nativeCache() {
        return (Cache<Object, Object>) Objects
                .requireNonNull(cacheManager.getCache(CacheConfig.ATTRIBUTE_SEARCH_FIELDS_CACHE))
                .getNativeCache();
    }
}
