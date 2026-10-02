package com.otilm.core.integration.attribute;

import com.github.benmanes.caffeine.cache.Cache;
import com.otilm.api.exception.ValidationException;
import com.otilm.api.model.client.attribute.RequestAttributeV2;
import com.otilm.api.model.client.attribute.custom.CustomAttributeCreateRequestDto;
import com.otilm.api.model.client.attribute.custom.CustomAttributeDefinitionDetailDto;
import com.otilm.api.model.client.attribute.metadata.GlobalMetadataCreateRequestDto;
import com.otilm.api.model.client.attribute.metadata.GlobalMetadataDefinitionDetailDto;
import com.otilm.api.model.client.attribute.metadata.GlobalMetadataUpdateRequestDto;
import com.otilm.api.model.client.certificate.SearchRequestDto;
import com.otilm.api.model.client.certificate.SearchSortRequestDto;
import com.otilm.api.model.client.connector.v2.ConnectorVersion;
import com.otilm.api.model.common.attribute.common.AttributeType;
import com.otilm.api.model.common.attribute.common.content.AttributeContentType;
import com.otilm.api.model.common.attribute.common.properties.DataAttributeProperties;
import com.otilm.api.model.common.attribute.common.properties.MetadataAttributeProperties;
import com.otilm.api.model.common.attribute.v2.DataAttributeV2;
import com.otilm.api.model.common.attribute.v2.MetadataAttributeV2;
import com.otilm.api.model.common.attribute.v2.content.BaseAttributeContentV2;
import com.otilm.api.model.common.attribute.v2.content.StringAttributeContentV2;
import com.otilm.api.model.core.auth.Resource;
import com.otilm.api.model.core.connector.ConnectorStatus;
import com.otilm.api.model.core.listview.ListViewColumnDto;
import com.otilm.api.model.core.listview.ListViewDto;
import com.otilm.api.model.core.listview.ListViewFieldStatus;
import com.otilm.api.model.core.listview.ListViewFilterDto;
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
import com.otilm.core.dao.repository.AttributeDefinitionRepository;
import com.otilm.core.dao.repository.ConnectorRepository;
import com.otilm.core.model.SearchFieldObject;
import com.otilm.core.model.auth.ResourceAction;
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
import static org.assertj.core.api.Assertions.assertThatThrownBy;

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

    @Autowired
    private AttributeDefinitionRepository attributeDefinitionRepository;

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
    void aRequestNamingAMissingFieldRunsTheCatalogueQueryOnce() throws Exception {
        List<NamedField> missing = List.of(NamedField.of(FilterFieldSource.CUSTOM, "missing|TEXT"));

        assertThat(catalogueQueriesDuring(() -> catalogue.fieldsNaming(Resource.CERTIFICATE, false, missing)))
                .hasSize(1);
        assertThat(catalogueQueriesDuring(() -> catalogue.fieldsNaming(Resource.CERTIFICATE, false, missing)))
                .hasSize(1);
    }

    @Test
    void aNamedFieldAlreadyCachedRunsNoCatalogueQuery() throws Exception {
        createCustomAttribute("cached-field");
        catalogue.fields(Resource.CERTIFICATE, false);
        List<NamedField> cached = List.of(NamedField.of(FilterFieldSource.CUSTOM, "cached-field|TEXT"));

        assertThat(catalogueQueriesDuring(() -> catalogue.fieldsNaming(Resource.CERTIFICATE, false, cached))).isEmpty();
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

    @Test
    void aDeletedConnectorsDataFieldsLeaveTheCatalogue() throws Exception {
        Connector connector = savedConnector();
        writeDataAttributeToACertificate(connector, "connector-data");
        assertThat(catalogue.fields(Resource.CERTIFICATE, false))
                .anyMatch(row -> row.getAttributeName().equals("connector-data"));

        attributeEngine.deleteConnectorAttributeDefinitionsContent(connector.getUuid());

        assertThat(catalogue.fields(Resource.CERTIFICATE, false))
                .noneMatch(row -> row.getAttributeName().equals("connector-data"));
    }

    @Test
    void enablingOrDisablingACustomAttributeKeepsTheCachedEntry() throws Exception {
        UUID toggled = UUID.fromString(createCustomAttribute("toggled").getUuid());
        catalogue.fields(Resource.CERTIFICATE, false);

        attributeService.enableCustomAttribute(toggled, false);
        attributeService.enableCustomAttribute(toggled, true);

        assertThat(catalogueQueriesDuring(() -> catalogue.fields(Resource.CERTIFICATE, false))).isEmpty();
    }

    @Test
    void promotingOrDemotingConnectorMetadataKeepsTheCachedEntry() throws Exception {
        Connector connector = savedConnector();
        UUID metadata = UUID.randomUUID();
        writeMetadataToACertificate(connector, metadata, "connector-meta", "Connector meta", false);
        catalogue.fields(Resource.CERTIFICATE, false);

        GlobalMetadataDefinitionDetailDto promoted = attributeService
                .promoteConnectorMetadata(metadata, connector.getUuid());
        attributeService.demoteConnectorMetadata(UUID.fromString(promoted.getUuid()));

        assertThat(catalogueQueriesDuring(() -> catalogue.fields(Resource.CERTIFICATE, false))).isEmpty();
    }

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

    @Test
    void aViewWithAColumnOnAFieldCreatedElsewhereIsSaved() throws Exception {
        catalogue.fields(Resource.CERTIFICATE, false);
        onAnotherReplica(() -> createCustomAttribute("late-column"));

        ListViewRequestDto request = certificateView("late column", customColumn("late-column|TEXT"));

        assertThat(listViewService.createView(request).getColumns()).hasSize(1);
    }

    @Test
    void aViewFilteringOnAFieldCreatedElsewhereIsSaved() throws Exception {
        catalogue.fields(Resource.CERTIFICATE, false);
        onAnotherReplica(() -> createCustomAttribute("late-filter"));

        ListViewRequestDto request = certificateView("late filter", commonNameColumn());
        request.setFilters(List.of(lateFilter("late-filter|TEXT")));

        assertThat(listViewService.createView(request).getFilters()).hasSize(1);
    }

    @Test
    void aViewSortedByAFieldCreatedElsewhereIsSaved() throws Exception {
        catalogue.fields(Resource.CERTIFICATE, false);
        onAnotherReplica(() -> createCustomAttribute("late-order"));

        ListViewRequestDto request = certificateView("late order", commonNameColumn());
        request.setSort(new SearchSortRequestDto(FilterFieldSource.CUSTOM, "late-order|TEXT", SortDirection.ASC));

        assertThat(listViewService.createView(request).getSort()).isNotNull();
    }

    @Test
    void aViewSavedElsewhereKeepsItsColumnHere() throws Exception {
        catalogue.fields(Resource.CERTIFICATE, false);
        onAnotherReplica(() -> {
            createCustomAttribute("late-read");
            return listViewService.createView(certificateView("read view", customColumn("late-read|TEXT")));
        });

        assertThat(listViewService.listViews(Resource.CERTIFICATE))
                .singleElement()
                .satisfies(view -> assertThat(view.getColumns())
                        .singleElement()
                        .satisfies(column -> assertThat(column.getStatus()).isEqualTo(ListViewFieldStatus.AVAILABLE)));
    }

    @Test
    void aViewSavedElsewhereKeepsItsFilterHere() throws Exception {
        catalogue.fields(Resource.CERTIFICATE, false);
        onAnotherReplica(() -> {
            createCustomAttribute("late-read-filter");
            ListViewRequestDto request = certificateView("read filter", commonNameColumn());
            request.setFilters(List.of(lateFilter("late-read-filter|TEXT")));
            return listViewService.createView(request);
        });

        assertThat(listViewService.listViews(Resource.CERTIFICATE))
                .singleElement()
                .satisfies(view -> assertThat(view.getFilters())
                        .singleElement()
                        .satisfies(filter -> assertThat(filter.getStatus()).isEqualTo(ListViewFieldStatus.AVAILABLE)));
    }

    /**
     * Recreated on another replica, so this one's catalogue still lists the field under the definition the caller may
     * read. The replacement they may not read is neither bound nor disclosed, and the stored column does not read as
     * replaced by it.
     */
    @Test
    void aReplacementTheCallerMayNotReadIsNeitherBoundNorDisclosed() throws Exception {
        CustomAttributeDefinitionDetailDto original = createCustomAttribute("swapped");
        listViewService.createView(certificateView("swapped", customColumn("swapped|TEXT")));
        catalogue.fields(Resource.CERTIFICATE, false);
        CustomAttributeDefinitionDetailDto replacement = onAnotherReplica(() -> {
            attributeService.deleteCustomAttribute(UUID.fromString(original.getUuid()));
            return createCustomAttribute("swapped");
        });
        forbidObjectAccess(Resource.ATTRIBUTE, ResourceAction.MEMBERS, List.of(UUID.fromString(replacement.getUuid())));

        assertThat(catalogue.fields(Resource.CERTIFICATE, false))
                .anyMatch(row -> original.getUuid().equals(row.getDefinitionUuid().toString()));
        ListViewColumnDto read = listViewService.listViews(Resource.CERTIFICATE).getFirst().getColumns().getFirst();
        assertThat(read.getStatus()).isEqualTo(ListViewFieldStatus.UNAVAILABLE);
        assertThat(read.getAttributeDefinitionUuids()).containsExactly(UUID.fromString(original.getUuid()));
        ListViewRequestDto another = certificateView("another", customColumn("swapped|TEXT"));
        assertThatThrownBy(() -> listViewService.createView(another))
                .isInstanceOf(ValidationException.class)
                .hasMessageContaining("has no field swapped|TEXT");
    }

    @Test
    void aViewSavedElsewhereKeepsItsSortHere() throws Exception {
        catalogue.fields(Resource.CERTIFICATE, false);
        onAnotherReplica(() -> {
            createCustomAttribute("late-read-order");
            ListViewRequestDto request = certificateView("read order", commonNameColumn());
            request
                    .setSort(new SearchSortRequestDto(FilterFieldSource.CUSTOM, "late-read-order|TEXT",
                            SortDirection.ASC));
            return listViewService.createView(request);
        });

        assertThat(listViewService.listViews(Resource.CERTIFICATE))
                .singleElement()
                .satisfies(view -> assertThat(view.getSort()).isNotNull());
    }

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

    /**
     * The same metadata name is registered on keys and on certificates. A certificate view is bound to the certificate
     * definition alone, so once that one is gone a definition registered on certificates later is a replacement, even
     * though the key definition the view never showed is still there.
     */
    @Test
    void aMetadataColumnIsNotTakenOverOnceItsOwnDefinitionLeavesTheResource() throws Exception {
        Connector onKeys = savedConnector("keys-writer");
        Connector first = savedConnector("first-writer");
        writeMetadataTo(Resource.CRYPTOGRAPHIC_KEY, onKeys, "status");
        writeMetadataTo(Resource.CERTIFICATE, first, "status");
        UUID own = metadataDefinition(first, "status");
        ListViewDto created = listViewService
                .createView(certificateView("status",
                        new ListViewColumnDto(FilterFieldSource.META, "status|STRING", null)));
        assertThat(created.getColumns().getFirst().getAttributeDefinitionUuids()).containsExactly(own);

        transactionTemplate.executeWithoutResult(tx -> deleteMetadata(own));
        writeMetadataTo(Resource.CERTIFICATE, savedConnector("second-writer"), "status");

        ListViewColumnDto read = listViewService.listViews(Resource.CERTIFICATE).getFirst().getColumns().getFirst();
        assertThat(read.getStatus()).isEqualTo(ListViewFieldStatus.REPLACED);
        assertThat(read.getAttributeDefinitionUuids()).containsExactly(own);
    }

    /**
     * Deleted on another replica, so this one's catalogue still offers the field while no definition backs it. The
     * stored column reads as gone rather than replaced, and nothing can be bound to the field in that window.
     */
    @Test
    void aFieldNoDefinitionBacksAnyMoreIsUnavailableAndCannotBeBound() throws Exception {
        CustomAttributeDefinitionDetailDto gone = createCustomAttribute("gone-elsewhere");
        listViewService.createView(certificateView("gone", customColumn("gone-elsewhere|TEXT")));
        catalogue.fields(Resource.CERTIFICATE, false);

        onAnotherReplica(() -> {
            attributeService.deleteCustomAttribute(UUID.fromString(gone.getUuid()));
            return null;
        });

        assertThat(catalogue.fields(Resource.CERTIFICATE, false))
                .anyMatch(row -> "gone-elsewhere".equals(row.getAttributeName()));
        assertThat(listViewService.listViews(Resource.CERTIFICATE).getFirst().getColumns().getFirst().getStatus())
                .isEqualTo(ListViewFieldStatus.UNAVAILABLE);
        ListViewRequestDto another = certificateView("another", customColumn("gone-elsewhere|TEXT"));
        assertThatThrownBy(() -> listViewService.createView(another))
                .isInstanceOf(ValidationException.class)
                .hasMessageContaining("has no field gone-elsewhere|TEXT");
    }

    private void writeMetadataTo(Resource resource, Connector connector, String name) throws Exception {
        writeMetadata(resource, connector, UUID.randomUUID(), name, name, false);
    }

    private UUID metadataDefinition(Connector connector, String name) {
        return attributeDefinitionRepository
                .findByTypeAndConnectorUuidAndName(AttributeType.META, connector.getUuid(), name)
                .orElseThrow()
                .getUuid();
    }

    private void deleteMetadata(UUID definition) {
        try {
            attributeEngine.deleteAttributeDefinition(AttributeType.META, definition);
        } catch (Exception e) {
            throw new IllegalStateException(e);
        }
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
        writeMetadataToACertificate(savedConnector(), UUID.fromString(created.getUuid()), name, label, true);
        return created;
    }

    private void writeMetadataToACertificate(Connector connector, UUID uuid, String name, String label, boolean global)
            throws Exception {
        writeMetadata(Resource.CERTIFICATE, connector, uuid, name, label, global);
    }

    private void writeMetadata(Resource resource, Connector connector, UUID uuid, String name, String label,
            boolean global) throws Exception {
        MetadataAttributeProperties properties = new MetadataAttributeProperties();
        properties.setLabel(label);
        properties.setVisible(true);
        properties.setGlobal(global);
        MetadataAttributeV2 written = new MetadataAttributeV2();
        written.setUuid(uuid.toString());
        written.setName(name);
        written.setType(AttributeType.META);
        written.setContentType(AttributeContentType.STRING);
        written.setProperties(properties);
        written.setContent(List.of(new StringAttributeContentV2("alice")));
        attributeEngine
                .updateMetadataAttribute(written,
                        ObjectAttributeContentInfo
                                .builder(resource, UUID.randomUUID())
                                .connector(connector.getUuid())
                                .build());
    }

    private void writeDataAttributeToACertificate(Connector connector, String name) throws Exception {
        DataAttributeProperties properties = new DataAttributeProperties();
        properties.setLabel(name);
        DataAttributeV2 attribute = new DataAttributeV2();
        attribute.setUuid(UUID.randomUUID().toString());
        attribute.setName(name);
        attribute.setType(AttributeType.DATA);
        attribute.setContentType(AttributeContentType.STRING);
        attribute.setProperties(properties);
        attributeEngine.updateDataAttributeDefinitions(connector.getUuid(), null, List.of(attribute));

        // v2 content carries no type discriminator, so a request deserializes into the base content class
        BaseAttributeContentV2<String> content = new BaseAttributeContentV2<>();
        content.setReference("value");
        content.setData("value");
        RequestAttributeV2 written = new RequestAttributeV2();
        written.setUuid(UUID.fromString(attribute.getUuid()));
        written.setName(name);
        written.setContent(List.of(content));
        attributeEngine
                .updateObjectDataAttributesContent(ObjectAttributeContentInfo
                        .builder(Resource.CERTIFICATE, UUID.randomUUID())
                        .connector(connector.getUuid())
                        .build(), List.of(written));
    }

    private Connector savedConnector() {
        return savedConnector("attribute-writer");
    }

    private Connector savedConnector(String name) {
        Connector connector = new Connector();
        connector.setName(name);
        connector.setUrl("http://" + name + ":3665");
        connector.setVersion(ConnectorVersion.V1);
        connector.setStatus(ConnectorStatus.CONNECTED);
        return connectorRepository.save(connector);
    }

    private static SearchFieldObject metadataRow(List<SearchFieldObject> rows, String name) {
        return rows
                .stream()
                .filter(row -> row.getAttributeType() == AttributeType.META && row.getAttributeName().equals(name))
                .findFirst()
                .orElseThrow(() -> new AssertionError("no metadata row " + name + " in " + rows));
    }

    private static ListViewRequestDto certificateView(String name, ListViewColumnDto column) {
        ListViewRequestDto request = new ListViewRequestDto();
        request.setResource(Resource.CERTIFICATE);
        request.setName(name);
        request.setColumns(List.of(column));
        return request;
    }

    private static ListViewFilterDto lateFilter(String fieldIdentifier) {
        ListViewFilterDto filter = new ListViewFilterDto();
        filter.setFieldSource(FilterFieldSource.CUSTOM);
        filter.setFieldIdentifier(fieldIdentifier);
        filter.setCondition(FilterConditionOperator.EQUALS);
        filter.setValue("production");
        return filter;
    }

    private static ListViewColumnDto customColumn(String fieldIdentifier) {
        return new ListViewColumnDto(FilterFieldSource.CUSTOM, fieldIdentifier, null);
    }

    private static ListViewColumnDto commonNameColumn() {
        return new ListViewColumnDto(FilterFieldSource.PROPERTY, "COMMON_NAME", null);
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
    private <T> T onAnotherReplica(Callable<T> change) throws Exception {
        Map<Object, Object> entriesBeforeTheChange = Map.copyOf(nativeCache().asMap());
        T changed = change.call();
        nativeCache().invalidateAll();
        nativeCache().putAll(entriesBeforeTheChange);
        return changed;
    }

    @SuppressWarnings("unchecked")
    private Cache<Object, Object> nativeCache() {
        return (Cache<Object, Object>) Objects
                .requireNonNull(cacheManager.getCache(CacheConfig.ATTRIBUTE_SEARCH_FIELDS_CACHE))
                .getNativeCache();
    }
}
