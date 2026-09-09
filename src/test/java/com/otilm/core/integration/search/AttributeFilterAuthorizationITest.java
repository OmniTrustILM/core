package com.otilm.core.integration.search;

import com.otilm.api.exception.ValidationException;
import com.otilm.api.model.client.attribute.RequestAttributeV3;
import com.otilm.api.model.client.certificate.SearchColumnRequestDto;
import com.otilm.api.model.client.certificate.SearchFilterRequestDto;
import com.otilm.api.model.client.certificate.SearchRequestDto;
import com.otilm.api.model.client.certificate.SearchSortRequestDto;
import com.otilm.api.model.client.connector.v2.ConnectorVersion;
import com.otilm.api.model.client.discovery.DiscoveryListDto;
import com.otilm.api.model.common.attribute.common.AttributeType;
import com.otilm.api.model.common.attribute.common.content.AttributeContentType;
import com.otilm.api.model.common.attribute.common.properties.CustomAttributeProperties;
import com.otilm.api.model.common.attribute.common.properties.MetadataAttributeProperties;
import com.otilm.api.model.common.attribute.v3.CustomAttributeV3;
import com.otilm.api.model.common.attribute.v3.MetadataAttributeV3;
import com.otilm.api.model.common.attribute.v3.content.BaseAttributeContentV3;
import com.otilm.api.model.common.attribute.v3.content.TextAttributeContentV3;
import com.otilm.api.model.core.auth.Resource;
import com.otilm.api.model.core.discovery.DiscoveryStatus;
import com.otilm.api.model.core.search.FilterConditionOperator;
import com.otilm.api.model.core.search.FilterFieldSource;
import com.otilm.api.model.core.search.SearchFieldDataDto;
import com.otilm.api.model.core.search.SortDirection;
import com.otilm.core.attribute.engine.AttributeEngine;
import com.otilm.core.attribute.engine.records.ObjectAttributeContentInfo;
import com.otilm.core.dao.entity.AttributeContentItem;
import com.otilm.core.dao.entity.AttributeDefinition;
import com.otilm.core.dao.entity.Connector;
import com.otilm.core.dao.entity.Discovery;
import com.otilm.core.dao.repository.AttributeContentItemRepository;
import com.otilm.core.dao.repository.AttributeDefinitionRepository;
import com.otilm.core.dao.repository.ConnectorRepository;
import com.otilm.core.dao.repository.DiscoveryRepository;
import com.otilm.core.model.auth.ResourceAction;
import com.otilm.core.security.authz.SecurityFilter;
import com.otilm.core.security.authz.opa.dto.OpaRequestedResource;
import com.otilm.core.service.DiscoveryExternalService;
import com.otilm.core.util.BaseSpringBootTest;
import java.util.ArrayList;
import java.util.List;
import java.util.UUID;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;

import static com.otilm.core.util.builders.SearchFilterRequestDtoBuilder.aCustomAttributeFilter;
import static com.otilm.core.util.builders.SearchFilterRequestDtoBuilder.aMetaAttributeFilter;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.argThat;
import static org.mockito.Mockito.clearInvocations;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;

/**
 * Filtering an attribute reads its content, so it is gated like the projection that renders one and the ordering that
 * reads one for a sort key. A caller who may not read a value must not be able to ask questions about it either: the
 * rows an attribute filter returns are the rows matching the predicate, so an ungated filter answers direct questions
 * about content the same response would withhold.
 */
class AttributeFilterAuthorizationITest extends BaseSpringBootTest {

    private static final String ENVIRONMENT = "environment";

    /** Registered with {@code visible: false}, which is what the catalogue withholds a column and an ordering for. */
    private static final String HIDDEN = "hidden-environment";

    private static final String HIDDEN_METADATA = "hidden-metadata-environment";

    @Autowired
    private DiscoveryExternalService discoveryService;

    @Autowired
    private DiscoveryRepository discoveryRepository;

    @Autowired
    private ConnectorRepository connectorRepository;

    @Autowired
    private AttributeEngine attributeEngine;

    @Autowired
    private AttributeDefinitionRepository attributeDefinitionRepository;

    @Autowired
    private AttributeContentItemRepository attributeContentItemRepository;

    private UUID definitionUuid;

    /** Metadata is connector-scoped, so the definition write needs a connector row to point at. */
    private UUID connectorUuid;

    @BeforeEach
    void loadData() throws Exception {
        Connector connector = new Connector();
        connector.setName("attribute-filter-connector");
        connector.setUrl("http://localhost:0/attribute-filter");
        connector.setVersion(ConnectorVersion.V2);
        connectorUuid = connectorRepository.saveAndFlush(connector).getUuid();

        definitionUuid = registerCustomAttribute();

        seedDiscovery("first-created", "charlie");
        seedDiscovery("second-created", "alpha");
        seedDiscovery("third-created", "bravo");
    }

    @Test
    void anAttributeTheCallerMayNotReadCannotNarrowTheListing() {
        restrictObjectAccess(Resource.ATTRIBUTE, ResourceAction.MEMBERS);

        Assertions.assertEquals(List.of(), listNamesFilteredByEnvironment("alpha"));
    }

    @Test
    void anAttributeTheCallerMayReadNarrowsTheListing() {
        Assertions.assertEquals(List.of("second-created"), listNamesFilteredByEnvironment("alpha"));
    }

    @Test
    void aRestrictedCallerIsNotToldWhichObjectsCarryAValue() {
        restrictObjectAccess(Resource.ATTRIBUTE, ResourceAction.MEMBERS);

        Assertions.assertEquals(List.of(), listNamesFiltered(FilterConditionOperator.NOT_EMPTY, null));
    }

    @Test
    void aNegatedConditionKeepsEveryRowForARestrictedCaller() {
        restrictObjectAccess(Resource.ATTRIBUTE, ResourceAction.MEMBERS);

        Assertions
                .assertEquals(List.of("first-created", "second-created", "third-created"),
                        listNamesFiltered(FilterConditionOperator.NOT_EQUALS, "alpha").stream().sorted().toList());
    }

    @Test
    void contentOfADisabledCustomDefinitionCannotNarrowTheListing() {
        AttributeDefinition definition = attributeDefinitionRepository
                .findByAttributeUuid(definitionUuid)
                .orElseThrow();
        definition.setEnabled(false);
        attributeDefinitionRepository.saveAndFlush(definition);

        Assertions.assertEquals(List.of(), listNamesFilteredByEnvironment("alpha"));
    }

    @Test
    void encryptedContentCannotNarrowTheListingByValue() {
        encryptStoredContent("alpha");

        Assertions.assertEquals(List.of(), listNamesFilteredByEnvironment("alpha"));
    }

    @Test
    void encryptedContentStillAnswersAPresenceFilter() {
        encryptStoredContent("alpha");

        Assertions
                .assertEquals(List.of("first-created", "second-created", "third-created"),
                        listNamesFiltered(FilterConditionOperator.NOT_EMPTY, null).stream().sorted().toList());
    }

    @Test
    void contentOfAHiddenAttributeCannotNarrowTheListing() throws Exception {
        UUID hiddenUuid = registerCustomAttribute(HIDDEN, AttributeContentType.TEXT, false);
        storeContent("second-created", hiddenUuid, HIDDEN, "alpha");

        Assertions
                .assertEquals(List.of(),
                        listNamesFiltered(HIDDEN, AttributeContentType.TEXT, FilterConditionOperator.EQUALS, "alpha"));
    }

    @Test
    void aHiddenAttributeDoesNotAnswerAPresenceFilterEither() throws Exception {
        UUID hiddenUuid = registerCustomAttribute(HIDDEN, AttributeContentType.TEXT, false);
        storeContent("second-created", hiddenUuid, HIDDEN, "alpha");

        Assertions
                .assertEquals(List.of(),
                        listNamesFiltered(HIDDEN, AttributeContentType.TEXT, FilterConditionOperator.NOT_EMPTY, null));
    }

    @Test
    void aSecretAttributeCannotBeFilteredByValue() throws Exception {
        registerCustomAttribute("filter-secret-probe", AttributeContentType.SECRET, true);

        Assertions
                .assertThrows(ValidationException.class, () -> listNamesFiltered("filter-secret-probe",
                        AttributeContentType.SECRET, FilterConditionOperator.EQUALS, "anything"));
    }

    @Test
    void aSecretAttributeIsOfferedPresenceConditionsAlone() throws Exception {
        // The refusal above is only safe because the catalogue never offers a value condition for these content
        // types; otherwise the picker would publish a filter the listing then rejects.
        registerCustomAttribute("filter-secret-probe", AttributeContentType.SECRET, true);

        SearchFieldDataDto field = attributeEngine
                .getResourceSearchableFields(Resource.DISCOVERY, false)
                .stream()
                .flatMap(group -> group.getSearchFieldData().stream())
                .filter(item -> ("filter-secret-probe|" + AttributeContentType.SECRET.name())
                        .equals(item.getFieldIdentifier()))
                .findFirst()
                .orElseThrow();

        Assertions
                .assertEquals(List.of(FilterConditionOperator.EMPTY, FilterConditionOperator.NOT_EMPTY),
                        field.getConditions());
    }

    @Test
    void aSecretAttributeStillAnswersAPresenceFilter() throws Exception {
        UUID secretUuid = registerCustomAttribute("filter-secret-probe", AttributeContentType.SECRET, true);
        storeContent("second-created", secretUuid, "filter-secret-probe", "s3cret");

        Assertions
                .assertEquals(List.of("second-created"), listNamesFiltered("filter-secret-probe",
                        AttributeContentType.SECRET, FilterConditionOperator.NOT_EMPTY, null));
    }

    @Test
    void aHiddenMetadataDefinitionStillFiltersByValue() throws Exception {
        // A connector's `visible: false` is a display hint, not a permission, and the catalogue publishes the field
        // as filterable - so gating it would silently answer "no rows" for content the listing may read.
        seedHiddenMetadata("second-created", "alpha");

        Assertions
                .assertEquals(List.of("second-created"), listNames(aMetaAttributeFilter(HIDDEN_METADATA,
                        AttributeContentType.TEXT, FilterConditionOperator.EQUALS, "alpha")));
    }

    /**
     * Resolving the caller's attribute permissions is a synchronous authorization call, and one listing reaches
     * attribute content four times over: the page predicate, the count predicate, the sort key and the projection.
     */
    @Test
    void oneListingResolvesTheCallersAttributePermissionsOnce() {
        // Anything the setup above authorized has already been counted, so only what the listing itself asks remains.
        clearInvocations(opaClient);

        listFilteredSortedAndProjectedByEnvironment();

        verify(opaClient, times(1)).checkObjectAccess(any(), argThat(this::isAttributeMembersRequest), any(), any());
    }

    private boolean isAttributeMembersRequest(OpaRequestedResource request) {
        return request != null && request.getProperties() != null
                && Resource.ATTRIBUTE.getCode().equals(request.getProperties().get("name"))
                && ResourceAction.MEMBERS.getCode().equals(request.getProperties().get("action"));
    }

    /** Moves one stored value to the encrypted column, which is where content of an encrypted attribute lives. */
    private void encryptStoredContent(String value) {
        AttributeDefinition definition = attributeDefinitionRepository
                .findByAttributeUuid(definitionUuid)
                .orElseThrow();
        List<AttributeContentItem> items = attributeContentItemRepository
                .findByAttributeDefinitionUuid(definition.getUuid());
        AttributeContentItem stored = items
                .stream()
                .filter(item -> item.getJson() != null && item.getJson().getData().toString().equals(value))
                .findFirst()
                .orElseThrow();
        stored.setEncryptedData("ciphertext");
        attributeContentItemRepository.saveAndFlush(stored);
    }

    private List<String> listNamesFilteredByEnvironment(String value) {
        return listNamesFiltered(FilterConditionOperator.EQUALS, value);
    }

    private List<String> listNamesFiltered(FilterConditionOperator condition, String value) {
        return listNamesFiltered(ENVIRONMENT, AttributeContentType.TEXT, condition, value);
    }

    private List<String> listNamesFiltered(String attributeName, AttributeContentType contentType,
            FilterConditionOperator condition, String value) {
        return listNames(aCustomAttributeFilter(attributeName, contentType, condition, value));
    }

    private List<String> listNames(SearchFilterRequestDto filter) {
        SearchRequestDto request = new SearchRequestDto();
        request.setPageNumber(1);
        request.setItemsPerPage(10);
        request.setFilters(List.of(filter));
        return listNames(request);
    }

    /** One request that filters, orders and projects the same attribute - the three paths that read its content. */
    private List<String> listFilteredSortedAndProjectedByEnvironment() {
        String fieldIdentifier = ENVIRONMENT + "|" + AttributeContentType.TEXT.name();

        SearchRequestDto request = new SearchRequestDto();
        request.setPageNumber(1);
        request.setItemsPerPage(10);
        request
                .setFilters(List
                        .of(aCustomAttributeFilter(ENVIRONMENT, AttributeContentType.TEXT,
                                FilterConditionOperator.NOT_EMPTY, null)));
        request.setSort(new SearchSortRequestDto(FilterFieldSource.CUSTOM, fieldIdentifier, SortDirection.ASC));
        request.setColumns(List.of(new SearchColumnRequestDto(FilterFieldSource.CUSTOM, fieldIdentifier)));
        return listNames(request);
    }

    private List<String> listNames(SearchRequestDto request) {
        return discoveryService
                .listDiscoveries(SecurityFilter.create(), request)
                .getDiscoveries()
                .stream()
                .map(DiscoveryListDto::getName)
                .toList();
    }

    /** Metadata registered {@code visible: false}, which is how a connector marks a technical attribute. */
    private void seedHiddenMetadata(String discoveryName, String value) throws Exception {
        Discovery discovery = discoveryRepository.findByName(discoveryName).orElseThrow();
        MetadataAttributeV3 meta = new MetadataAttributeV3();
        meta.setUuid(UUID.randomUUID().toString());
        meta.setName(HIDDEN_METADATA);
        meta.setType(AttributeType.META);
        meta.setContentType(AttributeContentType.TEXT);
        MetadataAttributeProperties properties = new MetadataAttributeProperties();
        properties.setLabel(HIDDEN_METADATA);
        properties.setVisible(false);
        properties.setGlobal(false);
        meta.setProperties(properties);
        meta.setContent(List.of(new TextAttributeContentV3(null, value)));
        attributeEngine
                .updateMetadataAttribute(meta,
                        ObjectAttributeContentInfo
                                .builder(Resource.DISCOVERY, discovery.getUuid())
                                .connector(connectorUuid)
                                .build());
    }

    private UUID registerCustomAttribute() throws Exception {
        return registerCustomAttribute(ENVIRONMENT, AttributeContentType.TEXT, true);
    }

    private UUID registerCustomAttribute(String name, AttributeContentType contentType, boolean visible)
            throws Exception {
        CustomAttributeV3 attribute = new CustomAttributeV3();
        UUID uuid = UUID.randomUUID();
        attribute.setUuid(uuid.toString());
        attribute.setName(name);
        attribute.setType(AttributeType.CUSTOM);
        attribute.setContentType(contentType);
        CustomAttributeProperties properties = new CustomAttributeProperties();
        properties.setLabel(name);
        properties.setVisible(visible);
        attribute.setProperties(properties);
        attributeEngine.updateCustomAttributeDefinition(attribute, List.of(Resource.DISCOVERY));
        return uuid;
    }

    private void seedDiscovery(String name, String environmentValue) throws Exception {
        Discovery discovery = new Discovery();
        discovery.setName(name);
        discovery.setStatus(DiscoveryStatus.COMPLETED);
        discovery.setConnectorStatus(DiscoveryStatus.COMPLETED);
        // The list DTO reads both, so a discovery without them cannot be mapped for the response.
        discovery.setConnectorUuid(connectorUuid);
        discovery.setConnectorName("attribute-filter-connector");
        discovery = discoveryRepository.save(discovery);

        attributeEngine
                .updateObjectCustomAttributesContent(Resource.DISCOVERY, discovery.getUuid(),
                        List.of(customContent(environmentValue)));
    }

    /** Writes one value of another registered attribute onto an already-seeded discovery. */
    private void storeContent(String discoveryName, UUID attributeUuid, String attributeName, String value)
            throws Exception {
        Discovery discovery = discoveryRepository.findByName(discoveryName).orElseThrow();
        RequestAttributeV3 requestAttribute = new RequestAttributeV3();
        requestAttribute.setUuid(attributeUuid);
        requestAttribute.setName(attributeName);
        requestAttribute.setContent(List.of(new TextAttributeContentV3(null, value)));
        attributeEngine
                .updateObjectCustomAttributesContent(Resource.DISCOVERY, discovery.getUuid(),
                        List.of(requestAttribute));
    }

    private RequestAttributeV3 customContent(String value) {
        RequestAttributeV3 requestAttribute = new RequestAttributeV3();
        requestAttribute.setUuid(definitionUuid);
        requestAttribute.setName(ENVIRONMENT);
        List<BaseAttributeContentV3<?>> content = new ArrayList<>();
        content.add(new TextAttributeContentV3(null, value));
        requestAttribute.setContent(content);
        return requestAttribute;
    }
}
