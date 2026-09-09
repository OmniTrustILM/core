package com.otilm.core.integration.search;

import com.otilm.api.exception.AttributeException;
import com.otilm.api.model.client.attribute.RequestAttributeV3;
import com.otilm.api.model.client.certificate.DiscoveryResponseDto;
import com.otilm.api.model.client.certificate.SearchColumnRequestDto;
import com.otilm.api.model.client.certificate.SearchRequestDto;
import com.otilm.api.model.client.connector.v2.ConnectorVersion;
import com.otilm.api.model.client.discovery.DiscoveryListDto;
import com.otilm.api.model.common.attribute.common.AttributeType;
import com.otilm.api.model.common.attribute.common.content.AttributeContentType;
import com.otilm.api.model.common.attribute.common.properties.CustomAttributeProperties;
import com.otilm.api.model.common.attribute.common.properties.MetadataAttributeProperties;
import com.otilm.api.model.common.attribute.v3.CustomAttributeV3;
import com.otilm.api.model.common.attribute.v3.MetadataAttributeV3;
import com.otilm.api.model.common.attribute.v3.content.BaseAttributeContentV3;
import com.otilm.api.model.common.attribute.v3.content.StringAttributeContentV3;
import com.otilm.api.model.common.attribute.v3.content.TextAttributeContentV3;
import com.otilm.api.model.core.auth.Resource;
import com.otilm.api.model.core.connector.AuthType;
import com.otilm.api.model.core.connector.ConnectorStatus;
import com.otilm.api.model.core.discovery.DiscoveryStatus;
import com.otilm.api.model.core.search.FilterFieldSource;
import com.otilm.core.attribute.engine.AttributeEngine;
import com.otilm.core.attribute.engine.records.ObjectAttributeContentInfo;
import com.otilm.core.dao.entity.Connector;
import com.otilm.core.dao.entity.Discovery;
import com.otilm.core.dao.repository.ConnectorRepository;
import com.otilm.core.dao.repository.DiscoveryRepository;
import com.otilm.core.model.auth.ResourceAction;
import com.otilm.core.security.authz.SecurityFilter;
import com.otilm.core.service.DiscoveryExternalService;
import com.otilm.core.util.BaseSpringBootTest;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.UUID;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;

/** Projection of attribute-sourced columns into a listing, exercised end to end through the discovery listing. */
class AttributeColumnProjectionITest extends BaseSpringBootTest {

    private static final String ENVIRONMENT = "environment";
    private static final String OWNING_TEAM = "owning-team";

    @Autowired
    private DiscoveryRepository discoveryRepository;

    @Autowired
    private ConnectorRepository connectorRepository;

    @Autowired
    private DiscoveryExternalService discoveryService;

    @Autowired
    private AttributeEngine attributeEngine;

    private Discovery withValues;
    private Discovery withoutValues;

    private UUID environmentUuid;
    private UUID owningTeamUuid;

    /**
     * A persisted connector, because a metadata definition's {@code connector_uuid} carries a foreign key to it. No
     * connector is contacted; the row only has to exist.
     */
    private Connector connector;

    @BeforeEach
    void loadData() throws Exception {
        connector = saveConnector();
        withValues = saveDiscovery("discovery-with-values");
        withoutValues = saveDiscovery("discovery-without-values");

        environmentUuid = registerCustomAttribute(ENVIRONMENT, "Environment");
        owningTeamUuid = registerCustomAttribute(OWNING_TEAM, "Owning team");

        attributeEngine
                .updateObjectCustomAttributesContent(Resource.DISCOVERY, withValues.getUuid(),
                        List
                                .of(attributeContent(environmentUuid, ENVIRONMENT, "production", "staging", "dr-site"),
                                        attributeContent(owningTeamUuid, OWNING_TEAM, "Platform")));
    }

    private Connector saveConnector() {
        Connector saved = new Connector();
        saved.setName("attribute-projection-connector");
        saved.setUrl("http://localhost:0/attribute-projection");
        saved.setVersion(ConnectorVersion.V2);
        saved.setStatus(ConnectorStatus.CONNECTED);
        saved.setAuthType(AuthType.NONE);
        return connectorRepository.save(saved);
    }

    private Discovery saveDiscovery(String name) {
        Discovery discovery = new Discovery();
        discovery.setName(name);
        // The list DTO stringifies the connector reference, so it has to be set even though no
        // connector is contacted here.
        discovery.setConnectorUuid(connector.getUuid());
        discovery.setConnectorName(connector.getName());
        discovery.setStatus(DiscoveryStatus.COMPLETED);
        discovery.setConnectorStatus(DiscoveryStatus.COMPLETED);
        discovery.setKind("test-kind");
        return discoveryRepository.save(discovery);
    }

    private UUID registerCustomAttribute(String name, String label) throws Exception {
        return registerCustomAttribute(name, label, true);
    }

    private UUID registerCustomAttribute(String name, String label, boolean visible) throws Exception {
        CustomAttributeV3 attribute = new CustomAttributeV3();
        attribute.setUuid(UUID.randomUUID().toString());
        attribute.setName(name);
        attribute.setType(AttributeType.CUSTOM);
        attribute.setContentType(AttributeContentType.TEXT);
        CustomAttributeProperties properties = new CustomAttributeProperties();
        properties.setLabel(label);
        properties.setList(true);
        properties.setMultiSelect(true);
        properties.setVisible(visible);
        attribute.setProperties(properties);
        attributeEngine.updateCustomAttributeDefinition(attribute, List.of(Resource.DISCOVERY));
        return UUID.fromString(attribute.getUuid());
    }

    private static RequestAttributeV3 attributeContent(UUID uuid, String name, String... values) {
        RequestAttributeV3 requestAttribute = new RequestAttributeV3();
        requestAttribute.setUuid(uuid);
        requestAttribute.setName(name);
        List<BaseAttributeContentV3<?>> content = new ArrayList<>();
        for (String value : values) {
            content.add(new TextAttributeContentV3(null, value));
        }
        requestAttribute.setContent(content);
        return requestAttribute;
    }

    /** The identifier the catalogue publishes for an attribute field: its name and its content type. */
    private static String fieldIdentifier(String attributeName) {
        return fieldIdentifier(attributeName, AttributeContentType.TEXT);
    }

    private static String fieldIdentifier(String attributeName, AttributeContentType contentType) {
        return attributeName + "|" + contentType.name();
    }

    private static SearchColumnRequestDto customColumn(String attributeName) {
        return new SearchColumnRequestDto(FilterFieldSource.CUSTOM, fieldIdentifier(attributeName));
    }

    private static SearchColumnRequestDto metadataColumn(String attributeName) {
        return new SearchColumnRequestDto(FilterFieldSource.META,
                fieldIdentifier(attributeName, AttributeContentType.STRING));
    }

    private void storeMetadata(String name, String label, String value) throws AttributeException {
        MetadataAttributeV3 meta = new MetadataAttributeV3();
        meta.setUuid(UUID.randomUUID().toString());
        meta.setName(name);
        meta.setType(AttributeType.META);
        meta.setContentType(AttributeContentType.STRING);
        MetadataAttributeProperties properties = new MetadataAttributeProperties();
        properties.setLabel(label);
        properties.setVisible(true);
        properties.setGlobal(false);
        meta.setProperties(properties);
        meta.setContent(List.of(new StringAttributeContentV3(value)));
        // Metadata is always connector-scoped, so the write is refused without one. The discovery fixture carries a
        // connector uuid for the same reason its list DTO needs one, and no connector is contacted here.
        attributeEngine
                .updateMetadataAttribute(meta,
                        ObjectAttributeContentInfo
                                .builder(Resource.DISCOVERY, withValues.getUuid())
                                .connector(connector.getUuid())
                                .build());
    }

    private List<DiscoveryListDto> list(List<SearchColumnRequestDto> columns) {
        SearchRequestDto request = new SearchRequestDto();
        request.setColumns(columns);
        DiscoveryResponseDto response = discoveryService.listDiscoveries(SecurityFilter.create(), request);
        return response.getDiscoveries();
    }

    private DiscoveryListDto entry(List<DiscoveryListDto> discoveries, Discovery discovery) {
        return discoveries
                .stream()
                .filter(item -> item.getUuid().equals(discovery.getUuid().toString()))
                .findFirst()
                .orElseThrow(
                        () -> new AssertionError("Discovery %s is not on the page".formatted(discovery.getName())));
    }

    @Test
    void requestingAnAttributeColumnReturnsItsValue() {
        List<DiscoveryListDto> discoveries = list(List.of(customColumn(OWNING_TEAM)));

        Map<String, List<BaseAttributeContentV3<?>>> custom = entry(discoveries, withValues)
                .getAttributeValues()
                .get(FilterFieldSource.CUSTOM);
        Assertions.assertEquals(1, custom.get(fieldIdentifier(OWNING_TEAM)).size());
        Assertions.assertEquals("Platform", custom.get(fieldIdentifier(OWNING_TEAM)).getFirst().getData());
    }

    @Test
    void valuesAreKeyedBySourceThenIdentifier() {
        List<DiscoveryListDto> discoveries = list(List.of(customColumn(OWNING_TEAM), customColumn(ENVIRONMENT)));

        Map<FilterFieldSource, Map<String, List<BaseAttributeContentV3<?>>>> values = entry(discoveries, withValues)
                .getAttributeValues();
        Assertions.assertEquals(Set.of(FilterFieldSource.CUSTOM), values.keySet());
        Assertions
                .assertEquals(Set.of(fieldIdentifier(OWNING_TEAM), fieldIdentifier(ENVIRONMENT)),
                        values.get(FilterFieldSource.CUSTOM).keySet());
    }

    @Test
    void aMultiValuedAttributeKeepsTheOrderItWasStoredIn() {
        List<DiscoveryListDto> discoveries = list(List.of(customColumn(ENVIRONMENT)));

        List<BaseAttributeContentV3<?>> values = entry(discoveries, withValues)
                .getAttributeValues()
                .get(FilterFieldSource.CUSTOM)
                .get(fieldIdentifier(ENVIRONMENT));
        Assertions
                .assertEquals(List.of("production", "staging", "dr-site"),
                        values.stream().map(value -> (Object) value.getData()).toList());
    }

    @Test
    void anObjectWithoutAValueIsStillReturned() {
        List<DiscoveryListDto> discoveries = list(List.of(customColumn(ENVIRONMENT)));

        Assertions.assertNull(entry(discoveries, withoutValues).getAttributeValues());
    }

    @Test
    void aRequestedColumnTheObjectHasNoValueForIsAbsentRatherThanEmpty() throws Exception {
        Discovery partial = saveDiscovery("discovery-partial");
        attributeEngine
                .updateObjectCustomAttributesContent(Resource.DISCOVERY, partial.getUuid(),
                        List.of(attributeContent(environmentUuid, ENVIRONMENT, "staging")));

        List<DiscoveryListDto> discoveries = list(List.of(customColumn(ENVIRONMENT), customColumn(OWNING_TEAM)));

        // The one it owns is projected and the one it does not is simply absent - not present and empty, which is
        // what would make the frontend render a blank cell for a column the object has no value for.
        Map<String, List<BaseAttributeContentV3<?>>> custom = entry(discoveries, partial)
                .getAttributeValues()
                .get(FilterFieldSource.CUSTOM);
        Assertions.assertEquals(Set.of(fieldIdentifier(ENVIRONMENT)), custom.keySet());
        Assertions.assertEquals("staging", custom.get(fieldIdentifier(ENVIRONMENT)).getFirst().getData());
    }

    @Test
    void aCustomColumnTheCallerMayNotReadProjectsNoValues() {
        // Resource LIST access is not enough to read a restricted custom attribute: without the caller's attribute
        // permissions on the projection query, naming the attribute as a column would return its plaintext.
        restrictObjectAccess(Resource.ATTRIBUTE, ResourceAction.MEMBERS);

        List<DiscoveryListDto> discoveries = list(List.of(customColumn(ENVIRONMENT), customColumn(OWNING_TEAM)));

        Assertions.assertNull(entry(discoveries, withValues).getAttributeValues());
    }

    @Test
    void aHiddenAttributeColumnProjectsNoValues() throws Exception {
        // The definition says its values are not to be shown to a user, which is what a column does with them. The
        // catalogue withholds such a field, but that flag is a hint on a response the caller is free to ignore, so
        // the projection query excludes the definition and its values are never loaded.
        UUID hiddenUuid = registerCustomAttribute("helper-only", "Helper only", false);
        Discovery hidden = saveDiscovery("discovery-hidden-attribute");
        attributeEngine
                .updateObjectCustomAttributesContent(Resource.DISCOVERY, hidden.getUuid(),
                        List.of(attributeContent(hiddenUuid, "helper-only", "internal")));

        List<DiscoveryListDto> discoveries = list(List.of(customColumn("helper-only")));

        Assertions.assertNull(entry(discoveries, hidden).getAttributeValues());
    }

    @Test
    void aMetadataColumnIsProjected() throws Exception {
        // Metadata definitions are created without `enabled` set, so a predicate requiring it excludes the whole
        // source. Only custom definitions carry the flag, so it is applied to those alone.
        storeMetadata(OWNING_TEAM, "Owning team", "Platform");

        List<DiscoveryListDto> discoveries = list(List.of(metadataColumn(OWNING_TEAM)));

        Map<String, List<BaseAttributeContentV3<?>>> metadata = entry(discoveries, withValues)
                .getAttributeValues()
                .get(FilterFieldSource.META);
        Assertions
                .assertEquals("Platform",
                        metadata.get(fieldIdentifier(OWNING_TEAM, AttributeContentType.STRING)).getFirst().getData());
    }

    @Test
    void aRequestWithoutColumnsProjectsNothing() {
        List<DiscoveryListDto> discoveries = list(null);

        Assertions.assertTrue(discoveries.stream().allMatch(item -> item.getAttributeValues() == null));
    }

    @Test
    void anEmptyColumnListProjectsNothing() {
        List<DiscoveryListDto> discoveries = list(List.of());

        Assertions.assertTrue(discoveries.stream().allMatch(item -> item.getAttributeValues() == null));
    }

    @Test
    void aPropertyColumnProjectsNothing() {
        // Property values are already on the entry; only attribute-sourced columns need loading.
        List<DiscoveryListDto> discoveries = list(
                List.of(new SearchColumnRequestDto(FilterFieldSource.PROPERTY, "DISCOVERY_NAME")));

        Assertions.assertTrue(discoveries.stream().allMatch(item -> item.getAttributeValues() == null));
    }

    @Test
    void anUnknownAttributeColumnLeavesTheListingIntact() {
        // A saved view naming an attribute that has since been deleted must not fail the listing that carries it.
        List<DiscoveryListDto> discoveries = list(List.of(customColumn("attribute-that-no-longer-exists")));

        Assertions.assertFalse(discoveries.isEmpty());
        Assertions.assertTrue(discoveries.stream().allMatch(item -> item.getAttributeValues() == null));
    }

    @Test
    void anIdentifierWithoutAContentTypeIsIgnored() {
        List<DiscoveryListDto> discoveries = list(
                List.of(new SearchColumnRequestDto(FilterFieldSource.CUSTOM, ENVIRONMENT)));

        Assertions.assertFalse(discoveries.isEmpty());
        Assertions.assertTrue(discoveries.stream().allMatch(item -> item.getAttributeValues() == null));
    }

    @Test
    void anAttributeOfAnotherSourceIsNotReturnedForACustomColumn() {
        // The same name may exist under another attribute type; a column addresses one source only.
        List<DiscoveryListDto> discoveries = list(
                List.of(new SearchColumnRequestDto(FilterFieldSource.META, fieldIdentifier(ENVIRONMENT))));

        Assertions.assertTrue(discoveries.stream().allMatch(item -> item.getAttributeValues() == null));
    }
}
