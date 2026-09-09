package com.otilm.core.integration.search;

import com.otilm.api.exception.ValidationException;
import com.otilm.api.model.client.attribute.RequestAttributeV3;
import com.otilm.api.model.client.certificate.DiscoveryResponseDto;
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
import com.otilm.api.model.common.attribute.v3.content.StringAttributeContentV3;
import com.otilm.api.model.common.attribute.v3.content.TextAttributeContentV3;
import com.otilm.api.model.core.auth.Resource;
import com.otilm.api.model.core.connector.AuthType;
import com.otilm.api.model.core.connector.ConnectorStatus;
import com.otilm.api.model.core.discovery.DiscoveryStatus;
import com.otilm.api.model.core.search.FilterConditionOperator;
import com.otilm.api.model.core.search.FilterFieldSource;
import com.otilm.api.model.core.search.SearchFieldDataDto;
import com.otilm.api.model.core.search.SortDirection;
import com.otilm.core.attribute.engine.AttributeEngine;
import com.otilm.core.attribute.engine.records.ObjectAttributeContentInfo;
import com.otilm.core.dao.entity.Connector;
import com.otilm.core.dao.entity.Discovery;
import com.otilm.core.dao.repository.ConnectorRepository;
import com.otilm.core.dao.repository.DiscoveryRepository;
import com.otilm.core.security.authz.SecurityFilter;
import com.otilm.core.service.DiscoveryExternalService;
import com.otilm.core.util.BaseSpringBootTest;
import java.util.ArrayList;
import java.util.List;
import java.util.UUID;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;

import static com.otilm.core.integration.search.CatalogueFields.field;
import static com.otilm.core.util.builders.SearchFilterRequestDtoBuilder.aCustomAttributeFilter;
import static com.otilm.core.util.builders.SearchFilterRequestDtoBuilder.aMetaAttributeFilter;

/**
 * One hidden custom attribute read through every path that has to answer whether its values may be shown: the
 * catalogue, the column projection, an ordering and a filter. All four resolve it from the mirrored column, and this
 * pins that they agree.
 *
 * <p>
 * The metadata cases beside them pin the one place the paths diverge: a metadata definition carries the flag as a
 * connector display hint, so it withholds a column and a sort key but leaves the values filterable.
 */
class HiddenAttributeAgreementITest extends BaseSpringBootTest {

    private static final String HIDDEN = "internal-routing";
    private static final String VISIBLE = "environment";

    /** Registered twice, once hidden and once visible, which is what collapses into one catalogue field. */
    private static final String DUPLICATED_META = "connector-region";
    private static final String HIDDEN_META = "connector-internal";

    @Autowired
    private DiscoveryRepository discoveryRepository;

    @Autowired
    private ConnectorRepository connectorRepository;

    @Autowired
    private DiscoveryExternalService discoveryService;

    @Autowired
    private AttributeEngine attributeEngine;

    private Connector connector;
    private Discovery alpha;
    private Discovery beta;

    @BeforeEach
    void loadData() throws Exception {
        connector = saveConnector();
        alpha = saveDiscovery(connector, "discovery-alpha");
        beta = saveDiscovery(connector, "discovery-beta");

        UUID hiddenUuid = registerCustomAttribute(HIDDEN, false);
        UUID visibleUuid = registerCustomAttribute(VISIBLE, true);

        storeContent(alpha, hiddenUuid, HIDDEN, "aaa");
        storeContent(beta, hiddenUuid, HIDDEN, "zzz");
        storeContent(alpha, visibleUuid, VISIBLE, "production");

        // The lower value sits behind the hidden definition, so an ordering that reads it puts alpha first -
        // which is also the fixture order, so the expected sequence cannot arise from a sort that never ran.
        storeMetadata(alpha, DUPLICATED_META, "aaa", false);
        storeMetadata(beta, DUPLICATED_META, "zzz", true);
        storeMetadata(alpha, HIDDEN_META, "internal", false);
    }

    @Test
    void theCatalogueOffersTheHiddenFieldNeitherAsAColumnNorForOrdering() {
        SearchFieldDataDto hidden = field(discoveryService.getSearchableFieldInformationByGroup(), identifier(HIDDEN))
                .orElseThrow();

        Assertions.assertEquals(false, hidden.getDisplayable());
        Assertions.assertEquals(false, hidden.getSortable());
    }

    @Test
    void theCatalogueOffersTheHiddenFieldNoValueCondition() {
        SearchFieldDataDto hidden = field(discoveryService.getSearchableFieldInformationByGroup(), identifier(HIDDEN))
                .orElseThrow();

        Assertions
                .assertEquals(List.of(FilterConditionOperator.EMPTY, FilterConditionOperator.NOT_EMPTY),
                        hidden.getConditions());
    }

    @Test
    void theCatalogueStillOffersAVisibleFieldBesideIt() {
        SearchFieldDataDto visible = field(discoveryService.getSearchableFieldInformationByGroup(), identifier(VISIBLE))
                .orElseThrow();

        Assertions.assertEquals(true, visible.getDisplayable());
        Assertions.assertEquals(true, visible.getSortable());
        Assertions.assertTrue(visible.getConditions().contains(FilterConditionOperator.EQUALS));
    }

    @Test
    void aColumnOnTheHiddenFieldProjectsNothing() {
        SearchRequestDto request = new SearchRequestDto();
        request.setColumns(List.of(new SearchColumnRequestDto(FilterFieldSource.CUSTOM, identifier(HIDDEN))));

        List<DiscoveryListDto> discoveries = list(request);

        // Both fixtures on the page, so the per-entry assertion below is not vacuous. Unsorted, hence order-free.
        Assertions.assertEquals(List.of(alpha.getName(), beta.getName()), names(request).stream().sorted().toList());
        for (DiscoveryListDto discovery : discoveries) {
            Assertions.assertNull(discovery.getAttributeValues());
        }
    }

    @Test
    void anOrderingOnTheHiddenFieldIsRefused() {
        SearchRequestDto request = new SearchRequestDto();
        request.setSort(new SearchSortRequestDto(FilterFieldSource.CUSTOM, identifier(HIDDEN), SortDirection.ASC));

        Assertions.assertThrows(ValidationException.class, () -> names(request));
    }

    @Test
    void anOrderingOnTheVisibleFieldIsApplied() {
        SearchRequestDto request = new SearchRequestDto();
        request.setSort(new SearchSortRequestDto(FilterFieldSource.CUSTOM, identifier(VISIBLE), SortDirection.ASC));

        Assertions.assertEquals(List.of(alpha.getName(), beta.getName()), names(request));
    }

    @Test
    void aFilterOnTheHiddenFieldMatchesNothing() {
        SearchRequestDto request = new SearchRequestDto();
        SearchFilterRequestDto filter = aCustomAttributeFilter(HIDDEN, AttributeContentType.TEXT,
                FilterConditionOperator.EQUALS, "aaa");
        request.setFilters(List.of(filter));

        Assertions.assertEquals(List.of(), names(request));
    }

    @Test
    void aHiddenMetadataFieldKeepsItsValueConditionsAndStaysFilterable() {
        SearchFieldDataDto hiddenMeta = field(discoveryService.getSearchableFieldInformationByGroup(),
                identifier(HIDDEN_META, AttributeContentType.STRING)).orElseThrow();
        SearchRequestDto request = new SearchRequestDto();
        request
                .setFilters(List
                        .of(aMetaAttributeFilter(HIDDEN_META, AttributeContentType.STRING,
                                FilterConditionOperator.EQUALS, "internal")));

        Assertions.assertTrue(hiddenMeta.getConditions().contains(FilterConditionOperator.EQUALS));
        Assertions.assertEquals(List.of(alpha.getName()), names(request));
    }

    @Test
    void anOrderingOnADuplicatedMetadataFieldReadsOnlyTheVisibleDefinition() {
        String metadataField = identifier(DUPLICATED_META, AttributeContentType.STRING);
        SearchRequestDto request = new SearchRequestDto();
        request.setSort(new SearchSortRequestDto(FilterFieldSource.META, metadataField, SortDirection.ASC));
        request.setColumns(List.of(new SearchColumnRequestDto(FilterFieldSource.META, metadataField)));

        List<DiscoveryListDto> discoveries = list(request);

        Assertions
                .assertEquals(List.of(beta.getName(), alpha.getName()),
                        discoveries.stream().map(DiscoveryListDto::getName).toList());
        Assertions
                .assertEquals("zzz",
                        discoveries
                                .getFirst()
                                .getAttributeValues()
                                .get(FilterFieldSource.META)
                                .get(metadataField)
                                .getFirst()
                                .getData());
        Assertions.assertNull(discoveries.getLast().getAttributeValues());
    }

    private List<String> names(SearchRequestDto request) {
        return list(request).stream().map(DiscoveryListDto::getName).toList();
    }

    private List<DiscoveryListDto> list(SearchRequestDto request) {
        DiscoveryResponseDto response = discoveryService.listDiscoveries(SecurityFilter.create(), request);
        return response.getDiscoveries();
    }

    private static String identifier(String attributeName) {
        return identifier(attributeName, AttributeContentType.TEXT);
    }

    private static String identifier(String attributeName, AttributeContentType contentType) {
        return attributeName + "|" + contentType.name();
    }

    private UUID registerCustomAttribute(String name, boolean visible) throws Exception {
        CustomAttributeV3 attribute = new CustomAttributeV3();
        attribute.setUuid(UUID.randomUUID().toString());
        attribute.setName(name);
        attribute.setType(AttributeType.CUSTOM);
        attribute.setContentType(AttributeContentType.TEXT);
        CustomAttributeProperties properties = new CustomAttributeProperties();
        properties.setLabel(name);
        properties.setVisible(visible);
        attribute.setProperties(properties);
        attributeEngine.updateCustomAttributeDefinition(attribute, List.of(Resource.DISCOVERY));
        return UUID.fromString(attribute.getUuid());
    }

    /** A fresh attribute uuid each call, which is what registers a second definition under the same name. */
    private void storeMetadata(Discovery discovery, String name, String value, boolean visible) throws Exception {
        MetadataAttributeV3 meta = new MetadataAttributeV3();
        meta.setUuid(UUID.randomUUID().toString());
        meta.setName(name);
        meta.setType(AttributeType.META);
        meta.setContentType(AttributeContentType.STRING);
        MetadataAttributeProperties properties = new MetadataAttributeProperties();
        properties.setLabel(name);
        properties.setVisible(visible);
        properties.setGlobal(false);
        meta.setProperties(properties);
        meta.setContent(List.of(new StringAttributeContentV3(value)));
        attributeEngine
                .updateMetadataAttribute(meta,
                        ObjectAttributeContentInfo
                                .builder(Resource.DISCOVERY, discovery.getUuid())
                                .connector(connector.getUuid())
                                .build());
    }

    private void storeContent(Discovery discovery, UUID definitionUuid, String name, String value) throws Exception {
        RequestAttributeV3 requestAttribute = new RequestAttributeV3();
        requestAttribute.setUuid(definitionUuid);
        requestAttribute.setName(name);
        List<BaseAttributeContentV3<?>> content = new ArrayList<>();
        content.add(new TextAttributeContentV3(null, value));
        requestAttribute.setContent(content);
        attributeEngine
                .updateObjectCustomAttributesContent(Resource.DISCOVERY, discovery.getUuid(),
                        List.of(requestAttribute));
    }

    private Connector saveConnector() {
        Connector saved = new Connector();
        saved.setName("hidden-attribute-connector");
        saved.setUrl("http://localhost:0/hidden-attribute");
        saved.setVersion(ConnectorVersion.V2);
        saved.setStatus(ConnectorStatus.CONNECTED);
        saved.setAuthType(AuthType.NONE);
        return connectorRepository.save(saved);
    }

    private Discovery saveDiscovery(Connector connector, String name) {
        Discovery discovery = new Discovery();
        discovery.setName(name);
        discovery.setConnectorUuid(connector.getUuid());
        discovery.setConnectorName(connector.getName());
        discovery.setStatus(DiscoveryStatus.COMPLETED);
        discovery.setConnectorStatus(DiscoveryStatus.COMPLETED);
        discovery.setKind("test-kind");
        return discoveryRepository.save(discovery);
    }
}
