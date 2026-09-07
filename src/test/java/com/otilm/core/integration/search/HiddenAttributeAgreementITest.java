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
import com.otilm.api.model.common.attribute.v3.CustomAttributeV3;
import com.otilm.api.model.common.attribute.v3.content.BaseAttributeContentV3;
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

/**
 * One hidden custom attribute read through every path that has to answer whether its values may be shown: the
 * catalogue, the column projection, an ordering and a filter. All four resolve it from the mirrored column, and this
 * pins that they agree.
 */
class HiddenAttributeAgreementITest extends BaseSpringBootTest {

    private static final String HIDDEN = "internal-routing";
    private static final String VISIBLE = "environment";

    @Autowired
    private DiscoveryRepository discoveryRepository;

    @Autowired
    private ConnectorRepository connectorRepository;

    @Autowired
    private DiscoveryExternalService discoveryService;

    @Autowired
    private AttributeEngine attributeEngine;

    private Discovery alpha;
    private Discovery beta;

    @BeforeEach
    void loadData() throws Exception {
        Connector connector = saveConnector();
        alpha = saveDiscovery(connector, "discovery-alpha");
        beta = saveDiscovery(connector, "discovery-beta");

        UUID hiddenUuid = registerCustomAttribute(HIDDEN, false);
        UUID visibleUuid = registerCustomAttribute(VISIBLE, true);

        storeContent(alpha, hiddenUuid, HIDDEN, "aaa");
        storeContent(beta, hiddenUuid, HIDDEN, "zzz");
        storeContent(alpha, visibleUuid, VISIBLE, "production");
    }

    @Test
    void theCatalogueOffersTheHiddenFieldNeitherAsAColumnNorForOrdering() {
        SearchFieldDataDto hidden = field(discoveryService.getSearchableFieldInformationByGroup(), identifier(HIDDEN))
                .orElseThrow();

        Assertions.assertEquals(false, hidden.getDisplayable());
        Assertions.assertEquals(false, hidden.getSortable());
    }

    @Test
    void theCatalogueStillOffersAVisibleFieldBesideIt() {
        SearchFieldDataDto visible = field(discoveryService.getSearchableFieldInformationByGroup(), identifier(VISIBLE))
                .orElseThrow();

        Assertions.assertEquals(true, visible.getDisplayable());
        Assertions.assertEquals(true, visible.getSortable());
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

    private List<String> names(SearchRequestDto request) {
        return list(request).stream().map(DiscoveryListDto::getName).toList();
    }

    private List<DiscoveryListDto> list(SearchRequestDto request) {
        DiscoveryResponseDto response = discoveryService.listDiscoveries(SecurityFilter.create(), request);
        return response.getDiscoveries();
    }

    private static String identifier(String attributeName) {
        return attributeName + "|" + AttributeContentType.TEXT.name();
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
