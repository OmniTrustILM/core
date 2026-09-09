package com.otilm.core.integration.search;

import com.otilm.api.exception.ValidationException;
import com.otilm.api.model.client.certificate.SearchRequestDto;
import com.otilm.api.model.client.certificate.SearchSortRequestDto;
import com.otilm.api.model.common.attribute.common.AttributeType;
import com.otilm.api.model.common.attribute.common.content.AttributeContentType;
import com.otilm.api.model.common.attribute.common.properties.CustomAttributeProperties;
import com.otilm.api.model.common.attribute.v3.CustomAttributeV3;
import com.otilm.api.model.core.auth.Resource;
import com.otilm.api.model.core.search.FilterFieldSource;
import com.otilm.api.model.core.search.SearchFieldDataByGroupDto;
import com.otilm.api.model.core.search.SearchFieldDataDto;
import com.otilm.api.model.core.search.SortDirection;
import com.otilm.core.attribute.engine.AttributeEngine;
import com.otilm.core.enums.FilterField;
import com.otilm.core.security.authz.SecurityFilter;
import com.otilm.core.service.CbomExternalService;
import com.otilm.core.service.DiscoveryExternalService;
import com.otilm.core.service.SigningRecordExternalService;
import com.otilm.core.service.TimeQualityConfigurationExternalService;
import com.otilm.core.service.v2.ConnectorExternalService;
import com.otilm.core.util.BaseSpringBootTest;
import com.otilm.core.util.SearchHelper;
import java.util.List;
import java.util.UUID;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.EnumSource;
import org.springframework.beans.factory.annotation.Autowired;

import static com.otilm.core.integration.search.CatalogueFields.allFields;
import static com.otilm.core.integration.search.CatalogueFields.field;
import static com.otilm.core.integration.search.CatalogueFields.propertyFields;

/**
 * The {@code displayable} and {@code sortable} flags a published column catalogue carries. Property fields resolve
 * theirs against the JPA metamodel, so they are asserted here rather than in a plain unit test.
 */
class ColumnCatalogueFlagsITest extends BaseSpringBootTest {

    @Autowired
    private DiscoveryExternalService discoveryService;

    @Autowired
    private CbomExternalService cbomService;

    @Autowired
    private SigningRecordExternalService signingRecordService;

    @Autowired
    private TimeQualityConfigurationExternalService timeQualityConfigurationService;

    @Autowired
    private ConnectorExternalService connectorService;

    @Autowired
    private AttributeEngine attributeEngine;

    @Test
    void everyPublishedFieldAnswersBothFlags() {
        // A flag left null reaches the picker as "unknown", and an absent flag is read as a no - so a field that
        // simply forgot to answer would silently disappear from the column list.
        for (SearchFieldDataDto item : allFields(discoveryService.getSearchableFieldInformationByGroup())) {
            Assertions.assertNotNull(item.getDisplayable(), item.getFieldIdentifier());
            Assertions.assertNotNull(item.getSortable(), item.getFieldIdentifier());
        }
    }

    @Test
    void anOrdinaryPropertyFieldIsDisplayable() {
        SearchFieldDataDto kind = field(discoveryService.getSearchableFieldInformationByGroup(),
                FilterField.DISCOVERY_KIND.name()).orElseThrow();

        Assertions.assertEquals(true, kind.getDisplayable());
    }

    /**
     * Discovery is one of the listings that applies a requested sort, so its orderable property fields advertise it.
     * The catalogue promising an ordering the listing then discards is the failure this guards, in both directions: a
     * wired listing must say so, and {@code CryptographicAssetSearchableFieldsITest.noFieldReportsSortable} holds the
     * other side, where an unwired listing reports nothing sortable.
     */
    @Test
    void aPropertyFieldOfAWiredListingIsSortable() {
        SearchFieldDataDto name = field(discoveryService.getSearchableFieldInformationByGroup(),
                FilterField.DISCOVERY_NAME.name()).orElseThrow();

        Assertions.assertEquals(true, name.getSortable());
    }

    /**
     * A field whose path cannot be ordered by stays non-sortable on a wired listing: the resource being wired is not on
     * its own enough.
     */
    @Test
    void aNonOrderablePropertyFieldOfAWiredListingIsNotSortable() {
        for (SearchFieldDataDto item : propertyFields(discoveryService.getSearchableFieldInformationByGroup())) {
            boolean orderable = SearchHelper.isOrderableField(FilterField.valueOf(item.getFieldIdentifier()));
            Assertions.assertEquals(orderable, item.getSortable(), item.getFieldIdentifier());
        }
    }

    @Test
    void aNativeArrayPropertyFieldIsDisplayable() {
        // A multi-valued field has no single scalar key to order a row by, but it does have values to render. Taken
        // from the connector catalogue because a listing outside the column pipeline offers no columns at all.
        SearchFieldDataDto features = field(connectorService.getSearchableFieldInformationByGroup(),
                FilterField.CONNECTOR_FEATURES.name()).orElseThrow();

        Assertions.assertEquals(true, features.getDisplayable());
    }

    @Test
    void anOrdinaryPropertyFieldWouldBeOrderable() {
        Assertions.assertTrue(SearchHelper.isOrderableField(FilterField.DISCOVERY_KIND));
    }

    @Test
    void aNativeArrayPropertyFieldWouldNotBeOrderable() {
        // It holds many values per row, so there is no single value to order the row by.
        Assertions.assertFalse(SearchHelper.isOrderableField(FilterField.TIME_QUALITY_CONFIGURATION_NTP_SERVERS));
    }

    /**
     * A usage field persists a set of flags as one integer and renders the decoded set, so ordering the page by the
     * column would order it by a number that bears no relation to the list in the cell.
     */
    @ParameterizedTest
    @EnumSource(value = FilterField.class, names = {"KEY_USAGE", "CKI_USAGE", "CERT_REQUEST_KEY_USAGE"})
    void aBitmaskBackedPropertyFieldWouldNotBeOrderable(FilterField filterField) {
        Assertions.assertFalse(SearchHelper.isOrderableField(filterField));
    }

    @ParameterizedTest
    @EnumSource(value = FilterField.class,
            names = {"OCSP_VALIDATION", "CRL_VALIDATION", "SIGNATURE_VALIDATION", "PRIVATE_KEY"})
    void aDerivedPropertyFieldWouldNotBeOrderable(FilterField filterField) {
        // What these display is not what their attribute holds: the validation-check fields each name one check
        // inside one serialized validation result, and PRIVATE_KEY shows whether a joined key type is one particular
        // type, so ordering by the attribute would order by something the column does not show.
        Assertions.assertFalse(SearchHelper.isOrderableField(filterField));
    }

    /**
     * Discovery applies a requested sort, so a displayable attribute of its catalogue advertises ordering too.
     */
    @Test
    void aDisplayableAttributeFieldOfAWiredListingIsSortable() throws Exception {
        registerCustomAttribute("catalogue-flag-probe", AttributeContentType.TEXT);

        SearchFieldDataDto attribute = field(discoveryService.getSearchableFieldInformationByGroup(),
                "catalogue-flag-probe|" + AttributeContentType.TEXT.name()).orElseThrow();
        Assertions.assertEquals(true, attribute.getDisplayable());
        Assertions.assertEquals(true, attribute.getSortable());
    }

    /**
     * A column the catalogue withholds cannot be ordered on either - there is nothing to order by when the value is
     * never rendered. Secret content is the clearest case.
     */
    @Test
    void anAttributeFieldWithheldAsAColumnIsNotSortable() throws Exception {
        registerCustomAttribute("catalogue-secret-probe", AttributeContentType.SECRET);

        SearchFieldDataDto attribute = field(discoveryService.getSearchableFieldInformationByGroup(),
                "catalogue-secret-probe|" + AttributeContentType.SECRET.name()).orElseThrow();
        Assertions.assertEquals(false, attribute.getDisplayable());
        Assertions.assertEquals(false, attribute.getSortable());
    }

    /**
     * A file cell renders the file's name and media type, and a resource cell the referenced object's name; a sort key
     * reads the stored reference instead, so these stay displayable columns that cannot be ordered on.
     */
    @ParameterizedTest
    @EnumSource(value = AttributeContentType.class, names = {"FILE", "RESOURCE"})
    void anAttributeWhoseCellIsNotItsSortKeyIsDisplayableButNotSortable(AttributeContentType contentType)
            throws Exception {
        registerCustomAttribute("catalogue-composite-probe", contentType);

        SearchFieldDataDto attribute = field(discoveryService.getSearchableFieldInformationByGroup(),
                "catalogue-composite-probe|" + contentType.name()).orElseThrow();
        Assertions.assertEquals(true, attribute.getDisplayable());
        Assertions.assertEquals(false, attribute.getSortable());
    }

    /**
     * The flag is a hint on a response the caller is free to ignore, so a listing that would discard the ordering
     * refuses the request rather than answering it with the default order and no explanation.
     */
    @Test
    void anUnwiredListingRefusesASortRatherThanDiscardingIt() {
        SearchRequestDto request = new SearchRequestDto();
        request.setPageNumber(1);
        request.setItemsPerPage(10);
        request
                .setSort(new SearchSortRequestDto(FilterFieldSource.PROPERTY,
                        FilterField.TIME_QUALITY_CONFIGURATION_NAME.name(), SortDirection.ASC));

        Assertions
                .assertThrows(ValidationException.class, () -> timeQualityConfigurationService
                        .listTimeQualityConfigurations(request, SecurityFilter.create()));
    }

    @Test
    void aCodeBlockAttributeIsNotOfferedAsAColumn() throws Exception {
        registerCustomAttribute("catalogue-codeblock-probe", AttributeContentType.CODEBLOCK);

        SearchFieldDataDto attribute = field(discoveryService.getSearchableFieldInformationByGroup(),
                "catalogue-codeblock-probe|" + AttributeContentType.CODEBLOCK.name()).orElseThrow();
        Assertions.assertEquals(false, attribute.getDisplayable());
    }

    @Test
    void aHiddenAttributeIsNotOfferedAsAColumn() throws Exception {
        // The definition says its values are not to be shown to a user; a column is a place they would be shown.
        registerCustomAttribute("catalogue-hidden-probe", AttributeContentType.TEXT, false);

        SearchFieldDataDto attribute = field(discoveryService.getSearchableFieldInformationByGroup(),
                "catalogue-hidden-probe|" + AttributeContentType.TEXT.name()).orElseThrow();
        Assertions.assertEquals(false, attribute.getDisplayable());
    }

    @Test
    void aResourceWithoutCustomAttributesPublishesNoEmptyGroup() {
        // CBOMs and signing records carry no custom attributes; the catalogue says so by leaving the group out
        // rather than by publishing an empty one for the picker to render as a bare heading.
        for (List<SearchFieldDataByGroupDto> catalogue : List
                .of(cbomService.getSearchableFieldInformationByGroup(),
                        signingRecordService.getSearchableFieldInformation())) {
            Assertions
                    .assertTrue(catalogue
                            .stream()
                            .noneMatch(group -> group.getSearchFieldData() == null
                                    || group.getSearchFieldData().isEmpty()));
            Assertions
                    .assertTrue(catalogue
                            .stream()
                            .noneMatch(group -> group.getFilterFieldSource() == FilterFieldSource.CUSTOM));
        }
    }

    private void registerCustomAttribute(String name, AttributeContentType contentType) throws Exception {
        registerCustomAttribute(name, contentType, true);
    }

    private void registerCustomAttribute(String name, AttributeContentType contentType, boolean visible)
            throws Exception {
        CustomAttributeV3 attribute = new CustomAttributeV3();
        attribute.setUuid(UUID.randomUUID().toString());
        attribute.setName(name);
        attribute.setType(AttributeType.CUSTOM);
        attribute.setContentType(contentType);
        CustomAttributeProperties properties = new CustomAttributeProperties();
        properties.setLabel(name);
        properties.setVisible(visible);
        attribute.setProperties(properties);
        attributeEngine.updateCustomAttributeDefinition(attribute, List.of(Resource.DISCOVERY));
    }
}
