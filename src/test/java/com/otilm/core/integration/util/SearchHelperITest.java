package com.otilm.core.integration.util;

import com.otilm.api.model.common.attribute.common.AttributeType;
import com.otilm.api.model.common.attribute.common.content.AttributeContentType;
import com.otilm.api.model.common.attribute.common.content.data.ProtectionLevel;
import com.otilm.api.model.common.attribute.common.properties.CustomAttributeProperties;
import com.otilm.api.model.common.attribute.common.properties.DataAttributeProperties;
import com.otilm.api.model.common.attribute.v3.CustomAttributeV3;
import com.otilm.api.model.common.attribute.v3.DataAttributeV3;
import com.otilm.api.model.common.attribute.v3.content.DateAttributeContentV3;
import com.otilm.api.model.common.attribute.v3.content.StringAttributeContentV3;
import com.otilm.api.model.core.auth.Resource;
import com.otilm.api.model.core.search.FilterConditionOperator;
import com.otilm.api.model.core.search.FilterFieldType;
import com.otilm.api.model.core.search.SearchFieldDataDto;
import com.otilm.core.enums.FilterField;
import com.otilm.core.enums.SearchFieldTypeEnum;
import com.otilm.core.model.SearchFieldObject;
import com.otilm.core.util.BaseSpringBootTest;
import com.otilm.core.util.SearchHelper;
import java.time.LocalDate;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import org.assertj.core.api.InstanceOfAssertFactories;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatCode;

class SearchHelperITest extends BaseSpringBootTest {

    @Test
    void testPrepareSearchForJSON() {
        SearchFieldObject attributeSearchInfo = new SearchFieldObject(AttributeContentType.TIME);
        SearchFieldDataDto searchFieldDataDto = SearchHelper
                .prepareSearchForJSON(attributeSearchInfo, false, Resource.DISCOVERY);
        assertThat(searchFieldDataDto.getConditions()).isNotEmpty();
        assertThat(searchFieldDataDto.getConditions())
                .as("Condition should not contain IN_NEXT operator")
                .doesNotContain(FilterConditionOperator.IN_NEXT);
        assertThat(searchFieldDataDto.getConditions())
                .as("Condition should not contain IN_PAST operator")
                .doesNotContain(FilterConditionOperator.IN_PAST);

        attributeSearchInfo.setProtectionLevel(ProtectionLevel.ENCRYPTED);
        searchFieldDataDto = SearchHelper.prepareSearchForJSON(attributeSearchInfo, false, Resource.DISCOVERY);
        assertThat(searchFieldDataDto.getConditions())
                .isEqualTo(List.of(FilterConditionOperator.EMPTY, FilterConditionOperator.NOT_EMPTY));
    }

    @Test
    void testCreateSearchFieldObject() {
        DataAttributeV3 attributeV3 = new DataAttributeV3();
        attributeV3.setName("name");
        LocalDate now = LocalDate.now();
        attributeV3.setContent(List.of(new DateAttributeContentV3(now)));
        DataAttributeProperties dataAttributeProperties = new DataAttributeProperties();
        dataAttributeProperties.setList(true);
        attributeV3.setContentType(AttributeContentType.DATE);
        attributeV3.setProperties(dataAttributeProperties);
        SearchFieldObject searchFieldObject = new SearchFieldObject(attributeV3.getName(), attributeV3.getContentType(),
                AttributeType.DATA, "label", true, attributeV3);
        assertThat(searchFieldObject.getContentItems()).isEqualTo(List.of(now.toString()));

        dataAttributeProperties.setList(false);
        attributeV3.setProperties(dataAttributeProperties);
        searchFieldObject = new SearchFieldObject(attributeV3.getName(), attributeV3.getContentType(),
                AttributeType.DATA, "label", true, attributeV3);
        assertThat(searchFieldObject.getContentItems()).isNull();

        dataAttributeProperties.setList(true);
        dataAttributeProperties.setProtectionLevel(ProtectionLevel.ENCRYPTED);
        attributeV3.setProperties(dataAttributeProperties);
        searchFieldObject = new SearchFieldObject(attributeV3.getName(), attributeV3.getContentType(),
                AttributeType.DATA, "label", true, attributeV3);
        assertThat(searchFieldObject.getContentItems()).isNull();

        CustomAttributeV3 customAttributeV3 = new CustomAttributeV3();
        customAttributeV3.setName("name");
        customAttributeV3.setContent(List.of(new StringAttributeContentV3("string")));
        CustomAttributeProperties customAttributeProperties = new CustomAttributeProperties();
        customAttributeProperties.setList(true);
        customAttributeV3.setContentType(AttributeContentType.DATE);
        customAttributeV3.setProperties(customAttributeProperties);
        searchFieldObject = new SearchFieldObject(customAttributeV3.getName(), customAttributeV3.getContentType(),
                AttributeType.CUSTOM, "label", true, customAttributeV3);
        assertThat(searchFieldObject.getContentItems()).isEqualTo(List.of("string"));

        customAttributeProperties.setList(false);
        customAttributeV3.setProperties(customAttributeProperties);
        searchFieldObject = new SearchFieldObject(customAttributeV3.getName(), customAttributeV3.getContentType(),
                AttributeType.CUSTOM, "label", true, customAttributeV3);
        assertThat(searchFieldObject.getContentItems()).isNull();
        customAttributeProperties.setList(true);
        customAttributeProperties.setProtectionLevel(ProtectionLevel.ENCRYPTED);
        customAttributeV3.setProperties(customAttributeProperties);
        searchFieldObject = new SearchFieldObject(customAttributeV3.getName(), customAttributeV3.getContentType(),
                AttributeType.CUSTOM, "label", true, customAttributeV3);
        assertThat(searchFieldObject.getContentItems()).isNull();

    }

    @Test
    void testPrepareSearchForJSONDeduplicatesSameNameAndContentType() {
        SearchFieldObject fromConnectorA = new SearchFieldObject("username", AttributeContentType.STRING,
                AttributeType.META);
        fromConnectorA.setLabel("Username");
        SearchFieldObject fromConnectorB = new SearchFieldObject("username", AttributeContentType.STRING,
                AttributeType.META);
        fromConnectorB.setLabel("Username");

        List<SearchFieldDataDto> fields = SearchHelper
                .prepareSearchForJSON(List.of(fromConnectorA, fromConnectorB), Resource.DISCOVERY);

        assertThat(fields).hasSize(1);
        assertThat(fields.getFirst().getFieldIdentifier()).isEqualTo("username|STRING");
        assertThat(fields.getFirst().getFieldLabel())
                .as("no content type suffix when the field name is unique after deduplication")
                .isEqualTo("Username");
    }

    @Test
    void testPrepareSearchForJSONKeepsContentTypeSuffixForSameNameWithDifferentContentTypes() {
        SearchFieldObject stringVariantA = new SearchFieldObject("port", AttributeContentType.STRING,
                AttributeType.META);
        stringVariantA.setLabel("Port");
        SearchFieldObject stringVariantB = new SearchFieldObject("port", AttributeContentType.STRING,
                AttributeType.META);
        stringVariantB.setLabel("Port");
        SearchFieldObject integerVariant = new SearchFieldObject("port", AttributeContentType.INTEGER,
                AttributeType.META);
        integerVariant.setLabel("Port");

        List<SearchFieldDataDto> fields = SearchHelper
                .prepareSearchForJSON(List.of(stringVariantA, stringVariantB, integerVariant), Resource.DISCOVERY);

        assertThat(fields)
                .extracting(SearchFieldDataDto::getFieldIdentifier)
                .containsExactlyInAnyOrder("port|STRING", "port|INTEGER");
        assertThat(fields)
                .extracting(SearchFieldDataDto::getFieldLabel)
                .containsExactlyInAnyOrder("Port (string)", "Port (integer)");
    }

    @Test
    void testPrepareSearchForJSONMergedFieldKeepsValueOperatorsWhenAnyDuplicateIsPlain() {
        SearchFieldObject encrypted = new SearchFieldObject("username", AttributeContentType.STRING,
                AttributeType.META);
        encrypted.setLabel("Username");
        encrypted.setProtectionLevel(ProtectionLevel.ENCRYPTED);
        SearchFieldObject plain = new SearchFieldObject("username", AttributeContentType.STRING, AttributeType.META);
        plain.setLabel("Username");

        List<SearchFieldDataDto> fields = SearchHelper
                .prepareSearchForJSON(List.of(encrypted, plain), Resource.DISCOVERY);

        assertThat(fields).hasSize(1);
        assertThat(fields.getFirst().getConditions())
                .contains(FilterConditionOperator.EQUALS, FilterConditionOperator.CONTAINS);
    }

    @Test
    void testPrepareSearchForJSONMergedFieldStaysRestrictedWhenAllDuplicatesAreEncrypted() {
        SearchFieldObject encryptedA = new SearchFieldObject("username", AttributeContentType.STRING,
                AttributeType.META);
        encryptedA.setLabel("Username");
        encryptedA.setProtectionLevel(ProtectionLevel.ENCRYPTED);
        SearchFieldObject encryptedB = new SearchFieldObject("username", AttributeContentType.STRING,
                AttributeType.META);
        encryptedB.setLabel("Username");
        encryptedB.setProtectionLevel(ProtectionLevel.ENCRYPTED);

        List<SearchFieldDataDto> fields = SearchHelper
                .prepareSearchForJSON(List.of(encryptedA, encryptedB), Resource.DISCOVERY);

        assertThat(fields).hasSize(1);
        assertThat(fields.getFirst().getConditions())
                .isEqualTo(List.of(FilterConditionOperator.EMPTY, FilterConditionOperator.NOT_EMPTY));
    }

    @Test
    void testPrepareSearchForJSONMergedListFieldUnionsContentItems() {
        SearchFieldObject listA = new SearchFieldObject("environment", AttributeContentType.STRING, AttributeType.DATA);
        listA.setLabel("Environment");
        listA.setList(true);
        listA.setContentItems(List.of("dev", "test"));
        SearchFieldObject listB = new SearchFieldObject("environment", AttributeContentType.STRING, AttributeType.DATA);
        listB.setLabel("Environment");
        listB.setList(true);
        listB.setContentItems(List.of("test", "prod"));

        List<SearchFieldDataDto> fields = SearchHelper.prepareSearchForJSON(List.of(listA, listB), Resource.DISCOVERY);

        assertThat(fields).hasSize(1);
        assertThat(fields.getFirst().getValue()).isEqualTo(List.of("dev", "test", "prod"));
    }

    @Test
    void testPrepareSearchForJSONMergedFieldStaysFreeFormWhenAnyDuplicateIsNotList() {
        SearchFieldObject listVariant = new SearchFieldObject("environment", AttributeContentType.STRING,
                AttributeType.DATA);
        listVariant.setLabel("Environment");
        listVariant.setList(true);
        listVariant.setMultiSelect(true);
        listVariant.setContentItems(List.of("dev", "test"));
        SearchFieldObject freeFormVariant = new SearchFieldObject("environment", AttributeContentType.STRING,
                AttributeType.DATA);
        freeFormVariant.setLabel("Environment");

        List<SearchFieldDataDto> fields = SearchHelper
                .prepareSearchForJSON(List.of(listVariant, freeFormVariant), Resource.DISCOVERY);

        assertThat(fields).hasSize(1);
        assertThat(fields.getFirst().getType())
                .as("free-form input must survive the merge so any value stays enterable")
                .isEqualTo(FilterFieldType.STRING);
        assertThat(fields.getFirst().getValue()).isNull();
        assertThat(fields.getFirst().isMultiValue()).isFalse();
    }

    @Test
    void testPrepareSearchForJSONMergedFieldIsVisibleWhenAnyDuplicateIsVisible() {
        List<SearchFieldDataDto> fields = SearchHelper
                .prepareSearchForJSON(List.of(visibilityFieldObject(false), visibilityFieldObject(true)),
                        Resource.DISCOVERY);
        List<SearchFieldDataDto> fieldsReversed = SearchHelper
                .prepareSearchForJSON(List.of(visibilityFieldObject(true), visibilityFieldObject(false)),
                        Resource.DISCOVERY);

        assertThat(fields).hasSize(1);
        assertThat(fields.getFirst().getDisplayable())
                .as("projection and filtering keep the visible definition's content, so the field must be offered")
                .isTrue();
        assertThat(fieldsReversed.getFirst().getDisplayable())
                .as("and not depend on the (unordered) query result order")
                .isTrue();
    }

    @Test
    void testPrepareSearchForJSONMergedFieldStaysHiddenWhenEveryDuplicateIsHidden() {
        List<SearchFieldDataDto> fields = SearchHelper
                .prepareSearchForJSON(List.of(visibilityFieldObject(false), visibilityFieldObject(false)),
                        Resource.DISCOVERY);

        assertThat(fields).hasSize(1);
        assertThat(fields.getFirst().getDisplayable()).isFalse();
    }

    private static SearchFieldObject visibilityFieldObject(boolean visible) {
        SearchFieldObject field = new SearchFieldObject("username", AttributeContentType.STRING, AttributeType.META);
        field.setLabel("Username");
        field.setVisible(visible);
        return field;
    }

    @Test
    void testPrepareSearchForJSONMergeIsDeterministicRegardlessOfInputOrder() {
        SearchFieldObject labeledUser = new SearchFieldObject("username", AttributeContentType.STRING,
                AttributeType.META);
        labeledUser.setLabel("User");
        SearchFieldObject labeledUsername = new SearchFieldObject("username", AttributeContentType.STRING,
                AttributeType.META);
        labeledUsername.setLabel("Username");

        List<SearchFieldDataDto> fields = SearchHelper
                .prepareSearchForJSON(List.of(labeledUsername, labeledUser), Resource.DISCOVERY);
        List<SearchFieldDataDto> fieldsReversed = SearchHelper
                .prepareSearchForJSON(List.of(labeledUser, labeledUsername), Resource.DISCOVERY);

        assertThat(fields).hasSize(1);
        assertThat(fields.getFirst().getFieldLabel())
                .as("merged label must not depend on the (unordered) query result order")
                .isEqualTo(fieldsReversed.getFirst().getFieldLabel());
    }

    @Test
    void testPrepareSearchForJSONMergeIsDeterministicWhenDuplicatesShareTheLabel() {
        List<SearchFieldDataDto> fields = SearchHelper
                .prepareSearchForJSON(
                        List.of(listFieldObject(List.of("dev", "test")), listFieldObject(List.of("prod"))),
                        Resource.DISCOVERY);
        List<SearchFieldDataDto> fieldsReversed = SearchHelper
                .prepareSearchForJSON(
                        List.of(listFieldObject(List.of("prod")), listFieldObject(List.of("dev", "test"))),
                        Resource.DISCOVERY);

        assertThat(fields).hasSize(1);
        assertThat(fields.getFirst().getValue())
                .as("merged content item order must not depend on the (unordered) query result order")
                .isEqualTo(fieldsReversed.getFirst().getValue());
    }

    private static SearchFieldObject listFieldObject(List<String> contentItems) {
        SearchFieldObject field = new SearchFieldObject("environment", AttributeContentType.STRING, AttributeType.DATA);
        field.setLabel("Environment");
        field.setList(true);
        field.setContentItems(contentItems);
        return field;
    }

    @Test
    void testPrepareSearchCount() {
        Set<FilterField> shouldHaveCountOperator = Set
                .of(FilterField.CONNECTOR_FUNCTION_GROUP, FilterField.CONNECTOR_INTERFACE, FilterField.GROUP_NAME,
                        FilterField.SUCCEEDING_CERTIFICATES, FilterField.PRECEDING_CERTIFICATES,
                        FilterField.CERT_LOCATION_NAME, FilterField.CK_GROUP, FilterField.SECRET_SYNC_VAULT_PROFILE,
                        FilterField.SECRET_GROUP_NAME);
        Set<FilterField> withCountOperator = new HashSet<>();
        for (FilterField filterField : FilterField.values()) {
            SearchFieldDataDto searchFieldDataDto = SearchHelper.prepareSearch(filterField, List.of("sampleValue"));
            if (searchFieldDataDto
                    .getConditions()
                    .containsAll(Set
                            .of(FilterConditionOperator.COUNT_EQUAL, FilterConditionOperator.COUNT_NOT_EQUAL,
                                    FilterConditionOperator.COUNT_GREATER_THAN,
                                    FilterConditionOperator.COUNT_LESS_THAN))) {
                withCountOperator.add(filterField);
            }
        }
        assertThat(withCountOperator).isEqualTo(shouldHaveCountOperator);
    }

    @Test
    void testPrepareSearchJsonArray() {
        Set<FilterField> jsonArrays = Set.of(FilterField.AUDIT_LOG_RESOURCE_NAME, FilterField.AUDIT_LOG_RESOURCE_UUID);
        for (FilterField filterField : jsonArrays) {
            SearchFieldDataDto searchFieldDataDto = SearchHelper.prepareSearch(filterField);
            assertThat(new HashSet<>(searchFieldDataDto.getConditions()))
                    .isEqualTo(Set
                            .of(FilterConditionOperator.EQUALS, FilterConditionOperator.NOT_EQUALS,
                                    FilterConditionOperator.NOT_EMPTY, FilterConditionOperator.EMPTY));
        }
    }

    /**
     * A {@code NATIVE_ARRAY} field reports {@link FilterFieldType#LIST} but is not {@link SearchFieldTypeEnum#LIST}.
     * Callers that route on the second hand it no values at all, while the null-stripping branch keys off the first --
     * so it used to cast that absence to a list and every resource carrying such a field answered its filter-field
     * endpoint with HTTP 500. {@code Resource.OID} and {@code Resource.TIME_QUALITY_CONFIGURATION} both did.
     */
    @Test
    void aNativeArrayFieldIsPreparedWhenNoValuesAreSupplied() {
        FilterField field = FilterField.OID_ENTRY_ALT_CODES;

        assertThat(field.getType()).isEqualTo(SearchFieldTypeEnum.NATIVE_ARRAY);
        assertThat(field.getType().getFieldType())
                .as("the disagreement this test exists for")
                .isEqualTo(FilterFieldType.LIST);
        assertThat(field.getEnumClass()).isNull();

        assertThatCode(() -> SearchHelper.prepareSearch(field)).doesNotThrowAnyException();
        assertThat(SearchHelper.prepareSearch(field).getValue()).isNull();
    }

    @Test
    void suppliedValuesStillLoseTheirNullEntry() {
        List<String> withNull = new ArrayList<>(Arrays.asList("a", null, "b"));

        SearchFieldDataDto prepared = SearchHelper.prepareSearch(FilterField.OID_ENTRY_ALT_CODES, withNull);

        assertThat(prepared.getValue())
                .asInstanceOf(InstanceOfAssertFactories.list(String.class))
                .containsExactly("a", "b");
        assertThat(withNull).as("the caller's list is not mutated").containsExactly("a", null, "b");
    }

    @Test
    void everyNativeArrayFieldWithoutAnEnumIsPreparable() {
        List<FilterField> nativeArrayFields = Arrays
                .stream(FilterField.values())
                .filter(field -> field.getType() == SearchFieldTypeEnum.NATIVE_ARRAY && field.getEnumClass() == null)
                .toList();

        assertThat(nativeArrayFields).as("at least one such field exists, or this test proves nothing").isNotEmpty();

        for (FilterField field : nativeArrayFields) {
            assertThatCode(() -> SearchHelper.prepareSearch(field)).as("field %s", field).doesNotThrowAnyException();
        }
    }
}
