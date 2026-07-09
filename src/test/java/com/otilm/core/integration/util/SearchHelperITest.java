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
import com.otilm.api.model.core.search.FilterConditionOperator;
import com.otilm.api.model.core.search.FilterFieldType;
import com.otilm.api.model.core.search.SearchFieldDataDto;
import com.otilm.core.enums.FilterField;
import com.otilm.core.model.SearchFieldObject;
import com.otilm.core.util.BaseSpringBootTest;
import com.otilm.core.util.SearchHelper;
import org.junit.jupiter.api.Test;

import java.time.LocalDate;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

import static org.assertj.core.api.Assertions.assertThat;

class SearchHelperITest extends BaseSpringBootTest {

    @Test
    void testPrepareSearchForJSON() {
        SearchFieldObject attributeSearchInfo = new SearchFieldObject(AttributeContentType.TIME);
        SearchFieldDataDto searchFieldDataDto = SearchHelper.prepareSearchForJSON(attributeSearchInfo, false);
        assertThat(searchFieldDataDto.getConditions()).isNotEmpty();
        assertThat(searchFieldDataDto.getConditions()).as("Condition should not contain IN_NEXT operator").doesNotContain(FilterConditionOperator.IN_NEXT);
        assertThat(searchFieldDataDto.getConditions()).as("Condition should not contain IN_PAST operator").doesNotContain(FilterConditionOperator.IN_PAST);

        attributeSearchInfo.setProtectionLevel(ProtectionLevel.ENCRYPTED);
        searchFieldDataDto = SearchHelper.prepareSearchForJSON(attributeSearchInfo, false);
        assertThat(searchFieldDataDto.getConditions()).isEqualTo(List.of(FilterConditionOperator.EMPTY, FilterConditionOperator.NOT_EMPTY));
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
        SearchFieldObject searchFieldObject = new SearchFieldObject(attributeV3.getName(), attributeV3.getContentType(), AttributeType.DATA, "label", attributeV3);
        assertThat(searchFieldObject.getContentItems()).isEqualTo(List.of(now.toString()));

        dataAttributeProperties.setList(false);
        attributeV3.setProperties(dataAttributeProperties);
        searchFieldObject = new SearchFieldObject(attributeV3.getName(), attributeV3.getContentType(), AttributeType.DATA, "label", attributeV3);
        assertThat(searchFieldObject.getContentItems()).isNull();

        dataAttributeProperties.setList(true);
        dataAttributeProperties.setProtectionLevel(ProtectionLevel.ENCRYPTED);
        attributeV3.setProperties(dataAttributeProperties);
        searchFieldObject = new SearchFieldObject(attributeV3.getName(), attributeV3.getContentType(), AttributeType.DATA, "label", attributeV3);
        assertThat(searchFieldObject.getContentItems()).isNull();

        CustomAttributeV3 customAttributeV3 = new CustomAttributeV3();
        customAttributeV3.setName("name");
        customAttributeV3.setContent(List.of(new StringAttributeContentV3("string")));
        CustomAttributeProperties customAttributeProperties = new CustomAttributeProperties();
        customAttributeProperties.setList(true);
        customAttributeV3.setContentType(AttributeContentType.DATE);
        customAttributeV3.setProperties(customAttributeProperties);
        searchFieldObject = new SearchFieldObject(customAttributeV3.getName(), customAttributeV3.getContentType(), AttributeType.CUSTOM, "label", customAttributeV3);
        assertThat(searchFieldObject.getContentItems()).isEqualTo(List.of("string"));

        customAttributeProperties.setList(false);
        customAttributeV3.setProperties(customAttributeProperties);
        searchFieldObject = new SearchFieldObject(customAttributeV3.getName(), customAttributeV3.getContentType(), AttributeType.CUSTOM, "label", customAttributeV3);
        assertThat(searchFieldObject.getContentItems()).isNull();
        customAttributeProperties.setList(true);
        customAttributeProperties.setProtectionLevel(ProtectionLevel.ENCRYPTED);
        customAttributeV3.setProperties(customAttributeProperties);
        searchFieldObject = new SearchFieldObject(customAttributeV3.getName(), customAttributeV3.getContentType(), AttributeType.CUSTOM, "label", customAttributeV3);
        assertThat(searchFieldObject.getContentItems()).isNull();

    }

    @Test
    void testPrepareSearchForJSONDeduplicatesSameNameAndContentType() {
        SearchFieldObject fromConnectorA = new SearchFieldObject("username", AttributeContentType.STRING, AttributeType.META);
        fromConnectorA.setLabel("Username");
        SearchFieldObject fromConnectorB = new SearchFieldObject("username", AttributeContentType.STRING, AttributeType.META);
        fromConnectorB.setLabel("Username");

        List<SearchFieldDataDto> fields = SearchHelper.prepareSearchForJSON(List.of(fromConnectorA, fromConnectorB));

        assertThat(fields).hasSize(1);
        assertThat(fields.getFirst().getFieldIdentifier()).isEqualTo("username|STRING");
        assertThat(fields.getFirst().getFieldLabel()).as("no content type suffix when the field name is unique after deduplication").isEqualTo("Username");
    }

    @Test
    void testPrepareSearchForJSONKeepsContentTypeSuffixForSameNameWithDifferentContentTypes() {
        SearchFieldObject stringVariantA = new SearchFieldObject("port", AttributeContentType.STRING, AttributeType.META);
        stringVariantA.setLabel("Port");
        SearchFieldObject stringVariantB = new SearchFieldObject("port", AttributeContentType.STRING, AttributeType.META);
        stringVariantB.setLabel("Port");
        SearchFieldObject integerVariant = new SearchFieldObject("port", AttributeContentType.INTEGER, AttributeType.META);
        integerVariant.setLabel("Port");

        List<SearchFieldDataDto> fields = SearchHelper.prepareSearchForJSON(List.of(stringVariantA, stringVariantB, integerVariant));

        assertThat(fields).extracting(SearchFieldDataDto::getFieldIdentifier).containsExactlyInAnyOrder("port|STRING", "port|INTEGER");
        assertThat(fields).extracting(SearchFieldDataDto::getFieldLabel).containsExactlyInAnyOrder("Port (string)", "Port (integer)");
    }

    @Test
    void testPrepareSearchForJSONMergedFieldKeepsValueOperatorsWhenAnyDuplicateIsPlain() {
        SearchFieldObject encrypted = new SearchFieldObject("username", AttributeContentType.STRING, AttributeType.META);
        encrypted.setLabel("Username");
        encrypted.setProtectionLevel(ProtectionLevel.ENCRYPTED);
        SearchFieldObject plain = new SearchFieldObject("username", AttributeContentType.STRING, AttributeType.META);
        plain.setLabel("Username");

        List<SearchFieldDataDto> fields = SearchHelper.prepareSearchForJSON(List.of(encrypted, plain));

        assertThat(fields).hasSize(1);
        assertThat(fields.getFirst().getConditions()).contains(FilterConditionOperator.EQUALS, FilterConditionOperator.CONTAINS);
    }

    @Test
    void testPrepareSearchForJSONMergedFieldStaysRestrictedWhenAllDuplicatesAreEncrypted() {
        SearchFieldObject encryptedA = new SearchFieldObject("username", AttributeContentType.STRING, AttributeType.META);
        encryptedA.setLabel("Username");
        encryptedA.setProtectionLevel(ProtectionLevel.ENCRYPTED);
        SearchFieldObject encryptedB = new SearchFieldObject("username", AttributeContentType.STRING, AttributeType.META);
        encryptedB.setLabel("Username");
        encryptedB.setProtectionLevel(ProtectionLevel.ENCRYPTED);

        List<SearchFieldDataDto> fields = SearchHelper.prepareSearchForJSON(List.of(encryptedA, encryptedB));

        assertThat(fields).hasSize(1);
        assertThat(fields.getFirst().getConditions()).isEqualTo(List.of(FilterConditionOperator.EMPTY, FilterConditionOperator.NOT_EMPTY));
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

        List<SearchFieldDataDto> fields = SearchHelper.prepareSearchForJSON(List.of(listA, listB));

        assertThat(fields).hasSize(1);
        assertThat(fields.getFirst().getValue()).isEqualTo(List.of("dev", "test", "prod"));
    }

    @Test
    void testPrepareSearchForJSONMergedFieldStaysFreeFormWhenAnyDuplicateIsNotList() {
        SearchFieldObject listVariant = new SearchFieldObject("environment", AttributeContentType.STRING, AttributeType.DATA);
        listVariant.setLabel("Environment");
        listVariant.setList(true);
        listVariant.setMultiSelect(true);
        listVariant.setContentItems(List.of("dev", "test"));
        SearchFieldObject freeFormVariant = new SearchFieldObject("environment", AttributeContentType.STRING, AttributeType.DATA);
        freeFormVariant.setLabel("Environment");

        List<SearchFieldDataDto> fields = SearchHelper.prepareSearchForJSON(List.of(listVariant, freeFormVariant));

        assertThat(fields).hasSize(1);
        assertThat(fields.getFirst().getType()).as("free-form input must survive the merge so any value stays enterable").isEqualTo(FilterFieldType.STRING);
        assertThat(fields.getFirst().getValue()).isNull();
        assertThat(fields.getFirst().isMultiValue()).isFalse();
    }

    @Test
    void testPrepareSearchForJSONMergeIsDeterministicRegardlessOfInputOrder() {
        SearchFieldObject labeledUser = new SearchFieldObject("username", AttributeContentType.STRING, AttributeType.META);
        labeledUser.setLabel("User");
        SearchFieldObject labeledUsername = new SearchFieldObject("username", AttributeContentType.STRING, AttributeType.META);
        labeledUsername.setLabel("Username");

        List<SearchFieldDataDto> fields = SearchHelper.prepareSearchForJSON(List.of(labeledUsername, labeledUser));
        List<SearchFieldDataDto> fieldsReversed = SearchHelper.prepareSearchForJSON(List.of(labeledUser, labeledUsername));

        assertThat(fields).hasSize(1);
        assertThat(fields.getFirst().getFieldLabel())
                .as("merged label must not depend on the (unordered) query result order")
                .isEqualTo(fieldsReversed.getFirst().getFieldLabel());
    }

    @Test
    void testPrepareSearchForJSONMergeIsDeterministicWhenDuplicatesShareTheLabel() {
        List<SearchFieldDataDto> fields = SearchHelper.prepareSearchForJSON(
                List.of(listFieldObject(List.of("dev", "test")), listFieldObject(List.of("prod"))));
        List<SearchFieldDataDto> fieldsReversed = SearchHelper.prepareSearchForJSON(
                List.of(listFieldObject(List.of("prod")), listFieldObject(List.of("dev", "test"))));

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
        Set<FilterField> shouldHaveCountOperator = Set.of(FilterField.CONNECTOR_FUNCTION_GROUP, FilterField.CONNECTOR_INTERFACE, FilterField.GROUP_NAME, FilterField.SUCCEEDING_CERTIFICATES, FilterField.PRECEDING_CERTIFICATES, FilterField.CERT_LOCATION_NAME, FilterField.CK_GROUP, FilterField.SECRET_SYNC_VAULT_PROFILE, FilterField.SECRET_GROUP_NAME);
        Set<FilterField> withCountOperator = new HashSet<>();
        for (FilterField filterField : FilterField.values()) {
            SearchFieldDataDto searchFieldDataDto = SearchHelper.prepareSearch(filterField, List.of("sampleValue"));
            if (searchFieldDataDto.getConditions().containsAll(Set.of(FilterConditionOperator.COUNT_EQUAL, FilterConditionOperator.COUNT_NOT_EQUAL, FilterConditionOperator.COUNT_GREATER_THAN, FilterConditionOperator.COUNT_LESS_THAN)))
                withCountOperator.add(filterField);
            }
        assertThat(withCountOperator).isEqualTo(shouldHaveCountOperator);
    }

    @Test
    void testPrepareSearchJsonArray() {
        Set<FilterField> jsonArrays = Set.of(FilterField.AUDIT_LOG_RESOURCE_NAME, FilterField.AUDIT_LOG_RESOURCE_UUID);
        for (FilterField filterField : jsonArrays) {
            SearchFieldDataDto searchFieldDataDto = SearchHelper.prepareSearch(filterField);
            assertThat(new HashSet<>(searchFieldDataDto.getConditions()))
                    .isEqualTo(Set.of(FilterConditionOperator.EQUALS, FilterConditionOperator.NOT_EQUALS, FilterConditionOperator.NOT_EMPTY, FilterConditionOperator.EMPTY));
        }
    }
}
