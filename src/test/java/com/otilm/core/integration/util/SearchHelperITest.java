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
