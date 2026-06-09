package com.otilm.core.util;

import com.otilm.api.model.common.attribute.common.content.AttributeContentType;
import com.otilm.api.model.common.attribute.common.content.data.ProtectionLevel;
import com.otilm.api.model.common.enums.IPlatformEnum;
import com.otilm.api.model.common.enums.PlatformEnum;
import com.otilm.api.model.core.search.FilterConditionOperator;
import com.otilm.api.model.core.search.FilterFieldType;
import com.otilm.api.model.core.search.SearchFieldDataDto;
import com.otilm.core.comparator.SearchFieldDataComparator;
import com.otilm.core.enums.FilterField;
import com.otilm.core.enums.SearchFieldTypeEnum;
import com.otilm.core.model.SearchFieldObject;
import jakarta.persistence.metamodel.Attribute;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

public class SearchHelper {

    private static final String SEARCH_LABEL_TEMPLATE = "%s (%s)";

    public static SearchFieldDataDto prepareSearch(final FilterField fieldNameEnum) {
        return prepareSearch(fieldNameEnum, null);
    }

    public static SearchFieldDataDto prepareSearch(final FilterField filterField, Object values) {
        final SearchFieldDataDto fieldDataDto = new SearchFieldDataDto();
        fieldDataDto.setFieldIdentifier(filterField.name());
        fieldDataDto.setFieldLabel(filterField.getLabel());
        fieldDataDto.setMultiValue(filterField.getType().isMultiValue());
        List<FilterConditionOperator> conditionOperators = new ArrayList<>(getInitialCapacity(filterField));

        if (filterField.getFieldAttribute() == null) {
            conditionOperators = new ArrayList<>(List.of(FilterConditionOperator.EMPTY, FilterConditionOperator.NOT_EMPTY));
        }

        if (filterField.getType() == SearchFieldTypeEnum.LIST && filterField.getJoinAttributes() != null && filterField.getJoinAttributes().stream().anyMatch(Attribute::isCollection)) {
            conditionOperators.addAll(List.of(FilterConditionOperator.COUNT_EQUAL, FilterConditionOperator.COUNT_NOT_EQUAL, FilterConditionOperator.COUNT_GREATER_THAN, FilterConditionOperator.COUNT_LESS_THAN));
        }

        fieldDataDto.setConditions(conditionOperators);
        fieldDataDto.setType(filterField.getType().getFieldType());
        // Do not add null value to List filter
        if (filterField.getType().getFieldType() == FilterFieldType.LIST && filterField.getEnumClass() == null) {
            values = new ArrayList<>((List<?>) values);
            ((List<?>) values).remove(null);
        }
        fieldDataDto.setValue(values);

        if (filterField.getEnumClass() != null) {
            fieldDataDto.setPlatformEnum(PlatformEnum.findByClass(filterField.getEnumClass()));
            if (values == null) {
                fieldDataDto.setValue(Arrays.stream(fieldDataDto.getPlatformEnum().getEnumClass().getEnumConstants()).map(IPlatformEnum::getCode).sorted().toList());
            }
        }

        return fieldDataDto;
    }

    private static List<FilterConditionOperator> getInitialCapacity(FilterField filterField) {
        if (filterField.getJsonPath() != null && FilterPredicatesBuilder.isJsonArray(filterField)) return List.of(FilterConditionOperator.EQUALS, FilterConditionOperator.NOT_EQUALS, FilterConditionOperator.EMPTY, FilterConditionOperator.NOT_EMPTY);
        return filterField.getType().getFieldType() == FilterFieldType.BOOLEAN && filterField.getExpectedValue() != null ? List.of(FilterConditionOperator.EQUALS, FilterConditionOperator.NOT_EQUALS) : filterField.getType().getConditions();
    }

    public static SearchFieldDataDto prepareSearchForJSON(final SearchFieldObject attributeSearchInfo, final boolean hasDuplicateInList) {
        final SearchFieldTypeEnum searchFieldTypeEnum = retrieveSearchFieldTypeEnumByContentType(attributeSearchInfo.getAttributeContentType(), attributeSearchInfo.isList());
        final SearchFieldDataDto fieldDataDto = new SearchFieldDataDto();
        fieldDataDto.setFieldIdentifier(attributeSearchInfo.getAttributeName() + "|" + attributeSearchInfo.getAttributeContentType().name());
        fieldDataDto.setFieldLabel(hasDuplicateInList ? String.format(SEARCH_LABEL_TEMPLATE, attributeSearchInfo.getLabel(), attributeSearchInfo.getAttributeContentType().getCode()) : attributeSearchInfo.getLabel());
        fieldDataDto.setMultiValue(attributeSearchInfo.isMultiSelect());
        List<FilterConditionOperator> conditionOperators = new ArrayList<>(searchFieldTypeEnum.getConditions());
        if (attributeSearchInfo.getAttributeContentType() == AttributeContentType.TIME)
            conditionOperators.removeAll(List.of(FilterConditionOperator.IN_NEXT, FilterConditionOperator.IN_PAST));
        if (attributeSearchInfo.getProtectionLevel() == ProtectionLevel.ENCRYPTED) {
            conditionOperators = List.of(FilterConditionOperator.EMPTY, FilterConditionOperator.NOT_EMPTY);
        }
        fieldDataDto.setConditions(conditionOperators);
        fieldDataDto.setType(searchFieldTypeEnum.getFieldType());
        fieldDataDto.setValue(attributeSearchInfo.getContentItems());
        fieldDataDto.setAttributeContentType(attributeSearchInfo.getAttributeContentType());
        return fieldDataDto;
    }

    private static SearchFieldTypeEnum retrieveSearchFieldTypeEnumByContentType(AttributeContentType attributeContentType, boolean isList) {
        if (isList) {
            return SearchFieldTypeEnum.LIST;
        }

        SearchFieldTypeEnum searchFieldTypeEnum = null;
        switch (attributeContentType) {
            case DATE, DATETIME, TIME -> searchFieldTypeEnum = SearchFieldTypeEnum.DATE;
            case INTEGER, FLOAT -> searchFieldTypeEnum = SearchFieldTypeEnum.NUMBER;
            case BOOLEAN -> searchFieldTypeEnum = SearchFieldTypeEnum.BOOLEAN;
            default -> searchFieldTypeEnum = SearchFieldTypeEnum.STRING;
        }
        return searchFieldTypeEnum;
    }

    public static List<SearchFieldDataDto> prepareSearchForJSON(final List<SearchFieldObject> searchFieldObjectList) {
        final List<String> duplicatesOfNames = filterDuplicity(searchFieldObjectList);
        return searchFieldObjectList.stream().map(attribute -> prepareSearchForJSON(attribute, duplicatesOfNames.contains(attribute.getAttributeName()))).sorted(new SearchFieldDataComparator()).toList();
    }

    private static List<String> filterDuplicity(final List<SearchFieldObject> searchFieldObjectList) {
        final List<String> uniqueNames = new ArrayList<>();
        final List<String> duplicatesOfNames = new ArrayList<>();
        searchFieldObjectList.forEach(attr -> {
            if (uniqueNames.contains(attr.getAttributeName())) {
                duplicatesOfNames.add(attr.getAttributeName());
            } else {
                uniqueNames.add(attr.getAttributeName());
            }
        });
        return duplicatesOfNames;
    }


}
