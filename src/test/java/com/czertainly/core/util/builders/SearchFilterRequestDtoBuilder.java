package com.czertainly.core.util.builders;

import com.otilm.api.model.client.certificate.SearchFilterRequestDto;
import com.otilm.api.model.common.attribute.common.content.AttributeContentType;
import com.otilm.api.model.core.search.FilterConditionOperator;
import com.otilm.api.model.core.search.FilterFieldSource;
import com.otilm.core.enums.FilterField;

import java.io.Serializable;

public class SearchFilterRequestDtoBuilder {

    private FilterFieldSource fieldSource = FilterFieldSource.PROPERTY;
    private FilterField field;
    private AttributeContentType attributeContentType;
    private String attributeName;
    private FilterConditionOperator condition = FilterConditionOperator.EQUALS;
    private Serializable value;

    public static SearchFilterRequestDtoBuilder aSearchFilter() {
        return new SearchFilterRequestDtoBuilder();
    }

    public static SearchFilterRequestDto aPropertyFilter(FilterField field, FilterConditionOperator operator, Serializable value) {
        return aSearchFilter().withField(field).withCondition(operator).withValue(value).build();
    }

    public static SearchFilterRequestDto aPropertyEqualsFilter(FilterField field, Serializable value) {
        return aPropertyFilter(field, FilterConditionOperator.EQUALS, value);
    }

    public static SearchFilterRequestDto aPropertyNotEqualsFilter(FilterField field, Serializable value) {
        return aPropertyFilter(field, FilterConditionOperator.NOT_EQUALS, value);
    }

    public static SearchFilterRequestDto aPropertyEmptyFilter(FilterField field) {
        return aPropertyFilter(field, FilterConditionOperator.EMPTY, null);
    }

    public static SearchFilterRequestDto aPropertyNotEmptyFilter(FilterField field) {
        return aPropertyFilter(field, FilterConditionOperator.NOT_EMPTY, null);
    }

    private static SearchFilterRequestDto anAttributeFilter(FilterFieldSource source, String name, AttributeContentType type, FilterConditionOperator operator, Serializable value) {
        return aSearchFilter().withFieldSource(source).withAttribute(name, type).withCondition(operator).withValue(value).build();
    }

    public static SearchFilterRequestDto aCustomAttributeFilter(String name, AttributeContentType type, FilterConditionOperator operator, Serializable value) {
        return anAttributeFilter(FilterFieldSource.CUSTOM, name, type, operator, value);
    }

    public static SearchFilterRequestDto aMetaAttributeFilter(String name, AttributeContentType type, FilterConditionOperator operator, Serializable value) {
        return anAttributeFilter(FilterFieldSource.META, name, type, operator, value);
    }

    public SearchFilterRequestDtoBuilder withField(FilterField field) {
        this.field = field;
        return this;
    }

    public SearchFilterRequestDtoBuilder withFieldSource(FilterFieldSource src) {
        this.fieldSource = src;
        return this;
    }

    public SearchFilterRequestDtoBuilder withAttributeContentType(AttributeContentType attributeContentType) {
        this.attributeContentType = attributeContentType;
        return this;
    }

    public SearchFilterRequestDtoBuilder withAttribute(String name, AttributeContentType type) {
        this.attributeName = name;
        this.attributeContentType = type;
        return this;
    }

    public SearchFilterRequestDtoBuilder withCondition(FilterConditionOperator c) {
        this.condition = c;
        return this;
    }

    public SearchFilterRequestDtoBuilder withValue(Serializable value) {
        this.value = value;
        return this;
    }

    public SearchFilterRequestDto build() {
        if (field == null && attributeName == null) {
            throw new IllegalStateException("Either a FilterField or an attribute name must be set before calling build()");
        }
        return new SearchFilterRequestDto(fieldSource, fieldIdentifier(), condition, value);
    }

    private String fieldIdentifier() {
        if (attributeName != null) {
            return attributeName + "|" + attributeContentType.name();
        }
        return attributeContentType == null
                ? field.name()
                : field.name() + "|" + attributeContentType.name();
    }
}
