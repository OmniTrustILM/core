package com.czertainly.core.util.builders;

import com.otilm.api.model.core.search.FilterConditionOperator;
import com.otilm.api.model.core.search.FilterFieldSource;
import com.czertainly.core.enums.FilterField;
import com.czertainly.core.search.SearchFilterRequestDtoDummy;

import java.io.Serializable;

public class SearchFilterRequestDtoBuilder {

    private FilterFieldSource fieldSource = FilterFieldSource.PROPERTY;
    private String fieldIdentifier;
    private FilterConditionOperator condition = FilterConditionOperator.EQUALS;
    private Serializable value;

    public static SearchFilterRequestDtoBuilder aSearchFilter() {
        return new SearchFilterRequestDtoBuilder();
    }

    public static SearchFilterRequestDtoDummy aPropertyEqualsFilter(FilterField field, Serializable value) {
        return aSearchFilter().withField(field).withValue(value).build();
    }

    public SearchFilterRequestDtoBuilder withField(FilterField field) {
        this.fieldIdentifier = field.name();
        return this;
    }

    public SearchFilterRequestDtoBuilder withFieldSource(FilterFieldSource src) {
        this.fieldSource = src;
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

    public SearchFilterRequestDtoDummy build() {
        return new SearchFilterRequestDtoDummy(fieldSource, fieldIdentifier, condition, value);
    }
}
