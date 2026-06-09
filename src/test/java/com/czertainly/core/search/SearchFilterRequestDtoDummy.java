package com.czertainly.core.search;

import com.otilm.api.model.client.certificate.SearchFilterRequestDto;
import com.otilm.api.model.core.search.FilterConditionOperator;
import com.otilm.api.model.core.search.FilterFieldSource;

import java.io.Serializable;

public class SearchFilterRequestDtoDummy extends SearchFilterRequestDto {

    private FilterFieldSource filterFieldSource;
    private String fieldIdentifier;
    private FilterConditionOperator condition;
    private Serializable value;

    public SearchFilterRequestDtoDummy(FilterFieldSource filterFieldSource, String fieldIdentifier, FilterConditionOperator condition, Serializable value) {
        this.filterFieldSource = filterFieldSource;
        this.fieldIdentifier = fieldIdentifier;
        this.condition = condition;
        this.value = value;
    }

    @Override
    public FilterFieldSource getFieldSource() {
        return filterFieldSource;
    }

    @Override
    public FilterConditionOperator getCondition() {
        return condition;
    }

    @Override
    public String getFieldIdentifier() {
        return fieldIdentifier;
    }

    @Override
    public Serializable getValue() {
        return value;
    }

}
