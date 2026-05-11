package com.czertainly.core.enums;

import com.czertainly.api.model.core.search.FilterConditionOperator;
import com.czertainly.api.model.core.search.FilterFieldType;

import java.time.LocalDate;
import java.time.LocalDateTime;
import java.util.List;

public enum SearchFieldTypeEnum {

    STRING(FilterFieldType.STRING,
            List.of(FilterConditionOperator.CONTAINS, FilterConditionOperator.NOT_CONTAINS, FilterConditionOperator.EQUALS, FilterConditionOperator.NOT_EQUALS, FilterConditionOperator.EMPTY, FilterConditionOperator.NOT_EMPTY, FilterConditionOperator.STARTS_WITH, FilterConditionOperator.ENDS_WITH,
                    FilterConditionOperator.MATCHES, FilterConditionOperator.NOT_MATCHES)
            , false, null),
    DATE(FilterFieldType.DATE,
            List.of(FilterConditionOperator.EQUALS, FilterConditionOperator.NOT_EQUALS, FilterConditionOperator.GREATER, FilterConditionOperator.GREATER_OR_EQUAL, FilterConditionOperator.LESSER, FilterConditionOperator.LESSER_OR_EQUAL, FilterConditionOperator.EMPTY, FilterConditionOperator.NOT_EMPTY,
                    FilterConditionOperator.IN_NEXT, FilterConditionOperator.IN_PAST)
            , false, LocalDate.class),
    DATETIME(FilterFieldType.DATETIME,
            List.of(FilterConditionOperator.EQUALS, FilterConditionOperator.NOT_EQUALS, FilterConditionOperator.GREATER, FilterConditionOperator.GREATER_OR_EQUAL, FilterConditionOperator.LESSER, FilterConditionOperator.LESSER_OR_EQUAL, FilterConditionOperator.EMPTY, FilterConditionOperator.NOT_EMPTY,
                    FilterConditionOperator.IN_NEXT, FilterConditionOperator.IN_PAST)
            , false, LocalDateTime.class),
    NUMBER(FilterFieldType.NUMBER,
            List.of(FilterConditionOperator.EQUALS, FilterConditionOperator.NOT_EQUALS, FilterConditionOperator.GREATER, FilterConditionOperator.GREATER_OR_EQUAL, FilterConditionOperator.LESSER, FilterConditionOperator.LESSER_OR_EQUAL, FilterConditionOperator.EMPTY, FilterConditionOperator.NOT_EMPTY)
            , false, Integer.class),
    LIST(FilterFieldType.LIST,
            List.of(FilterConditionOperator.EQUALS, FilterConditionOperator.NOT_EQUALS, FilterConditionOperator.EMPTY, FilterConditionOperator.NOT_EMPTY)
            , true, null),
    // Like LIST but the underlying column is a native PostgreSQL array (text[]).
    // EQUALS/NOT_EQUALS use = ANY(column) instead of column = value.
    NATIVE_ARRAY(FilterFieldType.LIST,
            List.of(FilterConditionOperator.EQUALS, FilterConditionOperator.NOT_EQUALS, FilterConditionOperator.EMPTY, FilterConditionOperator.NOT_EMPTY)
            , true, null),
    BOOLEAN(FilterFieldType.BOOLEAN,
         List.of(FilterConditionOperator.EQUALS, FilterConditionOperator.NOT_EQUALS, FilterConditionOperator.EMPTY, FilterConditionOperator.NOT_EMPTY), false, Boolean.class)
    ;


    private FilterFieldType fieldType;

    private List<FilterConditionOperator> conditions;

    private boolean multiValue;

    private Class<?> expressionClass;

    SearchFieldTypeEnum(final FilterFieldType fieldType, final List<FilterConditionOperator> conditions, final boolean multiValue, Class<?> expressionClass) {
        this.fieldType = fieldType;
        this.conditions = conditions;
        this.multiValue = multiValue;
        this.expressionClass = expressionClass;
    }

    public FilterFieldType getFieldType() {
        return fieldType;
    }

    public List<FilterConditionOperator> getConditions() {
        return conditions;
    }

    public boolean isMultiValue() {
        return multiValue;
    }

    public Class<?> getExpressionClass() {
        return expressionClass;
    }
}
