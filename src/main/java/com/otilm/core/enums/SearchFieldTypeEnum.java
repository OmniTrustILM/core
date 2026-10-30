package com.otilm.core.enums;

import com.otilm.api.model.core.search.FilterConditionOperator;
import com.otilm.api.model.core.search.FilterFieldType;

import java.time.LocalDate;
import java.time.LocalDateTime;
import java.util.List;

public enum SearchFieldTypeEnum {

    STRING(FilterFieldType.STRING,
            List
                    .of(FilterConditionOperator.CONTAINS, FilterConditionOperator.NOT_CONTAINS,
                            FilterConditionOperator.EQUALS, FilterConditionOperator.NOT_EQUALS,
                            FilterConditionOperator.EMPTY, FilterConditionOperator.NOT_EMPTY,
                            FilterConditionOperator.STARTS_WITH, FilterConditionOperator.ENDS_WITH,
                            FilterConditionOperator.MATCHES, FilterConditionOperator.NOT_MATCHES),
            false, null),
    DATE(FilterFieldType.DATE,
            List
                    .of(FilterConditionOperator.EQUALS, FilterConditionOperator.NOT_EQUALS,
                            FilterConditionOperator.GREATER, FilterConditionOperator.GREATER_OR_EQUAL,
                            FilterConditionOperator.LESSER, FilterConditionOperator.LESSER_OR_EQUAL,
                            FilterConditionOperator.EMPTY, FilterConditionOperator.NOT_EMPTY,
                            FilterConditionOperator.IN_NEXT, FilterConditionOperator.IN_PAST),
            false, LocalDate.class),
    DATETIME(FilterFieldType.DATETIME,
            List
                    .of(FilterConditionOperator.EQUALS, FilterConditionOperator.NOT_EQUALS,
                            FilterConditionOperator.GREATER, FilterConditionOperator.GREATER_OR_EQUAL,
                            FilterConditionOperator.LESSER, FilterConditionOperator.LESSER_OR_EQUAL,
                            FilterConditionOperator.EMPTY, FilterConditionOperator.NOT_EMPTY,
                            FilterConditionOperator.IN_NEXT, FilterConditionOperator.IN_PAST),
            false, LocalDateTime.class),
    NUMBER(FilterFieldType.NUMBER,
            List
                    .of(FilterConditionOperator.EQUALS, FilterConditionOperator.NOT_EQUALS,
                            FilterConditionOperator.GREATER, FilterConditionOperator.GREATER_OR_EQUAL,
                            FilterConditionOperator.LESSER, FilterConditionOperator.LESSER_OR_EQUAL,
                            FilterConditionOperator.EMPTY, FilterConditionOperator.NOT_EMPTY),
            false, Integer.class),
    LIST(FilterFieldType.LIST,
            List
                    .of(FilterConditionOperator.EQUALS, FilterConditionOperator.NOT_EQUALS,
                            FilterConditionOperator.EMPTY, FilterConditionOperator.NOT_EMPTY),
            true, null),
    // Like LIST but the underlying column is a native PostgreSQL array (text[]), so EQUALS asks membership rather
    // than equality: it matches a row whose array holds the value, not one whose array is the value.
    // The predicate is containment -- PostgresFunctionContributor.ARRAY_CONTAINS_PATTERN, `col @> ARRAY[value]`.
    // Not `value = ANY(col)`, which answers the same question and cannot be answered by any index at all; that
    // form un-indexes every membership filter on every field of this type, so it must not come back.
    NATIVE_ARRAY(FilterFieldType.LIST,
            List
                    .of(FilterConditionOperator.CONTAINS, FilterConditionOperator.NOT_CONTAINS,
                            FilterConditionOperator.EQUALS, FilterConditionOperator.NOT_EQUALS,
                            FilterConditionOperator.EMPTY, FilterConditionOperator.NOT_EMPTY),
            true, null),
    // For fields whose value is not meaningful to the user (for example an internal UUID reference):
    // only the presence of a value can be tested, never the value itself.
    PRESENCE(FilterFieldType.STRING, List.of(FilterConditionOperator.EMPTY, FilterConditionOperator.NOT_EMPTY), false,
            null),
    // A single text input matched case-insensitively across several columns at once; which columns is
    // defined per FilterField in FilterPredicatesBuilder. Only CONTAINS is offered: the field spans
    // columns, so per-column operators (EQUALS, EMPTY, ...) have no single answer.
    FREE_TEXT(FilterFieldType.STRING, List.of(FilterConditionOperator.CONTAINS), false, null),
    BOOLEAN(FilterFieldType.BOOLEAN,
            List
                    .of(FilterConditionOperator.EQUALS, FilterConditionOperator.NOT_EQUALS,
                            FilterConditionOperator.EMPTY, FilterConditionOperator.NOT_EMPTY),
            false, Boolean.class);

    private FilterFieldType fieldType;

    private List<FilterConditionOperator> conditions;

    private boolean multiValue;

    private Class<?> expressionClass;

    SearchFieldTypeEnum(final FilterFieldType fieldType, final List<FilterConditionOperator> conditions,
            final boolean multiValue, Class<?> expressionClass) {
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
