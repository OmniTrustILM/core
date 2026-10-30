package com.otilm.core.dao;

import com.otilm.api.model.common.enums.IPlatformEnum;

/**
 * Grouping on a nullable column yields a NULL group, so the convenience constructors must tolerate a null grouping
 * value and pass it through — callers decide which placeholder label represents it.
 */
public record AggregateResultDto(String aggregatedValue, Number aggregation) {

    public AggregateResultDto(Integer aggregatedValue, Number aggregation) {
        this(aggregatedValue == null ? null : aggregatedValue.toString(), aggregation);
    }

    public AggregateResultDto(IPlatformEnum aggregatedValue, Number aggregation) {
        this(aggregatedValue == null ? null : aggregatedValue.getCode(), aggregation);
    }
}
