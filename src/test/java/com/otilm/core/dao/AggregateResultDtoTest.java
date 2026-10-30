package com.otilm.core.dao;

import com.otilm.api.model.common.enums.IPlatformEnum;
import com.otilm.api.model.core.certificate.CertificateState;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

class AggregateResultDtoTest {

    @Test
    void integerConstructorConvertsValueToString() {
        AggregateResultDto result = new AggregateResultDto(Integer.valueOf(2048), 5L);

        Assertions.assertEquals("2048", result.aggregatedValue());
        Assertions.assertEquals(5L, result.aggregation());
    }

    @Test
    void enumConstructorUsesCode() {
        AggregateResultDto result = new AggregateResultDto(CertificateState.ISSUED, 5L);

        Assertions.assertEquals(CertificateState.ISSUED.getCode(), result.aggregatedValue());
    }

    /**
     * Grouping on a nullable column produces a NULL group; Hibernate instantiates the DTO with a null grouping value,
     * and callers map that null to their own placeholder label.
     */
    @Test
    void integerConstructorAcceptsNullValue() {
        AggregateResultDto result = new AggregateResultDto((Integer) null, 5L);

        Assertions.assertNull(result.aggregatedValue());
        Assertions.assertEquals(5L, result.aggregation());
    }

    @Test
    void enumConstructorAcceptsNullValue() {
        AggregateResultDto result = new AggregateResultDto((IPlatformEnum) null, 5L);

        Assertions.assertNull(result.aggregatedValue());
        Assertions.assertEquals(5L, result.aggregation());
    }
}
