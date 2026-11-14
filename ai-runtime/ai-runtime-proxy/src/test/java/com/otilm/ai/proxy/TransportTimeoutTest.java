package com.otilm.ai.proxy;

import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;

import static org.junit.jupiter.api.Assertions.assertEquals;

class TransportTimeoutTest {
    @ParameterizedTest
    @CsvSource({"1,1", "999999,1", "1000000,1", "5000000,5", "5000000000,5000"})
    void neverDisablesASocketTimeoutByRoundingASmallBudgetToZero(long nanos, long expectedMillis) {
        assertEquals(expectedMillis, CoreRpcClient.transportTimeout(nanos).toMilliseconds());
    }
}
