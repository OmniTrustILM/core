package com.otilm.ai.proxy;

import org.apache.hc.core5.util.Timeout;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;

import static org.assertj.core.api.Assertions.assertThat;

class TransportTimeoutTest {
    @ParameterizedTest
    @CsvSource({"1,1", "999999,1", "1000000,1", "5000000,5", "5000000000,5000"})
    void returnsPositiveTimeout_whenRemainingBudgetIsSubMillisecondOrLarger(long remainingNanos, long expectedMillis) {
        // given — a remaining budget that must never round down to a disabled (zero) socket timeout

        // when
        Timeout timeout = CoreRpcClient.transportTimeout(remainingNanos);

        // then
        assertThat(timeout.toMilliseconds()).isEqualTo(expectedMillis);
    }
}
