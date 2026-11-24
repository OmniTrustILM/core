package com.otilm.core.messaging.jms.configuration;

import java.time.Duration;
import java.util.List;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;

class RenewalInfoPropertiesTest {

    @Test
    void unsetValuesTakeTheirDefaults() {
        RenewalInfoProperties props = new RenewalInfoProperties(0, 0, 0, null, null, 0);

        assertEquals(60_000, props.sweepIntervalMs());
        assertEquals(200, props.maxPerAuthority());
        assertEquals(500, props.enrolPerSweep());
        assertEquals(List.of(Duration.ofMinutes(5), Duration.ofMinutes(15), Duration.ofHours(1), Duration.ofHours(6)),
                props.backoff());
        assertEquals(Duration.ofMinutes(15), props.lease());
        assertEquals(4, props.executorThreads());
    }

    @Test
    void configuredValuesAreKept() {
        RenewalInfoProperties props = new RenewalInfoProperties(1000, 10, 20, List.of(Duration.ofSeconds(1)),
                Duration.ofMinutes(1), 2);

        assertEquals(1000, props.sweepIntervalMs());
        assertEquals(10, props.maxPerAuthority());
        assertEquals(20, props.enrolPerSweep());
        assertEquals(List.of(Duration.ofSeconds(1)), props.backoff());
        assertEquals(Duration.ofMinutes(1), props.lease());
        assertEquals(2, props.executorThreads());
    }
}
