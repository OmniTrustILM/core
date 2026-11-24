package com.otilm.core.messaging.jms.configuration;

import java.time.Duration;
import java.util.List;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

class RenewalInfoPropertiesTest {

    @Test
    void appliesDefaults_whenValuesAreUnset() {
        // given
        int unsetNumber = 0;

        // when
        RenewalInfoProperties props = new RenewalInfoProperties(unsetNumber, unsetNumber, unsetNumber, null, null,
                unsetNumber);

        // then
        assertThat(props.sweepIntervalMs()).isEqualTo(60_000);
        assertThat(props.maxPerAuthority()).isEqualTo(200);
        assertThat(props.enrolPerSweep()).isEqualTo(500);
        assertThat(props.backoff())
                .isEqualTo(List
                        .of(Duration.ofMinutes(5), Duration.ofMinutes(15), Duration.ofHours(1), Duration.ofHours(6)));
        assertThat(props.lease()).isEqualTo(Duration.ofMinutes(15));
        assertThat(props.executorThreads()).isEqualTo(4);
    }

    @Test
    void keepsValues_whenConfigured() {
        // given
        List<Duration> configuredBackoff = List.of(Duration.ofSeconds(1));

        // when
        RenewalInfoProperties props = new RenewalInfoProperties(1000, 10, 20, configuredBackoff, Duration.ofMinutes(1),
                2);

        // then
        assertThat(props.sweepIntervalMs()).isEqualTo(1000);
        assertThat(props.maxPerAuthority()).isEqualTo(10);
        assertThat(props.enrolPerSweep()).isEqualTo(20);
        assertThat(props.backoff()).isEqualTo(configuredBackoff);
        assertThat(props.lease()).isEqualTo(Duration.ofMinutes(1));
        assertThat(props.executorThreads()).isEqualTo(2);
    }
}
