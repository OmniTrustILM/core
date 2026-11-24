package com.otilm.core.service.renewal;

import java.time.Instant;
import java.util.Optional;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

class PolicyWindowTest {

    private static final Instant NOT_BEFORE = Instant.parse("2026-01-01T00:00:00Z");
    private static final Instant NOT_AFTER = Instant.parse("2026-04-11T00:00:00Z");

    @Test
    void placesTheWindowAtThePercentagesOfTheLifetime() {
        // when
        Optional<Window> window = PolicyWindow.compute(NOT_BEFORE, NOT_AFTER, 67, 80);

        // then
        assertThat(window)
                .contains(new Window(Instant.parse("2026-03-09T00:00:00Z"), Instant.parse("2026-03-22T00:00:00Z")));
    }

    @Test
    void truncatesToTheMillisecond() {
        // given
        Instant notAfter = NOT_BEFORE.plusMillis(1001);

        // when
        Optional<Window> window = PolicyWindow.compute(NOT_BEFORE, notAfter, 67, 80);

        // then
        assertThat(window).contains(new Window(NOT_BEFORE.plusMillis(670), NOT_BEFORE.plusMillis(800)));
    }

    @Test
    void hasNoWindowWithoutValidityDates() {
        assertThat(PolicyWindow.compute(null, NOT_AFTER, 67, 80)).isEmpty();
        assertThat(PolicyWindow.compute(NOT_BEFORE, null, 67, 80)).isEmpty();
    }

    @Test
    void hasNoWindowWithoutLifetime() {
        assertThat(PolicyWindow.compute(NOT_BEFORE, NOT_BEFORE, 67, 80)).isEmpty();
        assertThat(PolicyWindow.compute(NOT_AFTER, NOT_BEFORE, 67, 80)).isEmpty();
    }
}
