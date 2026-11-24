package com.otilm.core.service.renewal;

import java.time.Instant;
import java.util.Optional;
import java.util.stream.Stream;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.api.Named.named;
import static org.junit.jupiter.params.provider.Arguments.arguments;

class PolicyWindowTest {

    private static final Instant NOT_BEFORE = Instant.parse("2026-01-01T00:00:00Z");
    private static final Instant NOT_AFTER = Instant.parse("2026-04-11T00:00:00Z");

    @Test
    void placesTheWindowAtThePercentagesOfTheLifetime_whenValidityDatesAreSet() {
        // given
        int startPercent = 67;
        int endPercent = 80;

        // when
        Optional<Window> window = PolicyWindow.compute(NOT_BEFORE, NOT_AFTER, startPercent, endPercent);

        // then
        assertThat(window)
                .contains(new Window(Instant.parse("2026-03-09T00:00:00Z"), Instant.parse("2026-03-22T00:00:00Z")));
    }

    @Test
    void truncatesToTheMillisecond_whenLifetimeHasFractionalMillisecondBoundaries() {
        // given
        Instant notAfterWithFractionalBoundaries = NOT_BEFORE.plusMillis(1001);

        // when
        Optional<Window> window = PolicyWindow.compute(NOT_BEFORE, notAfterWithFractionalBoundaries, 67, 80);

        // then
        assertThat(window).contains(new Window(NOT_BEFORE.plusMillis(670), NOT_BEFORE.plusMillis(800)));
    }

    @ParameterizedTest
    @MethodSource("missingValidityDates")
    void returnsNoWindow_whenValidityDateIsMissing(Instant notBefore, Instant notAfter) {
        // given — a certificate whose validity dates are not both known

        // when
        Optional<Window> window = PolicyWindow.compute(notBefore, notAfter, 67, 80);

        // then
        assertThat(window).isEmpty();
    }

    @ParameterizedTest
    @MethodSource("emptyLifetimes")
    void returnsNoWindow_whenLifetimeIsNotPositive(Instant notBefore, Instant notAfter) {
        // given — a validity period that does not span any time

        // when
        Optional<Window> window = PolicyWindow.compute(notBefore, notAfter, 67, 80);

        // then
        assertThat(window).isEmpty();
    }

    // ── Helpers ───────────────────────────────────────────────────────────────

    private static Stream<Arguments> missingValidityDates() {
        return Stream
                .of(arguments(named("notBefore missing", null), NOT_AFTER),
                        arguments(NOT_BEFORE, named("notAfter missing", null)));
    }

    private static Stream<Arguments> emptyLifetimes() {
        return Stream
                .of(arguments(named("zero lifetime", NOT_BEFORE), NOT_BEFORE),
                        arguments(named("notAfter before notBefore", NOT_AFTER), NOT_BEFORE));
    }
}
