package com.otilm.core.service.renewal.refresh;

import com.otilm.api.model.core.settings.CertificateRenewalInfoSettingsDto;
import java.time.Duration;
import java.time.Instant;
import java.util.List;
import java.util.function.DoubleSupplier;
import java.util.stream.Stream;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.CsvSource;
import org.junit.jupiter.params.provider.MethodSource;
import org.junit.jupiter.params.provider.NullSource;

import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.api.Named.named;

class RefreshScheduleTest {

    private static final Instant NOW = Instant.parse("2026-11-23T10:00:00Z");
    private static final RenewalInfoSettings SETTINGS = RenewalInfoSettings.DEFAULTS;
    private static final DoubleSupplier NO_JITTER = () -> 0.5;
    private static final List<Duration> RAMP = List
            .of(Duration.ofMinutes(5), Duration.ofMinutes(15), Duration.ofHours(1), Duration.ofHours(6));

    @Test
    void schedulesAtTheItemRetryAfter_whenTheItemAndTheResponseBothHaveOne() {
        // given
        var itemRetryAfter = 7200;
        var responseRetryAfter = 10000;

        // when
        Instant next = RefreshSchedule.next(NOW, itemRetryAfter, responseRetryAfter, SETTINGS, NO_JITTER);

        // then
        assertThat(next).isEqualTo(NOW.plusSeconds(itemRetryAfter));
    }

    @Test
    void schedulesAtTheResponseRetryAfter_whenTheItemHasNone() {
        // given
        var responseRetryAfter = 10000;

        // when
        Instant next = RefreshSchedule.next(NOW, null, responseRetryAfter, SETTINGS, NO_JITTER);

        // then
        assertThat(next).isEqualTo(NOW.plusSeconds(responseRetryAfter));
    }

    @Test
    void schedulesAtTheDefaultInterval_whenNoRetryAfterIsGiven() {
        // given — neither the item nor the response has a retry-after

        // when
        Instant next = RefreshSchedule.next(NOW, null, null, SETTINGS, NO_JITTER);

        // then
        assertThat(next).isEqualTo(NOW.plusSeconds(SETTINGS.defaultIntervalSeconds()));
    }

    @Test
    void raisesTheDelayToTheMinimum_whenTheRetryAfterIsBelowIt() {
        // given
        var belowMinimum = 10;

        // when
        Instant next = RefreshSchedule.next(NOW, belowMinimum, null, SETTINGS, NO_JITTER);

        // then
        assertThat(next).isEqualTo(NOW.plusSeconds(SETTINGS.minIntervalSeconds()));
    }

    @Test
    void lowersTheDelayToTheMaximum_whenTheRetryAfterIsAboveIt() {
        // given
        var aboveMaximum = 999999;

        // when
        Instant next = RefreshSchedule.next(NOW, aboveMaximum, null, SETTINGS, NO_JITTER);

        // then
        assertThat(next).isEqualTo(NOW.plusSeconds(SETTINGS.maxIntervalSeconds()));
    }

    @Test
    void keepsTheMinimum_whenJitterWouldShortenAClampedRetryAfter() {
        // given
        var belowMinimum = 10;
        DoubleSupplier lowestJitter = () -> 0.0;

        // when
        Instant next = RefreshSchedule.next(NOW, belowMinimum, null, SETTINGS, lowestJitter);

        // then
        assertThat(next).isEqualTo(NOW.plusSeconds(SETTINGS.minIntervalSeconds()));
    }

    @Test
    void keepsTheMaximum_whenJitterWouldLengthenAClampedRetryAfter() {
        // given
        var aboveMaximum = 999999;
        DoubleSupplier highestJitter = () -> 1.0;

        // when
        Instant next = RefreshSchedule.next(NOW, aboveMaximum, null, SETTINGS, highestJitter);

        // then
        assertThat(next).isEqualTo(NOW.plusSeconds(SETTINGS.maxIntervalSeconds()));
    }

    @ParameterizedTest
    @CsvSource({"0.0, 19440", "1.0, 23760"})
    void spreadsTheDefaultIntervalByTenPercent_whenJitterIsAtItsBounds(double random, long expectedSeconds) {
        // given
        DoubleSupplier jitter = () -> random;

        // when
        Instant next = RefreshSchedule.next(NOW, null, null, SETTINGS, jitter);

        // then
        assertThat(next).isEqualTo(NOW.plusSeconds(expectedSeconds));
    }

    @ParameterizedTest
    @MethodSource("rampSteps")
    void delaysByTheRampStep_whenTheAttemptIsWithinTheRamp(int attempt, Duration expectedDelay) {
        // given — the ramp of four delays

        // when
        Instant next = RefreshSchedule.backoff(NOW, attempt, RAMP);

        // then
        assertThat(next).isEqualTo(NOW.plus(expectedDelay));
    }

    @ParameterizedTest
    @CsvSource({"5", "500"})
    void delaysByTheLastStep_whenTheAttemptIsBeyondTheRamp(int attemptBeyondTheRamp) {
        // given — the ramp of four delays

        // when
        Instant next = RefreshSchedule.backoff(NOW, attemptBeyondTheRamp, RAMP);

        // then
        assertThat(next).isEqualTo(NOW.plus(Duration.ofHours(6)));
    }

    @Test
    void delaysByTheFirstStep_whenTheAttemptIsNotPositive() {
        // given
        var nonPositiveAttempt = 0;

        // when
        Instant next = RefreshSchedule.backoff(NOW, nonPositiveAttempt, RAMP);

        // then
        assertThat(next).isEqualTo(NOW.plus(Duration.ofMinutes(5)));
    }

    @ParameterizedTest
    @NullSource
    @MethodSource("emptySettings")
    void fallsBackToTheDefaults_whenTheSettingsHaveNoValues(CertificateRenewalInfoSettingsDto missingValues) {
        // given — settings that are absent or carry no value

        // when
        RenewalInfoSettings settings = RenewalInfoSettings.from(missingValues);

        // then
        assertThat(settings).isEqualTo(RenewalInfoSettings.DEFAULTS);
    }

    // ── Helpers ───────────────────────────────────────────────────────────────

    private static Stream<Arguments> rampSteps() {
        return Stream
                .of(Arguments.of(1, Duration.ofMinutes(5)), Arguments.of(2, Duration.ofMinutes(15)),
                        Arguments.of(3, Duration.ofHours(1)), Arguments.of(4, Duration.ofHours(6)));
    }

    private static Stream<Arguments> emptySettings() {
        return Stream.of(Arguments.of(named("an empty settings DTO", new CertificateRenewalInfoSettingsDto())));
    }
}
