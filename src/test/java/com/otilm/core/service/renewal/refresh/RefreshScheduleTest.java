package com.otilm.core.service.renewal.refresh;

import com.otilm.api.model.core.settings.CertificateRenewalInfoSettingsDto;
import java.time.Duration;
import java.time.Instant;
import java.util.List;
import java.util.function.DoubleSupplier;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.api.Assertions.assertEquals;

class RefreshScheduleTest {

    private static final Instant NOW = Instant.parse("2026-11-23T10:00:00Z");
    private static final RenewalInfoSettings SETTINGS = RenewalInfoSettings.DEFAULTS;
    private static final List<Duration> RAMP = List
            .of(Duration.ofMinutes(5), Duration.ofMinutes(15), Duration.ofHours(1), Duration.ofHours(6));

    @Test
    void itemRetryAfterWinsOverResponseAndDefault() {
        assertEquals(NOW.plusSeconds(7200), RefreshSchedule.next(NOW, 7200, 10000, SETTINGS, () -> 0.5));
    }

    @Test
    void responseRetryAfterIsUsedWithoutItemValue() {
        assertEquals(NOW.plusSeconds(10000), RefreshSchedule.next(NOW, null, 10000, SETTINGS, () -> 0.5));
    }

    @Test
    void defaultIntervalIsUsedWithoutRetryAfter() {
        assertEquals(NOW.plusSeconds(21600), RefreshSchedule.next(NOW, null, null, SETTINGS, () -> 0.5));
    }

    @Test
    void retryAfterBelowMinimumIsRaisedToMinimum() {
        assertEquals(NOW.plusSeconds(3600), RefreshSchedule.next(NOW, 10, null, SETTINGS, () -> 0.5));
    }

    @Test
    void retryAfterAboveMaximumIsLoweredToMaximum() {
        assertEquals(NOW.plusSeconds(86400), RefreshSchedule.next(NOW, 999999, null, SETTINGS, () -> 0.5));
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

    @Test
    void jitterSpreadsTenPercentEitherWay() {
        assertEquals(NOW.plusSeconds(19440), RefreshSchedule.next(NOW, null, null, SETTINGS, () -> 0.0));
        assertEquals(NOW.plusSeconds(23760), RefreshSchedule.next(NOW, null, null, SETTINGS, () -> 1.0));
    }

    @Test
    void backoffFollowsTheRamp() {
        assertEquals(NOW.plus(Duration.ofMinutes(5)), RefreshSchedule.backoff(NOW, 1, RAMP));
        assertEquals(NOW.plus(Duration.ofMinutes(15)), RefreshSchedule.backoff(NOW, 2, RAMP));
        assertEquals(NOW.plus(Duration.ofHours(1)), RefreshSchedule.backoff(NOW, 3, RAMP));
        assertEquals(NOW.plus(Duration.ofHours(6)), RefreshSchedule.backoff(NOW, 4, RAMP));
    }

    @Test
    void backoffStaysAtTheLastStepBeyondTheRamp() {
        assertEquals(NOW.plus(Duration.ofHours(6)), RefreshSchedule.backoff(NOW, 5, RAMP));
        assertEquals(NOW.plus(Duration.ofHours(6)), RefreshSchedule.backoff(NOW, 500, RAMP));
    }

    @Test
    void backoffUsesTheFirstStepForANonPositiveAttempt() {
        assertEquals(NOW.plus(Duration.ofMinutes(5)), RefreshSchedule.backoff(NOW, 0, RAMP));
    }

    @Test
    void settingsFallBackToDefaultsForMissingValues() {
        assertEquals(RenewalInfoSettings.DEFAULTS, RenewalInfoSettings.from(null));
        assertEquals(RenewalInfoSettings.DEFAULTS, RenewalInfoSettings.from(new CertificateRenewalInfoSettingsDto()));
    }
}
