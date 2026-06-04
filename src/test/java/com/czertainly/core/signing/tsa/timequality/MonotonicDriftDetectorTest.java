package com.czertainly.core.signing.tsa.timequality;

import com.czertainly.core.util.clocksource.TestClockSource;
import org.junit.jupiter.api.Test;

import java.time.Duration;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;

class MonotonicDriftDetectorTest {
    private static final Duration MAX_DRIFT_500MS = Duration.ofMillis(500);
    private static final UUID PROFILE_ID = UUID.fromString("00000000-0000-0000-0000-000000000001");

    @Test
    void returnsFalseWhenNoClockJump() {
        // given
        var clock = TestClockSource.aTestClock();
        var detector = new MonotonicDriftDetector(clock);

        detector.captureReference(PROFILE_ID, 0.0);

        // when both clocks advance by 10 seconds
        clock.advanceWallMillis(10_000);
        clock.advanceMonoNanos(10_000_000_000L);

        // then
        assertThat(detector.isDriftExceeded(PROFILE_ID, MAX_DRIFT_500MS)).isFalse();
    }

    @Test
    void detectsClockJumpForward() {
        // given
        var clock = TestClockSource.aTestClock();
        var detector = new MonotonicDriftDetector(clock);

        detector.captureReference(PROFILE_ID, 0.0);

        // when wall clock jumps 2s ahead, mono clock only 1s
        clock.advanceMonoNanos(1_000_000_000L);
        clock.advanceWallMillis(2_000);

        // then
        assertThat(detector.isDriftExceeded(PROFILE_ID, MAX_DRIFT_500MS)).isTrue();
    }

    @Test
    void detectsClockJumpBackward() {
        // given
        var clock = TestClockSource.aTestClock();
        var detector = new MonotonicDriftDetector(clock);

        detector.captureReference(PROFILE_ID, 0.0);

        // when mono advances 2s, wall stays the same → drift = -2000ms
        clock.advanceMonoNanos(2_000_000_000L);

        // then
        assertThat(detector.isDriftExceeded(PROFILE_ID, MAX_DRIFT_500MS)).isTrue();
    }

    @Test
    void allowsDriftWithinThreshold() {
        // given
        var clock = TestClockSource.aTestClock();
        var detector = new MonotonicDriftDetector(clock);

        detector.captureReference(PROFILE_ID, 0.0);

        // when small drift (400ms) within 500ms threshold
        clock.advanceMonoNanos(5_000_000_000L);
        clock.advanceWallMillis(5_400);

        // then
        assertThat(detector.isDriftExceeded(PROFILE_ID, MAX_DRIFT_500MS)).isFalse();
    }

    @Test
    void rejectsJustOverThreshold() {
        // given
        var clock = TestClockSource.aTestClock();
        var detector = new MonotonicDriftDetector(clock);

        detector.captureReference(PROFILE_ID, 0.0);

        // when drift = 501ms (just over 500ms threshold)
        clock.advanceMonoNanos(1_000_000_000L);
        clock.advanceWallMillis(1_501);

        // then
        assertThat(detector.isDriftExceeded(PROFILE_ID, MAX_DRIFT_500MS)).isTrue();
    }

    @Test
    void allowsAtExactThreshold() {
        // given — the check is `Math.abs(drift) > maxDrift`, so exactly-at-threshold must NOT trip
        var clock = TestClockSource.aTestClock();
        var detector = new MonotonicDriftDetector(clock);

        detector.captureReference(PROFILE_ID, 0.0);

        // when drift = 500ms (exactly at threshold)
        clock.advanceMonoNanos(1_000_000_000L);
        clock.advanceWallMillis(1_500);

        // then
        assertThat(detector.isDriftExceeded(PROFILE_ID, MAX_DRIFT_500MS)).isFalse();
    }

    @Test
    void returnsTrueWhenNoReferenceCaptured() {
        // given — detector created but no reference captured
        var detector = new MonotonicDriftDetector(TestClockSource.aTestClock());

        // then
        assertThat(detector.isDriftExceeded(PROFILE_ID, MAX_DRIFT_500MS)).isTrue();
    }

    @Test
    void returnsTrueAfterClearReference() {
        // given
        var detector = new MonotonicDriftDetector(TestClockSource.aTestClock());

        detector.captureReference(PROFILE_ID, 0.0);

        // when
        detector.clearReference(PROFILE_ID);

        // then
        assertThat(detector.isDriftExceeded(PROFILE_ID, MAX_DRIFT_500MS)).isTrue();
    }

    @Test
    void returnsTrueAfterRemove() {
        // given
        var detector = new MonotonicDriftDetector(TestClockSource.aTestClock());

        detector.captureReference(PROFILE_ID, 0.0);

        // when
        detector.remove(PROFILE_ID);

        // then — same fail-closed semantic as no-reference
        assertThat(detector.isDriftExceeded(PROFILE_ID, MAX_DRIFT_500MS)).isTrue();
    }

    @Test
    void compensatesForKnownNtpDriftAtCapture_measuredDriftPositiveAndAdvancesFaster() {
        // given — NTP reported 400ms drift at capture time
        var clock = TestClockSource.aTestClock();
        var detector = new MonotonicDriftDetector(clock);

        detector.captureReference(PROFILE_ID, 400.0); // positive drift = our wall clock is ahead

        // when wall drifts 200ms total, but 400ms was already known → effective drift = 600ms > 500ms
        clock.advanceMonoNanos(5_000_000_000L);
        clock.advanceWallMillis(5_200);

        // then
        assertThat(detector.isDriftExceeded(PROFILE_ID, MAX_DRIFT_500MS)).isTrue();
    }

    @Test
    void compensatesForKnownNtpDriftAtCapture_measuredDriftPositiveAndAdvancesSlower() {
        // given — NTP reported 400ms drift at capture time
        var clock = TestClockSource.aTestClock();
        var detector = new MonotonicDriftDetector(clock);

        detector.captureReference(PROFILE_ID, 400.0); // positive drift = our wall clock is ahead

        // when wall drifts -600ms total, but 400ms was already known → effective drift = |-200ms| < 500ms
        clock.advanceMonoNanos(5_000_000_000L);
        clock.advanceWallMillis(4_400);

        // then
        assertThat(detector.isDriftExceeded(PROFILE_ID, MAX_DRIFT_500MS)).isFalse();
    }

    @Test
    void compensatesForKnownNtpDriftAtCapture_measuredDriftNegativeAndAdvancesFaster() {
        // given — NTP reported 400ms drift at capture time
        var clock = TestClockSource.aTestClock();
        var detector = new MonotonicDriftDetector(clock);

        detector.captureReference(PROFILE_ID, -400.0); // negative drift = our wall clock is behind

        // when wall drifts 200ms total, but -400ms was already known → effective drift = 200ms < 500ms
        clock.advanceMonoNanos(5_000_000_000L);
        clock.advanceWallMillis(5_200);

        // then
        assertThat(detector.isDriftExceeded(PROFILE_ID, MAX_DRIFT_500MS)).isFalse();
    }

    @Test
    void compensatesForKnownNtpDriftAtCapture_measuredDriftNegativeAndAdvancesSlower() {
        // given — NTP reported 400ms drift at capture time
        var clock = TestClockSource.aTestClock();
        var detector = new MonotonicDriftDetector(clock);

        detector.captureReference(PROFILE_ID, -400.0); // negative drift = our wall clock is behind

        // when wall drifts -400ms total, but -400ms was already known → effective drift = |-800ms| > 500ms
        clock.advanceMonoNanos(5_000_000_000L);
        clock.advanceWallMillis(4_600);

        // then
        assertThat(detector.isDriftExceeded(PROFILE_ID, MAX_DRIFT_500MS)).isTrue();
    }
}
