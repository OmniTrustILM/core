package com.otilm.core.signing.tsa.timequality;

import com.otilm.api.model.messaging.timequality.LeapSecondWarning;
import com.otilm.core.util.clocksource.TestClockSource;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

class LeapSecondGuardTest {
    @Test
    void rejects_whenInGuardWindowAndLeapIndicatorPositive() {
        // given — wall clock at 23:59:59 UTC, leap second indicator POSITIVE
        var guard = new LeapSecondGuard(TestClockSource.ofWallTime("2026-06-30T23:59:59Z"));

        // when
        var result = guard.isLeapSecondRisk(LeapSecondWarning.POSITIVE);

        // then
        assertThat(result).isTrue();
    }

    @Test
    void rejects_whenInGuardWindowAndLeapIndicatorNegative() {
        // given — wall clock at 00:00:00.500 UTC, leap indicator NEGATIVE
        var guard = new LeapSecondGuard(TestClockSource.ofWallTime("2026-07-01T00:00:00.500Z"));

        // when
        var result = guard.isLeapSecondRisk(LeapSecondWarning.NEGATIVE);

        // then
        assertThat(result).isTrue();
    }

    @Test
    void allows_whenOutsideGuardWindowAndLeapIndicatorPositive() {
        // given — wall clock at 23:59:50 UTC, outside the guard window
        var guard = new LeapSecondGuard(TestClockSource.ofWallTime("2026-06-30T23:59:50Z"));

        // when
        var result = guard.isLeapSecondRisk(LeapSecondWarning.POSITIVE);

        // then
        assertThat(result).isFalse();
    }

    @Test
    void allows_whenLeapIndicatorNone() {
        // given — in guard window time but leap indicator NONE → no guard needed
        var guard = new LeapSecondGuard(TestClockSource.ofWallTime("2026-06-30T23:59:59Z"));

        // when
        var result = guard.isLeapSecondRisk(LeapSecondWarning.NONE);

        // then
        assertThat(result).isFalse();
    }

    @Test
    void allows_whenExactlyAtGuardWindowStartBoundary() {
        // given — wall clock at exactly 23:59:58.989 (start of guard window, exclusive)
        var guard = new LeapSecondGuard(TestClockSource.ofWallTime("2026-06-30T23:59:58.989Z"));

        // when — isAfter(23:59:58.989) = false, so just outside
        var result = guard.isLeapSecondRisk(LeapSecondWarning.POSITIVE);

        // then
        assertThat(result).isFalse();
    }

    @Test
    void allows_whenExactlyAtGuardWindowEndBoundary() {
        // given — wall clock at exactly 00:00:01.010 (end of guard window, exclusive)
        var guard = new LeapSecondGuard(TestClockSource.ofWallTime("2026-07-01T00:00:01.010Z"));

        // when — isBefore(00:00:01.010) = false, so just outside
        var result = guard.isLeapSecondRisk(LeapSecondWarning.POSITIVE);

        // then
        assertThat(result).isFalse();
    }
}
