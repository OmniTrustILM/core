package com.otilm.core.oid;

import java.time.Duration;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Pure unit coverage for the warning-repeat policy — no Spring context, no clock manipulation: an interval of zero
 * stands in for "the repeat window has elapsed", and a long interval for "it has not".
 */
class PersistentWarningThrottleTest {

    private static final Duration NEVER_ELAPSES = Duration.ofDays(1);
    private static final Duration ALWAYS_ELAPSED = Duration.ZERO;

    @Test
    void warnsWhenTheConditionFirstAppears() {
        PersistentWarningThrottle throttle = new PersistentWarningThrottle(NEVER_ELAPSES);

        assertThat(throttle.shouldWarn(true, true)).isTrue();
    }

    @Test
    void staysQuietWhileNothingChangedAndTheWindowHasNotElapsed() {
        PersistentWarningThrottle throttle = new PersistentWarningThrottle(NEVER_ELAPSES);
        throttle.shouldWarn(true, true);

        // The registry rebuilds every 30s by default; this is the case that would otherwise flood.
        assertThat(throttle.shouldWarn(false, true)).isFalse();
        assertThat(throttle.shouldWarn(false, true)).isFalse();
    }

    @Test
    void warnsAgainOnceTheWindowElapsesEvenWithoutAChange() {
        // The point of the policy: a lasting condition stays visible in recent log output, so its
        // absence means resolved rather than already-reported.
        PersistentWarningThrottle throttle = new PersistentWarningThrottle(ALWAYS_ELAPSED);
        throttle.shouldWarn(true, true);

        assertThat(throttle.shouldWarn(false, true)).isTrue();
    }

    @Test
    void warnsOnAChangeEvenInsideTheWindow() {
        // A different set of conflicting tokens is new information, not a repeat.
        PersistentWarningThrottle throttle = new PersistentWarningThrottle(NEVER_ELAPSES);
        throttle.shouldWarn(true, true);

        assertThat(throttle.shouldWarn(true, true)).isTrue();
    }

    @Test
    void staysQuietWhenThereIsNothingToReport() {
        PersistentWarningThrottle throttle = new PersistentWarningThrottle(ALWAYS_ELAPSED);

        assertThat(throttle.shouldWarn(true, false)).isFalse();
        assertThat(throttle.shouldWarn(false, false)).isFalse();
    }

    @Test
    void reportsARecurrenceImmediatelyRatherThanWaitingOutTheOldWindow() {
        // given — a condition that appeared, then resolved
        PersistentWarningThrottle throttle = new PersistentWarningThrottle(NEVER_ELAPSES);
        throttle.shouldWarn(true, true);
        throttle.shouldWarn(true, false);

        // when / then — the same condition returning must not be muted by the earlier occurrence
        assertThat(throttle.shouldWarn(false, true)).isTrue();
    }
}
