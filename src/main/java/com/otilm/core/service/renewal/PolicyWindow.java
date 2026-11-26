package com.otilm.core.service.renewal;

import java.time.Duration;
import java.time.Instant;
import java.util.Optional;

/**
 * The renewal window an RA profile policy gives a certificate: the given percentages of its lifetime, counted from its
 * start and truncated to the millisecond, which is also how the bulk recomputation in SQL places it.
 */
public final class PolicyWindow {

    private static final int PERCENT = 100;

    private PolicyWindow() {
    }

    public static Optional<Window> compute(Instant notBefore, Instant notAfter, int startPercent, int endPercent) {
        if (notBefore == null || notAfter == null || !notAfter.isAfter(notBefore)) {
            return Optional.empty();
        }
        long lifetimeMillis = Duration.between(notBefore, notAfter).toMillis();
        Instant start = notBefore.plusMillis(lifetimeMillis * startPercent / PERCENT);
        Instant end = notBefore.plusMillis(lifetimeMillis * endPercent / PERCENT);
        if (!end.isAfter(start)) {
            return Optional.empty();
        }
        return Optional.of(new Window(start, end));
    }
}
