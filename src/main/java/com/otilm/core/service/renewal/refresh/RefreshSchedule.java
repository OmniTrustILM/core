package com.otilm.core.service.renewal.refresh;

import java.time.Duration;
import java.time.Instant;
import java.util.List;
import java.util.function.DoubleSupplier;

/** Computes when the renewal information of a certificate is asked for again. */
public final class RefreshSchedule {

    private static final double JITTER = 0.1;

    private RefreshSchedule() {
    }

    /**
     * The next refresh after an answer: the item's retry-after, else the response's, else the default interval, clamped
     * to the configured bounds and spread by up to 10 % either way.
     *
     * @param random a source of numbers in [0, 1)
     */
    public static Instant next(Instant now, Integer itemRetryAfter, Integer responseRetryAfter,
            RenewalInfoSettings settings, DoubleSupplier random) {
        int seconds = settings.defaultIntervalSeconds();
        if (itemRetryAfter != null) {
            seconds = itemRetryAfter;
        } else if (responseRetryAfter != null) {
            seconds = responseRetryAfter;
        }
        int clamped = Math.clamp(seconds, settings.minIntervalSeconds(), settings.maxIntervalSeconds());
        double factor = 1 + (random.getAsDouble() * 2 - 1) * JITTER;
        return now.plusMillis(Math.round(clamped * 1000 * factor));
    }

    /**
     * The next refresh after a failure. {@code attempt} counts the failures including this one, so 1 is the first delay
     * of the ramp; beyond its end the last delay repeats.
     */
    public static Instant backoff(Instant now, int attempt, List<Duration> ramp) {
        int index = Math.clamp(attempt - 1, 0, ramp.size() - 1);
        return now.plus(ramp.get(index));
    }
}
