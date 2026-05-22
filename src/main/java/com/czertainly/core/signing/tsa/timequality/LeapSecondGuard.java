package com.czertainly.core.signing.tsa.timequality;

import com.czertainly.api.model.messaging.timequality.LeapSecondWarning;
import com.czertainly.core.util.clocksource.ClockSource;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.time.Instant;
import java.time.LocalTime;
import java.time.ZoneOffset;

public class LeapSecondGuard {

    private static final Logger logger = LoggerFactory.getLogger(LeapSecondGuard.class);

    private static final LocalTime GUARD_WINDOW_START = LocalTime.of(23, 59, 58, 989_000_000);
    private static final LocalTime GUARD_WINDOW_END = LocalTime.of(0, 0, 1, 10_000_000);

    private final ClockSource clockSource;

    public LeapSecondGuard(ClockSource clockSource) {
        this.clockSource = clockSource;
    }

    public boolean isLeapSecondRisk(LeapSecondWarning leapSecondWarning) {
        if (leapSecondWarning == LeapSecondWarning.NONE) {
            return false;
        }

        if (isInGuardWindow(clockSource.wallTimeMillis())) {
            logger.warn("Leap second guard active (indicator={})", leapSecondWarning);
            return true;
        }

        return false;
    }

    static boolean isInGuardWindow(long wallTimeMillis) {
        var time = LocalTime.ofInstant(Instant.ofEpochMilli(wallTimeMillis), ZoneOffset.UTC);
        return time.isAfter(GUARD_WINDOW_START) || time.isBefore(GUARD_WINDOW_END);
    }
}
