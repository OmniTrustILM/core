package com.otilm.core.util.clocksource;

import java.time.Instant;

public interface ClockSource {

    long wallTimeMillis();

    long monotonicNanos();

    Instant wallTimeInstant();
}
