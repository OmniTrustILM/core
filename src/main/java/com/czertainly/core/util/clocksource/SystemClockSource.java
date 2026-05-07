package com.czertainly.core.util.clocksource;

import org.springframework.stereotype.Component;

import java.time.Instant;

@Component
public class SystemClockSource implements ClockSource {

    @Override
    public long wallTimeMillis() {
        return System.currentTimeMillis();
    }

    @Override
    public long monotonicNanos() {
        return System.nanoTime();
    }

    @Override
    public Instant wallTimeInstant() {
        return Instant.now();
    }
}
