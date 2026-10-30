package com.otilm.core.util.clocksource;

import java.time.Instant;
import org.springframework.stereotype.Component;

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
