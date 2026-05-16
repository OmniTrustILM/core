package com.czertainly.core.signing.tsa.timequality;

import com.czertainly.core.util.clocksource.ClockSource;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.time.Duration;
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicReference;

public class MonotonicDriftDetector {

    private static final Logger logger = LoggerFactory.getLogger(MonotonicDriftDetector.class);

    private final ClockSource clockSource;
    private final ConcurrentHashMap<UUID, AtomicReference<TimeReferencePair>> referencePairs = new ConcurrentHashMap<>();

    public MonotonicDriftDetector(ClockSource clockSource) {
        this.clockSource = clockSource;
    }

    public void captureReference(UUID id, double measuredDriftMs) {
        refFor(id).set(
                new TimeReferencePair(clockSource.wallTimeMillis(), clockSource.monotonicNanos(), measuredDriftMs));
    }

    public void clearReference(UUID id) {
        refFor(id).set(null);
    }

    public boolean isDriftExceeded(UUID id, Duration maxClockDrift) {
        var pair = refFor(id).get();
        if (pair == null) {
            return true;
        }

        long elapsedNanos = clockSource.monotonicNanos() - pair.monotonicNanos();
        long expectedWallMillis = pair.wallTimeMillis() + (elapsedNanos / 1_000_000);
        long actualWallMillis = clockSource.wallTimeMillis();
        long driftMillis = (actualWallMillis - expectedWallMillis) + (long) pair.measuredDriftMs();
        long maxDriftMillis = maxClockDrift.toMillis();

        if (Math.abs(driftMillis) > maxDriftMillis) {
            logger.warn("Clock drift detected: {}ms (max allowed: {}ms)", driftMillis, maxDriftMillis);
            return true;
        }

        return false;
    }

    private AtomicReference<TimeReferencePair> refFor(UUID id) {
        return referencePairs.computeIfAbsent(id, ignored -> new AtomicReference<>());
    }
}
