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
        referencePairs.computeIfAbsent(id, ignored -> new AtomicReference<>())
                .set(new TimeReferencePair(clockSource.wallTimeMillis(), clockSource.monotonicNanos(), measuredDriftMs));
    }

    public void clearReference(UUID id) {
        var ref = referencePairs.get(id);
        if (ref != null) {
            ref.set(null);
        }
    }

    public void remove(UUID id) {
        referencePairs.remove(id);
    }

    /**
     * Returns whether the wall clock has drifted beyond {@code maxClockDrift} since the last
     * reference was captured for this id. Fails closed: when no reference has been captured
     * (or after {@link #clearReference} / {@link #remove}), returns {@code true} so callers
     * treat the configuration as DEGRADED until an OK result arms the detector via
     * {@link #captureReference}.
     */
    public boolean isDriftExceeded(UUID id, Duration maxClockDrift) {
        var ref = referencePairs.get(id);
        var pair = ref != null ? ref.get() : null;
        if (pair == null) {
            return true;
        }

        long elapsedNanos = clockSource.monotonicNanos() - pair.monotonicNanos();
        long expectedWallMillis = pair.wallTimeMillis() + (elapsedNanos / 1_000_000);
        long actualWallMillis = clockSource.wallTimeMillis();
        long driftMillis = (actualWallMillis - expectedWallMillis) + Math.round(pair.measuredDriftMs());
        long maxDriftMillis = maxClockDrift.toMillis();

        if (Math.abs(driftMillis) > maxDriftMillis) {
            logger.warn("Clock drift detected: {}ms (max allowed: {}ms)", driftMillis, maxDriftMillis);
            return true;
        }

        return false;
    }

}
