package com.czertainly.core.util.serialnumber;


import com.czertainly.core.util.clocksource.ClockSource;
import lombok.extern.slf4j.Slf4j;

import java.math.BigInteger;
import java.time.Instant;
import java.util.concurrent.locks.ReentrantLock;


/**
 * Snowflake/Sonyflake-style 64-bit serial number generator that produces unique identifiers without
 * coordination between instances.
 *
 * <h2>Bit layout</h2>
 * <pre>
 * | Segment                  | Bits | Description                                                      |
 * |--------------------------|------|------------------------------------------------------------------|
 * | Timestamp (10 ms ticks)  |   40 | Ticks since custom epoch 2026-02-01T00:00:00Z; valid until ~2374 |
 * | Instance ID              |   16 | Lower 16 bits of the container's private IPv4, or explicit override |
 * | Sequence counter         |    8 | Per-tick counter; up to 256 serials per 10 ms window             |
 * | Total                    |   64 | Hex-aligned; within the 160-bit RFC 3161 limit                   |
 * </pre>
 *
 * Uniqueness is structural: the timestamp separates tokens across time, the instance ID separates
 * tokens across replicas, and the sequence counter separates tokens within the same tick on the same
 * instance. No locking, no network round-trips, no shared state.
 *
 * <p><b>Throughput:</b> up to 25,600 tokens/sec per instance (256 × 100 ticks/sec).
 *
 * <h2>Overflow &amp; clock-regression protection</h2>
 * <ul>
 *   <li><b>Sequence overflow</b> — when the 8-bit counter exhausts within a single 10 ms tick,
 *       waits for the next tick (max 10 ms wait; negligible relative to SignServer round-trip).</li>
 *   <li><b>Timestamp overflow</b> — rejects requests if the 40-bit tick field would overflow.</li>
 *   <li><b>Backward clock jump</b> — if the current time is behind the last issued tick, waits for
 *       the clock to catch up. Rejects if the jump exceeds 100 ms. No serial numbers are issued
 *       during the wait period.</li>
 * </ul>
 *
 * @see InstanceIdResolver
 */
@Slf4j
final class SnowflakeSerialNumberGenerator implements SerialNumberGenerator {

    /** Ticks are counted from this point, keeping values small and the 40-bit field valid until ~2374. */
    static final long EPOCH_MILLIS = Instant.parse("2026-02-01T00:00:00Z").toEpochMilli();
    /** Duration of one tick in milliseconds; determines time resolution and throughput ceiling. */
    static final int TICK_MS = 10;

    /** Number of bits allocated to the timestamp field. */
    static final int TICK_BITS = 40;
    /** Number of bits allocated to the instance ID field. */
    static final int INSTANCE_ID_BITS = 16;
    /** Number of bits allocated to the per-tick sequence counter field. */
    static final int SEQUENCE_BITS = 8;

    /** Instance ID occupies bits 8–23; shift past the 8-bit sequence field to reach it. */
    static final int INSTANCE_ID_SHIFT = SEQUENCE_BITS;
    /** Tick occupies bits 24–63; shift past both the sequence and instance ID fields to reach it. */
    static final int TICK_SHIFT = SEQUENCE_BITS + INSTANCE_ID_BITS;

    /** Maximum tick value before the 40-bit timestamp field overflows; valid until ~2374. */
    static final long MAX_TICK = (1L << TICK_BITS) - 1;
    /** Maximum instance ID value (65535); also used as the bitmask to extract the instance ID field. */
    static final int MAX_INSTANCE_ID = (1 << INSTANCE_ID_BITS) - 1;
    /** Maximum sequence value (255); also used as the bitmask to extract the sequence field. */
    static final int MAX_SEQUENCE = (1 << SEQUENCE_BITS) - 1;

    private final ClockSource clockSource;
    private final int instanceId;
    private final long maxClockDriftMs;
    private final ReentrantLock lock = new ReentrantLock();

    private long lastTick = -1;
    private int sequence = 0;

    SnowflakeSerialNumberGenerator(ClockSource clockSource, int instanceId) {
        if (instanceId < 0 || instanceId > MAX_INSTANCE_ID) {
            throw new IllegalArgumentException("instanceId must be 0–65535, got: " + instanceId);
        }
        this.clockSource = clockSource;
        this.instanceId = instanceId;
        this.maxClockDriftMs = 100;
    }

    @Override
    public BigInteger generate() {
        lock.lock();
        try {
            long currentTick = computeTick();

            if (currentTick < lastTick) {
                currentTick = waitForClockCatchUp(currentTick);
            }

            if (currentTick == lastTick) {
                sequence++;
                if (sequence > MAX_SEQUENCE) {
                    currentTick = waitForNextTick(currentTick);
                    sequence = 0;
                }
            } else {
                sequence = 0;
            }

            lastTick = currentTick;
            return BigInteger.valueOf(currentTick)
                    .shiftLeft(TICK_SHIFT)
                    .or(BigInteger.valueOf(instanceId).shiftLeft(INSTANCE_ID_SHIFT))
                    .or(BigInteger.valueOf(sequence));
        } finally {
            lock.unlock();
        }
    }

    private long computeTick() {
        long millis = clockSource.wallTimeMillis();
        if (millis < EPOCH_MILLIS) {
            throw new ClockDriftException("System clock is before epoch: " + Instant.ofEpochMilli(millis));
        }
        long tick = (millis - EPOCH_MILLIS) / TICK_MS;
        if (tick > MAX_TICK) {
            throw new SerialNumberGenerationException("Timestamp overflow: tick " + tick + " exceeds 40-bit maximum");
        }
        return tick;
    }

    private long waitForClockCatchUp(long currentTick) {
        long driftMs = (lastTick - currentTick) * TICK_MS;
        if (driftMs > maxClockDriftMs) {
            throw new ClockDriftException(
                    "Clock moved backward by " + driftMs + " ms, exceeding max drift of " + maxClockDriftMs + " ms");
        }

        log.warn("Clock moved backward by {} ms — waiting for clock to catch up before issuing next serial number", driftMs);
        while (currentTick < lastTick) {
            if (Thread.currentThread().isInterrupted()) {
                Thread.currentThread().interrupt();
                throw new SerialNumberGenerationException("Interrupted while waiting for clock to catch up");
            }
            Thread.onSpinWait();
            currentTick = computeTick();
        }
        return currentTick;
    }

    private long waitForNextTick(long currentTick) {
        log.warn("Sequence exhausted for tick {} — waiting for next tick; consider reducing request rate", currentTick);
        long nextTick = currentTick + 1;
        while (computeTick() < nextTick) {
            if (Thread.currentThread().isInterrupted()) {
                Thread.currentThread().interrupt();
                throw new SerialNumberGenerationException("Interrupted while waiting for next tick");
            }
            Thread.onSpinWait();
        }
        return nextTick;
    }
}
