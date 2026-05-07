package com.czertainly.core.util.serialnumber;

import com.czertainly.core.util.clocksource.ClockSource;
import com.czertainly.core.util.clocksource.SystemClockSource;
import com.czertainly.core.util.clocksource.TestClockSource;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;

import java.math.BigInteger;
import java.time.Instant;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicInteger;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class SnowflakeSerialNumberGeneratorTest {
    private static final long EPOCH = SnowflakeSerialNumberGenerator.EPOCH_MILLIS;
    private static final int TICK_MS = SnowflakeSerialNumberGenerator.TICK_MS;
    private static final int TICK_SHIFT = SnowflakeSerialNumberGenerator.TICK_SHIFT;
    private static final int INSTANCE_ID_SHIFT = SnowflakeSerialNumberGenerator.INSTANCE_ID_SHIFT;
    private static final int MAX_SEQUENCE = SnowflakeSerialNumberGenerator.MAX_SEQUENCE;
    private static final int MAX_INSTANCE_ID = SnowflakeSerialNumberGenerator.MAX_INSTANCE_ID;
    private static final int INSTANCE_ID = 42;

    @Test
    void shouldComposeCorrectBitLayout() {
        // given
        long startTime = EPOCH + 150;
        var clock = TestClockSource.ofWallTimeMillis(startTime);
        var generator = new SnowflakeSerialNumberGenerator(clock, INSTANCE_ID);

        // when
        BigInteger id = generator.generate();

        // then — layout: (tick << TICK_SHIFT) | (instanceId << INSTANCE_ID_SHIFT) | sequence
        long tick = id.shiftRight(TICK_SHIFT).longValue();
        int extractedInstanceId = id.shiftRight(INSTANCE_ID_SHIFT).and(BigInteger.valueOf(MAX_INSTANCE_ID)).intValue();
        int sequence = id.and(BigInteger.valueOf(MAX_SEQUENCE)).intValue();

        assertThat(id.bitLength()).isLessThanOrEqualTo(TICK_SHIFT + INSTANCE_ID_SHIFT);
        assertThat(tick).isEqualTo((startTime - EPOCH) / TICK_MS);
        assertThat(extractedInstanceId).isEqualTo(INSTANCE_ID);
        assertThat(sequence).isZero();
    }

    @Test
    void shouldIncrementSequenceWithinSameTick() {
        // given
        var clock = TestClockSource.ofWallTimeMillis(EPOCH + 100);
        var generator = new SnowflakeSerialNumberGenerator(clock, INSTANCE_ID);

        // when
        BigInteger first = generator.generate();
        BigInteger second = generator.generate();
        BigInteger third = generator.generate();

        // then
        assertThat(first.and(BigInteger.valueOf(MAX_SEQUENCE)).intValue()).isZero();
        assertThat(second.and(BigInteger.valueOf(MAX_SEQUENCE)).intValue()).isEqualTo(1);
        assertThat(third.and(BigInteger.valueOf(MAX_SEQUENCE)).intValue()).isEqualTo(2);
    }

    @Test
    void shouldResetSequenceOnNewTick() {
        // given
        long startTime = EPOCH + 100;
        var clock = TestClockSource.ofWallTimeMillis(startTime);
        var generator = new SnowflakeSerialNumberGenerator(clock, INSTANCE_ID);
        generator.generate(); // sequence = 0
        generator.generate(); // sequence = 1

        // when — advance to next tick
        clock.advanceWallMillis(10);
        BigInteger id = generator.generate();

        // then
        assertThat(id.and(BigInteger.valueOf(MAX_SEQUENCE)).intValue()).isZero();
        assertThat(id.shiftRight(TICK_SHIFT).longValue()).isEqualTo((startTime + TICK_MS - EPOCH) / TICK_MS);
    }

    @Test
    void shouldSpinWaitOnSequenceOverflow() {
        // given — clock stays at same tick for 256 calls, then takes 5 extra
        // polls before advancing to the next tick (simulating actual spin-wait)
        var pollCount = new AtomicInteger();
        long startTime = EPOCH + 100;
        int spinIterationsBeforeAdvance = 5;
        ClockSource advancingClock = new ClockSource() {
            @Override
            public long wallTimeMillis() {
                int count = pollCount.incrementAndGet();
                // First 256 calls: one per generate(), all at the same tick.
                // After overflow, the spin-wait loop polls repeatedly.
                // Simulate several polls still at the old tick before advancing.
                if (count > MAX_SEQUENCE + 1 + spinIterationsBeforeAdvance) {
                    return startTime + TICK_MS; // next tick
                }
                return startTime;
            }

            @Override
            public long monotonicNanos() {
                return 0;
            }

            @Override
            public Instant wallTimeInstant() {
                return Instant.ofEpochMilli(wallTimeMillis());
            }
        };
        var generator = new SnowflakeSerialNumberGenerator(advancingClock, INSTANCE_ID);

        // when — generate MAX_SEQUENCE+2 IDs (0–MAX_SEQUENCE fill the sequence, last one triggers spin-wait)
        BigInteger[] ids = new BigInteger[MAX_SEQUENCE + 2];
        for (int i = 0; i < MAX_SEQUENCE + 2; i++) {
            ids[i] = generator.generate();
        }

        // then — the spin-wait loop polled multiple times before the tick advanced
        long expectedTick = (startTime - EPOCH) / 10;
        assertThat(pollCount.get()).isGreaterThan(MAX_SEQUENCE + 1 + spinIterationsBeforeAdvance);
        // first MAX_SEQUENCE+1 IDs at the initial tick
        assertThat(ids[0].shiftRight(TICK_SHIFT).longValue()).isEqualTo(expectedTick);
        assertThat(ids[MAX_SEQUENCE].and(BigInteger.valueOf(MAX_SEQUENCE)).intValue()).isEqualTo(MAX_SEQUENCE);
        // last ID at next tick with sequence 0
        assertThat(ids[MAX_SEQUENCE + 1].shiftRight(TICK_SHIFT).longValue()).isEqualTo(expectedTick + 1);
        assertThat(ids[MAX_SEQUENCE + 1].and(BigInteger.valueOf(MAX_SEQUENCE)).intValue()).isZero();
    }

    @Test
    @Timeout(2)
    void shouldWaitOnSmallBackwardClockJump() {
        // given
        long startTime = EPOCH + 200;
        var clock = TestClockSource.ofWallTimeMillis(startTime);
        var generator = new SnowflakeSerialNumberGenerator(clock, INSTANCE_ID);
        generator.generate(); // establishes lastTick = 20

        // when — clock jumps backward by 50ms (within tolerance of 100ms), then recovers
        clock.wallTimeMillis(startTime - 50);
        Thread.startVirtualThread(() -> {
            try {
                Thread.sleep(100);
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
            }
            clock.wallTimeMillis(startTime);
        });
        BigInteger id = generator.generate();

        // then — generated at the recovered tick (200 / 10 = 20)
        assertThat(id.shiftRight(TICK_SHIFT).longValue()).isEqualTo((startTime - EPOCH) / TICK_MS);
    }

    @Test
    void shouldThrowWhenClockIsBeforeEpoch() {
        // given
        var clock = TestClockSource.ofWallTimeMillis(EPOCH - 1);
        var generator = new SnowflakeSerialNumberGenerator(clock, INSTANCE_ID);

        // then
        assertThatThrownBy(generator::generate)
                .isInstanceOf(ClockDriftException.class)
                .hasMessageContaining("before epoch");
    }

    @Test
    @Timeout(2)
    void shouldThrowOnLargeBackwardClockJump() {
        // given
        long startTime = EPOCH + 2000;
        var clock = TestClockSource.ofWallTimeMillis(startTime);
        var generator = new SnowflakeSerialNumberGenerator(clock, INSTANCE_ID);
        generator.generate();

        // when — clock jumps backward by 110ms (exceeds tolerance of 100ms)
        clock.wallTimeMillis(startTime - 110);

        // then
        assertThatThrownBy(generator::generate)
                .isInstanceOf(ClockDriftException.class)
                .hasMessageContaining("110 ms");
    }

    @Test
    void shouldThrowOnTimestampOverflow() {
        // given — set clock past the 40-bit tick maximum
        long overflowMillis = EPOCH + (SnowflakeSerialNumberGenerator.MAX_TICK + 1) * SnowflakeSerialNumberGenerator.TICK_MS;
        var clock = TestClockSource.ofWallTimeMillis(overflowMillis);
        var generator = new SnowflakeSerialNumberGenerator(clock, INSTANCE_ID);

        // then
        assertThatThrownBy(generator::generate)
                .isInstanceOf(SerialNumberGenerationException.class)
                .hasMessageContaining("overflow");
    }

    @Test
    void shouldGenerateMonotonicallyIncreasingIds() {
        // given
        var clock = TestClockSource.ofWallTimeMillis(EPOCH + 100);
        var generator = new SnowflakeSerialNumberGenerator(clock, INSTANCE_ID);

        // when
        BigInteger previous = generator.generate();
        for (int i = 0; i < 1000; i++) {
            if (i % 10 == 0) {
                clock.advanceWallMillis(10);
            }
            BigInteger current = generator.generate();

            // then
            assertThat(current).isGreaterThan(previous);
            previous = current;
        }
    }

    @Test
    void shouldGenerateDistinctIdsFromConcurrentVirtualThreads() throws InterruptedException {
        // given
        var clock = new SystemClockSource();
        var generator = new SnowflakeSerialNumberGenerator(clock, INSTANCE_ID);
        Set<BigInteger> ids = ConcurrentHashMap.newKeySet(); // This is a set = will only contain unique IDs, no duplicates
        int threadCount = 100;
        int idsPerThread = 100;

        // when
        Thread[] threads = new Thread[threadCount];
        for (int t = 0; t < threadCount; t++) {
            threads[t] = Thread.startVirtualThread(() -> {
                for (int i = 0; i < idsPerThread; i++) {
                    ids.add(generator.generate());
                }
            });
        }
        for (Thread thread : threads) {
            thread.join();
        }

        // then - a SET should contain all generated IDs
        assertThat(ids).hasSize(threadCount * idsPerThread);
    }
}