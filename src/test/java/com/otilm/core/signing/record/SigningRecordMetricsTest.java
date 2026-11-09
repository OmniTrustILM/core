package com.otilm.core.signing.record;

import io.micrometer.core.instrument.MeterRegistry;
import io.micrometer.core.instrument.Timer;
import io.micrometer.core.instrument.simple.SimpleMeterRegistry;
import java.util.UUID;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.function.Executable;

import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

/**
 * Unit test for {@link SigningRecordMetrics#timed(String, int, java.util.function.Supplier)} over a
 * {@link SimpleMeterRegistry}. The helper wraps the action in a {@code finally}-stopped timer sample, so duration is
 * recorded under the mode's {@code signing_record.write.duration} timer whether the action succeeds or throws — and a
 * thrown action propagates unchanged. The counters incremented inside the action ({@code persist},
 * {@code persist.failed}) are pinned against each strategy in their own unit tests.
 */
class SigningRecordMetricsTest {

    private static final String SUCCESSFUL_WRITE = "successful write";

    private MeterRegistry registry;
    private SigningRecordMetrics metrics;

    @BeforeEach
    void setUp() {
        registry = new SimpleMeterRegistry();
        metrics = new SigningRecordMetrics(registry);
    }

    @Test
    void timed_recordsOneSampleUnderTheModeTimer_whenActionSucceeds() {
        // given
        var mode = "IMMEDIATE";

        // when
        metrics.timed(mode, 1, () -> SUCCESSFUL_WRITE);

        // then
        assertEquals(1, durationSampleCount(mode));
    }

    @Test
    void timed_tagsTheTimerByMode_soModesAreMeasuredIndependently() {
        // when
        metrics.timed("IMMEDIATE", 1, () -> SUCCESSFUL_WRITE);
        metrics.timed("DEFERRED_DURABLE", 1, () -> SUCCESSFUL_WRITE);

        // then
        assertEquals(1, durationSampleCount("IMMEDIATE"));
        assertEquals(1, durationSampleCount("DEFERRED_DURABLE"));
    }

    @Test
    void timed_stillRecordsTheSampleAndPropagates_whenActionThrows() {
        // given
        var mode = "IMMEDIATE";
        var failure = new RuntimeException("db down");

        // when
        Executable timed = () -> metrics.timed(mode, 1, () -> {
            throw failure;
        });

        // then
        var thrown = assertThrows(RuntimeException.class, timed);
        assertEquals(failure, thrown); // original exception propagates unwrapped
        assertEquals(1, durationSampleCount(mode)); // finally records the failed write too
    }

    @Test
    void returnsTheActionResult_whenActionSucceeds() {
        // given
        var recordUuid = UUID.randomUUID();

        // when
        UUID returned = metrics.timed("IMMEDIATE", 1, () -> recordUuid);

        // then
        assertThat(returned).isEqualTo(recordUuid);
    }

    private long durationSampleCount(String mode) {
        Timer timer = registry.find("signing_record.write.duration").tag("mode", mode).tag("batch", "false").timer();
        return timer == null ? 0L : timer.count();
    }
}
