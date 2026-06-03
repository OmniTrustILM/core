package com.czertainly.core.signing.record;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;

import java.util.concurrent.atomic.AtomicInteger;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.fail;
import static org.mockito.ArgumentMatchers.anyLong;
import static org.mockito.Mockito.doAnswer;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.timeout;
import static org.mockito.Mockito.verify;

/**
 * Tests the thread lifecycle of {@link SigningRecordBestEffortFlusher}: {@code start()} must drive the writer
 * repeatedly with the configured interval, and {@code stop()} must halt the loop. The writer itself is mocked —
 * all queue/DB logic lives in {@link BestEffortSigningRecordWriter} and is covered by its own tests.
 * <p>
 * These are inherently timing-based (a real background thread). The mock emulates the real writer by blocking
 * for the poll timeout it is handed, so the loop paces itself instead of busy-spinning.
 */
class SigningRecordBestEffortFlusherTest {

    private SigningRecordBestEffortFlusher flusher;

    @AfterEach
    void tearDown() {
        if (flusher != null) {
            flusher.stop();
        }
    }

    @Test
    void start_drivesWriterRepeatedlyWithConfiguredInterval() throws Exception {
        // given
        var flushIntervalMs = 50L;
        var writer = mock(BestEffortSigningRecordWriter.class);
        blockForPollTimeout(writer);
        flusher = new SigningRecordBestEffortFlusher(writer, flushIntervalMs);

        // when
        flusher.start();

        // then
        var atLeastTwoIterations = timeout(2_000L).atLeast(2);
        verify(writer, atLeastTwoIterations).drainAndPersistBatch(flushIntervalMs);
    }

    @Test
    void stop_haltsTheLoop() throws Exception {
        // given
        var flushIntervalMs = 20L;
        var invocations = new AtomicInteger();
        var writer = mock(BestEffortSigningRecordWriter.class);
        countAndBlockForPollTimeout(writer, invocations);
        flusher = new SigningRecordBestEffortFlusher(writer, flushIntervalMs);
        flusher.start();
        awaitLoopRunning(invocations);

        // when
        flusher.stop();

        // then — once the loop observes the stop it makes no further calls
        var quietPeriodMs = 200L; // many flush intervals: a live loop would keep incrementing
        Thread.sleep(quietPeriodMs); // let any in-flight iteration finish before snapshotting
        var countAfterStop = invocations.get();
        Thread.sleep(quietPeriodMs);
        assertEquals(countAfterStop, invocations.get(), "flusher kept driving the writer after stop()");
    }

    /**
     * Emulates the real writer blocking up to the poll timeout it is handed, so the loop paces itself.
     */
    private void blockForPollTimeout(BestEffortSigningRecordWriter writer) {
        try {
            doAnswer(invocation -> {
                Thread.sleep(invocation.<Long>getArgument(0));
                return null;
            }).when(writer).drainAndPersistBatch(anyLong());
        } catch (InterruptedException e) {
            throw new IllegalStateException(e); // stubbing only — never thrown here
        }
    }

    private void countAndBlockForPollTimeout(BestEffortSigningRecordWriter writer, AtomicInteger invocations) {
        try {
            doAnswer(invocation -> {
                invocations.incrementAndGet();
                Thread.sleep(invocation.<Long>getArgument(0));
                return null;
            }).when(writer).drainAndPersistBatch(anyLong());
        } catch (InterruptedException e) {
            throw new IllegalStateException(e); // stubbing only — never thrown here
        }
    }

    private void awaitLoopRunning(AtomicInteger invocations) throws InterruptedException {
        var deadlineNanos = System.nanoTime() + 2_000_000_000L; // 2s
        while (invocations.get() < 1) {
            if (System.nanoTime() > deadlineNanos) {
                fail("flusher never drove the writer after start()");
            }
            Thread.sleep(5L);
        }
    }
}
