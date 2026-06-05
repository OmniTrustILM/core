package com.czertainly.core.service.writer.signingrecord;

import com.czertainly.core.dao.entity.signing.SigningRecord;
import com.czertainly.core.dao.repository.signing.SigningRecordRepository;
import com.czertainly.core.mapper.signing.SigningRecordInputMapper;
import com.czertainly.core.signing.record.*;
import io.micrometer.core.instrument.MeterRegistry;
import io.micrometer.core.instrument.Timer;
import io.micrometer.core.instrument.simple.SimpleMeterRegistry;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.function.Executable;
import org.springframework.transaction.PlatformTransactionManager;

import java.util.List;

import static com.czertainly.core.model.signing.SigningProfileModelBuilder.aSigningProfile;
import static com.czertainly.core.model.signing.SigningRecordPolicyModelBuilder.notRecording;
import static com.czertainly.core.model.signing.SigningRecordPolicyModelBuilder.recordingEverything;
import static com.czertainly.core.signing.record.SigningRecordInputBuilder.aSigningRecordInput;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyLong;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;

/**
 * Pure unit test for {@link BestEffortSigningRecordWriter} over a mocked {@link BestEffortSigningRecordQueue}.
 * The writer's job is narrow: skip empty policies, map + count, dispatch to the right backpressure method,
 * and persist a polled batch in one transaction (counting losses without propagating). Queue mechanics —
 * eviction, blocking, batching — are covered against the real queue in {@link BestEffortSigningRecordQueueTest}.
 */
class BestEffortSigningRecordWriterUnitTest {

    private static final int MAX_BATCH_SIZE = 200;

    private MeterRegistry registry;
    private SigningRecordMetrics metrics;
    private SigningRecordRepository repository;
    private PlatformTransactionManager txm;
    private BestEffortSigningRecordQueue queue;

    @BeforeEach
    void setUp() {
        registry = new SimpleMeterRegistry();
        metrics = new SigningRecordMetrics(registry);
        repository = mock(SigningRecordRepository.class);
        txm = mock(PlatformTransactionManager.class);
        queue = mock(BestEffortSigningRecordQueue.class);
    }

    @Test
    void record_skipsAndCounts_whenPolicyRecordsNothing() {
        // given
        var notRecordingInput = aSigningRecordInput()
                .signingProfile(
                        aSigningProfile()
                                .recordPolicy(
                                        notRecording()
                                                .build())
                                .build())
                .build();
        var writer = createWriter(BestEffortBackpressurePolicy.DROP_OLDEST);

        // when
        writer.record(notRecordingInput);

        // then
        assertEquals(1, skippedCounter());
        verifyNoInteractions(queue, repository);
    }

    @Test
    void record_enqueuesDroppingAndCountsQueued_underDropOldestPolicy() throws Exception {
        // given
        var writer = createWriter(BestEffortBackpressurePolicy.DROP_OLDEST);

        // when
        writer.record(recordableInput());

        // then
        assertEquals(1, queuedCounter("BEST_EFFORT"));
        assertEquals(1, durationSampleCount("BEST_EFFORT"));
        verify(queue).enqueueDropping(any(SigningRecord.class));
        verify(queue, never()).enqueueBlocking(any());
    }

    @Test
    void record_recordsEvictedDropMetric_whenDropOldestEvicts() {
        // given
        var evictedByQueue = 2;
        when(queue.enqueueDropping(any())).thenReturn(evictedByQueue);
        var writer = createWriter(BestEffortBackpressurePolicy.DROP_OLDEST);

        // when
        writer.record(recordableInput());

        // then
        assertEquals(evictedByQueue, droppedCounter("evicted_oldest"));
    }

    @Test
    void record_enqueuesBlocking_underBlockPolicy() throws Exception {
        // given
        var writer = createWriter(BestEffortBackpressurePolicy.BLOCK);

        // when
        writer.record(recordableInput());

        // then
        verify(queue).enqueueBlocking(any(SigningRecord.class));
        verify(queue, never()).enqueueDropping(any());
    }

    @Test
    void record_countsInterruptedDropAndSkipsQueued_whenBlockingInterrupted() throws Exception {
        // given
        doThrow(new InterruptedException()).when(queue).enqueueBlocking(any());
        var writer = createWriter(BestEffortBackpressurePolicy.BLOCK);

        // when
        writer.record(recordableInput());

        // then
        assertEquals(1, droppedCounter("interrupted"));
        assertEquals(0, queuedCounter("BEST_EFFORT"));
    }

    @Test
    void drainAndPersistBatch_persistsPolledBatch_inOneTransaction() throws Exception {
        // setup
        var writer = createWriter(BestEffortBackpressurePolicy.DROP_OLDEST);

        // given
        var timeout = 200L;
        var batch = List.of(new SigningRecord(), new SigningRecord());
        when(queue.pollBatch(eq(MAX_BATCH_SIZE), eq(timeout))).thenReturn(batch);

        // when
        writer.drainAndPersistBatch(timeout);

        // then
        verify(repository).saveAll(batch);
    }

    @Test
    void drainAndPersistBatch_returnsWithoutPersisting_whenBatchEmpty() throws Exception {
        // setup
        var writer = createWriter(BestEffortBackpressurePolicy.DROP_OLDEST);

        // given
        when(queue.pollBatch(eq(MAX_BATCH_SIZE), anyLong())).thenReturn(List.of());

        // when
        writer.drainAndPersistBatch(noWait());

        // then
        verify(repository, never()).saveAll(any());
    }

    @Test
    void drainAndPersistBatch_countsPersistFailureAndLostRecordsByBatchSizeAndDoesNotThrow_whenSaveFails() throws Exception {
        // setup
        var writer = createWriter(BestEffortBackpressurePolicy.DROP_OLDEST);

        // given
        var batch = List.of(new SigningRecord(), new SigningRecord(), new SigningRecord());
        when(queue.pollBatch(eq(MAX_BATCH_SIZE), anyLong())).thenReturn(batch);
        doThrow(new RuntimeException("db down")).when(repository).saveAll(any());

        // when
        writer.drainAndPersistBatch(noWait()); // swallows the failure: best-effort records may be lost

        // then
        assertEquals(batch.size(), persistFailedCounter("BEST_EFFORT"));
        assertEquals(batch.size(), droppedCounter("flush_failed"));
    }

    @Test
    void drainAndPersistBatch_propagatesInterrupt_whenQueuePollInterrupted() throws Exception {
        // given
        when(queue.pollBatch(eq(MAX_BATCH_SIZE), anyLong())).thenThrow(new InterruptedException());
        var writer = createWriter(BestEffortBackpressurePolicy.DROP_OLDEST);

        // when
        Executable drain = () -> writer.drainAndPersistBatch(noWait());

        // then
        assertThrows(InterruptedException.class, drain);
    }

    private BestEffortSigningRecordWriter createWriter(BestEffortBackpressurePolicy policy) {
        return new BestEffortSigningRecordWriter(repository, new SigningRecordInputMapper(), metrics, txm, queue, policy, MAX_BATCH_SIZE);
    }

    private SigningRecordInput recordableInput() {
        return aSigningRecordInput()
                .signingProfile(aSigningProfile().recordPolicy(recordingEverything().build()).build())
                .build();
    }

    private long noWait() {
        return 0L;
    }

    private double skippedCounter() {
        return registry.get("signing_record.skipped_no_content_policy.total").counter().count();
    }

    private double queuedCounter(String mode) {
        var counter = registry.find("signing_record.queued.total").tag("mode", mode).counter();
        return counter == null ? 0d : counter.count();
    }

    private double droppedCounter(String reason) {
        return registry.get("signing_record.best_effort.dropped.total").tag("reason", reason).counter().count();
    }

    private double persistFailedCounter(String mode) {
        var counter = registry.find("signing_record.persist.failed.total").tag("mode", mode).counter();
        return counter == null ? 0d : counter.count();
    }

    private long durationSampleCount(String mode) {
        Timer timer = registry.find("signing_record.write.duration_ms").tag("mode", mode).timer();
        return timer == null ? 0L : timer.count();
    }
}
