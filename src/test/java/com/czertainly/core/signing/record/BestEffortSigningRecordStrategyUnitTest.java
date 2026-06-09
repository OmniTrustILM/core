package com.czertainly.core.signing.record;

import com.czertainly.core.dao.entity.signing.SigningRecord;
import com.czertainly.core.mapper.signing.SigningRecordInputMapper;
import com.czertainly.core.service.writer.signingrecord.SigningRecordWriter;
import io.micrometer.core.instrument.MeterRegistry;
import io.micrometer.core.instrument.Timer;
import io.micrometer.core.instrument.simple.SimpleMeterRegistry;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.function.Executable;

import java.util.List;

import static com.czertainly.core.model.signing.SigningProfileModelBuilder.aSigningProfile;
import static com.czertainly.core.model.signing.SigningRecordPolicyModelBuilder.notRecording;
import static com.czertainly.core.model.signing.SigningRecordPolicyModelBuilder.recordingDisabled;
import static com.czertainly.core.model.signing.SigningRecordPolicyModelBuilder.recordingEverything;
import static com.czertainly.core.signing.record.SigningRecordInputBuilder.aSigningRecordInput;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
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
 * Pure unit test for {@link BestEffortSigningRecordStrategy} over a mocked {@link BestEffortSigningRecordQueue}
 * and {@link SigningRecordWriter}. The strategy's job is narrow: every call ticks the intake funnel; an empty
 * policy is skipped, otherwise it maps and dispatches to the right backpressure method (admission is the intake
 * accept, an interrupted block is {@code intake.failed{interrupted}}, an eviction is the standalone
 * {@code best_effort.evicted} post-acceptance loss). The async flush is the stage-2 {@code persist} pair,
 * counting losses without propagating. Queue mechanics — eviction, blocking, batching — are covered against the
 * real queue in {@link BestEffortSigningRecordQueueTest}.
 */
class BestEffortSigningRecordStrategyUnitTest {

    private static final int MAX_BATCH_SIZE = 200;
    private static final String MODE = "BEST_EFFORT";

    private MeterRegistry registry;
    private SigningRecordMetrics metrics;
    private SigningRecordWriter writer;
    private BestEffortSigningRecordQueue queue;

    @BeforeEach
    void setUp() {
        registry = new SimpleMeterRegistry();
        metrics = new SigningRecordMetrics(registry);
        writer = mock(SigningRecordWriter.class);
        queue = mock(BestEffortSigningRecordQueue.class);
    }

    @Test
    void record_countsIntakeSkipped_whenRecordingDisabled() {
        // given
        var recordingDisabledInput = aSigningRecordInput()
                .signingProfile(
                        aSigningProfile()
                                .recordPolicy(
                                        recordingDisabled()
                                                .build())
                                .build())
                .build();
        var strategy = createStrategy(BestEffortBackpressurePolicy.DROP_OLDEST);

        // when
        strategy.recordSigning(recordingDisabledInput);

        // then
        assertEquals(1, intakeCounter(MODE));
        assertEquals(1, intakeSkippedCounter(MODE));
        verifyNoInteractions(queue, writer);
    }

    @Test
    void record_enqueuesMetadataOnlyRecord_whenRecordingEnabledButNoContentSelected() {
        // given
        var metadataOnlyInput = aSigningRecordInput()
                .signingProfile(
                        aSigningProfile()
                                .recordPolicy(
                                        notRecording()
                                                .build())
                                .build())
                .build();
        var strategy = createStrategy(BestEffortBackpressurePolicy.DROP_OLDEST);

        // when
        strategy.recordSigning(metadataOnlyInput);

        // then
        assertEquals(1, intakeCounter(MODE));
        assertEquals(0, intakeSkippedCounter(MODE));
        verify(queue).enqueueDropping(any(SigningRecord.class));
    }

    @Test
    void record_enqueuesDroppingAndCountsIntake_underDropOldestPolicy() throws Exception {
        // given
        var strategy = createStrategy(BestEffortBackpressurePolicy.DROP_OLDEST);

        // when
        strategy.recordSigning(recordableInput());

        // then
        assertEquals(1, intakeCounter(MODE));
        assertEquals(0, intakeFailedCounter(MODE, SigningRecordMetrics.REASON_INTERRUPTED));
        assertEquals(1, durationSampleCount(MODE));
        verify(queue).enqueueDropping(any(SigningRecord.class));
        verify(queue, never()).enqueueBlocking(any());
    }

    @Test
    void record_recordsEvictedLossMetric_whenDropOldestEvicts() {
        // given
        var evictedByQueue = 2;
        when(queue.enqueueDropping(any())).thenReturn(evictedByQueue);
        var strategy = createStrategy(BestEffortBackpressurePolicy.DROP_OLDEST);

        // when
        strategy.recordSigning(recordableInput());

        // then
        assertEquals(evictedByQueue, evictedCounter());
    }

    @Test
    void record_enqueuesBlocking_underBlockPolicy() throws Exception {
        // given
        var strategy = createStrategy(BestEffortBackpressurePolicy.BLOCK);

        // when
        strategy.recordSigning(recordableInput());

        // then
        verify(queue).enqueueBlocking(any(SigningRecord.class));
        verify(queue, never()).enqueueDropping(any());
    }

    @Test
    void record_countsIntakeFailedInterrupted_whenBlockingInterrupted() throws Exception {
        // given
        doThrow(new InterruptedException()).when(queue).enqueueBlocking(any());
        var strategy = createStrategy(BestEffortBackpressurePolicy.BLOCK);

        // when
        strategy.recordSigning(recordableInput());

        // then
        assertEquals(1, intakeFailedCounter(MODE, SigningRecordMetrics.REASON_INTERRUPTED));
    }

    @Test
    void drainAndPersistBatch_persistsPolledBatchAndCountsPersist_throughTheWriter() throws Exception {
        // setup
        var strategy = createStrategy(BestEffortBackpressurePolicy.DROP_OLDEST);

        // given
        var timeout = 200L;
        var batch = List.of(new SigningRecord(), new SigningRecord());
        when(queue.pollBatch(MAX_BATCH_SIZE, timeout)).thenReturn(batch);

        // when
        strategy.drainAndPersistBatch(timeout);

        // then
        verify(writer).insertBatch(batch);
        assertEquals(batch.size(), persistCounter(MODE));
        assertEquals(0, persistFailedCounter(MODE));
    }

    @Test
    void drainAndPersistBatch_returnsWithoutPersisting_whenBatchEmpty() throws Exception {
        // setup
        var strategy = createStrategy(BestEffortBackpressurePolicy.DROP_OLDEST);

        // given
        when(queue.pollBatch(eq(MAX_BATCH_SIZE), anyLong())).thenReturn(List.of());

        // when
        strategy.drainAndPersistBatch(noWait());

        // then
        verify(writer, never()).insertBatch(any());
        assertEquals(0, persistCounter(MODE));
    }

    @Test
    void drainAndPersistBatch_countsPersistAttemptAndFailureByBatchSizeAndDoesNotThrow_whenInsertFails() throws Exception {
        // setup
        var strategy = createStrategy(BestEffortBackpressurePolicy.DROP_OLDEST);

        // given
        var batch = List.of(new SigningRecord(), new SigningRecord(), new SigningRecord());
        when(queue.pollBatch(eq(MAX_BATCH_SIZE), anyLong())).thenReturn(batch);
        doThrow(new RuntimeException("db down")).when(writer).insertBatch(any());

        // when
        strategy.drainAndPersistBatch(noWait()); // swallows the failure: best-effort records may be lost

        // then
        assertEquals(batch.size(), persistCounter(MODE)); // attempt is counted before the insert
        assertEquals(batch.size(), persistFailedCounter(MODE));
    }

    @Test
    void drainAndPersistBatch_propagatesInterrupt_whenQueuePollInterrupted() throws Exception {
        // given
        when(queue.pollBatch(eq(MAX_BATCH_SIZE), anyLong())).thenThrow(new InterruptedException());
        var strategy = createStrategy(BestEffortBackpressurePolicy.DROP_OLDEST);

        // when
        Executable drain = () -> strategy.drainAndPersistBatch(noWait());

        // then
        assertThrows(InterruptedException.class, drain);
    }

    private BestEffortSigningRecordStrategy createStrategy(BestEffortBackpressurePolicy policy) {
        var properties = new SigningRecordBestEffortProperties(1, policy, 1L, MAX_BATCH_SIZE);
        return new BestEffortSigningRecordStrategy(metrics, writer, new SigningRecordInputMapper(), queue, properties);
    }

    private SigningRecordInput recordableInput() {
        return aSigningRecordInput()
                .signingProfile(aSigningProfile().recordPolicy(recordingEverything().build()).build())
                .build();
    }

    private long noWait() {
        return 0L;
    }

    private double intakeCounter(String mode) {
        var counter = registry.find("signing_record.intake").tag("mode", mode).counter();
        return counter == null ? 0d : counter.count();
    }

    private double intakeSkippedCounter(String mode) {
        var counter = registry.find("signing_record.intake.skipped").tag("mode", mode).counter();
        return counter == null ? 0d : counter.count();
    }

    private double intakeFailedCounter(String mode, String reason) {
        var counter = registry.find("signing_record.intake.failed").tag("mode", mode).tag("reason", reason).counter();
        return counter == null ? 0d : counter.count();
    }

    private double evictedCounter() {
        var counter = registry.find("signing_record.best_effort.evicted").counter();
        return counter == null ? 0d : counter.count();
    }

    private double persistCounter(String mode) {
        var counter = registry.find("signing_record.persist").tag("mode", mode).counter();
        return counter == null ? 0d : counter.count();
    }

    private double persistFailedCounter(String mode) {
        var counter = registry.find("signing_record.persist.failed").tag("mode", mode).counter();
        return counter == null ? 0d : counter.count();
    }

    private long durationSampleCount(String mode) {
        Timer timer = registry.find("signing_record.write.duration").tag("mode", mode).timer();
        return timer == null ? 0L : timer.count();
    }
}
