package com.czertainly.core.signing.record;

import com.czertainly.core.cluster.ClusterOperationSynchronizer;
import com.czertainly.core.dao.repository.signing.SigningRecordOutboxRepository;
import com.czertainly.core.service.writer.signingrecord.OutboxSigningRecordWriter;
import io.micrometer.core.instrument.MeterRegistry;
import io.micrometer.core.instrument.simple.SimpleMeterRegistry;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.function.Executable;

import java.util.List;
import java.util.UUID;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyInt;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/**
 * Pure unit test for {@link SigningRecordOutboxDrainer} over a mocked repository, per-row writer, and
 * cluster synchronizer. The drainer's job is narrow: acquire the cluster-wide drain lock (or skip if another
 * node holds it), read successive drainable batches, delegate each row to
 * {@link OutboxSigningRecordWriter#drainRow(java.util.UUID)}, and on failure record the attempt via
 * {@link OutboxSigningRecordWriter#recordFailure(java.util.UUID, String)} while leaving the healthy rows
 * drained. The claim query projects only row UUIDs, so the drainer threads UUIDs (not entities) to the
 * writer. Poison exclusion lives in the query and the per-row transaction isolation, idempotent copy, and
 * field fidelity are covered against a real database in {@link SigningRecordOutboxDrainerTest}.
 */
class SigningRecordOutboxDrainerUnitTest {

    private static final int DEFAULT_BATCH_SIZE = 200;
    private static final int DEFAULT_POISON_THRESHOLD = 10;
    private static final int DEFAULT_MAX_BATCHES_PER_RUN = 100;

    private MeterRegistry registry;
    private SigningRecordMetrics metrics;
    private SigningRecordOutboxRepository outboxRepo;
    private OutboxSigningRecordWriter writer;
    private ClusterOperationSynchronizer clusterSynchronizer;

    @BeforeEach
    void setUp() {
        registry = new SimpleMeterRegistry();
        metrics = new SigningRecordMetrics(registry);
        outboxRepo = mock(SigningRecordOutboxRepository.class);
        writer = mock(OutboxSigningRecordWriter.class);
        clusterSynchronizer = mock(ClusterOperationSynchronizer.class);
        when(clusterSynchronizer.tryLock(ClusterOperationSynchronizer.Operation.SIGNING_RECORD_OUTBOX_DRAIN))
                .thenReturn(true);
    }

    @Test
    void drainOnce_drainsEachRowThroughTheWriterAndCountsThem() {
        // given
        var batch = List.of(aUuid(), aUuid(), aUuid());
        when(outboxRepo.findDrainableBatch(anyInt(), anyInt())).thenReturn(batch);
        when(writer.drainRow(any())).thenReturn(true);

        // when
        createDrainer().drainOnce();

        // then
        batch.forEach(uuid -> verify(writer).drainRow(uuid));
        verify(writer, never()).recordFailure(any(), any());
        assertEquals(3, drainedCount());
    }

    @Test
    void drainOnce_doesNothing_whenNoDrainableRows() {
        // given
        when(outboxRepo.findDrainableBatch(anyInt(), anyInt())).thenReturn(List.of());

        // when
        createDrainer().drainOnce();

        // then
        verify(writer, never()).drainRow(any());
        verify(writer, never()).recordFailure(any(), any());
        assertEquals(0, drainedCount());
    }

    @Test
    void drainOnce_skipsEntirely_whenAnotherInstanceHoldsTheLock() {
        // given
        when(clusterSynchronizer.tryLock(ClusterOperationSynchronizer.Operation.SIGNING_RECORD_OUTBOX_DRAIN))
                .thenReturn(false);

        // when
        createDrainer().drainOnce();

        // then
        verify(outboxRepo, never()).findDrainableBatch(anyInt(), anyInt());
        verify(writer, never()).drainRow(any());
    }

    @Test
    void drainOnce_recordsFailureAndKeepsRow_whenTheWriterThrows() {
        // given
        var failingUuid = aUuid();
        var dbError = "constraint violation";
        when(outboxRepo.findDrainableBatch(anyInt(), anyInt())).thenReturn(List.of(failingUuid));
        when(writer.drainRow(failingUuid)).thenThrow(new RuntimeException(dbError));

        // when
        createDrainer().drainOnce();

        // then
        verify(writer).recordFailure(failingUuid, dbError);
        assertEquals(1, failedCount());
        assertEquals(0, drainedCount());
    }

    @Test
    void drainOnce_continuesToTheNextRow_whenRecordingTheFailureItselfThrows() {
        // given a row whose drain fails and whose failure-recording also fails, followed by a healthy row
        var brokenUuid = aUuid();
        var healthyUuid = aUuid();
        when(outboxRepo.findDrainableBatch(anyInt(), anyInt())).thenReturn(List.of(brokenUuid, healthyUuid));
        when(writer.drainRow(brokenUuid)).thenThrow(new RuntimeException("drain failed"));
        doThrow(new RuntimeException("db unavailable")).when(writer).recordFailure(eq(brokenUuid), any());
        when(writer.drainRow(healthyUuid)).thenReturn(true);

        // when / then the failed bookkeeping does not abort the batch — the healthy row is still drained
        assertDoesNotThrow(() -> createDrainer().drainOnce());
        verify(writer).drainRow(healthyUuid);
        assertEquals(1, drainedCount());
    }

    @Test
    void drainOnce_drainsHealthyRowsAndIsolatesTheFailingOne_inAMixedBatch() {
        // given
        var healthyUuid = aUuid();
        var failingUuid = aUuid();
        var dbError = "FK violation on signing_profile_uuid";
        when(outboxRepo.findDrainableBatch(anyInt(), anyInt())).thenReturn(List.of(healthyUuid, failingUuid));
        when(writer.drainRow(healthyUuid)).thenReturn(true);
        when(writer.drainRow(failingUuid)).thenThrow(new RuntimeException(dbError));

        // when
        createDrainer().drainOnce();

        // then
        verify(writer).recordFailure(failingUuid, dbError);
        verify(writer, never()).recordFailure(eq(healthyUuid), any());
        assertEquals(1, failedCount());
        assertEquals(1, drainedCount());
    }

    @Test
    void drainOnce_doesNotCountARowTheWriterReportsAsAlreadyDrained() {
        // given a row the writer found already gone (drained by an earlier pass or another node)
        var takenUuid = aUuid();
        when(outboxRepo.findDrainableBatch(anyInt(), anyInt())).thenReturn(List.of(takenUuid));
        when(writer.drainRow(takenUuid)).thenReturn(false);

        // when
        createDrainer().drainOnce();

        // then
        verify(writer, never()).recordFailure(any(), any());
        assertEquals(0, drainedCount());
        assertEquals(0, failedCount());
    }

    @Test
    void drainOnce_keepsDrainingWhileBatchesAreFull_andStopsOnAShortBatch() {
        // given a full batch followed by a short one (batch size 2)
        var batchSize = 2;
        when(outboxRepo.findDrainableBatch(anyInt(), anyInt()))
                .thenReturn(List.of(aUuid(), aUuid()), List.of(aUuid()));
        when(writer.drainRow(any())).thenReturn(true);

        // when
        createDrainer(batchSize, DEFAULT_POISON_THRESHOLD).drainOnce();

        // then both batches were drained and the loop stopped after the short one
        verify(writer, times(3)).drainRow(any());
        verify(outboxRepo, times(2)).findDrainableBatch(DEFAULT_POISON_THRESHOLD, batchSize);
        assertEquals(3, drainedCount());
    }

    @Test
    void drainOnce_stopsAtTheBatchCap_evenWhenMoreFullBatchesRemain() {
        // given every claim returns a full batch that drains completely, so work is always available
        var batchSize = 2;
        var maxBatchesPerRun = 3;
        when(outboxRepo.findDrainableBatch(anyInt(), anyInt()))
                .thenReturn(List.of(aUuid(), aUuid()));
        when(writer.drainRow(any())).thenReturn(true);

        // when
        createDrainer(batchSize, DEFAULT_POISON_THRESHOLD, maxBatchesPerRun).drainOnce();

        // then it claims exactly the cap's worth of batches and stops, leaving the rest for the next run
        verify(outboxRepo, times(maxBatchesPerRun)).findDrainableBatch(DEFAULT_POISON_THRESHOLD, batchSize);
        verify(writer, times(maxBatchesPerRun * batchSize)).drainRow(any());
    }

    @Test
    void drainOnce_swallowsExceptionAndDoesNotThrow_whenTheQueryFails() {
        // given
        when(outboxRepo.findDrainableBatch(anyInt(), anyInt())).thenThrow(new RuntimeException("db unavailable"));

        // when
        Executable drain = () -> createDrainer().drainOnce();

        // then
        assertDoesNotThrow(drain);
        verify(writer, never()).drainRow(any());
    }

    @Test
    void drainOnce_queriesUsingTheConfiguredBatchSizeAndPoisonThreshold() {
        // given
        var batchSize = 50;
        var poisonThreshold = 7;
        when(outboxRepo.findDrainableBatch(anyInt(), anyInt())).thenReturn(List.of());

        // when
        createDrainer(batchSize, poisonThreshold).drainOnce();

        // then
        verify(outboxRepo).findDrainableBatch(poisonThreshold, batchSize);
    }

    private SigningRecordOutboxDrainer createDrainer() {
        return createDrainer(DEFAULT_BATCH_SIZE, DEFAULT_POISON_THRESHOLD, DEFAULT_MAX_BATCHES_PER_RUN);
    }

    private SigningRecordOutboxDrainer createDrainer(int batchSize, int poisonThreshold) {
        return createDrainer(batchSize, poisonThreshold, DEFAULT_MAX_BATCHES_PER_RUN);
    }

    private SigningRecordOutboxDrainer createDrainer(int batchSize, int poisonThreshold, int maxBatchesPerRun) {
        return new SigningRecordOutboxDrainer(outboxRepo, writer, clusterSynchronizer, metrics,
                batchSize, poisonThreshold, maxBatchesPerRun);
    }

    private UUID aUuid() {
        return UUID.randomUUID();
    }

    private double drainedCount() {
        return counterValue("signing_record.outbox.drained.total");
    }

    private double failedCount() {
        return counterValue("signing_record.outbox.failed.total");
    }

    private double counterValue(String name) {
        var counter = registry.find(name).counter();
        return counter == null ? 0d : counter.count();
    }
}
