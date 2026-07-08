package com.otilm.core.signing.record;

import com.otilm.core.cluster.ClusterOperationSynchronizer;
import com.otilm.core.service.writer.signingrecord.SigningRecordWriter;
import io.micrometer.core.instrument.simple.SimpleMeterRegistry;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.mockito.ArgumentMatchers.anyInt;
import static org.mockito.Mockito.*;

/**
 * Pure unit test for {@link SigningRecordRetentionSweeper} over a mocked per-batch writer and cluster
 * synchronizer. Covers the lock gate, the per-sweep batch cap (which bounds how long the advisory lock and
 * its enclosing transaction stay open), the empty backlog, and the failure path with its metrics. The actual
 * retention SQL is covered against a real database in {@link com.otilm.core.integration.signing.record.SigningRecordRetentionSweeperITest}.
 */
class SigningRecordRetentionSweeperUnitTest {

    private static final int BATCH_SIZE = 10;
    private static final int MAX_BATCHES_PER_SWEEP = 3;

    private SimpleMeterRegistry registry;
    private SigningRecordWriter writer;
    private ClusterOperationSynchronizer clusterSynchronizer;
    private SigningRecordMetrics metrics;

    @BeforeEach
    void setUp() {
        registry = new SimpleMeterRegistry();
        writer = mock(SigningRecordWriter.class);
        clusterSynchronizer = mock(ClusterOperationSynchronizer.class);
        metrics = new SigningRecordMetrics(registry);
        when(clusterSynchronizer.tryLock(ClusterOperationSynchronizer.Operation.SIGNING_RECORD_RETENTION))
                .thenReturn(true);
    }

    @Test
    void sweep_stopsAtTheBatchCap_evenWhenMoreExpiredRecordsRemain() {
        // given every batch deletes a full batch, so more expired records always remain
        when(writer.deleteExpiredBatch(anyInt())).thenReturn(BATCH_SIZE);

        // when
        createSweeper().sweep();

        // then it deletes exactly the cap's worth of batches and counts them all
        verify(writer, times(MAX_BATCHES_PER_SWEEP)).deleteExpiredBatch(BATCH_SIZE);
        assertEquals(MAX_BATCHES_PER_SWEEP * BATCH_SIZE, retentionDeleted());
    }

    @Test
    void sweep_stopsEarly_whenABatchIsNotFull_andCountsEveryDeletedRow() {
        // given the first batch is full and the second is short (backlog exhausted)
        when(writer.deleteExpiredBatch(anyInt())).thenReturn(BATCH_SIZE, BATCH_SIZE - 1);

        // when
        createSweeper().sweep();

        // then it stops after the short batch, well under the cap, and counts both batches as one healthy run
        verify(writer, times(2)).deleteExpiredBatch(BATCH_SIZE);
        assertEquals(BATCH_SIZE + (BATCH_SIZE - 1), retentionDeleted());
        assertEquals(0, retentionFailed());
        assertEquals(1, retentionSweepRuns());
    }

    @Test
    void sweep_deletesNothingAndRecordsNoMetric_whenThereAreNoExpiredRecords() {
        // given the first batch already finds nothing
        when(writer.deleteExpiredBatch(anyInt())).thenReturn(0);

        // when
        createSweeper().sweep();

        // then it runs a single batch and records neither a deletion nor a failure
        verify(writer, times(1)).deleteExpiredBatch(BATCH_SIZE);
        assertEquals(0, retentionDeleted());
        assertEquals(0, retentionFailed());
    }

    @Test
    void sweep_recordsFailureButKeepsPartialProgress_whenALaterBatchThrows() {
        // given the first batch deletes a full batch and the second throws
        when(writer.deleteExpiredBatch(anyInt()))
                .thenReturn(BATCH_SIZE)
                .thenThrow(new RuntimeException("connection reset"));

        // when
        createSweeper().sweep();

        // then the failure is counted while the already-committed first batch still counts as deleted
        verify(writer, times(2)).deleteExpiredBatch(BATCH_SIZE);
        assertEquals(1, retentionFailed());
        assertEquals(BATCH_SIZE, retentionDeleted());
    }

    @Test
    void sweep_recordsFailureAndDeletesNothing_whenTheFirstBatchThrows() {
        // given the very first batch throws
        when(writer.deleteExpiredBatch(anyInt())).thenThrow(new RuntimeException("db unavailable"));

        // when
        createSweeper().sweep();

        // then the failure is counted and nothing is recorded as deleted
        assertEquals(1, retentionFailed());
        assertEquals(0, retentionDeleted());
    }

    @Test
    void sweep_skips_whenAnotherInstanceHoldsTheLock() {
        // given
        when(clusterSynchronizer.tryLock(ClusterOperationSynchronizer.Operation.SIGNING_RECORD_RETENTION))
                .thenReturn(false);

        // when
        createSweeper().sweep();

        // then no work is done and no metric is touched (the run counter ticks only post-lock)
        verify(writer, never()).deleteExpiredBatch(anyInt());
        assertEquals(0, retentionDeleted());
        assertEquals(0, retentionFailed());
        assertEquals(0, retentionSweepRuns());
    }

    private SigningRecordRetentionSweeper createSweeper() {
        return new SigningRecordRetentionSweeper(writer, metrics, clusterSynchronizer,
                new SigningRecordRetentionProperties(1, BATCH_SIZE, MAX_BATCHES_PER_SWEEP));
    }

    private double retentionDeleted() {
        return expiredCounter("signing_record.deleted");
    }

    private double retentionFailed() {
        return expiredCounter("signing_record.sweep.failed");
    }

    private double retentionSweepRuns() {
        return expiredCounter("signing_record.sweep");
    }

    private double expiredCounter(String name) {
        var counter = registry.find(name).tag("type", SigningRecordMetrics.DELETE_TYPE_EXPIRED).counter();
        return counter == null ? 0d : counter.count();
    }
}
