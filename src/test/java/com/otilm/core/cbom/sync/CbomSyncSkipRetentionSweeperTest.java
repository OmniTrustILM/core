package com.otilm.core.cbom.sync;

import com.otilm.core.cluster.ClusterOperationSynchronizer;
import com.otilm.core.service.writer.cbom.CbomSyncSkipRetentionWriter;
import java.time.OffsetDateTime;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyInt;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/**
 * The sweep's orchestration over a mocked writer: the lock gate, the batch loop and its cap, the cutoff it passes, and
 * what it reports when a batch fails. What the delete itself does is proved against PostgreSQL in the integration test.
 */
class CbomSyncSkipRetentionSweeperTest {

    private final CbomSyncSkipRetentionWriter writer = mock(CbomSyncSkipRetentionWriter.class);
    private final ClusterOperationSynchronizer lock = mock(ClusterOperationSynchronizer.class);
    private final CbomSyncSkipRetentionSweeper sweeper = new CbomSyncSkipRetentionSweeper(writer, lock);

    @Test
    void aContendedSweepDoesNotRun() {
        when(lock.tryLock(ClusterOperationSynchronizer.Operation.CBOM_SYNC_SKIP_RETENTION)).thenReturn(false);

        CbomSyncSkipRetentionSweeper.SweepOutcome outcome = sweeper.sweep(90);

        assertThat(outcome.ran()).isFalse();
        verify(writer, never()).deleteWrittenOffBatch(any(), anyInt());
    }

    @Test
    void theSweepDeletesInBatchesUntilAShortBatchAndPassesTheRetentionCutoff() {
        when(lock.tryLock(ClusterOperationSynchronizer.Operation.CBOM_SYNC_SKIP_RETENTION)).thenReturn(true);
        int batch = CbomSyncSkipRetentionSweeper.BATCH_SIZE;
        when(writer.deleteWrittenOffBatch(any(), anyInt())).thenReturn(batch, batch, 7);

        CbomSyncSkipRetentionSweeper.SweepOutcome outcome = sweeper.sweep(30);

        assertThat(outcome.ran()).isTrue();
        assertThat(outcome.aborted()).isFalse();
        assertThat(outcome.capped()).isFalse();
        assertThat(outcome.deleted()).isEqualTo(2 * batch + 7);
        assertThat(outcome.batches()).isEqualTo(3);
        ArgumentCaptor<OffsetDateTime> cutoff = ArgumentCaptor.forClass(OffsetDateTime.class);
        verify(writer, org.mockito.Mockito.times(3))
                .deleteWrittenOffBatch(cutoff.capture(), org.mockito.ArgumentMatchers.eq(batch));
        assertThat(cutoff.getValue())
                .isBetween(OffsetDateTime.now().minusDays(30).minusMinutes(1),
                        OffsetDateTime.now().minusDays(30).plusMinutes(1));
    }

    @Test
    void theSweepStopsAtItsCapAndSaysSo() {
        when(lock.tryLock(ClusterOperationSynchronizer.Operation.CBOM_SYNC_SKIP_RETENTION)).thenReturn(true);
        when(writer.deleteWrittenOffBatch(any(), anyInt())).thenReturn(CbomSyncSkipRetentionSweeper.BATCH_SIZE);

        CbomSyncSkipRetentionSweeper.SweepOutcome outcome = sweeper.sweep(90);

        assertThat(outcome.batches()).isEqualTo(CbomSyncSkipRetentionSweeper.MAX_BATCHES_PER_SWEEP);
        assertThat(outcome.capped()).isTrue();
        assertThat(outcome.deleted())
                .isEqualTo(
                        CbomSyncSkipRetentionSweeper.BATCH_SIZE * CbomSyncSkipRetentionSweeper.MAX_BATCHES_PER_SWEEP);
    }

    @Test
    void aFailingBatchAbortsTheSweepAndReportsWhatLandedBeforeIt() {
        when(lock.tryLock(ClusterOperationSynchronizer.Operation.CBOM_SYNC_SKIP_RETENTION)).thenReturn(true);
        when(writer.deleteWrittenOffBatch(any(), anyInt()))
                .thenReturn(CbomSyncSkipRetentionSweeper.BATCH_SIZE)
                .thenThrow(new IllegalStateException("connection lost"));

        CbomSyncSkipRetentionSweeper.SweepOutcome outcome = sweeper.sweep(90);

        assertThat(outcome.ran()).isTrue();
        assertThat(outcome.aborted()).isTrue();
        assertThat(outcome.deleted()).isEqualTo(CbomSyncSkipRetentionSweeper.BATCH_SIZE);
        assertThat(outcome.batches()).isEqualTo(1);
    }
}
