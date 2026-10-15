package com.otilm.core.service.handler;

import com.otilm.core.config.KeyImportProperties;
import com.otilm.core.service.writer.KeyImportRetentionWriter;
import java.util.Optional;
import java.util.concurrent.atomic.AtomicInteger;
import org.junit.jupiter.api.Test;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyInt;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

class KeyImportSweeperTest {

    private final KeyImportClaimer claimer = mock(KeyImportClaimer.class);
    private final KeyImportRetentionWriter retentionWriter = mock(KeyImportRetentionWriter.class);
    private final KeyImportSweeper sweeper = new KeyImportSweeper(claimer, mock(KeyImportReconciler.class),
            retentionWriter, new KeyImportProperties(null, null, null, null, null, null));

    /** A backlog of finished attempts is deleted over several runs, so one run does not hold up the next look. */
    @Test
    void sweep_deletesABoundedNumberOfBatchesARun() {
        // given
        when(claimer.claimNext()).thenReturn(Optional.empty());
        AtomicInteger batches = new AtomicInteger();
        when(retentionWriter.deleteFinishedBefore(any(), anyInt()))
                .thenAnswer(batch -> batches.incrementAndGet() <= KeyImportSweeper.MAX_DELETE_BATCHES_PER_RUN + 1
                        ? batch.getArgument(1)
                        : 0);

        // when
        sweeper.sweep();

        // then
        verify(retentionWriter, times(KeyImportSweeper.MAX_DELETE_BATCHES_PER_RUN))
                .deleteFinishedBefore(any(), anyInt());
    }
}
