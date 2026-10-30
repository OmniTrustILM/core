package com.otilm.core.messaging.jms.listeners.discovery;

import com.otilm.core.messaging.jms.producers.DiscoveryWorkProducer;
import com.otilm.core.messaging.model.DiscoveryWorkMessage;
import com.otilm.core.model.discovery.DiscoveryWorkType;
import java.time.OffsetDateTime;
import java.util.List;
import java.util.UUID;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyInt;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class DiscoveryWorkSweeperTest {

    @Mock
    private DiscoveryWorkClaimer workClaimer;
    @Mock
    private DiscoveryWorkProducer workProducer;
    @Mock
    private DiscoveryRunReaper runReaper;

    private static final int BATCH_SIZE = 200;

    private DiscoveryWorkSweeper sweeper;

    @BeforeEach
    void setUp() {
        sweeper = new DiscoveryWorkSweeper(workClaimer, workProducer, runReaper, BATCH_SIZE, 10);
    }

    @Test
    void noDueRows_sendsNothing() {
        when(workClaimer.claimDueBatch(eq(BATCH_SIZE), any(OffsetDateTime.class))).thenReturn(List.of());

        sweeper.sweep();

        verifyNoInteractions(workProducer);
    }

    @Test
    void everySweep_reapsUndrivableRuns() {
        when(workClaimer.claimDueBatch(eq(BATCH_SIZE), any(OffsetDateTime.class))).thenReturn(List.of());

        sweeper.sweep();

        verify(runReaper).reap();
    }

    @Test
    void due_sendsClaimedMessagesOutsideTheClaim() {
        DiscoveryWorkMessage msg = new DiscoveryWorkMessage(UUID.randomUUID(), DiscoveryWorkType.STATUS, 2);
        // A partial batch (< batchSize) ends the loop after one round.
        when(workClaimer.claimDueBatch(eq(BATCH_SIZE), any(OffsetDateTime.class))).thenReturn(List.of(msg));

        sweeper.sweep();

        verify(workProducer).produceMessage(msg);
        verify(workClaimer).claimDueBatch(anyInt(), any(OffsetDateTime.class));
    }

    @Test
    void sendFailure_doesNotAbortTheSweep() {
        DiscoveryWorkMessage msg = new DiscoveryWorkMessage(UUID.randomUUID(), DiscoveryWorkType.DRAIN, 1);
        when(workClaimer.claimDueBatch(eq(BATCH_SIZE), any(OffsetDateTime.class))).thenReturn(List.of(msg));
        doThrow(new RuntimeException("broker down")).when(workProducer).produceMessage(msg);

        // One bad send must not propagate — the row is already rescheduled and retries when next due.
        sweeper.sweep();

        verify(workProducer).produceMessage(msg);
        verify(runReaper).reap();
    }

    @Test
    void persistentBacklog_stopsExactlyAtMaxBatchesPerRun() {
        DiscoveryWorkSweeper cappedSweeper = new DiscoveryWorkSweeper(workClaimer, workProducer, runReaper, 1, 3);
        DiscoveryWorkMessage msg = new DiscoveryWorkMessage(UUID.randomUUID(), DiscoveryWorkType.STATUS, 0);
        // Every claim returns a full batch: without the cap this sweep would never yield the scheduler.
        when(workClaimer.claimDueBatch(eq(1), any(OffsetDateTime.class))).thenReturn(List.of(msg));

        cappedSweeper.sweep();

        verify(workClaimer, times(3)).claimDueBatch(eq(1), any(OffsetDateTime.class));
        verify(runReaper).reap();
    }

    @Test
    void everyBatchOfOneSweep_usesTheSameDueCutoff() {
        DiscoveryWorkSweeper singleRowBatches = new DiscoveryWorkSweeper(workClaimer, workProducer, runReaper, 1, 10);
        DiscoveryWorkMessage msg = new DiscoveryWorkMessage(UUID.randomUUID(), DiscoveryWorkType.DRAIN, 0);
        // A full first batch keeps the loop going; the second is empty and ends it.
        when(workClaimer.claimDueBatch(eq(1), any(OffsetDateTime.class)))
                .thenReturn(List.of(msg))
                .thenReturn(List.of());

        singleRowBatches.sweep();

        ArgumentCaptor<OffsetDateTime> cutoffs = ArgumentCaptor.forClass(OffsetDateTime.class);
        verify(workClaimer, times(2)).claimDueBatch(eq(1), cutoffs.capture());
        assertThat(cutoffs.getAllValues().get(0))
                .as("a row rescheduled by the first batch must never be due for the second")
                .isEqualTo(cutoffs.getAllValues().get(1));
    }
}
