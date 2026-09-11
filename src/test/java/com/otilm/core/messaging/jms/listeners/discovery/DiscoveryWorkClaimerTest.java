package com.otilm.core.messaging.jms.listeners.discovery;

import com.otilm.core.cluster.ClusterOperationSynchronizer;
import com.otilm.core.dao.entity.DiscoveryWork;
import com.otilm.core.dao.repository.DiscoveryWorkRepository;
import com.otilm.core.messaging.jms.configuration.DiscoveryWorkProperties;
import com.otilm.core.messaging.jms.configuration.StatusPollProperties;
import com.otilm.core.messaging.model.DiscoveryWorkMessage;
import com.otilm.core.model.discovery.DiscoveryWorkType;
import com.otilm.core.service.writer.discovery.DiscoveryWorkWriter;
import java.time.Duration;
import java.time.OffsetDateTime;
import java.util.List;
import java.util.UUID;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.data.domain.Pageable;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyInt;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.lenient;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class DiscoveryWorkClaimerTest {

    @Mock
    private ClusterOperationSynchronizer clusterSynchronizer;
    @Mock
    private DiscoveryWorkRepository workRepository;
    @Mock
    private DiscoveryWorkWriter workWriter;
    @Mock
    private DiscoveryWorkProperties workProperties;

    private static final int BATCH_SIZE = 200;
    private static final OffsetDateTime CUTOFF = OffsetDateTime.now();
    private static final Duration CLAIM_FLOOR = Duration.ofSeconds(35);

    private DiscoveryWorkClaimer claimer;

    @BeforeEach
    void setUp() {
        claimer = new DiscoveryWorkClaimer(clusterSynchronizer, workRepository, workWriter, workProperties,
                CLAIM_FLOOR);

        StatusPollProperties.PollSchedule schedule = new StatusPollProperties.PollSchedule(
                List.of(Duration.ofSeconds(5), Duration.ofSeconds(30)), 100);
        lenient().when(workProperties.scheduleFor(any())).thenReturn(schedule);
    }

    @Test
    void lockNotHeld_returnsEmptyAndReadsNothing() {
        when(clusterSynchronizer.tryLock(ClusterOperationSynchronizer.Operation.DISCOVERY_WORK_SWEEP))
                .thenReturn(false);

        assertThat(claimer.claimDueBatch(BATCH_SIZE, CUTOFF)).isEmpty();

        verify(workRepository, never()).findByNextDueAtLessThanEqualOrderByNextDueAt(any(), any());
        verify(workWriter, never()).reschedule(any(), any(), anyInt(), any());
    }

    @Test
    void noDueRows_returnsEmptyAndDoesNotReschedule() {
        when(clusterSynchronizer.tryLock(any())).thenReturn(true);
        when(workRepository
                .findByNextDueAtLessThanEqualOrderByNextDueAt(any(OffsetDateTime.class), any(Pageable.class)))
                .thenReturn(List.of());

        assertThat(claimer.claimDueBatch(BATCH_SIZE, CUTOFF)).isEmpty();

        verify(workWriter, never()).reschedule(any(), any(), anyInt(), any());
    }

    @Test
    void dueRow_buildsMessageAndAdvancesSchedule() {
        when(clusterSynchronizer.tryLock(any())).thenReturn(true);
        UUID runUuid = UUID.randomUUID();
        when(workRepository
                .findByNextDueAtLessThanEqualOrderByNextDueAt(any(OffsetDateTime.class), any(Pageable.class)))
                .thenReturn(List.of(workRow(runUuid, DiscoveryWorkType.DRAIN, 2)));

        List<DiscoveryWorkMessage> messages = claimer.claimDueBatch(BATCH_SIZE, CUTOFF);

        assertThat(messages).hasSize(1);
        assertThat(messages.get(0).discoveryUuid()).isEqualTo(runUuid);
        assertThat(messages.get(0).workType()).isEqualTo(DiscoveryWorkType.DRAIN);
        assertThat(messages.get(0).attempt()).isEqualTo(2);

        verify(workWriter).reschedule(eq(runUuid), eq(DiscoveryWorkType.DRAIN), eq(3), any(OffsetDateTime.class));
        // The due query runs against the caller's cutoff, not a fresh now() — the sweep-wide claim window.
        verify(workRepository).findByNextDueAtLessThanEqualOrderByNextDueAt(eq(CUTOFF), any(Pageable.class));
    }

    /**
     * A tick outlives its own backoff rung far more often than not — the early rungs are seconds and a connector call
     * may take its whole timeout. Nothing marks the row as being worked, so parking it at that rung invites the next
     * sweep to publish the same tick again.
     */
    @Test
    void aRungShorterThanATick_parksTheRowPastTheTickInstead() {
        when(clusterSynchronizer.tryLock(any())).thenReturn(true);
        UUID runUuid = UUID.randomUUID();
        when(workRepository
                .findByNextDueAtLessThanEqualOrderByNextDueAt(any(OffsetDateTime.class), any(Pageable.class)))
                .thenReturn(List.of(workRow(runUuid, DiscoveryWorkType.DRAIN, 0)));

        OffsetDateTime before = OffsetDateTime.now();
        claimer.claimDueBatch(BATCH_SIZE, CUTOFF);

        ArgumentCaptor<OffsetDateTime> parkedAt = ArgumentCaptor.forClass(OffsetDateTime.class);
        verify(workWriter).reschedule(eq(runUuid), eq(DiscoveryWorkType.DRAIN), eq(1), parkedAt.capture());
        // The rung for attempt 1 is 5s; the floor is what has to win.
        assertThat(parkedAt.getValue())
                .as("a row parked at its 5s rung is republished by the next sweep while its tick is still running")
                .isAfterOrEqualTo(before.plus(CLAIM_FLOOR));
    }

    @Test
    void aRungLongerThanTheFloor_keepsItsOwnCadence() {
        when(clusterSynchronizer.tryLock(any())).thenReturn(true);
        UUID runUuid = UUID.randomUUID();
        // Attempt 2 takes the ladder's ceiling, 30s here but minutes on the real STATUS ladder.
        when(workProperties.scheduleFor(any()))
                .thenReturn(new StatusPollProperties.PollSchedule(List.of(Duration.ofSeconds(5), Duration.ofMinutes(5)),
                        100));
        when(workRepository
                .findByNextDueAtLessThanEqualOrderByNextDueAt(any(OffsetDateTime.class), any(Pageable.class)))
                .thenReturn(List.of(workRow(runUuid, DiscoveryWorkType.STATUS, 1)));

        OffsetDateTime before = OffsetDateTime.now();
        claimer.claimDueBatch(BATCH_SIZE, CUTOFF);

        ArgumentCaptor<OffsetDateTime> parkedAt = ArgumentCaptor.forClass(OffsetDateTime.class);
        verify(workWriter).reschedule(eq(runUuid), eq(DiscoveryWorkType.STATUS), eq(2), parkedAt.capture());
        assertThat(parkedAt.getValue())
                .as("the floor must not shorten a ladder that already waits longer than it")
                .isAfterOrEqualTo(before.plusMinutes(5).minusSeconds(1));
    }

    /**
     * The floor outlives DRAIN's own ceiling, so it — not the ladder — sets what an idle drain settles at. Pinned
     * because it is a surprise: a reader of the ladder would expect thirty seconds, and the config said so once.
     */
    @Test
    void aCeilingShorterThanTheFloor_isOverriddenByIt() {
        when(clusterSynchronizer.tryLock(any())).thenReturn(true);
        UUID runUuid = UUID.randomUUID();
        // DRAIN's real ladder: its last rung is 30s, under the 35s floor.
        when(workProperties.scheduleFor(any()))
                .thenReturn(new StatusPollProperties.PollSchedule(
                        List.of(Duration.ofSeconds(1), Duration.ofSeconds(5), Duration.ofSeconds(30)), 100));
        when(workRepository
                .findByNextDueAtLessThanEqualOrderByNextDueAt(any(OffsetDateTime.class), any(Pageable.class)))
                .thenReturn(List.of(workRow(runUuid, DiscoveryWorkType.DRAIN, 3)));

        OffsetDateTime before = OffsetDateTime.now();
        claimer.claimDueBatch(BATCH_SIZE, CUTOFF);

        ArgumentCaptor<OffsetDateTime> parkedAt = ArgumentCaptor.forClass(OffsetDateTime.class);
        verify(workWriter).reschedule(eq(runUuid), eq(DiscoveryWorkType.DRAIN), eq(4), parkedAt.capture());
        assertThat(parkedAt.getValue())
                .as("an idle drain settles at the floor, not at the ladder's own ceiling")
                .isAfterOrEqualTo(before.plus(CLAIM_FLOOR));
    }

    private DiscoveryWork workRow(UUID runUuid, DiscoveryWorkType type, int attempt) {
        DiscoveryWork work = new DiscoveryWork();
        work.setDiscoveryUuid(runUuid);
        work.setWorkType(type);
        work.setAttempt(attempt);
        work.setNextDueAt(OffsetDateTime.now());
        return work;
    }
}
