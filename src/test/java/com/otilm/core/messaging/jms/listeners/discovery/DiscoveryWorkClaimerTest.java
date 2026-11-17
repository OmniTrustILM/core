package com.otilm.core.messaging.jms.listeners.discovery;

import com.otilm.core.cluster.ClusterOperationSynchronizer;
import com.otilm.core.dao.entity.DiscoveryWork;
import com.otilm.core.dao.repository.DiscoveryWorkRepository;
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

    private static final int BATCH_SIZE = 200;
    private static final OffsetDateTime CUTOFF = OffsetDateTime.now();
    private static final Duration LEASE_DURATION = Duration.ofMinutes(2);

    private DiscoveryWorkClaimer claimer;

    @BeforeEach
    void createClaimer() {
        claimer = new DiscoveryWorkClaimer(clusterSynchronizer, workRepository, workWriter, LEASE_DURATION);
    }

    @Test
    void returnsNothing_whenAnotherNodeHoldsTheSweepLock() {
        // given
        when(clusterSynchronizer.tryLock(ClusterOperationSynchronizer.Operation.DISCOVERY_WORK_SWEEP))
                .thenReturn(false);

        // when
        List<DiscoveryWorkMessage> messages = claimer.claimDueBatch(BATCH_SIZE, CUTOFF);

        // then
        assertThat(messages).isEmpty();
        verify(workRepository, never()).findClaimable(any(), any(), any());
        verify(workWriter, never()).claim(any(), any(), any(), anyInt(), any(), any(), any());
    }

    @Test
    void claimsNothing_whenNoRowIsClaimable() {
        // given
        when(clusterSynchronizer.tryLock(any(ClusterOperationSynchronizer.Operation.class))).thenReturn(true);
        when(workRepository.findClaimable(any(OffsetDateTime.class), any(OffsetDateTime.class), any(Pageable.class)))
                .thenReturn(List.of());

        // when
        List<DiscoveryWorkMessage> messages = claimer.claimDueBatch(BATCH_SIZE, CUTOFF);

        // then
        assertThat(messages).isEmpty();
        verify(workWriter, never()).claim(any(), any(), any(), anyInt(), any(), any(), any());
    }

    @Test
    void claimsTheRowOneAttemptUp_whenItIsClaimable() {
        // given
        when(clusterSynchronizer.tryLock(any(ClusterOperationSynchronizer.Operation.class))).thenReturn(true);
        var runUuid = UUID.randomUUID();
        var attemptAtClaim = 2;
        when(workRepository.findClaimable(any(OffsetDateTime.class), any(OffsetDateTime.class), any(Pageable.class)))
                .thenReturn(List.of(buildWorkRow(runUuid, DiscoveryWorkType.DRAIN, attemptAtClaim)));
        stubClaimSucceeding();

        // when
        List<DiscoveryWorkMessage> messages = claimer.claimDueBatch(BATCH_SIZE, CUTOFF);

        // then
        assertThat(messages).singleElement().satisfies(message -> {
            assertThat(message.discoveryUuid()).isEqualTo(runUuid);
            assertThat(message.workType()).isEqualTo(DiscoveryWorkType.DRAIN);
            assertThat(message.attempt()).isEqualTo(attemptAtClaim);
        });
        verify(workWriter)
                .claim(eq(runUuid), eq(DiscoveryWorkType.DRAIN), any(UUID.class), eq(attemptAtClaim + 1), eq(CUTOFF),
                        any(OffsetDateTime.class), any(OffsetDateTime.class));
        // The sweep-wide claim window: the due query runs against the caller's cutoff, not a fresh now().
        verify(workRepository).findClaimable(eq(CUTOFF), any(OffsetDateTime.class), any(Pageable.class));
    }

    @Test
    void carriesTheTokenItWroteToTheRow_whenClaimingIt() {
        // given
        when(clusterSynchronizer.tryLock(any(ClusterOperationSynchronizer.Operation.class))).thenReturn(true);
        when(workRepository.findClaimable(any(OffsetDateTime.class), any(OffsetDateTime.class), any(Pageable.class)))
                .thenReturn(List.of(buildWorkRow(UUID.randomUUID(), DiscoveryWorkType.STATUS, 0)));
        stubClaimSucceeding();

        // when
        List<DiscoveryWorkMessage> messages = claimer.claimDueBatch(BATCH_SIZE, CUTOFF);

        // then
        ArgumentCaptor<UUID> writtenToken = ArgumentCaptor.forClass(UUID.class);
        verify(workWriter).claim(any(), any(), writtenToken.capture(), anyInt(), any(), any(), any());
        assertThat(writtenToken.getValue()).isNotNull();
        assertThat(messages)
                .singleElement()
                .extracting(DiscoveryWorkMessage::leaseToken)
                .isEqualTo(writtenToken.getValue());
    }

    @Test
    void leasesTheRowForTheLeaseDuration_whenClaimingIt() {
        // given
        when(clusterSynchronizer.tryLock(any(ClusterOperationSynchronizer.Operation.class))).thenReturn(true);
        when(workRepository.findClaimable(any(OffsetDateTime.class), any(OffsetDateTime.class), any(Pageable.class)))
                .thenReturn(List.of(buildWorkRow(UUID.randomUUID(), DiscoveryWorkType.STATUS, 0)));
        stubClaimSucceeding();
        var beforeClaim = OffsetDateTime.now();

        // when
        claimer.claimDueBatch(BATCH_SIZE, CUTOFF);

        // then
        ArgumentCaptor<OffsetDateTime> leasedUntil = ArgumentCaptor.forClass(OffsetDateTime.class);
        verify(workWriter).claim(any(), any(), any(), anyInt(), any(), any(), leasedUntil.capture());
        assertThat(leasedUntil.getValue())
                .isAfterOrEqualTo(beforeClaim.plus(LEASE_DURATION))
                .isBeforeOrEqualTo(OffsetDateTime.now().plus(LEASE_DURATION));
    }

    @Test
    void publishesNothingForARow_whenATickLeasedItAfterTheSweepReadIt() {
        // given
        when(clusterSynchronizer.tryLock(any(ClusterOperationSynchronizer.Operation.class))).thenReturn(true);
        when(workRepository.findClaimable(any(OffsetDateTime.class), any(OffsetDateTime.class), any(Pageable.class)))
                .thenReturn(List.of(buildWorkRow(UUID.randomUUID(), DiscoveryWorkType.DRAIN, 0)));
        when(workWriter.claim(any(), any(), any(), anyInt(), any(), any(), any())).thenReturn(false);

        // when
        List<DiscoveryWorkMessage> messages = claimer.claimDueBatch(BATCH_SIZE, CUTOFF);

        // then
        assertThat(messages).isEmpty();
    }

    // ── Helpers ───────────────────────────────────────────────────────────────

    private void stubClaimSucceeding() {
        when(workWriter.claim(any(), any(), any(), anyInt(), any(), any(), any())).thenReturn(true);
    }

    private static DiscoveryWork buildWorkRow(UUID runUuid, DiscoveryWorkType type, int attempt) {
        DiscoveryWork work = new DiscoveryWork();
        work.setDiscoveryUuid(runUuid);
        work.setWorkType(type);
        work.setAttempt(attempt);
        work.setNextDueAt(OffsetDateTime.now());
        return work;
    }
}
