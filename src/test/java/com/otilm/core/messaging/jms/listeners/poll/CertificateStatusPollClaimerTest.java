package com.otilm.core.messaging.jms.listeners.poll;

import com.otilm.core.cluster.ClusterOperationSynchronizer;
import com.otilm.core.dao.entity.CertificateStatusPoll;
import com.otilm.core.dao.repository.CertificateStatusPollRepository;
import com.otilm.core.messaging.jms.configuration.StatusPollProperties;
import com.otilm.core.messaging.model.CertificateStatusPollMessage;
import com.otilm.core.service.handler.authority.CertificateOperation;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.data.domain.Pageable;

import java.time.Duration;
import java.time.OffsetDateTime;
import java.util.List;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyInt;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.lenient;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class CertificateStatusPollClaimerTest {

    @Mock private ClusterOperationSynchronizer clusterSynchronizer;
    @Mock private CertificateStatusPollRepository pollRepository;
    @Mock private StatusPollProperties statusPollProperties;

    private static final int BATCH_SIZE = 200;

    private CertificateStatusPollClaimer claimer;

    @BeforeEach
    void setUp() {
        claimer = new CertificateStatusPollClaimer(clusterSynchronizer, pollRepository, statusPollProperties);

        StatusPollProperties.PollSchedule schedule = new StatusPollProperties.PollSchedule(
                List.of(Duration.ofSeconds(5), Duration.ofSeconds(30)), 100);
        lenient().when(statusPollProperties.scheduleFor(any())).thenReturn(schedule);
    }

    @Test
    void lockNotHeld_returnsEmptyAndReadsNothing() {
        when(clusterSynchronizer.tryLock(ClusterOperationSynchronizer.Operation.PROVIDER_STATUS_POLL_SWEEP))
                .thenReturn(false);

        assertThat(claimer.claimDueBatch(BATCH_SIZE)).isEmpty();

        verify(pollRepository, never()).findByNextPollAtLessThanEqualOrderByNextPollAt(any(), any());
        verify(pollRepository, never()).reschedule(any(), anyInt(), any());
    }

    @Test
    void noDueRows_returnsEmptyAndDoesNotReschedule() {
        when(clusterSynchronizer.tryLock(any())).thenReturn(true);
        when(pollRepository.findByNextPollAtLessThanEqualOrderByNextPollAt(any(OffsetDateTime.class), any(Pageable.class)))
                .thenReturn(List.of());

        assertThat(claimer.claimDueBatch(BATCH_SIZE)).isEmpty();

        verify(pollRepository, never()).reschedule(any(), anyInt(), any());
    }

    @Test
    void dueRow_buildsMessageAndAdvancesSchedule() {
        when(clusterSynchronizer.tryLock(any())).thenReturn(true);
        UUID certUuid = UUID.randomUUID();
        when(pollRepository.findByNextPollAtLessThanEqualOrderByNextPollAt(any(OffsetDateTime.class), any(Pageable.class)))
                .thenReturn(List.of(pollRow(certUuid, CertificateOperation.ISSUE, 2)));

        List<CertificateStatusPollMessage> messages = claimer.claimDueBatch(BATCH_SIZE);

        assertThat(messages).hasSize(1);
        assertThat(messages.get(0).resourceUuid()).isEqualTo(certUuid);
        assertThat(messages.get(0).op()).isEqualTo(CertificateOperation.ISSUE);
        assertThat(messages.get(0).attempt()).isEqualTo(2);

        // attempt advanced and next_poll_at pushed out so the row is not re-claimed until next due.
        verify(pollRepository).reschedule(eq(certUuid), eq(3), any(OffsetDateTime.class));
    }

    private CertificateStatusPoll pollRow(UUID certUuid, CertificateOperation op, int attempt) {
        CertificateStatusPoll poll = new CertificateStatusPoll();
        poll.setCertificateUuid(certUuid);
        poll.setOperation(op);
        poll.setAttempt(attempt);
        poll.setNextPollAt(OffsetDateTime.now());
        return poll;
    }
}
