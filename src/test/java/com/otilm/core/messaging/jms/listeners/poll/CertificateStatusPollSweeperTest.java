package com.otilm.core.messaging.jms.listeners.poll;

import com.otilm.core.cluster.ClusterOperationSynchronizer;
import com.otilm.core.dao.entity.CertificateStatusPoll;
import com.otilm.core.dao.repository.CertificateStatusPollRepository;
import com.otilm.core.messaging.jms.configuration.StatusPollProperties;
import com.otilm.core.messaging.jms.producers.CertificateStatusPollProducer;
import com.otilm.core.messaging.model.CertificateStatusPollMessage;
import com.otilm.core.service.handler.authority.CertificateOperation;
import com.otilm.core.service.writer.statuspoll.CertificateStatusPollWriter;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.data.domain.Pageable;

import java.time.Duration;
import java.time.OffsetDateTime;
import java.util.List;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.lenient;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class CertificateStatusPollSweeperTest {

    @Mock private ClusterOperationSynchronizer clusterSynchronizer;
    @Mock private CertificateStatusPollRepository pollRepository;
    @Mock private CertificateStatusPollWriter pollWriter;
    @Mock private CertificateStatusPollProducer pollProducer;
    @Mock private StatusPollProperties statusPollProperties;

    private static final int BATCH_SIZE = 200;

    private CertificateStatusPollSweeper sweeper;

    @BeforeEach
    void setUp() {
        sweeper = new CertificateStatusPollSweeper(
                clusterSynchronizer, pollRepository, pollWriter, pollProducer, statusPollProperties, BATCH_SIZE, 10);

        StatusPollProperties.PollSchedule schedule = new StatusPollProperties.PollSchedule(
                List.of(Duration.ofSeconds(5), Duration.ofSeconds(30)), 100);
        lenient().when(statusPollProperties.scheduleFor(any())).thenReturn(schedule);
    }

    @Test
    void lockNotHeld_skipsEntirely() {
        when(clusterSynchronizer.tryLock(ClusterOperationSynchronizer.Operation.PROVIDER_STATUS_POLL_SWEEP))
                .thenReturn(false);

        sweeper.sweep();

        verifyNoInteractions(pollRepository, pollProducer, pollWriter);
    }

    @Test
    void noDueRows_enqueuesNothing() {
        when(clusterSynchronizer.tryLock(any())).thenReturn(true);
        when(pollRepository.findByNextPollAtLessThanEqualOrderByNextPollAt(any(OffsetDateTime.class), any(Pageable.class)))
                .thenReturn(List.of());

        sweeper.sweep();

        verifyNoInteractions(pollProducer, pollWriter);
    }

    @Test
    void dueRows_enqueuedAndRescheduled() {
        when(clusterSynchronizer.tryLock(any())).thenReturn(true);
        UUID certUuid = UUID.randomUUID();
        CertificateStatusPoll poll = pollRow(certUuid, CertificateOperation.ISSUE, 2);
        when(pollRepository.findByNextPollAtLessThanEqualOrderByNextPollAt(any(OffsetDateTime.class), any(Pageable.class)))
                .thenReturn(List.of(poll));

        sweeper.sweep();

        ArgumentCaptor<CertificateStatusPollMessage> msgCaptor =
                ArgumentCaptor.forClass(CertificateStatusPollMessage.class);
        verify(pollProducer).produceMessage(msgCaptor.capture());
        assertThat(msgCaptor.getValue().resourceUuid()).isEqualTo(certUuid);
        assertThat(msgCaptor.getValue().op()).isEqualTo(CertificateOperation.ISSUE);
        assertThat(msgCaptor.getValue().attempt()).isEqualTo(2);

        // attempt is advanced; next_poll_at is pushed out by the curve so the row is not re-claimed
        // until the next backoff step elapses.
        verify(pollWriter).reschedule(eq(certUuid), eq(3), any(OffsetDateTime.class));
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
