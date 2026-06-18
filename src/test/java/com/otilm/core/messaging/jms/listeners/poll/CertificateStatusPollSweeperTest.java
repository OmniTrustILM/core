package com.otilm.core.messaging.jms.listeners.poll;

import com.otilm.api.model.core.auth.Resource;
import com.otilm.core.messaging.jms.producers.CertificateStatusPollProducer;
import com.otilm.core.messaging.model.CertificateStatusPollMessage;
import com.otilm.core.service.handler.authority.CertificateOperation;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.util.List;
import java.util.UUID;

import static org.mockito.ArgumentMatchers.anyInt;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class CertificateStatusPollSweeperTest {

    @Mock private CertificateStatusPollClaimer pollClaimer;
    @Mock private CertificateStatusPollProducer pollProducer;

    private static final int BATCH_SIZE = 200;

    private CertificateStatusPollSweeper sweeper;

    @BeforeEach
    void setUp() {
        sweeper = new CertificateStatusPollSweeper(pollClaimer, pollProducer, BATCH_SIZE, 10);
    }

    @Test
    void noDueRows_sendsNothing() {
        when(pollClaimer.claimDueBatch(BATCH_SIZE)).thenReturn(List.of());

        sweeper.sweep();

        verifyNoInteractions(pollProducer);
    }

    @Test
    void due_sendsClaimedMessagesOutsideTheClaim() {
        CertificateStatusPollMessage msg = new CertificateStatusPollMessage(
                Resource.CERTIFICATE, UUID.randomUUID(), CertificateOperation.ISSUE, 2);
        // A partial batch (< batchSize) ends the loop after one round.
        when(pollClaimer.claimDueBatch(BATCH_SIZE)).thenReturn(List.of(msg));

        sweeper.sweep();

        verify(pollProducer).produceMessage(msg);
        // Claiming is the only transactional/lock-holding step; sends happen after it.
        verify(pollClaimer).claimDueBatch(anyInt());
    }
}
