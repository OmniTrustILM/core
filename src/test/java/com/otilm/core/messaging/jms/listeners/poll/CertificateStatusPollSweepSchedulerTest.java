package com.otilm.core.messaging.jms.listeners.poll;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import static org.mockito.Mockito.verify;

@ExtendWith(MockitoExtension.class)
class CertificateStatusPollSweepSchedulerTest {

    @Mock private CertificateStatusPollSweeper sweeper;

    @Test
    void sweepScheduled_delegatesToSweeper() {
        new CertificateStatusPollSweepScheduler(sweeper).sweepScheduled();

        verify(sweeper).sweep();
    }
}
