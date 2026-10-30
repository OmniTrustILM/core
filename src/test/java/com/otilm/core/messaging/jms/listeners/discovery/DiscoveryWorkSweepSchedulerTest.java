package com.otilm.core.messaging.jms.listeners.discovery;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import static org.mockito.Mockito.verify;

@ExtendWith(MockitoExtension.class)
class DiscoveryWorkSweepSchedulerTest {

    @Mock
    private DiscoveryWorkSweeper sweeper;

    @Test
    void sweepScheduled_delegatesToSweeper() {
        new DiscoveryWorkSweepScheduler(sweeper).sweepScheduled();

        verify(sweeper).sweep();
    }
}
