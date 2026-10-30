package com.otilm.core.messaging.jms.listeners.discovery;

import com.otilm.core.messaging.model.DiscoveryWorkMessage;
import com.otilm.core.model.discovery.DiscoveryWorkType;
import com.otilm.core.service.handler.discovery.DiscoveryDrainTickWorker;
import com.otilm.core.service.handler.discovery.DiscoveryProcessTickWorker;
import com.otilm.core.service.handler.discovery.DiscoveryStatusTickWorker;
import java.util.UUID;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import static org.assertj.core.api.Assertions.assertThatCode;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;

@ExtendWith(MockitoExtension.class)
class DiscoveryWorkListenerTest {

    @Mock
    private DiscoveryStatusTickWorker statusWorker;
    @Mock
    private DiscoveryDrainTickWorker drainWorker;
    @Mock
    private DiscoveryProcessTickWorker processWorker;

    private DiscoveryWorkListener listener;

    @BeforeEach
    void setUp() {
        listener = new DiscoveryWorkListener(statusWorker, drainWorker, processWorker);
    }

    @Test
    void statusTick_reachesTheStatusWorkerWithItsAttemptCount() {
        UUID runUuid = UUID.randomUUID();

        listener.processMessage(new DiscoveryWorkMessage(runUuid, DiscoveryWorkType.STATUS, 4));

        verify(statusWorker).tick(runUuid, 4);
    }

    @Test
    void drainTick_reachesTheDrainWorkerWithItsAttemptCount() {
        UUID runUuid = UUID.randomUUID();

        listener.processMessage(new DiscoveryWorkMessage(runUuid, DiscoveryWorkType.DRAIN, 2));

        verify(drainWorker).tick(runUuid, 2);
        verifyNoInteractions(statusWorker);
    }

    @Test
    void processTick_reachesTheProcessWorkerWithItsAttemptCount() {
        UUID runUuid = UUID.randomUUID();

        listener.processMessage(new DiscoveryWorkMessage(runUuid, DiscoveryWorkType.PROCESS, 7));

        verify(processWorker).tick(runUuid, 7);
        verifyNoInteractions(statusWorker, drainWorker);
    }

    @Test
    void failingTick_isSwallowedSoTheAgendaOwnsTheRetry() {
        UUID runUuid = UUID.randomUUID();
        doThrow(new IllegalStateException("connector blew up")).when(statusWorker).tick(runUuid, 0);

        // Letting this out would put the broker's redelivery loop on top of the agenda's backoff ladder,
        // retrying at the broker's cadence instead of the run's.
        assertThatCode(() -> listener.processMessage(new DiscoveryWorkMessage(runUuid, DiscoveryWorkType.STATUS, 0)))
                .doesNotThrowAnyException();
    }
}
