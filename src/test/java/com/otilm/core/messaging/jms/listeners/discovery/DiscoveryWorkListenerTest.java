package com.otilm.core.messaging.jms.listeners.discovery;

import com.otilm.core.messaging.jms.configuration.DiscoveryWorkProperties;
import com.otilm.core.messaging.jms.configuration.StatusPollProperties.PollSchedule;
import com.otilm.core.messaging.model.DiscoveryWorkMessage;
import com.otilm.core.model.discovery.DiscoveryWorkType;
import com.otilm.core.service.handler.discovery.DiscoveryDrainTickWorker;
import com.otilm.core.service.handler.discovery.DiscoveryProcessTickWorker;
import com.otilm.core.service.handler.discovery.DiscoveryStatusTickWorker;
import com.otilm.core.service.writer.discovery.DiscoveryWorkLease;
import com.otilm.core.service.writer.discovery.DiscoveryWorkTick;
import java.time.Duration;
import java.time.OffsetDateTime;
import java.util.List;
import java.util.Optional;
import java.util.UUID;
import org.assertj.core.api.ThrowableAssert.ThrowingCallable;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatCode;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyInt;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.lenient;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class DiscoveryWorkListenerTest {

    private static final PollSchedule LADDER = new PollSchedule(
            List.of(Duration.ofSeconds(1), Duration.ofSeconds(5), Duration.ofSeconds(30)), 170);

    @Mock
    private DiscoveryWorkLease lease;
    @Mock
    private DiscoveryWorkProperties workProperties;
    @Mock
    private DiscoveryStatusTickWorker statusWorker;
    @Mock
    private DiscoveryDrainTickWorker drainWorker;
    @Mock
    private DiscoveryProcessTickWorker processWorker;

    private DiscoveryWorkListener listener;

    @BeforeEach
    void createListener() {
        listener = new DiscoveryWorkListener(lease, workProperties, statusWorker, drainWorker, processWorker);
        lenient().when(workProperties.scheduleFor(any())).thenReturn(LADDER);
    }

    @Test
    void runsTheStatusWorker_whenAStatusTickIsAdmitted() {
        // given
        var message = message(DiscoveryWorkType.STATUS, 4);
        DiscoveryWorkTick tick = admit(message);

        // when
        listener.processMessage(message);

        // then
        verify(statusWorker).tick(tick);
        verifyNoInteractions(drainWorker, processWorker);
    }

    @Test
    void runsTheDrainWorker_whenADrainTickIsAdmitted() {
        // given
        var message = message(DiscoveryWorkType.DRAIN, 2);
        DiscoveryWorkTick tick = admit(message);

        // when
        listener.processMessage(message);

        // then
        verify(drainWorker).tick(tick);
        verifyNoInteractions(statusWorker, processWorker);
    }

    @Test
    void runsTheProcessWorker_whenAProcessTickIsAdmitted() {
        // given
        var message = message(DiscoveryWorkType.PROCESS, 7);
        DiscoveryWorkTick tick = admit(message);

        // when
        listener.processMessage(message);

        // then
        verify(processWorker).tick(tick);
        verifyNoInteractions(statusWorker, drainWorker);
    }

    @Test
    void neverRunsAWorker_whenTheTicksTokenIsNoLongerTheRows() {
        // given
        var staleMessage = message(DiscoveryWorkType.DRAIN, 0);
        when(lease.admit(staleMessage)).thenReturn(Optional.empty());

        // when
        listener.processMessage(staleMessage);

        // then
        verifyNoInteractions(statusWorker, drainWorker, processWorker);
    }

    @Test
    void reschedulesTheTickToItsNextRung_whenTheWorkerLeftItUnresolved() {
        // given
        var unresolvedAttempt = 1;
        var message = message(DiscoveryWorkType.DRAIN, unresolvedAttempt);
        DiscoveryWorkTick tick = admit(message);
        var beforeTick = OffsetDateTime.now();

        // when
        listener.processMessage(message);

        // then
        ArgumentCaptor<OffsetDateTime> nextDueAt = ArgumentCaptor.forClass(OffsetDateTime.class);
        verify(tick).reschedule(eq(unresolvedAttempt + 1), nextDueAt.capture());
        Duration nextRung = LADDER.delayFor(unresolvedAttempt + 1);
        assertThat(nextDueAt.getValue())
                .isAfterOrEqualTo(beforeTick.plus(nextRung))
                .isBeforeOrEqualTo(OffsetDateTime.now().plus(nextRung));
    }

    @Test
    void leavesTheTickAlone_whenTheWorkerResolvedIt() {
        // given
        var message = message(DiscoveryWorkType.STATUS, 0);
        DiscoveryWorkTick tick = admit(message);
        when(tick.resolved()).thenReturn(true);

        // when
        listener.processMessage(message);

        // then
        verify(tick, never()).reschedule(anyInt(), any());
    }

    @Test
    void swallowsAWorkerFailure_soTheAgendaOwnsTheRetry() {
        // given
        var message = message(DiscoveryWorkType.STATUS, 0);
        DiscoveryWorkTick tick = admit(message);
        doThrow(new IllegalStateException("connector blew up")).when(statusWorker).tick(tick);

        // when
        ThrowingCallable processMessage = () -> listener.processMessage(message);

        // then
        assertThatCode(processMessage).doesNotThrowAnyException();
        verify(tick).reschedule(eq(1), any(OffsetDateTime.class));
    }

    // ── Helpers ───────────────────────────────────────────────────────────────

    private static DiscoveryWorkMessage message(DiscoveryWorkType workType, int attempt) {
        return new DiscoveryWorkMessage(UUID.randomUUID(), workType, attempt, UUID.randomUUID());
    }

    private DiscoveryWorkTick admit(DiscoveryWorkMessage message) {
        DiscoveryWorkTick tick = mock(DiscoveryWorkTick.class);
        lenient().when(tick.discoveryUuid()).thenReturn(message.discoveryUuid());
        lenient().when(tick.workType()).thenReturn(message.workType());
        lenient().when(tick.attempt()).thenReturn(message.attempt());
        when(lease.admit(message)).thenReturn(Optional.of(tick));
        return tick;
    }
}
