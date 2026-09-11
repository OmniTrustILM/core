package com.otilm.core.messaging.jms.listeners.discovery;

import com.otilm.api.model.core.discovery.DiscoveryMessageSeverity;
import com.otilm.api.model.core.discovery.DiscoveryStatus;
import com.otilm.core.cluster.ClusterOperationSynchronizer;
import com.otilm.core.dao.entity.ConnectorInterfaceEntity;
import com.otilm.core.dao.entity.Discovery;
import com.otilm.core.dao.repository.ConnectorInterfaceRepository;
import com.otilm.core.dao.repository.DiscoveryCertificateRepository;
import com.otilm.core.dao.repository.DiscoveryRepository;
import com.otilm.core.dao.repository.DiscoveryWorkRepository;
import com.otilm.core.dao.repository.ScheduledJobHistoryRepository;
import com.otilm.core.events.transaction.TransactionHandler;
import com.otilm.core.service.handler.discovery.DiscoveryRunTerminator;
import com.otilm.core.service.handler.discovery.DiscoveryV2Client;
import com.otilm.core.service.writer.discovery.DiscoveryMessageWriter;
import com.otilm.core.service.writer.discovery.DiscoveryWorkWriter;
import com.otilm.core.util.DiscoveryRunMetaFixture;
import java.time.Duration;
import java.time.OffsetDateTime;
import java.time.ZoneOffset;
import java.util.List;
import java.util.Optional;
import java.util.UUID;
import java.util.function.Supplier;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.context.ApplicationEventPublisher;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatCode;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.lenient;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;

/**
 * Unit coverage for {@link DiscoveryRunReaper#reap()}'s per-run behaviors, with collaborators mocked.
 *
 * <p>
 * <b>Unit scope:</b> what a real-DB test cannot exercise deterministically — the under-lock re-assertions (skip a run
 * that gained agenda rows or escaped its stop), the post-commit connector cancel, and the per-run failure isolation
 * (one run's exception must not abort the rest of the batch).
 *
 * <p>
 * <b>Integration scope:</b> the selection predicates and terminal outcomes run against real Postgres in
 * {@link com.otilm.core.integration.discovery.DiscoveryWorkSweepITest}.
 */
@ExtendWith(MockitoExtension.class)
class DiscoveryRunReaperUnitTest {

    @Mock
    private DiscoveryRepository discoveryRepository;
    @Mock
    private DiscoveryWorkRepository workRepository;
    @Mock
    private DiscoveryWorkWriter workWriter;
    @Mock
    private DiscoveryMessageWriter messageWriter;
    @Mock
    private DiscoveryV2Client discoveryV2Client;
    @Mock
    private ConnectorInterfaceRepository connectorInterfaceRepository;
    @Mock
    private ApplicationEventPublisher eventPublisher;
    @Mock
    private ScheduledJobHistoryRepository scheduledJobHistoryRepository;
    @Mock
    private TransactionHandler transactionHandler;
    @Mock
    private ClusterOperationSynchronizer clusterSynchronizer;
    @Mock
    private DiscoveryCertificateRepository certificateRepository;

    private DiscoveryRunReaper reaper;

    @SuppressWarnings({"unchecked", "rawtypes"})
    @BeforeEach
    void setUp() {
        // A real terminator, not a mock: the reaper delegates the terminal mutation to it, and that mutation
        // is what these tests assert on. Of its collaborators, applyTerminalState reaches the message writer,
        // the event publisher and the certificate repository it counts staged rows with.
        reaper = new DiscoveryRunReaper(discoveryRepository, workRepository, workWriter, discoveryV2Client,
                connectorInterfaceRepository, transactionHandler, clusterSynchronizer,
                new DiscoveryRunTerminator(discoveryRepository, workWriter, messageWriter, transactionHandler,
                        eventPublisher, scheduledJobHistoryRepository, certificateRepository),
                Duration.ofMinutes(5), Duration.ofDays(7));
        // Execute the transactional lambdas inline so the real selection/reap logic runs under the test.
        lenient()
                .when(transactionHandler.runInNewTransaction(any(Supplier.class)))
                .thenAnswer(inv -> ((Supplier<?>) inv.getArgument(0)).get());
        lenient()
                .when(clusterSynchronizer.tryLock(ClusterOperationSynchronizer.Operation.DISCOVERY_WORK_SWEEP))
                .thenReturn(true);
        // Every fixture run is a v2 run, which is what makes it eligible for the connector-side cancel.
        ConnectorInterfaceEntity v2Interface = new ConnectorInterfaceEntity();
        v2Interface.setVersion("v2");
        lenient().when(connectorInterfaceRepository.findById(any())).thenReturn(Optional.of(v2Interface));
    }

    @Test
    void skipsAllWorkWhenAdvisoryLockNotAcquired() {
        when(clusterSynchronizer.tryLock(ClusterOperationSynchronizer.Operation.DISCOVERY_WORK_SWEEP))
                .thenReturn(false);

        reaper.reap();

        verify(discoveryRepository, never()).findWorkLostRunUuids(any(), any(), any());
        verify(discoveryRepository, never()).findExpiredStoppedRunUuids(any(), any());
        verify(discoveryRepository, never()).findWithLockByUuid(any());
    }

    @Test
    void workLost_skipsRunThatGainedAgendaRowsUnderLock() {
        Discovery run = run(DiscoveryStatus.IN_PROGRESS);
        selections(List.of(run.getUuid()), List.of());
        when(discoveryRepository.findWithLockByUuid(run.getUuid())).thenReturn(Optional.of(run));
        // Between selection and locking the run gained agenda rows: it is driven again.
        when(workRepository.existsByDiscoveryUuid(run.getUuid())).thenReturn(true);

        reaper.reap();

        assertThat(run.getStatus()).isEqualTo(DiscoveryStatus.IN_PROGRESS);
        assertThat(run.getEndTime()).isNull();
    }

    @Test
    void workLost_oneRunFailureDoesNotAbortTheBatch() {
        Discovery healthy = run(DiscoveryStatus.IN_PROGRESS);
        UUID failing = UUID.randomUUID();
        selections(List.of(failing, healthy.getUuid()), List.of());
        when(discoveryRepository.findWithLockByUuid(failing)).thenThrow(new RuntimeException("lock timeout"));
        when(discoveryRepository.findWithLockByUuid(healthy.getUuid())).thenReturn(Optional.of(healthy));
        when(workRepository.existsByDiscoveryUuid(healthy.getUuid())).thenReturn(false);

        assertThatCode(() -> reaper.reap()).doesNotThrowAnyException();

        assertThat(healthy.getStatus()).isEqualTo(DiscoveryStatus.FAILED);
        // A reaped run must record the same ending in its log as one a worker ended.
        verify(messageWriter)
                .appendRunEnded(healthy.getUuid(), DiscoveryMessageSeverity.ERROR,
                        "Discovery work lost; the run can no longer be driven");
    }

    @Test
    void workLost_tellsTheConnectorEvenWithNoHandleToReplay() throws Exception {
        Discovery withContext = run(DiscoveryStatus.IN_PROGRESS);
        withContext.setRunMeta(DiscoveryRunMetaFixture.runMeta("cursor", "abc"));
        Discovery withoutContext = run(DiscoveryStatus.IN_PROGRESS);
        selections(List.of(withContext.getUuid(), withoutContext.getUuid()), List.of());
        when(discoveryRepository.findWithLockByUuid(withContext.getUuid())).thenReturn(Optional.of(withContext));
        when(discoveryRepository.findWithLockByUuid(withoutContext.getUuid())).thenReturn(Optional.of(withoutContext));

        reaper.reap();

        assertThat(withContext.getStatus()).isEqualTo(DiscoveryStatus.FAILED);
        assertThat(withoutContext.getStatus()).isEqualTo(DiscoveryStatus.FAILED);
        // Both are told. A control call is addressed by runId with meta optional, so a run whose handle was
        // never persisted can still be scanning and can still be stopped -- skipping it would leave that scan running.
        verify(discoveryV2Client).cancel(withContext);
        verify(discoveryV2Client).cancel(withoutContext);
    }

    @Test
    void stopExpired_skipsResumedRunAndCancelsNothingOnTheConnector() throws Exception {
        // The run escaped its stop between selection and action: status moved off STOPPED, stoppedAt stale.
        Discovery resumed = run(DiscoveryStatus.IN_PROGRESS);
        resumed.setStoppedAt(OffsetDateTime.now(ZoneOffset.UTC).minusDays(30));
        selections(List.of(), List.of(resumed.getUuid()));
        when(discoveryRepository.findWithLockByUuid(resumed.getUuid())).thenReturn(Optional.of(resumed));

        reaper.reap();

        // No terminal transition committed, so nothing may reach the connector.
        verifyNoInteractions(discoveryV2Client);
        assertThat(resumed.getStatus()).isEqualTo(DiscoveryStatus.IN_PROGRESS);
        verify(workWriter, never()).deleteForRun(any());
    }

    @Test
    void stopExpired_oneRunFailureDoesNotAbortTheBatch() throws Exception {
        Discovery healthy = expiredStoppedRun();
        UUID failing = UUID.randomUUID();
        selections(List.of(), List.of(failing, healthy.getUuid()));
        when(discoveryRepository.findWithLockByUuid(failing)).thenThrow(new RuntimeException("lock timeout"));
        when(discoveryRepository.findWithLockByUuid(healthy.getUuid())).thenReturn(Optional.of(healthy));

        assertThatCode(() -> reaper.reap()).doesNotThrowAnyException();

        assertThat(healthy.getStatus()).isEqualTo(DiscoveryStatus.CANCELLED);
        verify(workWriter).deleteForRun(healthy.getUuid());
        // The cancel fired only after the terminal transition, replaying the pre-wipe run context.
        verify(discoveryV2Client).cancel(healthy);
        assertThat(healthy.getRunMeta()).isNotNull();
    }

    @Test
    void stopExpired_connectorCancelFailureDoesNotBlockTheLocalCancel() throws Exception {
        Discovery expired = expiredStoppedRun();
        selections(List.of(), List.of(expired.getUuid()));
        when(discoveryRepository.findWithLockByUuid(expired.getUuid())).thenReturn(Optional.of(expired));
        when(discoveryV2Client.cancel(any())).thenThrow(new IllegalStateException("connector unreachable"));

        assertThatCode(() -> reaper.reap()).doesNotThrowAnyException();

        assertThat(expired.getStatus()).isEqualTo(DiscoveryStatus.CANCELLED);
    }

    private void selections(List<UUID> workLost, List<UUID> stopExpired) {
        when(discoveryRepository.findWorkLostRunUuids(any(), any(), any())).thenReturn(workLost);
        when(discoveryRepository.findExpiredStoppedRunUuids(any(), any())).thenReturn(stopExpired);
    }

    @Test
    void workLost_sendsNothingForAV1Run() throws Exception {
        Discovery v1 = run(DiscoveryStatus.IN_PROGRESS);
        v1.setConnectorInterfaceUuid(null);
        selections(List.of(v1.getUuid()), List.of());
        when(discoveryRepository.findWithLockByUuid(v1.getUuid())).thenReturn(Optional.of(v1));

        reaper.reap();

        // A v1 run's provider call is synchronous and already over, so there is no scan to stop and no v2
        // endpoint to ask -- reaching for one would only produce a warning on every reap.
        assertThat(v1.getStatus()).isEqualTo(DiscoveryStatus.FAILED);
        verifyNoInteractions(discoveryV2Client);
    }

    private static Discovery run(DiscoveryStatus status) {
        Discovery run = new Discovery();
        run.setUuid(UUID.randomUUID());
        run.setStatus(status);
        run.setConnectorStatus(status);
        run.setConnectorInterfaceUuid(UUID.randomUUID());
        return run;
    }

    private static Discovery expiredStoppedRun() {
        Discovery run = run(DiscoveryStatus.STOPPED);
        run.setStoppedAt(OffsetDateTime.now(ZoneOffset.UTC).minusDays(8));
        run.setRunMeta(DiscoveryRunMetaFixture.runMeta("cursor", "abc"));
        return run;
    }
}
