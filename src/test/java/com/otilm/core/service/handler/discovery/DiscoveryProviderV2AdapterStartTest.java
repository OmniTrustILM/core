package com.otilm.core.service.handler.discovery;

import com.otilm.api.model.client.connector.v2.FeatureFlag;
import com.otilm.api.model.client.discovery.DiscoveryWindowMode;
import com.otilm.api.model.connector.discovery.v2.DiscoveryInitiateResponseDto;
import com.otilm.api.model.core.auth.Resource;
import com.otilm.api.model.core.discovery.DiscoveryStatus;
import com.otilm.core.dao.entity.ConnectorInterfaceEntity;
import com.otilm.core.dao.entity.Discovery;
import com.otilm.core.dao.repository.ConnectorInterfaceRepository;
import com.otilm.core.dao.repository.DiscoveryRepository;
import com.otilm.core.events.transaction.TransactionHandler;
import com.otilm.core.messaging.jms.configuration.DiscoveryWorkProperties;
import com.otilm.core.messaging.jms.configuration.StatusPollProperties;
import com.otilm.core.service.handler.ConnectorCapabilityService;
import com.otilm.core.service.writer.discovery.DiscoveryRunWriter;
import com.otilm.core.service.writer.discovery.DiscoveryWorkWriter;
import com.otilm.core.tasks.ScheduledJobInfo;
import java.time.Duration;
import java.time.OffsetDateTime;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.UUID;
import java.util.function.Function;
import org.assertj.core.api.ThrowableAssert.ThrowingCallable;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.ArgumentMatchers.isNull;
import static org.mockito.Mockito.lenient;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;

/**
 * The one window {@code DiscoveryStartFailureITest} cannot reach: everything the connector and the agenda need has
 * succeeded, and the failure is in mapping the detail Core hands back. Mocked, because no data can make that read fail
 * without also failing the bookkeeping before it.
 */
class DiscoveryProviderV2AdapterStartTest {

    private final DiscoveryRepository discoveryRepository = mock(DiscoveryRepository.class);
    private final DiscoveryDetailCounts detailCounts = mock(DiscoveryDetailCounts.class);
    private final ConnectorInterfaceRepository connectorInterfaceRepository = mock(ConnectorInterfaceRepository.class);
    private final DiscoveryV2Client client = mock(DiscoveryV2Client.class);
    private final DiscoveryWorkWriter workWriter = mock(DiscoveryWorkWriter.class);
    private final DiscoveryRunTerminator terminator = mock(DiscoveryRunTerminator.class);
    private final ConnectorCapabilityService capabilityService = mock(ConnectorCapabilityService.class);
    private final DiscoveryWindowResolver windowResolver = mock(DiscoveryWindowResolver.class);

    private final DiscoveryProviderV2Adapter adapter = new DiscoveryProviderV2Adapter(discoveryRepository, detailCounts,
            connectorInterfaceRepository, client, workWriter, terminator, capabilityService, new TransactionHandler(),
            new DiscoveryWorkProperties(new StatusPollProperties.PollSchedule(List.of(Duration.ofSeconds(1)), 3),
                    Map.of()),
            mock(DiscoveryRunWriter.class), new DiscoveryDeliveryModeOffer("buffered"), windowResolver);

    /**
     * A failure after both agenda rows are committed still has to tell the connector to drop the run: the run ends
     * terminal, so the reaper never collects it, and the scan would otherwise run until the connector's own timeout.
     */
    @Test
    void aStartWhoseDetailCannotBeMappedDropsTheRunAtTheConnector() throws Exception {
        Discovery run = new Discovery();
        run.setUuid(UUID.randomUUID());
        run.setStatus(DiscoveryStatus.IN_PROGRESS);
        run.setResources(List.of(Resource.CERTIFICATE));
        when(discoveryRepository.findByUuid(run.getUuid())).thenReturn(Optional.of(run));
        when(discoveryRepository.findWithLockByUuid(run.getUuid())).thenReturn(Optional.of(run));
        when(client.supportedResources(run)).thenReturn(List.of(Resource.CERTIFICATE));
        DiscoveryInitiateResponseDto response = new DiscoveryInitiateResponseDto();
        response.setCheckpoint(List.of());
        when(client.initiate(run)).thenReturn(response);
        when(detailCounts.forRun(run)).thenThrow(new IllegalStateException("counts unavailable"));
        when(terminator.endWith(eq(run.getUuid()), any())).thenReturn(true);

        // The failure path maps the same detail and fails the same way; what matters is what the start left behind.
        UUID runUuid = run.getUuid();
        assertThatThrownBy(() -> adapter.start(runUuid, null)).isInstanceOf(IllegalStateException.class);

        verify(client).cancel(run);
        @SuppressWarnings("unchecked")
        ArgumentCaptor<Function<Discovery, DiscoveryRunTerminator.Ending>> ending = ArgumentCaptor
                .forClass(Function.class);
        verify(terminator).endWith(eq(run.getUuid()), ending.capture());
        assertThat(ending.getValue().apply(run).status()).isEqualTo(DiscoveryStatus.FAILED);
    }

    @Test
    void recordsDiscoverSince_whenRunIsInitiated() throws Exception {
        // given
        var resolvedStart = OffsetDateTime.parse("2026-11-01T10:15:30Z");
        Discovery run = aWindowedRun(DiscoveryWindowMode.LOOKBACK);
        Discovery locked = copyOf(run);
        when(discoveryRepository.findWithLockByUuid(run.getUuid())).thenReturn(Optional.of(locked));
        when(windowResolver.resolve(eq(DiscoveryWindowMode.LOOKBACK), eq(run.getWindowLookback()), isNull()))
                .thenReturn(Optional.of(resolvedStart));
        when(client.initiate(run)).thenReturn(emptyInitiateResponse());
        when(detailCounts.forRun(any())).thenThrow(new IllegalStateException("counts unavailable"));
        when(terminator.endWith(eq(run.getUuid()), any())).thenReturn(true);
        UUID runUuid = run.getUuid();

        // when
        ThrowingCallable start = () -> adapter.start(runUuid, null);

        // then
        assertThatThrownBy(start).isInstanceOf(IllegalStateException.class);
        assertThat(locked.getDiscoverSince()).isEqualTo(resolvedStart);
    }

    @Test
    void failsStart_whenIncrementalFlagWithdrawn() throws Exception {
        // given
        Discovery run = aWindowedRun(DiscoveryWindowMode.LOOKBACK);
        when(capabilityService.supports(any(ConnectorInterfaceEntity.class), eq(FeatureFlag.DISCOVERY_INCREMENTAL)))
                .thenReturn(false);
        when(detailCounts.forRun(any())).thenThrow(new IllegalStateException("counts unavailable"));
        when(terminator.endWith(eq(run.getUuid()), any())).thenReturn(true);
        UUID runUuid = run.getUuid();

        // when
        ThrowingCallable start = () -> adapter.start(runUuid, null);

        // then
        assertThatThrownBy(start).isInstanceOf(IllegalStateException.class);
        verify(client, never()).supportedResources(any());
        verify(client, never()).initiate(any());
        @SuppressWarnings("unchecked")
        ArgumentCaptor<Function<Discovery, DiscoveryRunTerminator.Ending>> ending = ArgumentCaptor
                .forClass(Function.class);
        verify(terminator).endWith(eq(runUuid), ending.capture());
        DiscoveryRunTerminator.Ending failure = ending.getValue().apply(run);
        assertThat(failure.status()).isEqualTo(DiscoveryStatus.FAILED);
        assertThat(failure.reason()).contains("discoveryIncremental");
    }

    @Test
    void failsStartForCaller_whenIncrementalFlagWithdrawn() throws Exception {
        // given
        Discovery run = aWindowedRun(DiscoveryWindowMode.LOOKBACK);
        when(capabilityService.supports(any(ConnectorInterfaceEntity.class), eq(FeatureFlag.DISCOVERY_INCREMENTAL)))
                .thenReturn(false);
        when(detailCounts.forRun(any())).thenThrow(new IllegalStateException("counts unavailable"));
        when(terminator.endWith(eq(run.getUuid()), any())).thenReturn(true);
        UUID runUuid = run.getUuid();

        // when
        ThrowingCallable start = () -> adapter.startForCaller(runUuid);

        // then
        assertThatThrownBy(start).isInstanceOf(IllegalStateException.class);
        verify(client, never()).supportedResources(any());
        verify(client, never()).initiate(any());
        verify(terminator).endWith(eq(runUuid), any());
    }

    @Test
    void startsFullRunWithoutResolvingWindow_whenRunHasNoWindow() throws Exception {
        // given
        Discovery run = aWindowedRun(null);
        when(client.initiate(run)).thenReturn(emptyInitiateResponse());
        when(discoveryRepository.findWithLockByUuid(run.getUuid())).thenReturn(Optional.of(copyOf(run)));
        when(detailCounts.forRun(any())).thenThrow(new IllegalStateException("counts unavailable"));
        when(terminator.endWith(eq(run.getUuid()), any())).thenReturn(true);
        UUID runUuid = run.getUuid();

        // when
        ThrowingCallable start = () -> adapter.start(runUuid, null);

        // then
        assertThatThrownBy(start).isInstanceOf(IllegalStateException.class);
        verifyNoInteractions(windowResolver);
        verify(client).initiate(run);
    }

    @Test
    void startsFullRunWithoutResolvingWindow_whenFullWindowOnInterfaceWithoutIncrementalFlag() throws Exception {
        // given
        Discovery run = aWindowedRun(DiscoveryWindowMode.FULL);
        when(capabilityService.supports(any(ConnectorInterfaceEntity.class), eq(FeatureFlag.DISCOVERY_INCREMENTAL)))
                .thenReturn(false);
        when(client.initiate(run)).thenReturn(emptyInitiateResponse());
        when(discoveryRepository.findWithLockByUuid(run.getUuid())).thenReturn(Optional.of(copyOf(run)));
        when(detailCounts.forRun(any())).thenThrow(new IllegalStateException("counts unavailable"));
        when(terminator.endWith(eq(run.getUuid()), any())).thenReturn(true);
        UUID runUuid = run.getUuid();

        // when
        ThrowingCallable start = () -> adapter.start(runUuid, null);

        // then
        assertThatThrownBy(start).isInstanceOf(IllegalStateException.class);
        verifyNoInteractions(windowResolver);
        verify(client).initiate(run);
    }

    @Test
    void sendsAndRecordsLastSuccessfulRun_whenScheduledJobStartsIncrementalRun() throws Exception {
        // given
        var lastSuccessfulRun = OffsetDateTime.parse("2026-11-18T02:00:00Z");
        var jobInfo = new ScheduledJobInfo("nightly-job", UUID.randomUUID(), UUID.randomUUID());
        Discovery run = aWindowedRun(DiscoveryWindowMode.SINCE_LAST_SUCCESSFUL_RUN);
        Discovery locked = copyOf(run);
        when(discoveryRepository.findWithLockByUuid(run.getUuid())).thenReturn(Optional.of(locked));
        when(windowResolver.resolve(DiscoveryWindowMode.SINCE_LAST_SUCCESSFUL_RUN, null, jobInfo))
                .thenReturn(Optional.of(lastSuccessfulRun));
        when(client.initiate(run)).thenReturn(emptyInitiateResponse());
        when(detailCounts.forRun(any())).thenThrow(new IllegalStateException("counts unavailable"));
        when(terminator.endWith(eq(run.getUuid()), any())).thenReturn(true);
        UUID runUuid = run.getUuid();

        // when
        ThrowingCallable start = () -> adapter.start(runUuid, jobInfo);

        // then
        assertThatThrownBy(start).isInstanceOf(IllegalStateException.class);
        var sent = ArgumentCaptor.forClass(Discovery.class);
        verify(client).initiate(sent.capture());
        assertThat(sent.getValue().getDiscoverSince()).isEqualTo(lastSuccessfulRun);
        assertThat(locked.getDiscoverSince()).isEqualTo(lastSuccessfulRun);
    }

    @Test
    void keepsResolvedDiscoverSince_whenInitiateFails() throws Exception {
        // given
        var resolvedStart = OffsetDateTime.parse("2026-11-01T10:15:30Z");
        Discovery run = aWindowedRun(DiscoveryWindowMode.LOOKBACK);
        when(windowResolver.resolve(eq(DiscoveryWindowMode.LOOKBACK), eq(run.getWindowLookback()), isNull()))
                .thenReturn(Optional.of(resolvedStart));
        when(client.initiate(run)).thenThrow(new IllegalStateException("initiate timed out"));
        when(detailCounts.forRun(any())).thenThrow(new IllegalStateException("counts unavailable"));
        when(terminator.endWith(eq(run.getUuid()), any())).thenReturn(true);
        UUID runUuid = run.getUuid();

        // when
        ThrowingCallable start = () -> adapter.start(runUuid, null);

        // then
        assertThatThrownBy(start).isInstanceOf(IllegalStateException.class);
        @SuppressWarnings("unchecked")
        ArgumentCaptor<Function<Discovery, DiscoveryRunTerminator.Ending>> ending = ArgumentCaptor
                .forClass(Function.class);
        verify(terminator).endWith(eq(runUuid), ending.capture());
        Discovery failed = copyOf(run);
        ending.getValue().apply(failed);
        assertThat(failed.getDiscoverSince()).isEqualTo(resolvedStart);
    }

    // ── Helpers ───────────────────────────────────────────────────────────────

    private Discovery aWindowedRun(DiscoveryWindowMode mode) throws Exception {
        Discovery run = new Discovery();
        run.setUuid(UUID.randomUUID());
        run.setStatus(DiscoveryStatus.IN_PROGRESS);
        run.setResources(List.of(Resource.CERTIFICATE));
        run.setConnectorInterfaceUuid(UUID.randomUUID());
        run.setWindowMode(mode);
        run.setWindowLookback(mode == DiscoveryWindowMode.LOOKBACK ? Duration.ofDays(1) : null);
        when(discoveryRepository.findByUuid(run.getUuid())).thenReturn(Optional.of(run));
        when(client.supportedResources(run)).thenReturn(List.of(Resource.CERTIFICATE));
        var iface = new ConnectorInterfaceEntity();
        lenient()
                .when(connectorInterfaceRepository.findById(run.getConnectorInterfaceUuid()))
                .thenReturn(Optional.of(iface));
        lenient().when(capabilityService.supports(iface, FeatureFlag.DISCOVERY_INCREMENTAL)).thenReturn(true);
        return run;
    }

    private static Discovery copyOf(Discovery run) {
        Discovery copy = new Discovery();
        copy.setUuid(run.getUuid());
        copy.setStatus(DiscoveryStatus.IN_PROGRESS);
        copy.setConnectorInterfaceUuid(run.getConnectorInterfaceUuid());
        return copy;
    }

    private static DiscoveryInitiateResponseDto emptyInitiateResponse() {
        DiscoveryInitiateResponseDto response = new DiscoveryInitiateResponseDto();
        response.setCheckpoint(List.of());
        return response;
    }
}
