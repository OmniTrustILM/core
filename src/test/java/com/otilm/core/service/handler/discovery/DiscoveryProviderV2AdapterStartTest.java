package com.otilm.core.service.handler.discovery;

import com.otilm.api.model.connector.discovery.v2.DiscoveryInitiateResponseDto;
import com.otilm.api.model.core.auth.Resource;
import com.otilm.api.model.core.discovery.DiscoveryStatus;
import com.otilm.core.dao.entity.Discovery;
import com.otilm.core.dao.repository.ConnectorInterfaceRepository;
import com.otilm.core.dao.repository.DiscoveryRepository;
import com.otilm.core.events.transaction.TransactionHandler;
import com.otilm.core.messaging.jms.configuration.DiscoveryWorkProperties;
import com.otilm.core.messaging.jms.configuration.StatusPollProperties;
import com.otilm.core.service.handler.ConnectorCapabilityService;
import com.otilm.core.service.writer.discovery.DiscoveryWorkWriter;
import java.time.Duration;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.UUID;
import java.util.function.Function;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
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

    private final DiscoveryProviderV2Adapter adapter = new DiscoveryProviderV2Adapter(discoveryRepository, detailCounts,
            connectorInterfaceRepository, client, workWriter, terminator, capabilityService, new TransactionHandler(),
            new DiscoveryWorkProperties(new StatusPollProperties.PollSchedule(List.of(Duration.ofSeconds(1)), 3),
                    Map.of()));

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
        assertThatThrownBy(() -> adapter.start(run.getUuid(), null)).isInstanceOf(IllegalStateException.class);

        verify(client).cancel(run);
        @SuppressWarnings("unchecked")
        ArgumentCaptor<Function<Discovery, DiscoveryRunTerminator.Ending>> ending = ArgumentCaptor
                .forClass(Function.class);
        verify(terminator).endWith(eq(run.getUuid()), ending.capture());
        assertThat(ending.getValue().apply(run).status()).isEqualTo(DiscoveryStatus.FAILED);
    }
}
