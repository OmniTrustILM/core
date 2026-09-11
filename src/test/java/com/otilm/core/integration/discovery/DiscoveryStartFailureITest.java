package com.otilm.core.integration.discovery;

import com.otilm.api.model.connector.discovery.v2.DiscoveryInitiateResponseDto;
import com.otilm.api.model.core.auth.Resource;
import com.otilm.api.model.core.discovery.DiscoveryStatus;
import com.otilm.core.dao.entity.Discovery;
import com.otilm.core.dao.repository.DiscoveryRepository;
import com.otilm.core.service.handler.discovery.DiscoveryProviderV2Adapter;
import com.otilm.core.service.handler.discovery.DiscoveryV2Client;
import com.otilm.core.service.writer.discovery.DiscoveryWorkWriter;
import com.otilm.core.tasks.ScheduledJobInfo;
import com.otilm.core.util.BaseSpringBootTest;
import java.util.List;
import java.util.UUID;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.test.context.bean.override.mockito.MockitoBean;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.when;

/**
 * What a failed {@code start} leaves behind. Both the connector and the agenda writer are mocked, since nothing a
 * connector stub can do reaches the window below.
 */
class DiscoveryStartFailureITest extends BaseSpringBootTest {

    @MockitoBean
    private DiscoveryV2Client client;
    @MockitoBean
    private DiscoveryWorkWriter workWriter;

    @Autowired
    private DiscoveryProviderV2Adapter adapter;
    @Autowired
    private DiscoveryRepository discoveryRepository;

    @Test
    void aScheduledRunFailingAfterItWasRecordedDropsItsJobExecution() throws Exception {
        Discovery run = v2Run();
        when(client.supportedResources(any())).thenReturn(List.of(Resource.CERTIFICATE));
        DiscoveryInitiateResponseDto response = new DiscoveryInitiateResponseDto();
        response.setMeta(List.of());
        when(client.initiate(any())).thenReturn(response);
        // Fails after recordInitiated has committed the execution uuid -- the only point at which the run's own
        // ending has a scheduled part to announce.
        doThrow(new IllegalStateException("agenda write failed")).when(workWriter).schedule(any(), any(), any());
        ScheduledJobInfo job = new ScheduledJobInfo("nightly", UUID.randomUUID(), UUID.randomUUID());

        adapter.start(run.getUuid(), job);

        Discovery persisted = discoveryRepository.findByUuid(run.getUuid()).orElseThrow();
        assertThat(persisted.getStatus()).isEqualTo(DiscoveryStatus.FAILED);
        assertThat(persisted.getScheduledJobHistoryUuid())
                .as("a run whose ending still names its job execution finalizes that job history a second time")
                .isNull();
    }

    private Discovery v2Run() {
        Discovery run = new Discovery();
        run.setName("v2-scan-" + UUID.randomUUID());
        run.setKind("IP-HostName");
        run.setStatus(DiscoveryStatus.IN_PROGRESS);
        run.setConnectorStatus(DiscoveryStatus.IN_PROGRESS);
        run.setConnectorUuid(UUID.randomUUID());
        run.setConnectorName("network-discovery");
        // No interface association: the adapter is driven directly, so nothing here routes on it, and the failed
        // start maps a detail — which would dereference the association and need a real row behind it.
        run.setResources(List.of(Resource.CERTIFICATE));
        return discoveryRepository.saveAndFlush(run);
    }
}
