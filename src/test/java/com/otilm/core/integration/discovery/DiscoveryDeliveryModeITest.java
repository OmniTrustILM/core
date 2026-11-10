package com.otilm.core.integration.discovery;

import com.otilm.api.model.client.connector.v2.FeatureFlag;
import com.otilm.api.model.common.attribute.common.MetadataAttribute;
import com.otilm.api.model.connector.discovery.v2.DiscoveryDeliveryMode;
import com.otilm.api.model.connector.discovery.v2.DiscoveryInitiateResponseDto;
import com.otilm.api.model.connector.discovery.v2.DiscoveryStopResponseDto;
import com.otilm.api.model.core.auth.Resource;
import com.otilm.api.model.core.discovery.DiscoveryStatus;
import com.otilm.core.dao.entity.ConnectorInterfaceEntity;
import com.otilm.core.dao.entity.Discovery;
import com.otilm.core.dao.repository.ConnectorInterfaceRepository;
import com.otilm.core.dao.repository.ConnectorRepository;
import com.otilm.core.dao.repository.DiscoveryRepository;
import com.otilm.core.service.handler.discovery.DiscoveryDeliveryModeOffer;
import com.otilm.core.service.handler.discovery.DiscoveryProviderV2Adapter;
import com.otilm.core.service.handler.discovery.DiscoveryV2Client;
import com.otilm.core.service.writer.discovery.DiscoveryWorkWriter;
import com.otilm.core.util.BaseSpringBootTest;
import com.otilm.core.util.DiscoveryCheckpointFixture;
import com.otilm.core.util.DiscoveryInterfaceFixture;
import java.time.OffsetDateTime;
import java.time.ZoneOffset;
import java.util.List;
import java.util.UUID;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import org.springframework.test.util.ReflectionTestUtils;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/**
 * The delivery mode a connector chooses at initiate and resume, and the checkpoint revision stop and resume raise. The
 * connector and the agenda writer are mocked as in {@link DiscoveryStartFailureITest}, whose context this shares.
 */
class DiscoveryDeliveryModeITest extends BaseSpringBootTest {

    private static final String OFFER_FIELD = "deliveryModeOffer";
    private static final String STORED_HANDLE = "connectorRunId";
    private static final String RETURNED_HANDLE = "returnedPosition";

    @MockitoBean
    private DiscoveryV2Client client;
    @MockitoBean
    private DiscoveryWorkWriter workWriter;

    @Autowired
    private DiscoveryProviderV2Adapter adapter;
    @Autowired
    private DiscoveryDeliveryModeOffer shippedOffer;
    @Autowired
    private DiscoveryRepository discoveryRepository;
    @Autowired
    private ConnectorRepository connectorRepository;
    @Autowired
    private ConnectorInterfaceRepository connectorInterfaceRepository;

    @AfterEach
    void restoreTheShippedOffer() {
        ReflectionTestUtils.setField(adapter, OFFER_FIELD, shippedOffer);
    }

    @Test
    void recordsTheChosenMode_whenInitiateAnswersWithAnOfferedMode() throws Exception {
        // given
        offerCheckpointedAndBuffered();
        Discovery run = unstartedV2Run();
        stubInitiateAnswering(DiscoveryDeliveryMode.CHECKPOINTED);

        // when
        adapter.start(run.getUuid(), null);

        // then
        Discovery persisted = reload(run);
        assertThat(persisted.getStatus()).isEqualTo(DiscoveryStatus.IN_PROGRESS);
        assertThat(persisted.getDeliveryMode()).isEqualTo(DiscoveryDeliveryMode.CHECKPOINTED);
    }

    @Test
    void recordsBuffered_whenInitiateAnswersWithNoMode() throws Exception {
        // given
        Discovery run = unstartedV2Run();
        DiscoveryDeliveryMode noModeAnswered = null;
        stubInitiateAnswering(noModeAnswered);

        // when
        adapter.start(run.getUuid(), null);

        // then
        Discovery persisted = reload(run);
        assertThat(persisted.getStatus()).isEqualTo(DiscoveryStatus.IN_PROGRESS);
        assertThat(persisted.getDeliveryMode()).isEqualTo(DiscoveryDeliveryMode.BUFFERED);
    }

    @Test
    void failsTheRun_whenInitiateAnswersWithAModeThatWasNotOffered() throws Exception {
        // given
        offerBufferedOnly();
        Discovery run = unstartedV2Run();
        var notOffered = DiscoveryDeliveryMode.CHECKPOINTED;
        stubInitiateAnswering(notOffered);

        // when
        adapter.start(run.getUuid(), null);

        // then
        Discovery persisted = reload(run);
        assertThat(persisted.getStatus()).isEqualTo(DiscoveryStatus.FAILED);
        assertThat(persisted.getMessage())
                .containsIgnoringCase("the connector chose a delivery mode this platform did not offer")
                .contains(notOffered.getCode());
        verify(client).cancel(any());
    }

    @Test
    void raisesTheRevision_whenTheRunIsStopped() throws Exception {
        // given
        Discovery run = stoppableV2Run(DiscoveryStatus.IN_PROGRESS, DiscoveryDeliveryMode.BUFFERED);
        long revisionBefore = run.getCheckpointRevision();
        when(client.stop(any())).thenReturn(new DiscoveryStopResponseDto());

        // when
        adapter.stop(run);

        // then
        assertThat(reload(run).getCheckpointRevision()).isEqualTo(revisionBefore + 1);
    }

    @Test
    void raisesTheRevision_whenTheRunIsResumed() throws Exception {
        // given
        Discovery run = stoppableV2Run(DiscoveryStatus.STOPPED, DiscoveryDeliveryMode.BUFFERED);
        long revisionBefore = run.getCheckpointRevision();
        when(client.resume(any())).thenReturn(new DiscoveryInitiateResponseDto());

        // when
        adapter.resume(run);

        // then
        assertThat(reload(run).getCheckpointRevision()).isEqualTo(revisionBefore + 1);
    }

    @Test
    void keepsTheStoredCheckpoint_whenACheckpointedRunsStopAnswerCarriesOne() throws Exception {
        // given
        Discovery run = stoppableV2Run(DiscoveryStatus.IN_PROGRESS, DiscoveryDeliveryMode.CHECKPOINTED);
        DiscoveryStopResponseDto response = new DiscoveryStopResponseDto();
        response.setCheckpoint(olderPosition());
        when(client.stop(any())).thenReturn(response);

        // when
        adapter.stop(run);

        // then
        Discovery persisted = reload(run);
        assertThat(persisted.getStatus()).isEqualTo(DiscoveryStatus.STOPPED);
        assertThat(handleNameOf(persisted)).isEqualTo(STORED_HANDLE);
    }

    @Test
    void replacesTheStoredCheckpoint_whenABufferedRunsStopAnswerCarriesOne() throws Exception {
        // given
        Discovery run = stoppableV2Run(DiscoveryStatus.IN_PROGRESS, DiscoveryDeliveryMode.BUFFERED);
        DiscoveryStopResponseDto response = new DiscoveryStopResponseDto();
        response.setCheckpoint(olderPosition());
        when(client.stop(any())).thenReturn(response);

        // when
        adapter.stop(run);

        // then
        assertThat(handleNameOf(reload(run))).isEqualTo(RETURNED_HANDLE);
    }

    @Test
    void recordsCheckpointed_whenAResumeSwitchesABufferedRun() throws Exception {
        // given
        offerCheckpointedAndBuffered();
        Discovery run = stoppableV2Run(DiscoveryStatus.STOPPED, DiscoveryDeliveryMode.BUFFERED);
        when(client.resume(any())).thenReturn(resumeAnswering(DiscoveryDeliveryMode.CHECKPOINTED));

        // when
        adapter.resume(run);

        // then
        Discovery persisted = reload(run);
        assertThat(persisted.getStatus()).isEqualTo(DiscoveryStatus.IN_PROGRESS);
        assertThat(persisted.getDeliveryMode()).isEqualTo(DiscoveryDeliveryMode.CHECKPOINTED);
    }

    @Test
    void keepsTheStoredCheckpoint_whenAResumeAnswersInCheckpointedMode() throws Exception {
        // given
        offerCheckpointedAndBuffered();
        Discovery run = stoppableV2Run(DiscoveryStatus.STOPPED, DiscoveryDeliveryMode.BUFFERED);
        DiscoveryInitiateResponseDto response = resumeAnswering(DiscoveryDeliveryMode.CHECKPOINTED);
        response.setCheckpoint(olderPosition());
        when(client.resume(any())).thenReturn(response);

        // when
        adapter.resume(run);

        // then
        assertThat(handleNameOf(reload(run))).isEqualTo(STORED_HANDLE);
    }

    @Test
    void failsTheRun_whenAResumeAnswersWithAModeThatWasNotOffered() throws Exception {
        // given
        offerBufferedOnly();
        Discovery run = stoppableV2Run(DiscoveryStatus.STOPPED, DiscoveryDeliveryMode.BUFFERED);
        var notOffered = DiscoveryDeliveryMode.CHECKPOINTED;
        when(client.resume(any())).thenReturn(resumeAnswering(notOffered));

        // when
        adapter.resume(run);

        // then
        Discovery persisted = reload(run);
        assertThat(persisted.getStatus()).isEqualTo(DiscoveryStatus.FAILED);
        assertThat(persisted.getMessage())
                .containsIgnoringCase("the connector chose a delivery mode this platform did not offer")
                .contains(notOffered.getCode());
        verify(client).cancel(any());
    }

    // ── Helpers ───────────────────────────────────────────────────────────────

    /** What an operator who dropped checkpointed from discovery.delivery.modes offers. */
    private void offerBufferedOnly() {
        ReflectionTestUtils.setField(adapter, OFFER_FIELD, new DiscoveryDeliveryModeOffer("buffered"));
    }

    private void offerCheckpointedAndBuffered() {
        ReflectionTestUtils.setField(adapter, OFFER_FIELD, new DiscoveryDeliveryModeOffer("checkpointed,buffered"));
    }

    private void stubInitiateAnswering(DiscoveryDeliveryMode mode) throws Exception {
        DiscoveryInitiateResponseDto response = new DiscoveryInitiateResponseDto();
        response.setCheckpoint(DiscoveryCheckpointFixture.checkpoint(STORED_HANDLE, "run-42"));
        response.setDeliveryMode(mode);
        when(client.supportedResources(any())).thenReturn(List.of(Resource.CERTIFICATE));
        when(client.initiate(any())).thenReturn(response);
    }

    private static DiscoveryInitiateResponseDto resumeAnswering(DiscoveryDeliveryMode mode) {
        DiscoveryInitiateResponseDto response = new DiscoveryInitiateResponseDto();
        response.setDeliveryMode(mode);
        return response;
    }

    private static List<MetadataAttribute> olderPosition() {
        return DiscoveryCheckpointFixture.checkpoint(RETURNED_HANDLE, "an older position");
    }

    private static String handleNameOf(Discovery run) {
        return run.getCheckpoint().getFirst().getName();
    }

    private Discovery reload(Discovery run) {
        return discoveryRepository.findByUuid(run.getUuid()).orElseThrow();
    }

    private Discovery unstartedV2Run() {
        Discovery run = new Discovery();
        run.setName("v2-scan-" + UUID.randomUUID());
        run.setKind("IP-HostName");
        run.setStatus(DiscoveryStatus.IN_PROGRESS);
        run.setConnectorStatus(DiscoveryStatus.IN_PROGRESS);
        run.setConnectorUuid(UUID.randomUUID());
        run.setConnectorName("network-discovery");
        run.setResources(List.of(Resource.CERTIFICATE));
        return discoveryRepository.saveAndFlush(run);
    }

    private Discovery stoppableV2Run(DiscoveryStatus status, DiscoveryDeliveryMode mode) {
        ConnectorInterfaceEntity discoveryInterface = DiscoveryInterfaceFixture
                .v2Interface(connectorRepository, connectorInterfaceRepository, FeatureFlag.DISCOVERY_STOP_RESUME);
        Discovery run = new Discovery();
        run.setName("v2-scan-" + UUID.randomUUID());
        run.setKind("IP-HostName");
        run.setStatus(status);
        run.setConnectorStatus(status);
        run.setConnectorUuid(discoveryInterface.getConnectorUuid());
        run.setConnectorName("network-discovery");
        run.setConnectorInterfaceUuid(discoveryInterface.getUuid());
        run.setResources(List.of(Resource.CERTIFICATE));
        run.setStoppable(true);
        run.setDeliveryMode(mode);
        run.setCheckpointRevision(7);
        run.setCheckpoint(DiscoveryCheckpointFixture.checkpoint(STORED_HANDLE, "run-42"));
        if (status == DiscoveryStatus.STOPPED) {
            run.setStoppedAt(OffsetDateTime.now(ZoneOffset.UTC));
        }
        return discoveryRepository.saveAndFlush(run);
    }
}
