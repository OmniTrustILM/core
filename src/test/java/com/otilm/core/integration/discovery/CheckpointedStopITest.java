package com.otilm.core.integration.discovery;

import com.otilm.api.model.client.connector.v2.FeatureFlag;
import com.otilm.api.model.common.attribute.common.MetadataAttribute;
import com.otilm.api.model.connector.discovery.v2.DiscoveredItemDto;
import com.otilm.api.model.connector.discovery.v2.DiscoveredKeyDto;
import com.otilm.api.model.connector.discovery.v2.DiscoveryDeliveryMode;
import com.otilm.api.model.connector.discovery.v2.DiscoveryInitiateResponseDto;
import com.otilm.api.model.connector.discovery.v2.DiscoveryResultsResponseDto;
import com.otilm.api.model.connector.discovery.v2.DiscoveryStopResponseDto;
import com.otilm.api.model.core.discovery.DiscoveryStatus;
import com.otilm.core.dao.entity.Discovery;
import com.otilm.core.dao.entity.DiscoveryItem;
import com.otilm.core.dao.entity.DiscoveryWork;
import com.otilm.core.dao.repository.DiscoveryItemRepository;
import com.otilm.core.dao.repository.DiscoveryRepository;
import com.otilm.core.dao.repository.DiscoveryWorkRepository;
import com.otilm.core.messaging.jms.producers.DiscoveryWorkProducer;
import com.otilm.core.model.discovery.DiscoveryWorkType;
import com.otilm.core.service.handler.discovery.DiscoveryDrainTickWorker;
import com.otilm.core.service.handler.discovery.DiscoveryProviderV2Adapter;
import com.otilm.core.service.handler.discovery.DiscoveryStatusTickWorker;
import com.otilm.core.service.handler.discovery.DiscoveryV2Client;
import com.otilm.core.service.writer.discovery.DiscoveryWorkTick;
import com.otilm.core.service.writer.discovery.DiscoveryWorkWriter;
import com.otilm.core.util.BaseSpringBootTest;
import com.otilm.core.util.DiscoveryCheckpointFixture;
import com.otilm.core.util.seeders.DiscoveryRunSeeder;
import com.otilm.core.util.seeders.DiscoveryWorkTickSeeder;
import java.time.Duration;
import java.time.OffsetDateTime;
import java.time.ZoneOffset;
import java.util.List;
import java.util.Optional;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.test.context.bean.override.mockito.MockitoBean;

import static com.otilm.core.util.builders.DiscoveredKeyDtoBuilder.aPublicKey;
import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyInt;
import static org.mockito.ArgumentMatchers.anyLong;
import static org.mockito.Mockito.doAnswer;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.spy;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/**
 * How ticks treat a checkpointed run that is stopped, resumed or cancelled around them. For such a run a drain is the
 * scan itself, so nothing may reach the connector while the run is stopped. Stop, cancel and resume go through the real
 * adapter or mirror what it commits. The connector and the broker are mocked as in
 * {@link DiscoveryDrainTickWorkerITest}, whose context this shares.
 */
class CheckpointedStopITest extends BaseSpringBootTest {

    @MockitoBean
    private DiscoveryV2Client client;
    @MockitoBean
    private DiscoveryWorkProducer workProducer;

    @Autowired
    private DiscoveryDrainTickWorker drainWorker;
    @Autowired
    private DiscoveryStatusTickWorker statusWorker;
    @Autowired
    private DiscoveryProviderV2Adapter adapter;
    @Autowired
    private DiscoveryRepository discoveryRepository;
    @Autowired
    private DiscoveryItemRepository itemRepository;
    @Autowired
    private DiscoveryWorkRepository workRepository;
    @Autowired
    private DiscoveryWorkWriter workWriter;
    @Autowired
    private DiscoveryWorkTickSeeder tickSeeder;
    @Autowired
    private DiscoveryRunSeeder runSeeder;

    @Value("${discovery.work.stopped-poll-interval:PT5M}")
    private Duration stoppedPollInterval;

    @BeforeEach
    void stubTheStop() throws Exception {
        when(client.stop(any())).thenReturn(new DiscoveryStopResponseDto());
    }

    @Test
    void callsNothing_whenADrainTickAdmittedBeforeTheStopRuns() throws Exception {
        // given
        Discovery run = checkpointedRun();
        armRow(run, DiscoveryWorkType.DRAIN);
        DiscoveryWorkTick admittedBeforeTheStop = tickSeeder.admitTick(run.getUuid(), DiscoveryWorkType.DRAIN, 0);
        adapter.stop(reload(run));

        // when
        drainWorker.tick(admittedBeforeTheStop);

        // then
        verify(client, never()).results(any(), anyInt(), anyLong());
        assertThat(row(run, DiscoveryWorkType.DRAIN)).isEmpty();
        verify(workProducer, never()).produceMessage(any());
    }

    @Test
    void parksTheStatusRowWithoutAskingTheConnector_whenTheRunIsStopped() throws Exception {
        // given
        Discovery run = checkpointedRun();
        armRow(run, DiscoveryWorkType.STATUS);
        adapter.stop(reload(run));
        int attemptAfterTheStop = row(run, DiscoveryWorkType.STATUS).orElseThrow().getAttempt();
        DiscoveryWorkTick tick = tickSeeder.admitTick(run.getUuid(), DiscoveryWorkType.STATUS, attemptAfterTheStop);
        OffsetDateTime before = OffsetDateTime.now(ZoneOffset.UTC);

        // when
        statusWorker.tick(tick);

        // then
        verify(client, never()).status(any());
        DiscoveryWork statusRow = row(run, DiscoveryWorkType.STATUS).orElseThrow();
        assertThat(statusRow.getNextDueAt()).isAfterOrEqualTo(before.plus(stoppedPollInterval));
        assertThat(statusRow.getAttempt()).isEqualTo(attemptAfterTheStop);
        assertThat(statusRow.getLeaseToken()).isNull();
        assertThat(reload(run).getStatus()).isEqualTo(DiscoveryStatus.STOPPED);
    }

    @Test
    void leavesTheStatusRowDueNow_whenAResumeCommitsBeforeTheStoppedTickParksIt() throws Exception {
        // given
        Discovery run = checkpointedRun();
        armRow(run, DiscoveryWorkType.STATUS);
        adapter.stop(reload(run));
        when(client.resume(any())).thenReturn(resumedInCheckpointedMode());
        DiscoveryWorkTick readTheRunStopped = spy(tickSeeder.admitTick(run.getUuid(), DiscoveryWorkType.STATUS, 0));
        doAnswer(park -> {
            adapter.resume(reload(run));
            return park.callRealMethod();
        }).when(readTheRunStopped).reschedule(anyInt(), any());

        // when
        statusWorker.tick(readTheRunStopped);

        // then
        assertThat(row(run, DiscoveryWorkType.STATUS).orElseThrow().getNextDueAt())
                .isBeforeOrEqualTo(OffsetDateTime.now(ZoneOffset.UTC));
        assertThat(reload(run).getStatus()).isEqualTo(DiscoveryStatus.IN_PROGRESS);
    }

    @Test
    void dropsThePage_whenTheRunIsStoppedWhileItsSliceIsInFlight() throws Exception {
        // given
        Discovery run = checkpointedRun();
        List<MetadataAttribute> positionBeforeTheSlice = reload(run).getCheckpoint();
        armRow(run, DiscoveryWorkType.DRAIN);
        when(client.results(any(), anyInt(), anyLong())).thenAnswer(slice -> {
            adapter.stop(reload(run));
            return checkpointedPage(keyItem(1));
        });

        // when
        drainWorker.tick(tickSeeder.admitTick(run.getUuid(), DiscoveryWorkType.DRAIN, 0));

        // then
        Discovery stopped = reload(run);
        assertThat(stopped.getStatus()).isEqualTo(DiscoveryStatus.STOPPED);
        assertThat(stopped.getCheckpoint()).isEqualTo(positionBeforeTheSlice);
        assertThat(stagedRefs(run)).isEmpty();
        assertThat(row(run, DiscoveryWorkType.DRAIN)).isEmpty();
        verify(workProducer, never()).produceMessage(any());
    }

    @Test
    void dropsThePage_whenTheRunIsCancelledWhileItsSliceIsInFlight() throws Exception {
        // given
        Discovery run = checkpointedRun();
        armRow(run, DiscoveryWorkType.DRAIN);
        when(client.results(any(), anyInt(), anyLong())).thenAnswer(slice -> {
            adapter.cancel(reload(run));
            return checkpointedPage(keyItem(1));
        });

        // when
        drainWorker.tick(tickSeeder.admitTick(run.getUuid(), DiscoveryWorkType.DRAIN, 0));

        // then
        assertThat(reload(run).getStatus()).isEqualTo(DiscoveryStatus.CANCELLED);
        assertThat(stagedRefs(run)).isEmpty();
        assertThat(row(run, DiscoveryWorkType.DRAIN)).isEmpty();
        verify(workProducer, never()).produceMessage(any());
    }

    // ── Helpers ───────────────────────────────────────────────────────────────

    private static DiscoveryResultsResponseDto checkpointedPage(DiscoveredItemDto... items) {
        DiscoveryResultsResponseDto page = new DiscoveryResultsResponseDto();
        page.setItems(List.of(items));
        page.setHighestSequence((long) items.length);
        page.setMore(true);
        page.setCheckpoint(DiscoveryCheckpointFixture.checkpoint("position", "after-the-slice"));
        return page;
    }

    private static DiscoveredItemDto keyItem(long sequence) {
        DiscoveredKeyDto payload = aPublicKey().build();
        DiscoveredItemDto item = new DiscoveredItemDto();
        item.setSequence(sequence);
        item.setUniqueRef("key-" + sequence);
        item.setPayload(payload);
        return item;
    }

    private static DiscoveryInitiateResponseDto resumedInCheckpointedMode() {
        DiscoveryInitiateResponseDto response = new DiscoveryInitiateResponseDto();
        response.setDeliveryMode(DiscoveryDeliveryMode.CHECKPOINTED);
        return response;
    }

    private void armRow(Discovery run, DiscoveryWorkType workType) {
        workWriter.schedule(run.getUuid(), workType, OffsetDateTime.now(ZoneOffset.UTC).plusHours(1));
    }

    private Optional<DiscoveryWork> row(Discovery run, DiscoveryWorkType workType) {
        return workRepository
                .findAll()
                .stream()
                .filter(work -> work.getDiscoveryUuid().equals(run.getUuid()) && work.getWorkType() == workType)
                .findFirst();
    }

    private List<String> stagedRefs(Discovery run) {
        return itemRepository
                .findAll()
                .stream()
                .filter(item -> item.getDiscoveryUuid().equals(run.getUuid()))
                .map(DiscoveryItem::getUniqueRef)
                .toList();
    }

    private Discovery reload(Discovery run) {
        return discoveryRepository.findByUuid(run.getUuid()).orElseThrow();
    }

    private Discovery checkpointedRun() {
        Discovery run = runSeeder.seedV2Run(DiscoveryStatus.IN_PROGRESS, FeatureFlag.DISCOVERY_STOP_RESUME);
        run.setConnectorState("running");
        run.setStoppable(true);
        run.setDeliveryMode(DiscoveryDeliveryMode.CHECKPOINTED);
        run.setCheckpointRevision(3);
        run.setCheckpoint(DiscoveryCheckpointFixture.checkpoint("position", "cursor-0"));
        return discoveryRepository.saveAndFlush(run);
    }
}
