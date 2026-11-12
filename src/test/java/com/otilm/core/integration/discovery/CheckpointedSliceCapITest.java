package com.otilm.core.integration.discovery;

import com.otilm.api.model.common.attribute.common.MetadataAttribute;
import com.otilm.api.model.connector.discovery.v2.DiscoveryDeliveryMode;
import com.otilm.api.model.connector.discovery.v2.DiscoveryResultsResponseDto;
import com.otilm.api.model.connector.discovery.v2.DiscoveryRunState;
import com.otilm.api.model.connector.discovery.v2.DiscoveryStatusResponseDto;
import com.otilm.api.model.core.discovery.DiscoveryStatus;
import com.otilm.core.dao.entity.Discovery;
import com.otilm.core.dao.entity.DiscoveryWork;
import com.otilm.core.dao.repository.DiscoveryRepository;
import com.otilm.core.dao.repository.DiscoveryWorkRepository;
import com.otilm.core.messaging.jms.producers.DiscoveryWorkProducer;
import com.otilm.core.model.discovery.DiscoveryWorkType;
import com.otilm.core.service.handler.discovery.DiscoveryDrainTickWorker;
import com.otilm.core.service.handler.discovery.DiscoverySlicePermits;
import com.otilm.core.service.handler.discovery.DiscoveryStatusTickWorker;
import com.otilm.core.service.handler.discovery.DiscoveryV2Client;
import com.otilm.core.service.writer.discovery.DiscoveryWorkWriter;
import com.otilm.core.util.BaseSpringBootTest;
import com.otilm.core.util.DiscoveryCheckpointFixture;
import com.otilm.core.util.seeders.DiscoveryRunSeeder;
import com.otilm.core.util.seeders.DiscoveryWorkTickSeeder;
import java.time.Duration;
import java.time.OffsetDateTime;
import java.time.ZoneOffset;
import java.util.List;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.test.context.bean.override.mockito.MockitoBean;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyInt;
import static org.mockito.ArgumentMatchers.anyLong;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/**
 * The per-node cap on checkpointed drains at their connectors. The connector and the broker are mocked as in
 * {@link DiscoveryDrainTickWorkerITest}, whose context this shares. The permits are a singleton of that context, so
 * every test hands back what it took.
 */
class CheckpointedSliceCapITest extends BaseSpringBootTest {

    @MockitoBean
    private DiscoveryV2Client client;
    @MockitoBean
    private DiscoveryWorkProducer workProducer;

    @Autowired
    private DiscoveryDrainTickWorker drainWorker;
    @Autowired
    private DiscoveryStatusTickWorker statusWorker;
    @Autowired
    private DiscoverySlicePermits slicePermits;
    @Autowired
    private DiscoveryRepository discoveryRepository;
    @Autowired
    private DiscoveryRunSeeder runSeeder;
    @Autowired
    private DiscoveryWorkRepository workRepository;
    @Autowired
    private DiscoveryWorkWriter workWriter;
    @Autowired
    private DiscoveryWorkTickSeeder tickSeeder;

    @Value("${discovery.slice.max-concurrent-per-node:8}")
    private int maxConcurrentPerNode;

    private int permitsHeldByTheTest;
    private final CountDownLatch releaseTheSlices = new CountDownLatch(1);
    private final ExecutorService slices = Executors.newCachedThreadPool();

    @AfterEach
    void handBackThePermitsAndTheSlices() throws Exception {
        releaseTheSlices.countDown();
        slices.shutdown();
        slices.awaitTermination(30, TimeUnit.SECONDS);
        for (int permit = 0; permit < permitsHeldByTheTest; permit++) {
            slicePermits.release();
        }
    }

    @Test
    void defersWithoutCallingTheConnectorOrSpendingTheBudget_whenNoSlicePermitIsFree() throws Exception {
        // given
        Discovery run = runIn(DiscoveryDeliveryMode.CHECKPOINTED);
        var attemptTheTickWasClaimedAt = 5;
        armRow(run, DiscoveryWorkType.DRAIN, attemptTheTickWasClaimedAt);
        holdEveryFreePermit();

        // when
        drainWorker.tick(tickSeeder.admitTick(run.getUuid(), DiscoveryWorkType.DRAIN, attemptTheTickWasClaimedAt));

        // then
        verify(client, never()).results(any(), anyInt(), anyLong());
        DiscoveryWork drainRow = row(run, DiscoveryWorkType.DRAIN);
        assertThat(drainRow.getAttempt()).isEqualTo(attemptTheTickWasClaimedAt);
        assertThat(drainRow.getNextDueAt()).isBeforeOrEqualTo(OffsetDateTime.now(ZoneOffset.UTC));
        assertThat(drainRow.getLeaseToken()).isNull();
    }

    @Test
    void callsTheConnectorWithoutAPermit_whenTheRunIsBuffered() throws Exception {
        // given
        Discovery run = runIn(DiscoveryDeliveryMode.BUFFERED);
        armRow(run, DiscoveryWorkType.DRAIN, 0);
        holdEveryFreePermit();
        when(client.results(any(), anyInt(), anyLong())).thenReturn(emptyPage(false, null));

        // when
        drainWorker.tick(tickSeeder.admitTick(run.getUuid(), DiscoveryWorkType.DRAIN, 0));

        // then
        verify(client).results(any(), anyInt(), anyLong());
    }

    @Test
    void handsThePermitBack_whenTheConnectorCallFails() throws Exception {
        // given
        Discovery run = runIn(DiscoveryDeliveryMode.CHECKPOINTED);
        armRow(run, DiscoveryWorkType.DRAIN, 0);
        when(client.results(any(), anyInt(), anyLong())).thenThrow(new IllegalStateException("connector broke"));

        // when
        drainWorker.tick(tickSeeder.admitTick(run.getUuid(), DiscoveryWorkType.DRAIN, 0));

        // then
        assertThat(holdEveryFreePermit()).isEqualTo(maxConcurrentPerNode);
    }

    @Test
    void answersAStatusTickAtOnce_whenSlowSlicesHoldEveryPermit() throws Exception {
        // given
        when(client.status(any())).thenReturn(running());
        CountDownLatch slicesAtTheConnector = new CountDownLatch(maxConcurrentPerNode);
        when(client.results(any(), anyInt(), anyLong())).thenAnswer(slice -> {
            slicesAtTheConnector.countDown();
            releaseTheSlices.await(30, TimeUnit.SECONDS);
            return emptyPage(true, position("after-the-slice"));
        });
        for (int slice = 0; slice < maxConcurrentPerNode; slice++) {
            Discovery scanning = runIn(DiscoveryDeliveryMode.CHECKPOINTED);
            armRow(scanning, DiscoveryWorkType.DRAIN, 0);
            var tick = tickSeeder.admitTick(scanning.getUuid(), DiscoveryWorkType.DRAIN, 0);
            slices.submit(() -> drainWorker.tick(tick));
        }
        assertThat(slicesAtTheConnector.await(10, TimeUnit.SECONDS)).isTrue();
        Discovery polled = runIn(DiscoveryDeliveryMode.CHECKPOINTED);
        armRow(polled, DiscoveryWorkType.STATUS, 0);
        long startedAt = System.nanoTime();

        // when
        statusWorker.tick(tickSeeder.admitTick(polled.getUuid(), DiscoveryWorkType.STATUS, 0));

        // then
        Duration statusTookFor = Duration.ofNanos(System.nanoTime() - startedAt);
        assertThat(statusTookFor).isLessThan(Duration.ofSeconds(2));
        verify(client).status(any());
        assertThat(holdEveryFreePermit()).isZero();
    }

    // ── Helpers ───────────────────────────────────────────────────────────────

    private static DiscoveryResultsResponseDto emptyPage(boolean more, List<MetadataAttribute> checkpoint) {
        DiscoveryResultsResponseDto page = new DiscoveryResultsResponseDto();
        page.setItems(List.of());
        page.setHighestSequence(0L);
        page.setMore(more);
        page.setCheckpoint(checkpoint);
        return page;
    }

    private static DiscoveryStatusResponseDto running() {
        DiscoveryStatusResponseDto response = new DiscoveryStatusResponseDto();
        response.setState(DiscoveryRunState.RUNNING);
        response.setHighestSequence(0L);
        return response;
    }

    private static List<MetadataAttribute> position(String value) {
        return DiscoveryCheckpointFixture.checkpoint("position", value);
    }

    /** Takes every permit still free and keeps them until the test ends. */
    private int holdEveryFreePermit() {
        int taken = 0;
        while (slicePermits.tryAcquire()) {
            taken++;
        }
        permitsHeldByTheTest += taken;
        return taken;
    }

    private void armRow(Discovery run, DiscoveryWorkType workType, int attempt) {
        OffsetDateTime later = OffsetDateTime.now(ZoneOffset.UTC).plusHours(1);
        workWriter.schedule(run.getUuid(), workType, later);
        workWriter.reschedule(run.getUuid(), workType, attempt, later);
    }

    private DiscoveryWork row(Discovery run, DiscoveryWorkType workType) {
        return workRepository
                .findAll()
                .stream()
                .filter(work -> work.getDiscoveryUuid().equals(run.getUuid()) && work.getWorkType() == workType)
                .findFirst()
                .orElseThrow();
    }

    private Discovery runIn(DiscoveryDeliveryMode mode) {
        Discovery run = runSeeder.seedV2Run(DiscoveryStatus.IN_PROGRESS);
        run.setConnectorState("running");
        run.setDeliveryMode(mode);
        run.setCheckpointRevision(3);
        run.setCheckpoint(position("cursor-0"));
        return discoveryRepository.saveAndFlush(run);
    }
}
