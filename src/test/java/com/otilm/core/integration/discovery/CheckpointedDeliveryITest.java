package com.otilm.core.integration.discovery;

import com.otilm.api.exception.ConnectorProblemException;
import com.otilm.api.model.common.attribute.common.AttributeType;
import com.otilm.api.model.common.attribute.common.MetadataAttribute;
import com.otilm.api.model.common.attribute.common.content.AttributeContentType;
import com.otilm.api.model.common.attribute.v3.MetadataAttributeV3;
import com.otilm.api.model.common.attribute.v3.content.StringAttributeContentV3;
import com.otilm.api.model.common.error.ErrorCode;
import com.otilm.api.model.common.error.ProblemDetailExtended;
import com.otilm.api.model.connector.discovery.v2.DiscoveredItemDto;
import com.otilm.api.model.connector.discovery.v2.DiscoveredKeyDto;
import com.otilm.api.model.connector.discovery.v2.DiscoveryDeliveryMode;
import com.otilm.api.model.connector.discovery.v2.DiscoveryResultsResponseDto;
import com.otilm.api.model.connector.discovery.v2.DiscoveryRunState;
import com.otilm.api.model.connector.discovery.v2.DiscoveryStatusResponseDto;
import com.otilm.api.model.core.discovery.DiscoveryStatus;
import com.otilm.core.dao.entity.Discovery;
import com.otilm.core.dao.entity.DiscoveryItem;
import com.otilm.core.dao.repository.DiscoveryItemRepository;
import com.otilm.core.dao.repository.DiscoveryRepository;
import com.otilm.core.messaging.jms.listeners.discovery.DiscoveryWorkClaimer;
import com.otilm.core.messaging.jms.listeners.discovery.DiscoveryWorkListener;
import com.otilm.core.messaging.jms.producers.DiscoveryWorkProducer;
import com.otilm.core.messaging.model.DiscoveryWorkMessage;
import com.otilm.core.model.discovery.DiscoveryWorkType;
import com.otilm.core.service.handler.discovery.DiscoveryV2Client;
import com.otilm.core.service.writer.discovery.DiscoveryWorkWriter;
import com.otilm.core.util.BaseSpringBootTest;
import com.otilm.core.util.seeders.DiscoveryRunSeeder;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.time.OffsetDateTime;
import java.time.ZoneOffset;
import java.util.ArrayList;
import java.util.List;
import java.util.Queue;
import java.util.UUID;
import java.util.concurrent.ConcurrentLinkedQueue;
import java.util.stream.LongStream;
import java.util.stream.Stream;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Named;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.test.context.bean.override.mockito.MockitoBean;

import static com.otilm.core.util.builders.DiscoveredKeyDtoBuilder.aPublicKey;
import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.api.Named.named;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyInt;
import static org.mockito.ArgumentMatchers.anyLong;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.doAnswer;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/**
 * A checkpointed run driven from its first drain to the hand-over to processing, through the real sweep claim, listener
 * and lease. The connector is a stub that keeps no state of its own: like a checkpointed connector, it learns where the
 * scan stands only from the checkpoint Core sends. The broker is mocked as in {@link DiscoveryDrainTickWorkerITest},
 * whose context this shares; this test delivers what the workers publish.
 */
class CheckpointedDeliveryITest extends BaseSpringBootTest {

    private static final int TARGETS = 1_000;
    private static final int TARGETS_PER_SLICE = 25;
    private static final int ITEMS_PER_LIT_TARGET = 3;
    private static final long ITEMS_IN_THE_SCAN = (long) TARGETS / 10 * ITEMS_PER_LIT_TARGET;
    private static final int MAX_SWEEPS = 10;

    @MockitoBean
    private DiscoveryV2Client client;
    @MockitoBean
    private DiscoveryWorkProducer workProducer;

    @Autowired
    private DiscoveryWorkClaimer claimer;
    @Autowired
    private DiscoveryWorkListener listener;
    @Autowired
    private DiscoveryRepository discoveryRepository;
    @Autowired
    private DiscoveryItemRepository itemRepository;
    @Autowired
    private DiscoveryRunSeeder runSeeder;
    @Autowired
    private DiscoveryWorkWriter workWriter;

    private final Queue<DiscoveryWorkMessage> published = new ConcurrentLinkedQueue<>();
    private final List<DiscoveryWorkMessage> processTicks = new ArrayList<>();

    @BeforeEach
    void stubTheConnectorAndCaptureWhatTheWorkersPublish() throws Exception {
        DiscoveredKeyDto payload = aPublicKey().build();
        when(client.results(any(), anyInt(), anyLong()))
                .thenAnswer(call -> nextSlice(call.getArgument(0), call.getArgument(1), payload));
        when(client.status(any())).thenAnswer(call -> statusOf(call.getArgument(0)));
        doAnswer(call -> published.add(call.getArgument(0))).when(workProducer).produceMessage(any());
    }

    @ParameterizedTest
    @MethodSource("drainDeliveries")
    void handsTheRunOverWithEveryItemStagedOnce_whenTheScanReachesItsLastTarget(int deliveriesPerDrain)
            throws Exception {
        // given
        Discovery run = checkpointedRunAtTheFirstTarget();

        // when
        driveUntilHandedOver(run, deliveriesPerDrain);

        // then
        assertThat(reload(run).getStatus()).isEqualTo(DiscoveryStatus.PROCESSING);
        assertThat(stagedSequences(run))
                .containsExactlyElementsOf(LongStream.rangeClosed(1, ITEMS_IN_THE_SCAN).boxed().toList());
        verify(client, times(1)).status(any());
        verify(client).acknowledge(any(), eq(ITEMS_IN_THE_SCAN));
        assertThat(processTicks).hasSize(1);
    }

    // ── Helpers ───────────────────────────────────────────────────────────────

    private static Stream<Named<Integer>> drainDeliveries() {
        return Stream.of(named("each drain delivered once", 1), named("each drain delivered twice", 2));
    }

    /**
     * One slice of the scan from the position in the checkpoint: every tenth target holds three items, the rest are
     * dark. A request whose afterSequence is not the checkpoint's high water is refused, as the contract says.
     */
    private static DiscoveryResultsResponseDto nextSlice(Discovery run, int maxItems, DiscoveredKeyDto payload)
            throws ConnectorProblemException {
        long cursor = read(run.getCheckpoint(), "cursor");
        long highWater = read(run.getCheckpoint(), "hw");
        if (run.getLastAppliedSequence() != highWater) {
            throw notTheCheckpointsPosition();
        }
        List<DiscoveredItemDto> items = new ArrayList<>();
        long end = Math.min(cursor + TARGETS_PER_SLICE, TARGETS);
        for (long target = cursor; target < end && items.size() + ITEMS_PER_LIT_TARGET <= maxItems; target++) {
            if (target % 10 == 0) {
                for (int item = 0; item < ITEMS_PER_LIT_TARGET; item++) {
                    items.add(keyItem(++highWater, "target-" + target + "-key-" + item, payload));
                }
            }
            cursor = target + 1;
        }
        DiscoveryResultsResponseDto page = new DiscoveryResultsResponseDto();
        page.setItems(items);
        page.setHighestSequence(highWater);
        page.setMore(cursor < TARGETS);
        page.setCheckpoint(checkpointAt(cursor, highWater));
        return page;
    }

    private static DiscoveryStatusResponseDto statusOf(Discovery run) {
        DiscoveryStatusResponseDto status = new DiscoveryStatusResponseDto();
        boolean scanned = read(run.getCheckpoint(), "cursor") >= TARGETS;
        status.setState(scanned ? DiscoveryRunState.COMPLETED : DiscoveryRunState.RUNNING);
        status.setHighestSequence(read(run.getCheckpoint(), "hw"));
        return status;
    }

    private static ConnectorProblemException notTheCheckpointsPosition() {
        return new ConnectorProblemException(ProblemDetailExtended
                .fromErrorCode(ErrorCode.OPERATION_NOT_TRACKED, "afterSequence is not the checkpoint's high water",
                        URI.create("https://example.com"), null));
    }

    private static DiscoveredItemDto keyItem(long sequence, String uniqueRef, DiscoveredKeyDto payload) {
        DiscoveredItemDto item = new DiscoveredItemDto();
        item.setSequence(sequence);
        item.setUniqueRef(uniqueRef);
        item.setPayload(payload);
        return item;
    }

    /** Built the same way every time, so an unchanged position compares equal to the stored one. */
    private static List<MetadataAttribute> checkpointAt(long cursor, long highWater) {
        return List.of(checkpointEntry("cursor", cursor), checkpointEntry("hw", highWater));
    }

    private static MetadataAttribute checkpointEntry(String name, long value) {
        MetadataAttributeV3 attribute = new MetadataAttributeV3();
        attribute.setUuid(UUID.nameUUIDFromBytes(name.getBytes(StandardCharsets.UTF_8)).toString());
        attribute.setName(name);
        attribute.setType(AttributeType.META);
        attribute.setContentType(AttributeContentType.STRING);
        attribute.setContent(List.of(new StringAttributeContentV3(Long.toString(value))));
        return attribute;
    }

    private static long read(List<MetadataAttribute> checkpoint, String name) {
        return checkpoint
                .stream()
                .map(MetadataAttributeV3.class::cast)
                .filter(attribute -> attribute.getName().equals(name))
                .map(attribute -> ((StringAttributeContentV3) attribute.getContent().get(0)).getData())
                .map(Long::parseLong)
                .findFirst()
                .orElseThrow();
    }

    /**
     * Sweeps as the scheduler would and delivers every message the sweep and the workers publish, each drain as many
     * times as asked, as a broker that redelivers would. Processing ticks are collected rather than run.
     */
    private void driveUntilHandedOver(Discovery run, int deliveriesPerDrain) {
        for (int sweep = 0; sweep < MAX_SWEEPS && reload(run).getStatus() == DiscoveryStatus.IN_PROGRESS; sweep++) {
            published.addAll(claimer.claimDueBatch(10, OffsetDateTime.now(ZoneOffset.UTC)));
            DiscoveryWorkMessage message;
            while ((message = published.poll()) != null) {
                if (message.workType() == DiscoveryWorkType.PROCESS) {
                    processTicks.add(message);
                    continue;
                }
                int deliveries = message.workType() == DiscoveryWorkType.DRAIN ? deliveriesPerDrain : 1;
                for (int delivery = 0; delivery < deliveries; delivery++) {
                    listener.processMessage(message);
                }
            }
        }
    }

    private List<Long> stagedSequences(Discovery run) {
        return itemRepository
                .findAll()
                .stream()
                .filter(item -> item.getDiscoveryUuid().equals(run.getUuid()))
                .map(DiscoveryItem::getSequence)
                .sorted()
                .toList();
    }

    private Discovery reload(Discovery run) {
        return discoveryRepository.findByUuid(run.getUuid()).orElseThrow();
    }

    private Discovery checkpointedRunAtTheFirstTarget() {
        Discovery run = runSeeder.seedV2Run(DiscoveryStatus.IN_PROGRESS);
        run.setConnectorState("running");
        run.setDeliveryMode(DiscoveryDeliveryMode.CHECKPOINTED);
        run.setCheckpoint(checkpointAt(0, 0));
        run = discoveryRepository.saveAndFlush(run);
        OffsetDateTime now = OffsetDateTime.now(ZoneOffset.UTC);
        workWriter.schedule(run.getUuid(), DiscoveryWorkType.DRAIN, now);
        workWriter.schedule(run.getUuid(), DiscoveryWorkType.STATUS, now.plusHours(1));
        return run;
    }
}
