package com.otilm.core.integration.discovery;

import com.fasterxml.jackson.annotation.JsonProperty;
import com.otilm.api.exception.ConnectorException;
import com.otilm.api.exception.ConnectorProblemException;
import com.otilm.api.model.common.enums.cryptography.KeyAlgorithm;
import com.otilm.api.model.common.enums.cryptography.KeyType;
import com.otilm.api.model.common.error.ErrorCode;
import com.otilm.api.model.common.error.ProblemDetailExtended;
import com.otilm.api.model.connector.discovery.v2.DiscoveredItemDto;
import com.otilm.api.model.connector.discovery.v2.DiscoveredKeyDto;
import com.otilm.api.model.connector.discovery.v2.DiscoveryResultsResponseDto;
import com.otilm.api.model.core.discovery.DiscoveryStatus;
import com.otilm.core.dao.entity.ConnectorInterfaceEntity;
import com.otilm.core.dao.entity.Discovery;
import com.otilm.core.dao.entity.DiscoveryItem;
import com.otilm.core.dao.entity.DiscoveryWork;
import com.otilm.core.dao.repository.ConnectorInterfaceRepository;
import com.otilm.core.dao.repository.ConnectorRepository;
import com.otilm.core.dao.repository.DiscoveryItemRepository;
import com.otilm.core.dao.repository.DiscoveryRepository;
import com.otilm.core.dao.repository.DiscoveryWorkRepository;
import com.otilm.core.messaging.jms.producers.DiscoveryWorkProducer;
import com.otilm.core.messaging.model.DiscoveryWorkMessage;
import com.otilm.core.model.discovery.DiscoveryWorkType;
import com.otilm.core.service.handler.discovery.DiscoveryDrainTickWorker;
import com.otilm.core.service.handler.discovery.DiscoveryV2Client;
import com.otilm.core.service.writer.discovery.DiscoveryWorkWriter;
import com.otilm.core.util.BaseSpringBootTest;
import com.otilm.core.util.DiscoveryCheckpointFixture;
import com.otilm.core.util.DiscoveryInterfaceFixture;
import java.net.URI;
import java.time.OffsetDateTime;
import java.time.ZoneOffset;
import java.util.List;
import java.util.UUID;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.test.context.bean.override.mockito.MockitoBean;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyInt;
import static org.mockito.ArgumentMatchers.anyLong;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.atLeastOnce;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/**
 * What one drain tick does to a run: what it stages, whether it asks for another tick straight away, and when it hands
 * the run over to processing. The connector and the broker are both mocked — the assertions are about committed run
 * state and the agenda, plus the follow-up ticks this worker publishes itself.
 *
 * <p>
 * The worker commits in its own transactions, so seeded data has to be committed too.
 */
class DiscoveryDrainTickWorkerITest extends BaseSpringBootTest {

    @MockitoBean
    private DiscoveryV2Client client;
    @MockitoBean
    private DiscoveryWorkProducer workProducer;

    @Autowired
    private DiscoveryDrainTickWorker worker;
    @Autowired
    private DiscoveryRepository discoveryRepository;
    @Autowired
    private ConnectorRepository connectorRepository;
    @Autowired
    private ConnectorInterfaceRepository connectorInterfaceRepository;
    @Autowired
    private DiscoveryItemRepository itemRepository;
    @Autowired
    private DiscoveryWorkRepository workRepository;
    @Autowired
    private DiscoveryWorkWriter workWriter;

    @Test
    void pageWithMoreToCome_stagesItAndPublishesTheFollowUpTickItself() throws Exception {
        Discovery run = runStillScanning();
        armDrainRow(run, 0);
        when(client.results(any(), anyInt(), anyLong()))
                .thenReturn(page(9L, true, keyItem(1, "key-a"), keyItem(2, "key-b")));

        worker.tick(run.getUuid(), 0);

        assertThat(stagedRefs(run)).containsExactlyInAnyOrder("key-a", "key-b");
        assertThat(reload(run).getLastAppliedSequence()).isEqualTo(2);
        assertThat(publishedTicks())
                .as("the sweep's cadence is the recovery latency, not the drain's throughput ceiling")
                .containsExactly(new DiscoveryWorkMessage(run.getUuid(), DiscoveryWorkType.DRAIN, 0));
        assertThat(drainRow(run).getNextDueAt())
                .as("parked as a backstop, not due-now: a due-now row is one the sweep would claim and publish "
                        + "itself, racing the tick this worker just published")
                .isAfter(OffsetDateTime.now(ZoneOffset.UTC));
    }

    @Test
    void threePageRun_drainsEndToEndWithoutSpendingItsAttemptBudget() throws Exception {
        Discovery run = runStillScanning();
        armDrainRow(run, 0);
        when(client.results(any(), anyInt(), anyLong()))
                .thenReturn(page(3L, true, keyItem(1, "key-a")))
                .thenReturn(page(3L, true, keyItem(2, "key-b")))
                .thenReturn(page(3L, false, keyItem(3, "key-c")));

        worker.tick(run.getUuid(), 0);
        worker.tick(run.getUuid(), 0);
        worker.tick(run.getUuid(), 0);

        assertThat(stagedRefs(run)).containsExactlyInAnyOrder("key-a", "key-b", "key-c");
        assertThat(reload(run).getLastAppliedSequence()).isEqualTo(3);
        assertThat(reload(run).getStatus())
                .as("the connector is still scanning, so nothing hands over yet")
                .isEqualTo(DiscoveryStatus.IN_PROGRESS);
    }

    @Test
    void quietPageWhileTheConnectorIsStillScanning_slowsDownWithoutSpendingTheBudget() throws Exception {
        Discovery run = runStillScanning();
        armDrainRow(run, 40);
        when(client.results(any(), anyInt(), anyLong())).thenReturn(page(0L, false));

        worker.tick(run.getUuid(), 40);

        verify(workProducer, never()).produceMessage(any());
        assertThat(drainRow(run).getAttempt())
                .as("a valid empty answer refreshes the budget; only consecutive failures spend it")
                .isLessThan(40);
    }

    @Test
    void fullyDrainedCompletedRun_swapsToProcessingWithOneProcessRow() throws Exception {
        Discovery run = runTheConnectorFinished();
        armDrainRow(run, 0);
        workWriter.schedule(run.getUuid(), DiscoveryWorkType.STATUS, OffsetDateTime.now(ZoneOffset.UTC).plusHours(1));
        when(client.results(any(), anyInt(), anyLong()))
                .thenReturn(page(2L, false, keyItem(1, "key-a"), keyItem(2, "key-b")));

        worker.tick(run.getUuid(), 0);

        Discovery reloaded = reload(run);
        assertThat(reloaded.getStatus()).isEqualTo(DiscoveryStatus.PROCESSING);
        assertThat(reloaded.getCheckpoint())
                .as("the connector owns nothing from here on, so its handle is released")
                .isNull();
        assertThat(agenda(run)).extracting(DiscoveryWork::getWorkType).containsExactly(DiscoveryWorkType.PROCESS);
        assertThat(publishedTicks())
                .containsExactly(new DiscoveryWorkMessage(run.getUuid(), DiscoveryWorkType.PROCESS, 0));
        // The contract's full acknowledgement, and the only call that licences the connector to discard the
        // run's state: a drain at afterSequence == highestSequence, sent once the handover is durable.
        verify(client).acknowledge(any(), eq(2L));
    }

    @Test
    void cursorStillBehind_neverSendsTheFullAcknowledgement() throws Exception {
        Discovery run = runTheConnectorFinished();
        armDrainRow(run, 0);
        when(client.results(any(), anyInt(), anyLong()))
                .thenReturn(page(4L, false, keyItem(1, "key-a"), keyItem(2, "key-b")));

        worker.tick(run.getUuid(), 0);

        // Acknowledging here would tell the connector it may discard items 3 and 4 — the very ones Core is
        // still waiting for.
        verify(client, never()).acknowledge(any(), anyLong());
    }

    @Test
    void acknowledgementThatFails_leavesTheHandoverStanding() throws Exception {
        Discovery run = runTheConnectorFinished();
        armDrainRow(run, 0);
        when(client.results(any(), anyInt(), anyLong())).thenReturn(page(1L, false, keyItem(1, "key-a")));
        doThrow(new ConnectorException("connection reset")).when(client).acknowledge(any(), anyLong());

        worker.tick(run.getUuid(), 0);

        // Best-effort by design: the connector retains the run's state for 24 hours regardless, so a failed ack
        // costs retention, not data. Rolling the handover back would cost the import instead.
        Discovery reloaded = reload(run);
        assertThat(reloaded.getStatus()).isEqualTo(DiscoveryStatus.PROCESSING);
        assertThat(reloaded.getCheckpoint()).isNull();
        assertThat(agenda(run)).extracting(DiscoveryWork::getWorkType).containsExactly(DiscoveryWorkType.PROCESS);
        assertThat(publishedTicks())
                .containsExactly(new DiscoveryWorkMessage(run.getUuid(), DiscoveryWorkType.PROCESS, 0));
    }

    @Test
    void completedRunWhoseCursorLagsTheRunWideCount_drainsAgainInsteadOfSwapping() throws Exception {
        Discovery run = runTheConnectorFinished();
        armDrainRow(run, 0);
        // more:false, connector completed — but highestSequence is run-wide and still ahead of what was
        // handed over. Swapping here would strand items 3 and 4 at the connector forever.
        when(client.results(any(), anyInt(), anyLong()))
                .thenReturn(page(4L, false, keyItem(1, "key-a"), keyItem(2, "key-b")));

        worker.tick(run.getUuid(), 0);

        Discovery reloaded = reload(run);
        assertThat(reloaded.getStatus()).isEqualTo(DiscoveryStatus.IN_PROGRESS);
        assertThat(reloaded.getLastAppliedSequence()).isEqualTo(2);
        assertThat(agenda(run)).extracting(DiscoveryWork::getWorkType).containsExactly(DiscoveryWorkType.DRAIN);
        // Backs off up the ladder instead of publishing again: this branch can repeat without progress, and a
        // due-now retry would be an unbounded stream of results calls at a connector that may never catch up.
        verify(workProducer, never()).produceMessage(any());
        assertThat(drainRow(run).getAttempt()).isEqualTo(1);
        assertThat(drainRow(run).getNextDueAt()).isAfter(OffsetDateTime.now(ZoneOffset.UTC));
    }

    @Test
    void runTheConnectorNoLongerTracks_endsFailedAndReleasesEverything() throws Exception {
        Discovery run = runStillScanning();
        armDrainRow(run, 0);
        when(client.results(any(), anyInt(), anyLong())).thenThrow(notFound());

        worker.tick(run.getUuid(), 0);

        Discovery reloaded = reload(run);
        assertThat(reloaded.getStatus()).isEqualTo(DiscoveryStatus.FAILED);
        assertThat(reloaded.getCheckpoint()).isNull();
        assertThat(agenda(run)).isEmpty();
    }

    @Test
    void lastAllowedAttempt_endsTheRunFailed() throws Exception {
        Discovery run = runStillScanning();
        armDrainRow(run, 0);
        when(client.results(any(), anyInt(), anyLong())).thenThrow(new ConnectorException("connection reset"));

        worker.tick(run.getUuid(), 99);

        Discovery reloaded = reload(run);
        assertThat(reloaded.getStatus()).isEqualTo(DiscoveryStatus.FAILED);
        assertThat(reloaded.getMessage()).contains("stopped handing over");
        assertThat(agenda(run)).isEmpty();
    }

    @Test
    void transientFailureWithBudgetLeft_leavesTheRunAndItsAgendaAlone() throws Exception {
        Discovery run = runStillScanning();
        armDrainRow(run, 2);
        when(client.results(any(), anyInt(), anyLong())).thenThrow(new ConnectorException("connection reset"));

        worker.tick(run.getUuid(), 2);

        assertThat(reload(run).getStatus()).isEqualTo(DiscoveryStatus.IN_PROGRESS);
        assertThat(drainRow(run).getAttempt()).isEqualTo(2);
        verify(workProducer, never()).produceMessage(any());
    }

    @Test
    void runAlreadyProcessing_dropsItsOwnRowAndLeavesTheProcessRowDriving() throws Exception {
        Discovery run = runStillScanning();
        run.setStatus(DiscoveryStatus.PROCESSING);
        discoveryRepository.saveAndFlush(run);
        armDrainRow(run, 0);
        workWriter.schedule(run.getUuid(), DiscoveryWorkType.PROCESS, OffsetDateTime.now(ZoneOffset.UTC).plusHours(1));

        worker.tick(run.getUuid(), 0);

        // Taking the whole agenda here would delete the PROCESS row that drives the remaining import, and the
        // reaper would then read a live run with no work as lost and fail it.
        assertThat(agenda(run)).extracting(DiscoveryWork::getWorkType).containsExactly(DiscoveryWorkType.PROCESS);
        verify(client, never()).results(any(), anyInt(), anyLong());
    }

    @Test
    void pageMissingTheRequiredFields_isNotReadAsFinished() throws Exception {
        Discovery run = runTheConnectorFinished();
        armDrainRow(run, 0);
        DiscoveryResultsResponseDto malformed = new DiscoveryResultsResponseDto();
        malformed.setItems(List.of());
        when(client.results(any(), anyInt(), anyLong())).thenReturn(malformed);

        worker.tick(run.getUuid(), 0);

        // Reading a missing "more" as "no more items" would hand a half-drained run to processing and release
        // the connector handle, which is permanent silent loss.
        assertThat(reload(run).getStatus()).isEqualTo(DiscoveryStatus.IN_PROGRESS);
        assertThat(agenda(run)).extracting(DiscoveryWork::getWorkType).containsExactly(DiscoveryWorkType.DRAIN);
        verify(workProducer, never()).produceMessage(any());
    }

    @Test
    void connectorThatKeepsOmittingRequiredFields_endsTheRun() throws Exception {
        Discovery run = runTheConnectorFinished();
        armDrainRow(run, 0);
        DiscoveryResultsResponseDto malformed = new DiscoveryResultsResponseDto();
        malformed.setItems(List.of());
        when(client.results(any(), anyInt(), anyLong())).thenReturn(malformed);

        worker.tick(run.getUuid(), 99);

        Discovery reloaded = reload(run);
        assertThat(reloaded.getStatus()).isEqualTo(DiscoveryStatus.FAILED);
        assertThat(reloaded.getMessage()).contains("omitted a field the contract requires");
    }

    @Test
    void pageOmittingItemsEntirely_isNotReadAsAPageWithNoItems() throws Exception {
        Discovery run = runTheConnectorFinished();
        armDrainRow(run, 0);
        // The contract requires an explicit empty array for a page with no items, so a null is a non-answer
        // like a null "more" is. Read as "no discoveries" this page is fully drained and caught up, and the
        // run would hand over and release the connector handle with items still at the connector.
        DiscoveryResultsResponseDto noItemsField = new DiscoveryResultsResponseDto();
        noItemsField.setMore(false);
        noItemsField.setHighestSequence(0L);
        when(client.results(any(), anyInt(), anyLong())).thenReturn(noItemsField);

        worker.tick(run.getUuid(), 0);

        assertThat(reload(run).getStatus()).isEqualTo(DiscoveryStatus.IN_PROGRESS);
        assertThat(agenda(run)).extracting(DiscoveryWork::getWorkType).containsExactly(DiscoveryWorkType.DRAIN);
        verify(workProducer, never()).produceMessage(any());
        verify(client, never()).acknowledge(any(), anyLong());
    }

    @Test
    void unstageablePageWithBudgetLeft_isContainedInsteadOfEscapingToTheListener() throws Exception {
        Discovery run = runStillScanning();
        armDrainRow(run, 0);
        // A genuinely unstageable page: it passes every contract check, so nothing skips it, and its payload
        // still cannot be stored, however many times it is retried.
        when(client.results(any(), anyInt(), anyLong())).thenReturn(page(1L, false, unstageableKeyItem(1)));

        worker.tick(run.getUuid(), 0);

        // Contained here rather than left to the listener's log-and-acknowledge: the agenda row survives for the
        // sweep's claimer to push up the ladder, and the cursor is untouched by the rolled-back page.
        assertThat(reload(run).getStatus()).isEqualTo(DiscoveryStatus.IN_PROGRESS);
        assertThat(reload(run).getLastAppliedSequence()).isZero();
        assertThat(agenda(run)).extracting(DiscoveryWork::getWorkType).containsExactly(DiscoveryWorkType.DRAIN);
        verify(workProducer, never()).produceMessage(any());
    }

    @Test
    void pageCoreKeepsFailingToStage_endsTheRunWithoutBlamingTheConnector() throws Exception {
        Discovery run = runStillScanning();
        armDrainRow(run, 0);
        when(client.results(any(), anyInt(), anyLong())).thenReturn(page(1L, false, unstageableKeyItem(1)));

        worker.tick(run.getUuid(), 99);

        // The connector answered, and answered correctly. Reporting this as "the connector stopped handing over
        // items" would send an operator to the wrong system.
        Discovery reloaded = reload(run);
        assertThat(reloaded.getStatus()).isEqualTo(DiscoveryStatus.FAILED);
        assertThat(reloaded.getMessage())
                .isEqualTo("Core could not store the discovered items this run's connector " + "handed over");
        assertThat(agenda(run)).isEmpty();
    }

    @Test
    void staleFailureAfterHandover_leavesTheProcessingRunAlone() throws Exception {
        Discovery run = runTheConnectorFinished();
        run.setStatus(DiscoveryStatus.PROCESSING);
        discoveryRepository.saveAndFlush(run);
        workWriter.schedule(run.getUuid(), DiscoveryWorkType.PROCESS, OffsetDateTime.now(ZoneOffset.UTC).plusHours(1));

        // A drain request that went out before the handover, answering 404 after it. Ending the run here would
        // fail a healthy import and delete the PROCESS row driving it.
        worker.tick(run.getUuid(), 0);

        assertThat(reload(run).getStatus()).isEqualTo(DiscoveryStatus.PROCESSING);
        assertThat(agenda(run)).extracting(DiscoveryWork::getWorkType).containsExactly(DiscoveryWorkType.PROCESS);
    }

    private List<DiscoveryWorkMessage> publishedTicks() {
        ArgumentCaptor<DiscoveryWorkMessage> published = ArgumentCaptor.forClass(DiscoveryWorkMessage.class);
        verify(workProducer, atLeastOnce()).produceMessage(published.capture());
        return published.getAllValues();
    }

    private static DiscoveryResultsResponseDto page(long highestSequence, boolean more, DiscoveredItemDto... items) {
        DiscoveryResultsResponseDto page = new DiscoveryResultsResponseDto();
        page.setItems(List.of(items));
        page.setHighestSequence(highestSequence);
        page.setMore(more);
        return page;
    }

    /** Conformant on the wire and still unstorable: its payload refuses to serialize, on every attempt. */
    private static DiscoveredItemDto unstageableKeyItem(long sequence) {
        DiscoveredKeyDto payload = new DiscoveredKeyDto() {
            @JsonProperty
            public String getPoison() {
                throw new IllegalStateException("payload refuses to serialize");
            }
        };
        payload.setType(KeyType.PUBLIC_KEY);
        payload.setAlgorithm(KeyAlgorithm.RSA);
        DiscoveredItemDto item = new DiscoveredItemDto();
        item.setSequence(sequence);
        item.setUniqueRef("key-" + sequence);
        item.setPayload(payload);
        return item;
    }

    private static DiscoveredItemDto keyItem(long sequence, String uniqueRef) {
        DiscoveredKeyDto payload = new DiscoveredKeyDto();
        payload.setType(KeyType.PUBLIC_KEY);
        payload.setAlgorithm(KeyAlgorithm.RSA);
        DiscoveredItemDto item = new DiscoveredItemDto();
        item.setSequence(sequence);
        item.setUniqueRef(uniqueRef);
        item.setPayload(payload);
        return item;
    }

    private static ConnectorProblemException notFound() {
        return new ConnectorProblemException(ProblemDetailExtended
                .fromErrorCode(ErrorCode.OPERATION_NOT_TRACKED, "unknown run", URI.create("https://example.com"),
                        null));
    }

    private void armDrainRow(Discovery run, int attempt) {
        workWriter.schedule(run.getUuid(), DiscoveryWorkType.DRAIN, OffsetDateTime.now(ZoneOffset.UTC).plusHours(1));
        workWriter
                .reschedule(run.getUuid(), DiscoveryWorkType.DRAIN, attempt,
                        OffsetDateTime.now(ZoneOffset.UTC).plusHours(1));
    }

    private DiscoveryWork drainRow(Discovery run) {
        return agenda(run)
                .stream()
                .filter(row -> row.getWorkType() == DiscoveryWorkType.DRAIN)
                .findFirst()
                .orElseThrow();
    }

    private List<DiscoveryWork> agenda(Discovery run) {
        return workRepository.findAll().stream().filter(row -> row.getDiscoveryUuid().equals(run.getUuid())).toList();
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

    private Discovery runStillScanning() {
        return v2Run("running");
    }

    private Discovery runTheConnectorFinished() {
        return v2Run("completed");
    }

    private Discovery v2Run(String connectorState) {
        Discovery run = new Discovery();
        run.setName("v2-scan-" + UUID.randomUUID());
        run.setKind("IP-HostName");
        run.setStatus(DiscoveryStatus.IN_PROGRESS);
        run.setConnectorStatus(DiscoveryStatus.IN_PROGRESS);
        ConnectorInterfaceEntity discoveryInterface = DiscoveryInterfaceFixture
                .v2Interface(connectorRepository, connectorInterfaceRepository);
        run.setConnectorUuid(discoveryInterface.getConnectorUuid());
        run.setConnectorName("network-discovery");
        run.setConnectorInterfaceUuid(discoveryInterface.getUuid());
        run.setConnectorState(connectorState);
        run.setCheckpoint(DiscoveryCheckpointFixture.checkpoint("connectorRunId", "run-42"));
        return discoveryRepository.saveAndFlush(run);
    }
}
