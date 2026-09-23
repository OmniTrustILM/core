package com.otilm.core.integration.discovery;

import com.otilm.api.model.common.enums.cryptography.KeyAlgorithm;
import com.otilm.api.model.common.enums.cryptography.KeyFormat;
import com.otilm.api.model.common.enums.cryptography.KeyType;
import com.otilm.api.model.connector.discovery.v2.DiscoveredItemDto;
import com.otilm.api.model.connector.discovery.v2.DiscoveredKeyDto;
import com.otilm.api.model.connector.discovery.v2.DiscoveryResultsResponseDto;
import com.otilm.api.model.core.auth.Resource;
import com.otilm.api.model.core.discovery.DiscoveryMessageSeverity;
import com.otilm.api.model.core.discovery.DiscoveryStatus;
import com.otilm.core.dao.entity.CertificateContent;
import com.otilm.core.dao.entity.ConnectorInterfaceEntity;
import com.otilm.core.dao.entity.Discovery;
import com.otilm.core.dao.entity.DiscoveryCertificate;
import com.otilm.core.dao.entity.DiscoveryItem;
import com.otilm.core.dao.entity.DiscoveryMessage;
import com.otilm.core.dao.entity.DiscoveryWork;
import com.otilm.core.dao.repository.CertificateContentRepository;
import com.otilm.core.dao.repository.ConnectorInterfaceRepository;
import com.otilm.core.dao.repository.ConnectorRepository;
import com.otilm.core.dao.repository.DiscoveryCertificateRepository;
import com.otilm.core.dao.repository.DiscoveryItemRepository;
import com.otilm.core.dao.repository.DiscoveryMessageRepository;
import com.otilm.core.dao.repository.DiscoveryRepository;
import com.otilm.core.dao.repository.DiscoveryWorkRepository;
import com.otilm.core.events.handlers.CertificateDiscoveredEventHandler;
import com.otilm.core.events.handlers.discovery.DiscoveryRunCounts;
import com.otilm.core.messaging.jms.configuration.DiscoveryWorkProperties;
import com.otilm.core.messaging.jms.producers.DiscoveryWorkProducer;
import com.otilm.core.messaging.model.DiscoveryWorkMessage;
import com.otilm.core.model.auth.ResourceAction;
import com.otilm.core.model.discovery.DiscoveryMessageCode;
import com.otilm.core.model.discovery.DiscoveryWorkType;
import com.otilm.core.service.handler.discovery.DiscoveryEventIngestor;
import com.otilm.core.service.handler.discovery.DiscoveryProcessTickWorker;
import com.otilm.core.service.handler.discovery.DiscoveryRunTerminator;
import com.otilm.core.service.handler.discovery.DiscoveryRunTerminator.Ending;
import com.otilm.core.service.writer.DiscoveryWriter;
import com.otilm.core.service.writer.discovery.DiscoveryItemWriter;
import com.otilm.core.service.writer.discovery.DiscoveryMessageWriter;
import com.otilm.core.service.writer.discovery.DiscoveryWorkWriter;
import com.otilm.core.util.AuthHelper;
import com.otilm.core.util.BaseSpringBootTest;
import com.otilm.core.util.DiscoveryInterfaceFixture;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.time.OffsetDateTime;
import java.time.ZoneOffset;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;
import java.util.UUID;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.data.domain.PageRequest;
import org.springframework.test.context.TestPropertySource;
import org.springframework.test.context.bean.override.mockito.MockitoBean;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyList;
import static org.mockito.Mockito.atLeastOnce;
import static org.mockito.Mockito.doAnswer;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;

/**
 * How a run gets through its processing backlog and how it ends.
 *
 * <p>
 * The import pipeline is mocked at {@link CertificateDiscoveredEventHandler#processBatch}: what matters here is the
 * cursor discipline around it — that each batch claims only unprocessed rows, that a crashed batch is reclaimed rather
 * than skipped, and that the run's final status is read from the evidence its own rows carry. The pipeline's own
 * behaviour has its own tests.
 *
 * <p>
 * The worker commits in its own transactions, so seeded data has to be committed too.
 */
// One row per batch, so the walk through a backlog is observable rather than a single all-at-once pass.
@TestPropertySource(properties = "discovery.processing.batch-size=1")
class DiscoveryProcessTickWorkerITest extends BaseSpringBootTest {

    @MockitoBean
    private CertificateDiscoveredEventHandler importHandler;
    @MockitoBean
    private DiscoveryWorkProducer workProducer;
    // No auth service runs in the ITest, so the real authenticateAsUser would throw. Mocked to keep the identity
    // step observable: what matters here is that the worker installs the run's user before importing.
    @MockitoBean
    private AuthHelper authHelper;

    @Autowired
    private DiscoveryProcessTickWorker worker;
    @Autowired
    private DiscoveryRunTerminator terminator;
    @Autowired
    private DiscoveryWorkProperties workProperties;
    @Autowired
    private DiscoveryRepository discoveryRepository;
    @Autowired
    private ConnectorRepository connectorRepository;
    @Autowired
    private ConnectorInterfaceRepository connectorInterfaceRepository;
    @Autowired
    private DiscoveryCertificateRepository certificateRepository;
    @Autowired
    private CertificateContentRepository certificateContentRepository;
    @Autowired
    private DiscoveryWorkRepository workRepository;
    @Autowired
    private DiscoveryWriter discoveryWriter;
    @Autowired
    private DiscoveryWorkWriter workWriter;
    @Autowired
    private DiscoveryEventIngestor ingestor;
    @Autowired
    private DiscoveryItemRepository itemRepository;
    @Autowired
    private DiscoveryItemWriter itemWriter;
    @Autowired
    private DiscoveryMessageWriter messageWriter;
    @Autowired
    private DiscoveryMessageRepository messageRepository;

    private static final UUID RUN_OWNER = UUID.fromString("3f1d9a52-0000-4000-8000-00000000beef");

    private final List<Integer> claimedBatchSizes = new ArrayList<>();

    @Test
    void backlogLargerThanOneBatch_asksForTheNextBatchItself() throws Exception {
        Discovery run = processingRun();
        stageCertificates(run, 3);
        importsCleanly();

        worker.tick(run.getUuid(), 0);

        assertThat(reload(run).getStatus())
                .as("a batch that leaves work behind must not end the run")
                .isEqualTo(DiscoveryStatus.PROCESSING);
        assertThat(publishedTicks())
                .containsExactly(new DiscoveryWorkMessage(run.getUuid(), DiscoveryWorkType.PROCESS, 0));
        assertThat(agenda(run)).extracting(DiscoveryWork::getWorkType).containsExactly(DiscoveryWorkType.PROCESS);
    }

    @Test
    void runWithOnlyStagedKeys_isNotFinishedJustBecauseItHasNoCertificates() throws Exception {
        Discovery run = processingRun();
        stageKeys(run, 2);

        worker.tick(run.getUuid(), 0);

        // The backlog spans both staging stores. Counting certificates alone ends a keys-only run the moment it
        // starts processing, with every key still staged and nothing in the inventory.
        assertThat(reload(run).getStatus()).isEqualTo(DiscoveryStatus.PROCESSING);
    }

    @Test
    void stagedKeys_areImportedTickByTickUntilTheRunIsDone() throws Exception {
        Discovery run = processingRun();
        stageKeys(run, 2);

        worker.tick(run.getUuid(), 0);
        assertThat(reload(run).getStatus()).isEqualTo(DiscoveryStatus.PROCESSING);

        worker.tick(run.getUuid(), 0);

        assertThat(reload(run).getStatus()).isEqualTo(DiscoveryStatus.COMPLETED);
        assertThat(importedKeyItems(run)).as("both staged keys reached the inventory").isEqualTo(2);
    }

    @Test
    void mixedRun_waitsForItsKeysEvenOnceEveryCertificateIsIn() throws Exception {
        Discovery run = processingRun();
        stageCertificates(run, 1);
        // Two keys against a batch size of one, so the run still owes something after the certificate is in.
        stageKeys(run, 2);
        importsCleanly();

        worker.tick(run.getUuid(), 0);

        // Ending here would leave the second key staged with nothing to come back for it.
        assertThat(reload(run).getStatus()).isEqualTo(DiscoveryStatus.PROCESSING);

        worker.tick(run.getUuid(), 0);

        assertThat(reload(run).getStatus()).isEqualTo(DiscoveryStatus.COMPLETED);
        assertThat(importedKeyItems(run)).isEqualTo(2);
    }

    @Test
    void keyThatCannotBeIdentified_stopsAtItsOwnRowAndIsReportedOnTheRun() throws Exception {
        Discovery run = processingRun();
        stageUnusableKey(run);

        worker.tick(run.getUuid(), 0);

        DiscoveryItem failed = keyItemsOf(run).getFirst();
        assertThat(failed.getProcessedError()).isNotNull();
        assertThat(failed.getInventoryUuid()).as("nothing reached the inventory for it").isNull();
        assertThat(messages(run))
                .extracting(DiscoveryMessage::getCode)
                .contains(DiscoveryMessageCode.KEY_IMPORT_FAILED.code());
        // A row that carries a reason is accounted for, so the run finishes rather than stalling on it -- with a
        // warning, because something it discovered never made it in.
        Discovery ended = reload(run);
        assertThat(ended.getStatus()).isEqualTo(DiscoveryStatus.WARNING);
        // A keys-only run has nothing in the certificate list to look at.
        assertThat(ended.getMessage()).contains("items").doesNotContain("certificate list");
    }

    @Test
    void keysDrainedFromAConnector_reachTheInventoryAndTheListingSaysWhatTheyBecame() throws Exception {
        Discovery run = processingRun();
        // The whole way in: what a connector handed over, through staging, to the records an operator sees.
        ingestor.applyDrainPage(run.getUuid(), drainedKeys(run));

        worker.tick(run.getUuid(), 0);
        worker.tick(run.getUuid(), 0);

        assertThat(reload(run).getStatus()).isEqualTo(DiscoveryStatus.COMPLETED);
        assertThat(importedKeyItems(run)).isEqualTo(2);
        assertThat(itemRepository.listItems(run.getUuid(), Resource.CRYPTOGRAPHIC_KEY.name(), null, 10, 0))
                .allSatisfy(row -> {
                    assertThat(row.getInventoryUuid()).as("the listing says which record the item became").isNotNull();
                    assertThat(row.isProcessed()).isTrue();
                });
    }

    @Test
    void keyImportThatCouldNotRun_leavesItsRowsForTheNextTick() throws Exception {
        Discovery run = processingRun();
        stageKeys(run, 1);
        // Any failure of the page as a whole, rather than of one key: here the run may not create keys at all.
        denyResourceAccess(Resource.CRYPTOGRAPHIC_KEY, ResourceAction.CREATE);

        worker.tick(run.getUuid(), 0);

        DiscoveryItem untouched = keyItemsOf(run).getFirst();
        assertThat(untouched.getProcessedError()).as("a row the tick never judged carries no reason").isNull();
        assertThat(untouched.getInventoryUuid()).isNull();
        assertThat(reload(run).getStatus()).isEqualTo(DiscoveryStatus.PROCESSING);
        assertThat(processRow(run).getAttempt()).as("a tick that accounted for nothing backs off").isEqualTo(1);
        // A refusal no retry can pass: the run will end on its budget, and this is what it will point the operator at.
        assertThat(messages(run))
                .filteredOn(message -> DiscoveryMessageCode.BATCH_PROCESSING_FAILED.code().equals(message.getCode()))
                .singleElement()
                .satisfies(message -> {
                    assertThat(message.getSeverity()).isEqualTo(DiscoveryMessageSeverity.WARNING);
                    assertThat(message.getMessage()).contains("not allowed to create keys");
                });
    }

    @Test
    void runThatEndsOnItsBudget_saysWhyTheKeysItNeverReachedStayedOut() throws Exception {
        Discovery run = processingRun();
        stageKeys(run, 1);
        denyResourceAccess(Resource.CRYPTOGRAPHIC_KEY, ResourceAction.CREATE);
        int lastAttempt = workProperties.scheduleFor(DiscoveryWorkType.PROCESS).maxAttempts() - 1;

        worker.tick(run.getUuid(), lastAttempt);

        assertThat(reload(run).getStatus()).isEqualTo(DiscoveryStatus.WARNING);
        // Left without a reason, the row would read as waiting on a run that has ended.
        assertThat(keyItemsOf(run).getFirst().getProcessedError())
                .isEqualTo("Not imported: processing stopped before this key could be imported.");
    }

    @Test
    void keyImportWhoseUserCannotBeInstalled_backsOffRatherThanRetryingForever() throws Exception {
        Discovery run = processingRun();
        stageKeys(run, 1);
        doThrow(new IllegalStateException("no such user")).when(authHelper).authenticateAsUser(RUN_OWNER);

        // Escaping the tick would leave the attempt where it was, so the budget that ends a failing run never runs out.
        worker.tick(run.getUuid(), 0);

        assertThat(processRow(run).getAttempt()).isEqualTo(1);
        assertThat(messages(run))
                .extracting(DiscoveryMessage::getCode)
                .contains(DiscoveryMessageCode.BATCH_PROCESSING_FAILED.code());
    }

    @Test
    void importRunsAsTheUserWhoStartedTheRun() throws Exception {
        Discovery run = processingRun();
        stageCertificates(run, 1);
        importsCleanly();

        worker.tick(run.getUuid(), 0);

        // A tick arrives on a JMS thread with no principal, so without this the pipeline's CERTIFICATE:CREATE
        // check refuses every batch (see DiscoveryProcessTickWorker#authenticateAsTheRunsUser).
        verify(authHelper).authenticateAsUser(RUN_OWNER);
    }

    @Test
    void batchThatLeavesWorkBehind_reportsWhatIsLeftRatherThanItsOwnCompletion() throws Exception {
        Discovery run = processingRun();
        stageCertificates(run, 3);
        importsCleanly();

        worker.tick(run.getUuid(), 0);

        // The import pipeline counts progress against the batch it was handed. For a v2 run that batch is not
        // the run, so every batch would finish at 100% while the backlog is still draining.
        assertThat(reload(run).getMessage()).isEqualTo("Importing discovered items (2 remaining)");
    }

    @Test
    void repeatedTicks_walkTheBacklogToTheEndWithoutReprocessingARow() throws Exception {
        Discovery run = processingRun();
        stageCertificates(run, 3);
        importsCleanly();

        worker.tick(run.getUuid(), 0);
        worker.tick(run.getUuid(), 0);
        worker.tick(run.getUuid(), 0);

        assertThat(claimedBatchSizes).containsExactly(1, 1, 1);
        assertThat(reload(run).getStatus()).isEqualTo(DiscoveryStatus.COMPLETED);
    }

    @Test
    void batchThatDiedPartWayThrough_reclaimsOnlyTheRowsItNeverStamped() throws Exception {
        Discovery run = processingRun();
        // One content carrying three rows, so a single batch can die with part of its work committed. The
        // pipeline stamps a group's rows in their own transaction, so what it committed outlives the throw.
        stageCertificatesSharingContent(run, 3);
        stampsOneRowThenDies();

        worker.tick(run.getUuid(), 0);

        // A stamped row is an outcome, and the cursor is the only record of progress there is: reclaiming it
        // would run its triggers, histories and validation a second time.
        assertThat(backlog(run)).isEqualTo(2);
        assertThat(processRow(run).getAttempt())
                .as("a tick that accounted for something is progress, not a stall")
                .isZero();

        importsCleanly();
        worker.tick(run.getUuid(), 0);

        assertThat(claimedBatchSizes)
                .as("the second tick claims the remainder, never the stamped row")
                .containsExactly(3, 2);
        assertThat(backlog(run)).isZero();
        // COMPLETED, though the log carries the batch that died: the retry imported every row it left behind,
        // so there is nothing for an operator to act on. The message stays as the record of what happened, at a
        // severity that says the run recovered from it.
        assertThat(reload(run).getStatus()).isEqualTo(DiscoveryStatus.COMPLETED);
        assertThat(messages(run))
                .extracting(DiscoveryMessage::getCode)
                .contains(DiscoveryMessageCode.BATCH_PROCESSING_FAILED.code());
    }

    @Test
    void batchThatFailedBeforeStampingAnything_leavesTheBacklogIntact() throws Exception {
        Discovery run = processingRun();
        stageCertificates(run, 2);
        doThrow(new IllegalStateException("pod died mid-batch")).when(importHandler).processBatch(any(), anyList());

        worker.tick(run.getUuid(), 0);

        // Nothing stamped its rows, so the backlog is exactly what it was: the cursor is the only progress
        // record, and a batch that never committed made none.
        assertThat(certificateRepository
                .countByDiscoveryUuidAndNewlyDiscoveredTrueAndProcessedFalseAndProcessedErrorIsNull(run.getUuid()))
                .isEqualTo(2);
        assertThat(reload(run).getStatus()).isEqualTo(DiscoveryStatus.PROCESSING);
        // Caught here, not left to the listener's log-and-acknowledge, which would spend no budget.
        assertThat(processRow(run).getAttempt())
                .as("a batch that failed wholesale spends budget like any other tick that made no progress")
                .isEqualTo(1);
        verify(workProducer, never()).produceMessage(any());
    }

    @Test
    void batchThatAccountsForNothing_backsOffInsteadOfLoopingOnTheBroker() throws Exception {
        Discovery run = processingRun();
        stageCertificates(run, 2);
        // What the pipeline does with a row it never reached: records the reason, leaves processed false.
        importsWithoutStamping();

        worker.tick(run.getUuid(), 0);

        // Publishing here is what turns a stalled run into a tight loop against the broker, re-running the whole
        // import pipeline forever and never ending the run.
        verify(workProducer, never()).produceMessage(any());
        assertThat(processRow(run).getAttempt()).isEqualTo(1);
        assertThat(processRow(run).getNextDueAt()).isAfter(OffsetDateTime.now(ZoneOffset.UTC));
        assertThat(reload(run).getStatus()).isEqualTo(DiscoveryStatus.PROCESSING);
    }

    @Test
    void runThatNeverAccountsForItsBacklog_endsRatherThanStayingInProcessing() throws Exception {
        Discovery run = processingRun();
        stageCertificates(run, 2);
        importsWithoutStamping();
        int lastAttempt = workProperties.scheduleFor(DiscoveryWorkType.PROCESS).maxAttempts() - 1;

        worker.tick(run.getUuid(), lastAttempt);

        // The budget ends the run with a reason naming what was left behind, rather than backing off forever.
        Discovery reloaded = reload(run);
        assertThat(reloaded.getStatus()).isEqualTo(DiscoveryStatus.WARNING);
        assertThat(reloaded.getMessage()).contains("2 discovered item(s) that could not be imported");
        assertThat(agenda(run)).isEmpty();
    }

    @Test
    void rowsCarryingAReason_areNotReclaimedForever() throws Exception {
        Discovery run = processingRun();
        List<DiscoveryCertificate> staged = stageCertificates(run, 1);
        // The pipeline recorded why it could not import this row without stamping processed. That is an
        // outcome, so the backlog must not keep handing it back.
        discoveryWriter
                .recordProcessedError(List.of(staged.get(0).getUuid()), "the import transaction was rolled back");
        importsCleanly();

        worker.tick(run.getUuid(), 0);

        assertThat(reload(run).getStatus()).isEqualTo(DiscoveryStatus.WARNING);
        verify(importHandler, never()).processBatch(any(), anyList());
    }

    @Test
    void contentGroupLargerThanTheBatch_isClaimedWholeRatherThanSplit() throws Exception {
        Discovery run = processingRun();
        // One certificate found on three hosts: three rows, one content. batch-size is 1, so paging by row
        // would hand this group to three separate ticks and run its triggers and histories three times.
        stageCertificatesSharingContent(run, 3);
        importsCleanly();

        worker.tick(run.getUuid(), 0);

        assertThat(claimedBatchSizes).as("the group travels together, whatever the batch size says").containsExactly(3);
        assertThat(reload(run).getStatus()).isEqualTo(DiscoveryStatus.COMPLETED);
    }

    @Test
    void oneContentBiggerThanTheBudget_isStillClaimedWholeAndAlone() throws Exception {
        Discovery run = processingRun();
        // batch-size is 1, so this group is three times the budget. Splitting it would run its triggers and
        // histories three times; the group therefore wins and the tick carries it alone.
        stageCertificatesSharingContent(run, 3);
        stageCertificates(run, 1);
        importsCleanly();

        worker.tick(run.getUuid(), 0);

        assertThat(claimedBatchSizes)
                .as("the oversized group travels whole, and nothing else rides along with it")
                .containsExactly(3);
        assertThat(reload(run).getStatus()).isEqualTo(DiscoveryStatus.PROCESSING);
    }

    @Test
    void emptyBacklogWithNoFailures_endsTheRunCompleted() throws Exception {
        Discovery run = processingRun();

        worker.tick(run.getUuid(), 0);

        Discovery reloaded = reload(run);
        assertThat(reloaded.getStatus()).isEqualTo(DiscoveryStatus.COMPLETED);
        assertThat(reloaded.getEndTime()).isNotNull();
        assertThat(agenda(run)).isEmpty();
        verify(importHandler, never()).processBatch(any(), anyList());
    }

    @Test
    void batchThatFellShort_filesItsSummaryOnTheRunAsItGoes() throws Exception {
        Discovery run = processingRun();
        stageCertificates(run, 2);
        importsWith(new DiscoveryRunCounts(1, 0, 0, 0, false));

        worker.tick(run.getUuid(), 0);

        assertThat(messages(run))
                .as("an operator watching a long run sees what is going wrong while it is still going wrong")
                .singleElement()
                .satisfies(gap -> {
                    assertThat(gap.getCode()).isEqualTo(DiscoveryMessageCode.INVENTORY_GAP.code());
                    assertThat(gap.getSeverity()).isEqualTo(DiscoveryMessageSeverity.WARNING);
                    assertThat(gap.getOccurrences()).isEqualTo(1);
                    // The count is the occurrence column, not part of the text: it is what lets the next batch
                    // reporting the same gap add to this row instead of writing a second one.
                    assertThat(gap.getMessage()).doesNotContain("1 ");
                });
        assertThat(reload(run).getStatus()).isEqualTo(DiscoveryStatus.PROCESSING);
    }

    @Test
    void twoBatchesFallingShortTheSameWay_shareOneEntryCountedTwice() throws Exception {
        Discovery run = processingRun();
        stageCertificates(run, 2);
        importsWith(new DiscoveryRunCounts(1, 0, 0, 0, false));

        // Two ticks, each its own transaction: the second aggregates onto what the first committed.
        worker.tick(run.getUuid(), 0);
        worker.tick(run.getUuid(), 0);

        assertThat(messages(run))
                .filteredOn(message -> DiscoveryMessageCode.INVENTORY_GAP.code().equals(message.getCode()))
                .as("a run degraded the same way all day long is one entry, not one per batch")
                .singleElement()
                .satisfies(gap -> {
                    assertThat(gap.getOccurrences()).isEqualTo(2);
                    assertThat(gap.getLastSeenAt()).isAfter(gap.getFirstSeenAt());
                });
    }

    @Test
    void batchThatFailedWithNothingLeftToRetry_endsTheRunAsAWarning() throws Exception {
        Discovery run = processingRun();
        stageCertificates(run, 1);
        stampsEveryRowThenDies();

        worker.tick(run.getUuid(), 0);

        // The rows are imported and the backlog is empty, so no later tick will revisit this failure. Filing it
        // as retryable would leave the only record of it at a severity the ending ignores.
        assertThat(backlog(run)).isZero();
        assertThat(messages(run))
                .extracting(DiscoveryMessage::getCode)
                .contains(DiscoveryMessageCode.BATCH_PROCESSING_ABANDONED.code())
                .doesNotContain(DiscoveryMessageCode.BATCH_PROCESSING_FAILED.code());
        assertThat(reload(run).getStatus()).isEqualTo(DiscoveryStatus.WARNING);
    }

    @Test
    void batchWithNothingLeftToRetry_isJudgedOnItsOwnRowsNotTheRunsBacklog() throws Exception {
        Discovery run = processingRun();
        // Three rows at a batch size of one, so the first batch finishes while the run still has a backlog.
        stageCertificates(run, 3);
        stampsEveryRowThenDies();

        worker.tick(run.getUuid(), 0);

        // Two rows are left, but none belongs to the batch that failed, so nothing will ever retry it.
        assertThat(backlog(run)).isEqualTo(2);
        assertThat(messages(run))
                .extracting(DiscoveryMessage::getCode)
                .contains(DiscoveryMessageCode.BATCH_PROCESSING_ABANDONED.code())
                .doesNotContain(DiscoveryMessageCode.BATCH_PROCESSING_FAILED.code());

        importsCleanly();
        worker.tick(run.getUuid(), 0);
        worker.tick(run.getUuid(), 0);

        assertThat(backlog(run)).isZero();
        assertThat(reload(run).getStatus())
                .as("the batch that was never retried is what the run ends on")
                .isEqualTo(DiscoveryStatus.WARNING);
    }

    @Test
    void cleanBatch_addsNothingToTheRunMessageLog() throws Exception {
        Discovery run = processingRun();
        stageCertificates(run, 1);
        importsCleanly();

        worker.tick(run.getUuid(), 0);

        assertThat(messages(run))
                .as("only the terminal line, so a clean run's log is not noise")
                .singleElement()
                .satisfies(ending -> {
                    assertThat(ending.getCode()).isEqualTo(DiscoveryMessageCode.RUN_ENDED.code());
                    assertThat(ending.getMessage()).isEqualTo("Discovery completed successfully.");
                    assertThat(ending.getSeverity()).isEqualTo(DiscoveryMessageSeverity.INFO);
                });
    }

    @Test
    void rowThatRecordedAReason_endsTheRunAsAWarning() throws Exception {
        Discovery run = processingRun();
        List<DiscoveryCertificate> staged = stageCertificates(run, 2);
        // The pipeline's own bookkeeping stamps the reason; here it is the evidence the worker reads.
        importsCleanly();
        discoveryWriter.markProcessed(List.of(staged.get(0).getUuid()), "Import rolled back: the chain was incomplete");

        worker.tick(run.getUuid(), 0);
        worker.tick(run.getUuid(), 0);

        Discovery reloaded = reload(run);
        assertThat(reloaded.getStatus()).isEqualTo(DiscoveryStatus.WARNING);
        assertThat(reloaded.getMessage()).contains("warnings");
        assertThat(agenda(run)).isEmpty();
    }

    @Test
    void runThatIsNotProcessing_dropsTheTickWithoutImportingAnything() throws Exception {
        Discovery run = processingRun();
        run.setStatus(DiscoveryStatus.IN_PROGRESS);
        discoveryRepository.saveAndFlush(run);
        stageCertificates(run, 1);

        worker.tick(run.getUuid(), 0);

        verify(importHandler, never()).processBatch(any(), anyList());
        assertThat(reload(run).getStatus()).isEqualTo(DiscoveryStatus.IN_PROGRESS);
    }

    @Test
    void terminalRun_dropsTheTickAndClearsItsLeftoverAgenda() throws Exception {
        Discovery run = processingRun();
        run.setStatus(DiscoveryStatus.COMPLETED);
        discoveryRepository.saveAndFlush(run);

        worker.tick(run.getUuid(), 0);

        assertThat(agenda(run)).isEmpty();
        verify(importHandler, never()).processBatch(any(), anyList());
    }

    @Test
    void tickForADeletedRun_isDroppedWithoutFailing() {
        worker.tick(UUID.randomUUID(), 0);

        assertThat(workRepository.findAll()).isEmpty();
    }

    @Test
    void warningFromRunLevelEvidenceAlone_doesNotSendTheOperatorToTheCertificateList() throws Exception {
        Discovery run = processingRun();
        // A run-level gap with every row clean: a bookkeeping write that failed, or validation never queued.
        messageWriter
                .append(run.getUuid(), DiscoveryMessageSeverity.WARNING, DiscoveryMessageCode.VALIDATION_NOT_REQUESTED,
                        "Validation of the discovered certificates could not be requested.");

        worker.tick(run.getUuid(), 0);

        Discovery reloaded = reload(run);
        assertThat(reloaded.getStatus()).isEqualTo(DiscoveryStatus.WARNING);
        assertThat(reloaded.getMessage())
                .as("no row carries a reason, so the certificate list has nothing for the operator to find")
                .isEqualTo("Discovery completed with warnings. See this run's messages.");
    }

    @Test
    void rowStagedBeforeTheEndingCommits_stopsTheRunFromEnding() {
        Discovery run = processingRun();
        stageCertificates(run, 1);

        // What a drain page in flight across the handover does: its rows land while the process worker is
        // between counting an empty backlog and ending the run. Ending on the earlier count would leave them
        // staged, counted by nobody and never imported.
        boolean ended = terminator
                .endWith(run.getUuid(),
                        locked -> backlog(run) > 0
                                ? null
                                : new Ending(DiscoveryStatus.COMPLETED, "Discovery completed successfully."));

        assertThat(ended).isFalse();
        assertThat(reload(run).getStatus()).isEqualTo(DiscoveryStatus.PROCESSING);
        assertThat(agenda(run)).as("the run is still live, so its agenda must not be taken").hasSize(1);
    }

    @Test
    void endingDecidedUnderTheLock_readsTheRunAsItStandsWhenTheEndingCommits() {
        Discovery run = processingRun();
        // A late drain page appended a complaint after the worker had already read the run. Deciding from
        // anything read before the lock would report this run as completed successfully while it carries a
        // warning.
        messageWriter
                .append(run.getUuid(), DiscoveryMessageSeverity.WARNING, DiscoveryMessageCode.ITEM_SEQUENCE_MISSING,
                        "A discovered item arrived without a sequence and was skipped.");

        boolean ended = terminator
                .endWith(run.getUuid(),
                        locked -> messageRepository.countByDiscoveryUuid(locked.getUuid()) == 0
                                ? new Ending(DiscoveryStatus.COMPLETED, "Discovery completed successfully.")
                                : new Ending(DiscoveryStatus.WARNING, "Discovery completed with warnings."));

        assertThat(ended).isTrue();
        assertThat(reload(run).getStatus()).isEqualTo(DiscoveryStatus.WARNING);
    }

    /** Stubs the pipeline to do what a clean import does: stamp every row of the batch as processed. */
    private void importsCleanly() throws Exception {
        importsWith(new DiscoveryRunCounts(0, 0, 0, 0, false));
    }

    /**
     * A pipeline pass that stamps every row and then dies — a failure in the post-import work that runs after the
     * groups have already committed.
     */
    private void stampsEveryRowThenDies() throws Exception {
        doAnswer(invocation -> {
            List<DiscoveryCertificate> batch = invocation.getArgument(1);
            claimedBatchSizes.add(batch.size());
            discoveryWriter.markProcessed(batch.stream().map(DiscoveryCertificate::getUuid).toList(), null);
            throw new IllegalStateException("bookkeeping failed after the import committed");
        }).when(importHandler).processBatch(any(), anyList());
    }

    /** A pipeline pass that commits one row's outcome and then dies — a pod lost part way through a batch. */
    private void stampsOneRowThenDies() throws Exception {
        doAnswer(invocation -> {
            List<DiscoveryCertificate> batch = invocation.getArgument(1);
            claimedBatchSizes.add(batch.size());
            discoveryWriter.markProcessed(List.of(batch.get(0).getUuid()), null);
            throw new IllegalStateException("pod died mid-batch");
        }).when(importHandler).processBatch(any(), anyList());
    }

    private long backlog(Discovery run) {
        return certificateRepository
                .countByDiscoveryUuidAndNewlyDiscoveredTrueAndProcessedFalseAndProcessedErrorIsNull(run.getUuid());
    }

    /** A pipeline pass that records reasons but stamps nothing — what an unreachable batch looks like. */
    private void importsWithoutStamping() throws Exception {
        doAnswer(invocation -> {
            claimedBatchSizes.add(((List<?>) invocation.getArgument(1)).size());
            return new DiscoveryRunCounts(0, 0, 1, 0, false);
        }).when(importHandler).processBatch(any(), anyList());
    }

    private DiscoveryWork processRow(Discovery run) {
        return agenda(run).stream().findFirst().orElseThrow();
    }

    /** The same, but reporting the given gaps — the pipeline stamps its rows either way. */
    private void importsWith(DiscoveryRunCounts counts) throws Exception {
        doAnswer(invocation -> {
            List<DiscoveryCertificate> batch = invocation.getArgument(1);
            claimedBatchSizes.add(batch.size());
            discoveryWriter.markProcessed(batch.stream().map(DiscoveryCertificate::getUuid).toList(), null);
            return counts;
        }).when(importHandler).processBatch(any(), anyList());
    }

    private List<DiscoveryWorkMessage> publishedTicks() {
        ArgumentCaptor<DiscoveryWorkMessage> published = ArgumentCaptor.forClass(DiscoveryWorkMessage.class);
        verify(workProducer, atLeastOnce()).produceMessage(published.capture());
        return published.getAllValues();
    }

    private List<DiscoveryWork> agenda(Discovery run) {
        return workRepository.findAll().stream().filter(row -> row.getDiscoveryUuid().equals(run.getUuid())).toList();
    }

    private Discovery reload(Discovery run) {
        return discoveryRepository.findByUuid(run.getUuid()).orElseThrow();
    }

    private List<DiscoveryMessage> messages(Discovery run) {
        return messageRepository.findByDiscoveryUuidOrderByIdAsc(run.getUuid());
    }

    private List<DiscoveryCertificate> stageCertificates(Discovery run, int count) {
        for (int i = 0; i < count; i++) {
            // Each row needs its own content: the column is NOT NULL, and the pipeline groups rows by it.
            CertificateContent content = new CertificateContent();
            content.setFingerprint(UUID.randomUUID().toString());
            content.setContent("staged-" + i);
            DiscoveryCertificate staged = new DiscoveryCertificate();
            staged.setCertificateContent(certificateContentRepository.saveAndFlush(content));
            staged.setDiscovery(run);
            staged.setNewlyDiscovered(true);
            staged.setProcessed(false);
            staged.setCommonName("host-" + i + ".example.com");
            certificateRepository.saveAndFlush(staged);
        }
        return certificateRepository
                .findByDiscoveryUuidAndCertificateContentIdInAndNewlyDiscoveredTrueAndProcessedFalseAndProcessedErrorIsNull(
                        run.getUuid(),
                        certificateRepository
                                .findPendingContentWeights(run.getUuid(), PageRequest.of(0, 100))
                                .stream()
                                .map(weighted -> (Long) weighted[0])
                                .toList());
    }

    /** Rows for one shared certificate content — the same certificate found on several hosts. */
    private void stageCertificatesSharingContent(Discovery run, int rows) {
        CertificateContent content = new CertificateContent();
        content.setFingerprint(UUID.randomUUID().toString());
        content.setContent("shared-content");
        CertificateContent saved = certificateContentRepository.saveAndFlush(content);
        for (int i = 0; i < rows; i++) {
            DiscoveryCertificate staged = new DiscoveryCertificate();
            staged.setCertificateContent(saved);
            staged.setDiscovery(run);
            staged.setNewlyDiscovered(true);
            staged.setProcessed(false);
            staged.setCommonName("host-" + i + ".example.com");
            certificateRepository.saveAndFlush(staged);
        }
    }

    private void stageKeys(Discovery run, int count) {
        for (int i = 1; i <= count; i++) {
            DiscoveredKeyDto payload = new DiscoveredKeyDto();
            payload.setType(KeyType.PUBLIC_KEY);
            payload.setAlgorithm(KeyAlgorithm.RSA);
            payload.setLength(2048);
            payload.setPublicKeyFormat(KeyFormat.SPKI);
            payload.setFingerprint("fp-" + UUID.randomUUID());
            // Real material: a key is onboarded only once Core can read its public part.
            payload.setPublicKey(Base64.getEncoder().encodeToString(publicKeyMaterial(i)));
            DiscoveredItemDto item = new DiscoveredItemDto();
            item.setSequence((long) i);
            item.setUniqueRef("key-" + i);
            item.setPayload(payload);
            item.setDiscoveredAt(OffsetDateTime.now(ZoneOffset.UTC));
            itemWriter.stage(run.getUuid(), item, true);
        }
    }

    /** One page as a connector hands it over: two keys, each with its own material. */
    private DiscoveryResultsResponseDto drainedKeys(Discovery run) {
        DiscoveryResultsResponseDto page = new DiscoveryResultsResponseDto();
        page.setItems(List.of(drainedKey(1, "ssh://host-a:22"), drainedKey(2, "tls://host-b:443")));
        page.setHighestSequence(2L);
        page.setMore(false);
        return page;
    }

    private DiscoveredItemDto drainedKey(int sequence, String uniqueRef) {
        DiscoveredKeyDto payload = new DiscoveredKeyDto();
        payload.setType(KeyType.PUBLIC_KEY);
        payload.setAlgorithm(KeyAlgorithm.RSA);
        payload.setLength(2048);
        payload.setPublicKeyFormat(KeyFormat.SPKI);
        payload.setFingerprint("connector-fingerprint-" + uniqueRef);
        payload.setPublicKey(Base64.getEncoder().encodeToString(publicKeyMaterial(sequence)));
        DiscoveredItemDto item = new DiscoveredItemDto();
        item.setSequence((long) sequence);
        item.setUniqueRef(uniqueRef);
        item.setPayload(payload);
        item.setDiscoveredAt(OffsetDateTime.now(ZoneOffset.UTC));
        return item;
    }

    /** Distinct material per key, so two keys stay two records rather than deduplicating into one. */
    private static byte[] publicKeyMaterial(int seed) {
        try {
            KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
            generator.initialize(2048);
            return generator.generateKeyPair().getPublic().getEncoded();
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException(e);
        }
    }

    private void stageUnusableKey(Discovery run) {
        DiscoveredKeyDto payload = new DiscoveredKeyDto();
        payload.setType(KeyType.SECRET_KEY);
        payload.setAlgorithm(KeyAlgorithm.UNKNOWN);
        // No public part and no fingerprint: nothing here tells this key apart from any other.
        DiscoveredItemDto item = new DiscoveredItemDto();
        item.setSequence(1L);
        item.setUniqueRef("vault://unnamed");
        item.setPayload(payload);
        item.setDiscoveredAt(OffsetDateTime.now(ZoneOffset.UTC));
        itemWriter.stage(run.getUuid(), item, true);
    }

    private List<DiscoveryItem> keyItemsOf(Discovery run) {
        return itemRepository.findAll().stream().filter(item -> run.getUuid().equals(item.getDiscoveryUuid())).toList();
    }

    private long importedKeyItems(Discovery run) {
        return keyItemsOf(run).stream().filter(item -> item.getInventoryUuid() != null).count();
    }

    private Discovery processingRun() {
        Discovery run = new Discovery();
        run.setName("v2-scan-" + UUID.randomUUID());
        run.setKind("IP-HostName");
        run.setStatus(DiscoveryStatus.PROCESSING);
        run.setConnectorStatus(DiscoveryStatus.COMPLETED);
        ConnectorInterfaceEntity discoveryInterface = DiscoveryInterfaceFixture
                .v2Interface(connectorRepository, connectorInterfaceRepository);
        run.setConnectorUuid(discoveryInterface.getConnectorUuid());
        run.setConnectorName("network-discovery");
        run.setConnectorInterfaceUuid(discoveryInterface.getUuid());
        run.setStartedByUserUuid(RUN_OWNER);
        Discovery saved = discoveryRepository.saveAndFlush(run);
        workWriter
                .schedule(saved.getUuid(), DiscoveryWorkType.PROCESS, OffsetDateTime.now(ZoneOffset.UTC).plusHours(1));
        return saved;
    }
}
