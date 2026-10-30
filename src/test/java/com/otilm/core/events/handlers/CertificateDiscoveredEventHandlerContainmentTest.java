package com.otilm.core.events.handlers;

import com.otilm.core.dao.entity.DiscoveryCertificate;
import com.otilm.core.dao.entity.workflows.Trigger;
import com.otilm.core.dao.entity.workflows.TriggerAssociation;
import com.otilm.core.dao.entity.workflows.TriggerHistory;
import com.otilm.core.dao.repository.CertificateRepository;
import com.otilm.core.dao.repository.workflows.EventHistoryRepository;
import com.otilm.core.evaluator.CertificateTriggerEvaluator;
import com.otilm.core.events.handlers.discovery.DiscoveryCertificateOutcome;
import com.otilm.core.events.handlers.discovery.DiscoveryCertificateResult;
import com.otilm.core.events.handlers.discovery.DiscoveryContentGroup;
import com.otilm.core.events.handlers.discovery.DiscoveryImportRollbackException;
import com.otilm.core.events.handlers.discovery.DiscoveryRunAccumulator;
import com.otilm.core.events.handlers.discovery.DiscoveryRunContext;
import com.otilm.core.events.handlers.discovery.DiscoveryRunCounts;
import com.otilm.core.events.handlers.discovery.GroupImportResult;
import com.otilm.core.events.transaction.TransactionHandler;
import com.otilm.core.service.TriggerInternalService;
import com.otilm.core.service.writer.DiscoveryWriter;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Set;
import java.util.UUID;
import java.util.function.Supplier;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentMatchers;
import org.springframework.transaction.UnexpectedRollbackException;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyCollection;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.doAnswer;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/**
 * The post-processing phases that have to survive a failure of the phase before them. An escaping progress write ends
 * the run silently by skipping key association altogether; a group the consumption loop never reached does so by
 * leaving lost work out of the counts that decide the status.
 */
class CertificateDiscoveredEventHandlerContainmentTest {

    private final DiscoveryWriter discoveryWriter = mock(DiscoveryWriter.class);
    private final CertificateRepository certificateRepository = mock(CertificateRepository.class);
    private final TransactionHandler transactionHandler = mock(TransactionHandler.class);
    private final TriggerInternalService triggerService = mock(TriggerInternalService.class);
    private final EventHistoryRepository eventHistoryRepository = mock(EventHistoryRepository.class);
    private final CertificateDiscoveredEventHandler handler = new CertificateDiscoveredEventHandler(
            certificateRepository, mock(CertificateTriggerEvaluator.class));

    @BeforeEach
    void setUp() {
        doAnswer(invocation -> {
            invocation.getArgument(0, Runnable.class).run();
            return null;
        }).when(transactionHandler).runInNewTransaction(any(Runnable.class));

        handler.setTransactionHandler(transactionHandler);
        handler.setDiscoveryWriter(discoveryWriter);
        handler.setTriggerService(triggerService);
        // The failure record resolves the event history in its own transaction, so the repository must be present.
        handler.setEventHistoryRepository(eventHistoryRepository);
    }

    @Test
    void aFailedProgressWriteIsContainedAndCountedRatherThanThrown() {
        doThrow(new RuntimeException("could not reach the database"))
                .when(discoveryWriter)
                .updateProgressMessage(any(UUID.class), anyString());
        DiscoveryRunAccumulator accumulator = new DiscoveryRunAccumulator();

        handler.reportProgressSafely(runContext(), accumulator, 3);

        assertThat(accumulator.counts().bookkeepingFailures())
                .as("progress is cosmetic, but a run whose detail is incomplete is not clean")
                .isEqualTo(1);
    }

    @Test
    void groupsTheLoopNeverReachedAreRecordedAsNotAttempted() {
        DiscoveryRunAccumulator accumulator = new DiscoveryRunAccumulator();
        DiscoveryContentGroup consumed = group(1L, UUID.randomUUID());
        DiscoveryContentGroup unconsumed = group(2L, UUID.randomUUID(), UUID.randomUUID());

        handler.accountForUnconsumedGroups(accumulator, List.of(consumed, unconsumed), Set.of(1L));

        assertThat(accumulator.results())
                .as("only the unconsumed group's rows, and both of them")
                .hasSize(2)
                .allSatisfy(result -> {
                    assertThat(result.outcome()).isEqualTo(DiscoveryCertificateOutcome.NOT_ATTEMPTED);
                    assertThat(result.detail()).isEqualTo("the import did not run to a result");
                });
        assertThat(accumulator.counts().notAttempted())
                .as("one certificate on two hosts is one certificate")
                .isEqualTo(1);
        assertThat(accumulator.counts().allClear()).as("a run that lost work must not report itself clean").isFalse();
        // markProcessed would set processed = true on rows the platform never reached.
        verify(discoveryWriter).recordProcessedError(anyCollection(), anyString());
        verify(discoveryWriter, never()).markProcessed(anyCollection(), anyString());
    }

    /**
     * A probe failure escaping this phase would discard the key maps of every group that did consume, whose rows
     * already read as processed without a reason.
     */
    @Test
    void aFailedProbeIsContainedSoTheKeyPhaseStillRuns() {
        when(certificateRepository.existsByCertificateContentId(5L))
                .thenThrow(new org.springframework.dao.QueryTimeoutException("the probe timed out"));
        DiscoveryRunAccumulator accumulator = new DiscoveryRunAccumulator();

        handler.accountForUnconsumedGroups(accumulator, List.of(group(5L, UUID.randomUUID())), Set.of());

        assertThat(accumulator.counts().bookkeepingFailures())
                .as("the failure is recorded rather than thrown, so the caller reaches key association")
                .isEqualTo(1);
    }

    @Test
    void aFullyConsumedRunAccountsForNothingExtra() {
        DiscoveryRunAccumulator accumulator = new DiscoveryRunAccumulator();

        handler.accountForUnconsumedGroups(accumulator, List.of(group(1L, UUID.randomUUID())), Set.of(1L));

        assertThat(accumulator.results()).isEmpty();
        assertThat(accumulator.counts().allClear()).isTrue();
    }

    /**
     * The distinction the database exists to settle here: a group whose certificate is already committed did import, so
     * calling it never-attempted would claim a missing certificate that is sitting in the inventory.
     */
    @Test
    void anUnconsumedGroupWhoseCertificateCommittedIsAKeyGapNotAnUnattemptedImport() {
        when(certificateRepository.existsByCertificateContentId(2L)).thenReturn(true);
        DiscoveryRunAccumulator accumulator = new DiscoveryRunAccumulator();

        handler.accountForUnconsumedGroups(accumulator, List.of(group(2L, UUID.randomUUID())), Set.of());

        assertThat(accumulator.results()).singleElement().satisfies(result -> {
            assertThat(result.outcome()).isEqualTo(DiscoveryCertificateOutcome.KEY_ASSOCIATION_FAILED);
            assertThat(result.detail())
                    .isEqualTo("the certificate was imported, but the run stopped before its key could be associated");
        });
        DiscoveryRunCounts counts = accumulator.counts();
        assertThat(counts.keyGaps()).isEqualTo(1);
        assertThat(counts.notAttempted()).as("the certificate exists, so nothing here was left unattempted").isZero();
        assertThat(counts.inventoryGaps()).isZero();
        // The key phase owns these rows and writes them after aggregation.
        verify(discoveryWriter, never()).markProcessed(anyCollection(), anyString());
        verify(discoveryWriter, never()).recordProcessedError(anyCollection(), anyString());
    }

    /**
     * A failing action-trigger phase must leave the group's outcome alone. The certificate has committed by then, so
     * reporting a rollback would put a reason on rows whose certificate is in the inventory.
     */
    @Test
    void aFailingActionTriggerPhaseLeavesTheImportedResultIntact() {
        UUID rowUuid = UUID.randomUUID();
        UUID certificateUuid = UUID.randomUUID();
        GroupImportResult committed = new GroupImportResult(6L,
                List.of(new DiscoveryCertificateResult(rowUuid, DiscoveryCertificateOutcome.IMPORTED, null)), List.of(),
                true);
        when(transactionHandler
                .runInNewTransaction(ArgumentMatchers.<Supplier<CertificateDiscoveredEventHandler.ImportedGroup>>any()))
                .thenReturn(
                        new CertificateDiscoveredEventHandler.ImportedGroup(committed, certificateUuid, null, rowUuid));
        doThrow(new UnexpectedRollbackException("an execution poisoned the trigger transaction"))
                .when(transactionHandler)
                .runInNewTransaction(any(Runnable.class));

        GroupImportResult result = handler.importGroupSafely(runContextWithTriggers(), group(6L, rowUuid));

        assertThat(result.committed())
                .as("the import committed, so the group is imported however the triggers fared")
                .isTrue();
        assertThat(result.rowResults()).singleElement().satisfies(row -> {
            assertThat(row.outcome()).isEqualTo(DiscoveryCertificateOutcome.IMPORTED);
            assertThat(row.detail()).isNull();
        });
    }

    /**
     * Asserted structurally because no execution an integration test can reach fails unchecked. Sharing one transaction
     * is what let a single poisoned execution discard every other trigger's history and writes.
     */
    @Test
    void eachActionTriggerGetsItsOwnTransaction() {
        UUID rowUuid = UUID.randomUUID();
        GroupImportResult committed = new GroupImportResult(7L,
                List.of(new DiscoveryCertificateResult(rowUuid, DiscoveryCertificateOutcome.IMPORTED, null)), List.of(),
                true);
        when(transactionHandler
                .runInNewTransaction(ArgumentMatchers.<Supplier<CertificateDiscoveredEventHandler.ImportedGroup>>any()))
                .thenReturn(new CertificateDiscoveredEventHandler.ImportedGroup(committed, UUID.randomUUID(), null,
                        rowUuid));

        handler.importGroupSafely(runContextWithTriggers(3), group(7L, rowUuid));

        verify(transactionHandler, times(3)).runInNewTransaction(any(Runnable.class));
    }

    /**
     * A lost trigger transaction takes the evaluator's own record of the failure with it, so it is written again in a
     * fresh one. Only reachable with a stub, which is why the end-to-end tests cannot cover it.
     */
    @Test
    void aLostTriggerTransactionStillLeavesAFailureRecord() {
        UUID rowUuid = UUID.randomUUID();
        UUID certificateUuid = UUID.randomUUID();
        GroupImportResult committed = new GroupImportResult(8L,
                List.of(new DiscoveryCertificateResult(rowUuid, DiscoveryCertificateOutcome.IMPORTED, null)), List.of(),
                true);
        when(transactionHandler
                .runInNewTransaction(ArgumentMatchers.<Supplier<CertificateDiscoveredEventHandler.ImportedGroup>>any()))
                .thenReturn(
                        new CertificateDiscoveredEventHandler.ImportedGroup(committed, certificateUuid, null, rowUuid));
        TriggerHistory history = new TriggerHistory();
        history.setUuid(UUID.randomUUID());
        when(triggerService.createTriggerHistory(any(), any(), any(), any(), any(), any())).thenReturn(history);
        // The trigger's own transaction is lost; the one that records the failure is not.
        doThrow(new UnexpectedRollbackException("an execution poisoned the trigger transaction"))
                .doAnswer(invocation -> {
                    invocation.getArgument(0, Runnable.class).run();
                    return null;
                })
                .when(transactionHandler)
                .runInNewTransaction(any(Runnable.class));

        handler.importGroupSafely(runContextWithTriggers(), group(8L, rowUuid));

        verify(triggerService).createTriggerHistory(any(), any(), eq(certificateUuid), eq(rowUuid), any(), any());
        verify(triggerService).createTriggerHistoryRecord(eq(history.getUuid()), any(), any(), anyString());
    }

    /**
     * The reason a group carries out through its own rollback has to survive the shaping the orchestrator applies on
     * the way past. Shaped from an unclassified wrapper it would collapse to "an unexpected error occurred".
     */
    @Test
    void anAlreadyShapedRollbackReasonSurvivesTheOrchestratorsShaping() {
        when(transactionHandler
                .runInNewTransaction(ArgumentMatchers.<Supplier<CertificateDiscoveredEventHandler.ImportedGroup>>any()))
                .thenThrow(new DiscoveryImportRollbackException(
                        "trigger evaluation failed: the discovered certificate could not be parsed", null));

        GroupImportResult result = handler.importGroupSafely(runContext(), group(3L, UUID.randomUUID()));

        assertThat(result.committed()).isFalse();
        assertThat(result.rowResults()).singleElement().satisfies(row -> {
            assertThat(row.outcome()).isEqualTo(DiscoveryCertificateOutcome.IMPORT_ROLLED_BACK);
            assertThat(row.detail())
                    .isEqualTo("Import rolled back: trigger evaluation failed: "
                            + "the discovered certificate could not be parsed");
        });
    }

    @Test
    void anInterruptedGroupIsNotAttemptedRatherThanLost() {
        Thread.currentThread().interrupt();
        try {
            GroupImportResult result = handler.importGroupSafely(runContext(), group(4L, UUID.randomUUID()));

            assertThat(result.committed()).isFalse();
            assertThat(result.rowResults()).singleElement().satisfies(row -> {
                assertThat(row.outcome()).isEqualTo(DiscoveryCertificateOutcome.NOT_ATTEMPTED);
                assertThat(row.detail()).isEqualTo("the import was interrupted before it began");
            });
            assertThat(Thread.currentThread().isInterrupted())
                    .as("the interrupt must be reasserted, not swallowed")
                    .isTrue();
        } finally {
            Thread.interrupted();
        }
    }

    private DiscoveryRunContext runContextWithTriggers() {
        return runContextWithTriggers(1);
    }

    private DiscoveryRunContext runContextWithTriggers(int triggerCount) {
        List<TriggerAssociation> associations = new ArrayList<>();
        for (int i = 0; i < triggerCount; i++) {
            TriggerAssociation association = new TriggerAssociation();
            Trigger trigger = new Trigger();
            trigger.setUuid(UUID.randomUUID());
            association.setTrigger(trigger);
            associations.add(association);
        }
        return new DiscoveryRunContext(UUID.randomUUID(), "discovery", UUID.randomUUID(), "connector", "kind",
                UUID.randomUUID(), List.of(), associations, UUID.randomUUID(), UUID.randomUUID(), 7, null);
    }

    private DiscoveryRunContext runContext() {
        return new DiscoveryRunContext(UUID.randomUUID(), "discovery", UUID.randomUUID(), "connector", "kind",
                UUID.randomUUID(), List.of(), List.of(), UUID.randomUUID(), UUID.randomUUID(), 7, null);
    }

    private DiscoveryContentGroup group(Long contentId, UUID... rowUuids) {
        List<DiscoveryCertificate> rows = Arrays.stream(rowUuids).map(rowUuid -> {
            DiscoveryCertificate row = new DiscoveryCertificate();
            row.setUuid(rowUuid);
            return row;
        }).toList();
        return new DiscoveryContentGroup(contentId, rows);
    }
}
