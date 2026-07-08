package com.otilm.core.signing.record;

import com.otilm.core.cluster.ClusterOperationSynchronizer;
import com.otilm.core.dao.entity.signing.SigningRecord;
import com.otilm.core.dao.entity.signing.SigningRecordOutbox;
import com.otilm.core.dao.repository.signing.SigningRecordOutboxRepository;
import com.otilm.core.service.writer.signingrecord.SigningRecordWriter;
import jakarta.persistence.EntityManager;
import jakarta.persistence.PersistenceException;
import io.micrometer.core.instrument.MeterRegistry;
import io.micrometer.core.instrument.simple.SimpleMeterRegistry;
import org.hibernate.exception.ConstraintViolationException;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.function.Executable;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyInt;
import static org.mockito.ArgumentMatchers.anyIterable;
import static org.mockito.ArgumentMatchers.anyList;
import static org.mockito.ArgumentMatchers.argThat;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/**
 * Pure unit test for {@link SigningRecordOutboxDrainer} over a mocked repository, writer, and cluster
 * synchronizer. The drainer's job is narrow: acquire the cluster-wide drain lock (or skip if another node holds
 * it), read successive drainable batches, bulk-load and map the claimed outbox rows, and hand all mapped records
 * to {@link SigningRecordWriter#persistBatchAndDeleteOutbox} in one transaction (the fast path). When that batch
 * transaction fails (crash-recovery duplicate), each row is retried individually via
 * {@link SigningRecordWriter#saveRecordAndDeleteOutbox}, and failed per-row attempts are recorded via
 * {@link SigningRecordWriter#recordFailure(java.util.UUID, String)} while healthy rows are still drained. A batch
 * whose bulk load returns empty (all rows already gone) is skipped without touching the writer. Poison exclusion
 * lives in the claim query; per-row transaction isolation, idempotent copy, and field fidelity are covered
 * against a real database in {@link com.otilm.core.integration.signing.record.SigningRecordOutboxDrainerITest}.
 */
class SigningRecordOutboxDrainerUnitTest {

    private static final int DEFAULT_BATCH_SIZE = 200;
    private static final int DEFAULT_POISON_THRESHOLD = 10;
    private static final int DEFAULT_MAX_BATCHES_PER_RUN = 100;

    private MeterRegistry registry;
    private SigningRecordMetrics metrics;
    private SigningRecordOutboxRepository outboxRepo;
    private SigningRecordWriter writer;
    private ClusterOperationSynchronizer clusterSynchronizer;
    private Map<UUID, SigningRecordOutbox> claimableRows;

    @BeforeEach
    void setUp() {
        registry = new SimpleMeterRegistry();
        metrics = new SigningRecordMetrics(registry);
        outboxRepo = mock(SigningRecordOutboxRepository.class);
        writer = mock(SigningRecordWriter.class);
        clusterSynchronizer = mock(ClusterOperationSynchronizer.class);
        claimableRows = new HashMap<>();
        when(clusterSynchronizer.tryLock(ClusterOperationSynchronizer.Operation.SIGNING_RECORD_OUTBOX_DRAIN))
                .thenReturn(true);
    }

    @Test
    void drainOnce_drainsEachRowThroughTheWriterAndCountsThem() {
        // given
        var batch = List.of(aUuid(), aUuid(), aUuid());
        when(outboxRepo.findDrainableBatch(anyInt(), anyInt())).thenReturn(batch);
        anyClaimedRowIsPresent();

        // when
        createDrainer().drainOnce();

        // then
        verify(writer).persistBatchAndDeleteOutbox(anyList());
        verify(writer, never()).saveRecordAndDeleteOutbox(any());
        verify(writer, never()).recordFailure(any(), any());
        assertEquals(3, attemptedCount());
    }

    @Test
    void drainOnce_doesNothing_whenNoDrainableRows() {
        // given
        when(outboxRepo.findDrainableBatch(anyInt(), anyInt())).thenReturn(List.of());

        // when
        createDrainer().drainOnce();

        // then
        verify(writer, never()).saveRecordAndDeleteOutbox(any());
        verify(writer, never()).recordFailure(any(), any());
        assertEquals(0, attemptedCount());
    }

    @Test
    void drainOnce_skipsEntirely_whenAnotherInstanceHoldsTheLock() {
        // given
        when(clusterSynchronizer.tryLock(ClusterOperationSynchronizer.Operation.SIGNING_RECORD_OUTBOX_DRAIN))
                .thenReturn(false);

        // when
        createDrainer().drainOnce();

        // then
        verify(outboxRepo, never()).findDrainableBatch(anyInt(), anyInt());
        verify(writer, never()).saveRecordAndDeleteOutbox(any());
    }

    @Test
    void drainOnce_recordsFailureAndKeepsRow_whenTheWriterThrows() {
        // given the batch path fails, forcing per-row fallback where the row copy also fails
        var failingUuid = aUuid();
        when(outboxRepo.findDrainableBatch(anyInt(), anyInt())).thenReturn(List.of(failingUuid));
        aClaimableRow(failingUuid);
        doThrow(aConstraintViolation("batch failed")).when(writer).persistBatchAndDeleteOutbox(anyList());
        doThrow(new RuntimeException("constraint violation")).when(writer).saveRecordAndDeleteOutbox(recordFor(failingUuid));

        // when
        createDrainer().drainOnce();

        // then
        verify(writer).recordFailure(eq(failingUuid), any(String.class));
        assertEquals(1, failedCount());
        assertEquals(1, attemptedCount());
    }

    @Test
    void drainOnce_continuesToTheNextRow_whenRecordingTheFailureItselfThrows() {
        // given a row whose copy fails and whose failure-recording also fails, followed by a healthy row
        var brokenUuid = aUuid();
        var healthyUuid = aUuid();
        when(outboxRepo.findDrainableBatch(anyInt(), anyInt())).thenReturn(List.of(brokenUuid, healthyUuid));
        aClaimableRow(brokenUuid);
        aClaimableRow(healthyUuid);
        doThrow(aConstraintViolation("batch failed")).when(writer).persistBatchAndDeleteOutbox(anyList());
        doThrow(new RuntimeException("copy failed")).when(writer).saveRecordAndDeleteOutbox(recordFor(brokenUuid));
        doThrow(new RuntimeException("db unavailable")).when(writer).recordFailure(eq(brokenUuid), any());

        // when / then the failed bookkeeping does not abort the batch — the healthy row is still drained
        assertDoesNotThrow(() -> createDrainer().drainOnce());
        verify(writer).saveRecordAndDeleteOutbox(recordFor(healthyUuid));
        assertEquals(2, attemptedCount());
    }

    @Test
    void drainOnce_drainsHealthyRowsAndIsolatesTheFailingOne_inAMixedBatch() {
        // given the batch path fails, then per-row fallback: healthy succeeds, failing throws
        var healthyUuid = aUuid();
        var failingUuid = aUuid();
        when(outboxRepo.findDrainableBatch(anyInt(), anyInt())).thenReturn(List.of(healthyUuid, failingUuid));
        aClaimableRow(healthyUuid);
        aClaimableRow(failingUuid);
        doThrow(aConstraintViolation("batch failed")).when(writer).persistBatchAndDeleteOutbox(anyList());
        doThrow(new RuntimeException("FK violation on signing_profile_uuid")).when(writer).saveRecordAndDeleteOutbox(recordFor(failingUuid));

        // when
        createDrainer().drainOnce();

        // then
        verify(writer).recordFailure(eq(failingUuid), any(String.class));
        verify(writer, never()).recordFailure(eq(healthyUuid), any());
        assertEquals(1, failedCount());
        assertEquals(2, attemptedCount());
    }

    @Test
    void drainOnce_doesNotCountARowAlreadyGoneFromTheOutbox() {
        // given a batch where the bulk load returns empty (rows drained by another node or earlier pass)
        var takenUuid = aUuid();
        when(outboxRepo.findDrainableBatch(anyInt(), anyInt())).thenReturn(List.of(takenUuid));
        when(outboxRepo.findAllById(anyIterable())).thenReturn(List.of());

        // when
        createDrainer().drainOnce();

        // then
        verify(writer, never()).persistBatchAndDeleteOutbox(anyList());
        verify(writer, never()).saveRecordAndDeleteOutbox(any());
        verify(writer, never()).recordFailure(any(), any());
        assertEquals(0, attemptedCount());
        assertEquals(0, failedCount());
    }

    @Test
    void drainOnce_keepsDrainingWhileBatchesAreFull_andStopsOnAShortBatch() {
        // given a full batch followed by a short one (batch size 2)
        var batchSize = 2;
        when(outboxRepo.findDrainableBatch(anyInt(), anyInt()))
                .thenReturn(List.of(aUuid(), aUuid()), List.of(aUuid()));
        anyClaimedRowIsPresent();

        // when
        createDrainer(batchSize, DEFAULT_POISON_THRESHOLD).drainOnce();

        // then both batches were drained and the loop stopped after the short one
        verify(writer, times(2)).persistBatchAndDeleteOutbox(anyList());
        verify(writer, never()).saveRecordAndDeleteOutbox(any());
        verify(outboxRepo, times(2)).findDrainableBatch(DEFAULT_POISON_THRESHOLD, batchSize);
        assertEquals(3, attemptedCount());
    }

    @Test
    void drainOnce_stopsAtTheBatchCap_evenWhenMoreFullBatchesRemain() {
        // given every claim returns a full batch that drains completely, so work is always available
        var batchSize = 2;
        var maxBatchesPerRun = 3;
        when(outboxRepo.findDrainableBatch(anyInt(), anyInt()))
                .thenReturn(List.of(aUuid(), aUuid()));
        anyClaimedRowIsPresent();

        // when
        createDrainer(batchSize, DEFAULT_POISON_THRESHOLD, maxBatchesPerRun).drainOnce();

        // then it claims exactly the cap's worth of batches and stops, leaving the rest for the next run
        verify(outboxRepo, times(maxBatchesPerRun)).findDrainableBatch(DEFAULT_POISON_THRESHOLD, batchSize);
        verify(writer, times(maxBatchesPerRun)).persistBatchAndDeleteOutbox(anyList());
        verify(writer, never()).saveRecordAndDeleteOutbox(any());
    }

    @Test
    void drainOnce_swallowsExceptionAndDoesNotThrow_whenTheQueryFails() {
        // given
        when(outboxRepo.findDrainableBatch(anyInt(), anyInt())).thenThrow(new RuntimeException("db unavailable"));

        // when
        Executable drain = () -> createDrainer().drainOnce();

        // then
        assertDoesNotThrow(drain);
        verify(writer, never()).persistBatchAndDeleteOutbox(anyList());
        verify(writer, never()).saveRecordAndDeleteOutbox(any());
    }

    @Test
    void drainOnce_queriesUsingTheConfiguredBatchSizeAndPoisonThreshold() {
        // given
        var batchSize = 50;
        var poisonThreshold = 7;
        when(outboxRepo.findDrainableBatch(anyInt(), anyInt())).thenReturn(List.of());

        // when
        createDrainer(batchSize, poisonThreshold).drainOnce();

        // then
        verify(outboxRepo).findDrainableBatch(poisonThreshold, batchSize);
    }

    @Test
    void drainOnce_fallsBackToPerRowDraining_whenBatchTransactionFails() {
        // given two rows in a batch where the bulk transaction fails (crash-recovery duplicate on flush)
        var uuid1 = aUuid();
        var uuid2 = aUuid();
        when(outboxRepo.findDrainableBatch(anyInt(), anyInt())).thenReturn(List.of(uuid1, uuid2));
        aClaimableRow(uuid1);
        aClaimableRow(uuid2);
        doThrow(aConstraintViolation("could not execute batch")).when(writer)
                .persistBatchAndDeleteOutbox(anyList());

        // when
        createDrainer().drainOnce();

        // then each row is drained individually via the per-row fallback
        verify(writer).saveRecordAndDeleteOutbox(recordFor(uuid1));
        verify(writer).saveRecordAndDeleteOutbox(recordFor(uuid2));
        verify(writer, never()).recordFailure(any(), any());
        assertEquals(2, attemptedCount());
    }

    @Test
    void drainOnce_doesNotFallBackOrRecordFailures_whenBatchTransactionFailsTransiently() {
        // given the bulk transaction fails for a reason unrelated to a duplicate key (e.g. a dropped connection)
        var uuid1 = aUuid();
        var uuid2 = aUuid();
        when(outboxRepo.findDrainableBatch(anyInt(), anyInt())).thenReturn(List.of(uuid1, uuid2));
        aClaimableRow(uuid1);
        aClaimableRow(uuid2);
        doThrow(new RuntimeException("connection reset")).when(writer).persistBatchAndDeleteOutbox(anyList());

        // when / then the whole run aborts instead of poisoning every row in an otherwise-healthy batch
        assertDoesNotThrow(() -> createDrainer().drainOnce());
        verify(writer, never()).saveRecordAndDeleteOutbox(any());
        verify(writer, never()).recordFailure(any(), any());
    }

    private static RuntimeException aConstraintViolation(String message) {
        return new PersistenceException(message,
                new ConstraintViolationException(message, null, "signing_record_pkey"));
    }

    /**
     * Matches the {@link SigningRecord} the drainer maps from the outbox row with the given UUID — the record
     * shares its originating outbox row's UUID, so this discriminates the per-row writer call by identity.
     */
    private static SigningRecord recordFor(UUID uuid) {
        return argThat(signingRecord -> signingRecord != null && uuid.equals(signingRecord.getUuid()));
    }

    private SigningRecordOutbox aClaimableRow(UUID uuid) {
        SigningRecordOutbox row = new SigningRecordOutbox();
        row.setUuid(uuid);
        claimableRows.put(uuid, row);
        when(outboxRepo.findAllById(anyIterable())).thenAnswer(invocation -> {
            Iterable<UUID> ids = invocation.getArgument(0);
            List<SigningRecordOutbox> result = new ArrayList<>();
            for (UUID id : ids) {
                SigningRecordOutbox r = claimableRows.get(id);
                if (r != null)
                    result.add(r);
            }
            return result;
        });
        return row;
    }

    private void anyClaimedRowIsPresent() {
        when(outboxRepo.findAllById(anyIterable())).thenAnswer(invocation -> {
            Iterable<UUID> ids = invocation.getArgument(0);
            List<SigningRecordOutbox> result = new ArrayList<>();
            for (UUID id : ids) {
                SigningRecordOutbox row = new SigningRecordOutbox();
                row.setUuid(id);
                result.add(row);
            }
            return result;
        });
    }

    private SigningRecordOutboxDrainer createDrainer() {
        return createDrainer(DEFAULT_BATCH_SIZE, DEFAULT_POISON_THRESHOLD, DEFAULT_MAX_BATCHES_PER_RUN);
    }

    private SigningRecordOutboxDrainer createDrainer(int batchSize, int poisonThreshold) {
        return createDrainer(batchSize, poisonThreshold, DEFAULT_MAX_BATCHES_PER_RUN);
    }

    private SigningRecordOutboxDrainer createDrainer(int batchSize, int poisonThreshold, int maxBatchesPerRun) {
        return new SigningRecordOutboxDrainer(mock(EntityManager.class), outboxRepo, writer, clusterSynchronizer,
                metrics, new SigningRecordOutboxProperties(1L, batchSize, maxBatchesPerRun, poisonThreshold));
    }

    private UUID aUuid() {
        return UUID.randomUUID();
    }

    private double attemptedCount() {
        return persistCounterValue("signing_record.persist");
    }

    private double failedCount() {
        return persistCounterValue("signing_record.persist.failed");
    }

    private double persistCounterValue(String name) {
        var counter = registry.find(name).tag("mode", "DEFERRED_DURABLE").counter();
        return counter == null ? 0d : counter.count();
    }
}
