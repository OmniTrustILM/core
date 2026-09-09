package com.otilm.core.cbom.pqc;

import com.otilm.api.model.core.cryptoasset.CryptographicAssetType;
import com.otilm.api.model.core.cryptoasset.PqcVerdict;
import com.otilm.core.cbom.asset.identity.AssetNormalizer;
import com.otilm.core.cbom.asset.identity.IdentityTables;
import com.otilm.core.cluster.ClusterOperationSynchronizer;
import com.otilm.core.dao.repository.cbom.CryptoAssetRepository;
import com.otilm.core.model.cbom.PqcStaleVerdictRow;
import com.otilm.core.service.writer.cbom.CryptoAssetPqcVerdictWriter;
import io.micrometer.core.instrument.simple.SimpleMeterRegistry;
import java.util.ArrayList;
import java.util.List;
import java.util.UUID;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyInt;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/**
 * The sweep's control flow, without a database.
 *
 * <p>
 * These are the paths an integration test cannot reach cheaply: the per-sweep cap, the disabled switch, a contended
 * lock, a batch write that rolls back, a row whose evaluation throws, and the cursor advancing when the guard refuses
 * every write. Each one is a decision about what the sweep reports to an operator, and all of them were previously
 * asserted only by reading the code.
 */
class PqcVerdictSweeperTest {

    private static final UUID BEFORE_FIRST = new UUID(0L, 0L);

    private final CryptoAssetRepository repository = mock(CryptoAssetRepository.class);
    private final CryptoAssetPqcVerdictWriter writer = mock(CryptoAssetPqcVerdictWriter.class);
    private final ClusterOperationSynchronizer synchronizer = mock(ClusterOperationSynchronizer.class);

    @Test
    void aDisabledSweepDoesNotEvenTakeTheLock() {
        PqcVerdictSweeper sweeper = sweeper(5, 0);

        PqcVerdictSweeper.SweepOutcome outcome = sweeper.sweep();

        assertThat(outcome.ran()).isFalse();
        verify(synchronizer, never()).tryLock(any());
    }

    @Test
    void aContendedSweepReportsSkippedAndReadsNothing() {
        when(synchronizer.tryLock(ClusterOperationSynchronizer.Operation.CRYPTO_ASSET_PQC_SWEEP)).thenReturn(false);
        PqcVerdictSweeper sweeper = sweeper(5, 10);

        assertThat(sweeper.sweep().ran()).isFalse();
        verify(repository, never()).staleVerdictRows(anyInt(), any(), anyInt());
    }

    /** The cap bounds how long the outer transaction stays open, so it must stop the loop even with work left. */
    @Test
    void theSweepStopsAtThePerSweepCap() {
        lockHeld();
        when(repository.staleVerdictRows(anyInt(), any(), anyInt())).thenAnswer(call -> rows(5));
        everythingLands();

        PqcVerdictSweeper.SweepOutcome outcome = sweeper(5, 3).sweep();

        assertThat(outcome.batches()).isEqualTo(3);
        assertThat(outcome.read()).isEqualTo(15);
        assertThat(outcome.written()).isEqualTo(15);
        assertThat(outcome.aborted()).isFalse();
    }

    /** A short batch means the work list is exhausted; the loop must not ask again. */
    @Test
    void aShortBatchEndsTheSweep() {
        lockHeld();
        when(repository.staleVerdictRows(anyInt(), any(), anyInt())).thenReturn(rows(2)).thenReturn(List.of());
        everythingLands();

        assertThat(sweeper(5, 10).sweep().batches()).isEqualTo(1);
    }

    /**
     * The cursor is load-bearing exactly when a row stays on the work list after its batch, which is what a refused
     * write leaves behind. A written row leaves the result set on its own, so a sweep whose every write lands advances
     * through the table even with the cursor pinned at the nil uuid -- and would pass a test that only counts batches.
     *
     * <p>
     * With nothing written, a pinned cursor re-reads the first page until the per-sweep cap and every row behind it
     * goes unvisited on every run, while the job still reports a successful sweep of as many rows as the cap allows.
     */
    @Test
    void theCursorAdvancesEvenWhenTheGuardRefusesEveryWrite() {
        lockHeld();
        List<PqcStaleVerdictRow> first = rows(2);
        List<PqcStaleVerdictRow> second = rows(2);
        when(repository.staleVerdictRows(anyInt(), any(), anyInt())).thenAnswer(call -> {
            UUID after = call.getArgument(1);
            if (after.equals(BEFORE_FIRST)) {
                return first;
            }
            if (after.equals(last(first))) {
                return second;
            }
            return List.of();
        });
        when(writer.applyStaleBatch(any(), anyInt())).thenReturn(List.of());

        PqcVerdictSweeper.SweepOutcome outcome = sweeper(2, 10).sweep();

        ArgumentCaptor<UUID> cursor = ArgumentCaptor.captor();
        verify(repository, times(3)).staleVerdictRows(anyInt(), cursor.capture(), anyInt());
        assertThat(cursor.getAllValues()).containsExactly(BEFORE_FIRST, last(first), last(second));
        assertThat(outcome.batches()).isEqualTo(2);
        assertThat(outcome.read()).isEqualTo(4);
        assertThat(outcome.written()).isZero();
        assertThat(outcome.refused()).describedAs("refused rows are reported, and retried next sweep").isEqualTo(4);
    }

    /**
     * A batch shares one transaction, so a single row the database refuses rolls back every good write beside it. The
     * cursor restarts at the nil uuid every sweep, so a refusal that persists would be reached first on every run and
     * starve every stale row behind it -- the batch is therefore retried one row per transaction, and only the row
     * that still fails is left behind.
     */
    @Test
    void aBatchThatRollsBackIsRetriedOneRowPerTransaction() {
        lockHeld();
        List<PqcStaleVerdictRow> page = rows(3);
        UUID poisoned = page.get(2).uuid();
        when(repository.staleVerdictRows(anyInt(), any(), anyInt())).thenReturn(page).thenReturn(List.of());
        when(writer.applyStaleBatch(any(), anyInt())).thenThrow(new IllegalStateException("deadlock detected"));
        when(writer.applyStaleRow(any(), anyInt())).thenAnswer(call -> {
            PqcVerdictWrite write = call.getArgument(0);
            if (write.assetUuid().equals(poisoned)) {
                throw new IllegalStateException("new row for relation violates check constraint");
            }
            return true;
        });

        PqcVerdictSweeper.SweepOutcome outcome = sweeper(3, 10).sweep();

        verify(writer, times(3)).applyStaleRow(any(), anyInt());
        assertThat(outcome.written()).isEqualTo(2);
        assertThat(outcome.writeFailures()).isEqualTo(1);
        assertThat(outcome.refused()).isZero();
        assertThat(outcome.aborted()).describedAs("the sweep itself completed; one row did not").isFalse();
        assertThat(outcome.batches()).isEqualTo(1);
    }

    /**
     * A read that fails ends the sweep, and reporting a successful run would hide that behind the rows the earlier
     * batches did write.
     */
    @Test
    void aFailingWorkListReadStopsTheSweepAndIsReported() {
        lockHeld();
        when(repository.staleVerdictRows(anyInt(), any(), anyInt()))
                .thenReturn(rows(2))
                .thenThrow(new IllegalStateException("connection is closed"));
        everythingLands();

        PqcVerdictSweeper.SweepOutcome outcome = sweeper(2, 10).sweep();

        assertThat(outcome.aborted()).isTrue();
        assertThat(outcome.written()).isEqualTo(2);
    }

    /**
     * A row that cannot be evaluated is stamped, not skipped. Skipping keeps its old generation, so it returns at the
     * head of the work list on every sweep and, with a cap, starves everything behind it.
     */
    @Test
    void aRowThatCannotBeEvaluatedIsStampedSoTheSweepAdvances() {
        lockHeld();
        List<PqcStaleVerdictRow> poison = List.of(unreadablePayload());
        when(repository.staleVerdictRows(anyInt(), any(), anyInt())).thenReturn(poison).thenReturn(List.of());
        everythingLands();

        PqcVerdictSweeper.SweepOutcome outcome = sweeper(5, 10).sweep();

        assertThat(outcome.unevaluated()).isEqualTo(1);
        assertThat(outcome.written()).isEqualTo(1);
        ArgumentCaptor<List<PqcVerdictWrite>> batch = ArgumentCaptor.captor();
        verify(writer).applyStaleBatch(batch.capture(), anyInt());
        assertThat(batch.getValue()).hasSize(1);
        assertThat(batch.getValue().get(0).assetUuid()).isEqualTo(poison.get(0).uuid());
        assertThat(batch.getValue().get(0).decision().ruleId()).isEqualTo("EVALUATION-FAILED");
        assertThat(batch.getValue().get(0).decision().verdict()).isEqualTo(PqcVerdict.UNKNOWN);
    }

    /**
     * The stamp is a write like any other, and the guard can refuse it -- so counting the stamps the sweep built would
     * let the job report a row as recorded UNKNOWN while the row carries no verdict at all and is still on the work
     * list. Only the stamps that landed are counted.
     */
    @Test
    void aStampTheGuardRefusedIsNotReportedAsRecorded() {
        lockHeld();
        when(repository.staleVerdictRows(anyInt(), any(), anyInt()))
                .thenReturn(List.of(unreadablePayload()))
                .thenReturn(List.of());
        when(writer.applyStaleBatch(any(), anyInt())).thenReturn(List.of());

        PqcVerdictSweeper.SweepOutcome outcome = sweeper(5, 10).sweep();

        assertThat(outcome.unevaluated()).describedAs("nothing landed, so nothing was recorded").isZero();
        assertThat(outcome.read()).isEqualTo(1);
        assertThat(outcome.refused()).isEqualTo(1);
    }

    private void lockHeld() {
        when(synchronizer.tryLock(ClusterOperationSynchronizer.Operation.CRYPTO_ASSET_PQC_SWEEP)).thenReturn(true);
    }

    private void everythingLands() {
        when(writer.applyStaleBatch(any(), anyInt())).thenAnswer(call -> {
            List<PqcVerdictWrite> batch = call.getArgument(0);
            return batch.stream().map(PqcVerdictWrite::assetUuid).toList();
        });
    }

    /** The stored payload is not JSON, so the row throws before any rule runs. */
    private static PqcStaleVerdictRow unreadablePayload() {
        return new PqcStaleVerdictRow(UUID.randomUUID(), CryptographicAssetType.ALGORITHM, "boom", null, null, null,
                null, null, null, null, null, "{\"relatedCryptoMaterialProperties\": ", 7L);
    }

    private static UUID last(List<PqcStaleVerdictRow> page) {
        return page.get(page.size() - 1).uuid();
    }

    private static List<PqcStaleVerdictRow> rows(int count) {
        List<PqcStaleVerdictRow> rows = new ArrayList<>(count);
        for (int i = 0; i < count; i++) {
            rows
                    .add(new PqcStaleVerdictRow(UUID.randomUUID(), CryptographicAssetType.ALGORITHM, "RSA", null, "rsa",
                            null, "2048", null, null, null, null, null, i + 1L));
        }
        return rows;
    }

    private PqcVerdictSweeper sweeper(int batchSize, int maxBatches) {
        return new PqcVerdictSweeper(repository, writer, new PqcEvaluator(new AssetNormalizer(IdentityTables.load())),
                synchronizer, new SimpleMeterRegistry(), new PqcSweepProperties(batchSize, maxBatches));
    }
}
