package com.otilm.core.cbom.ingest;

import com.otilm.core.cluster.ClusterOperationSynchronizer;
import com.otilm.core.dao.repository.cbom.CryptoAssetRepository;
import com.otilm.core.dao.repository.cbom.CryptoAssetSourceRepository;
import com.otilm.core.events.transaction.TransactionHandler;
import com.otilm.core.service.writer.cbom.CryptoAssetAliasWriter;
import com.otilm.core.service.writer.cbom.CryptoAssetSourceWriter;
import com.otilm.core.service.writer.cbom.CryptoAssetWriter;
import java.util.List;
import java.util.UUID;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;
import org.mockito.InOrder;
import org.springframework.data.domain.Limit;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.inOrder;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/**
 * The withdrawal's control flow, without a database: how it batches, what it does when the cluster lock is contended,
 * and the one ordering a database would reveal only as an intermittent deadlock. The orphan rule itself is pinned
 * against real PostgreSQL in {@code CryptoAssetInventoryITest}, because it turns on the source rows and the alias
 * cascade that only the repository's own query reads.
 */
class CbomAssetDetachServiceTest {

    private static final UUID CBOM = UUID.randomUUID();

    private final CryptoAssetSourceWriter sourceWriter = mock(CryptoAssetSourceWriter.class);
    private final CryptoAssetWriter assetWriter = mock(CryptoAssetWriter.class);
    private final CryptoAssetSourceRepository sourceRepository = mock(CryptoAssetSourceRepository.class);
    private final CryptoAssetRepository assetRepository = mock(CryptoAssetRepository.class);
    private final ClusterOperationSynchronizer synchronizer = mock(ClusterOperationSynchronizer.class);

    @Test
    void theAliasLockIsTakenBeforeTheFirstAssetRowLock() {
        UUID asset = sourcedAsset();
        when(synchronizer.tryLock(anyString())).thenReturn(true);
        when(assetRepository.orphansAmong(any())).thenReturn(List.of());

        service(100).withdraw(CBOM);

        InOrder order = inOrder(synchronizer, sourceWriter);
        order.verify(synchronizer).lock(CryptoAssetAliasWriter.ALIAS_DECISION_LOCK);
        order.verify(sourceWriter).detachCbom(asset, CBOM);
    }

    @Test
    void aContendedClusterLockWithdrawsNothingAndSaysSo() {
        sourcedAsset();
        when(synchronizer.tryLock(anyString())).thenReturn(false);

        CbomAssetDetachService.Withdrawal withdrawal = service(100).withdraw(CBOM);

        assertThat(withdrawal).isEqualTo(new CbomAssetDetachService.Withdrawal(0, 0, 0, false));
        verify(sourceWriter, never()).detachCbom(any(), any());
        verify(assetWriter, never()).delete(any());
    }

    /**
     * Each batch is its own slice of the list. Without the moving offset the first slice is withdrawn twice and
     * everything past it never at all, which is the data-loss shape this loop can have -- so what is asserted is what
     * each batch contained, not how many batches there were.
     */
    @Test
    void eachBatchWithdrawsItsOwnSliceOfTheLinks() {
        UUID first = UUID.randomUUID();
        UUID second = UUID.randomUUID();
        UUID third = UUID.randomUUID();
        pages(2, List.of(first, second), List.of(third));
        when(synchronizer.tryLock(anyString())).thenReturn(true);
        when(assetRepository.orphansAmong(any())).thenReturn(List.of());

        service(2).withdraw(CBOM);

        verify(sourceWriter).detachCbom(first, CBOM);
        verify(sourceWriter).detachCbom(second, CBOM);
        verify(sourceWriter).detachCbom(third, CBOM);
        verify(sourceWriter, times(3)).detachCbom(any(), any());
        // One lock acquisition per batch transaction: three links at a batch size of two is two transactions, and the
        // second page is short, so no third pass is needed to learn that the list is empty.
        verify(synchronizer, times(2)).tryLock(CbomAssetIngestService.assetSyncLockKey(CBOM));

        // And the orphan question is asked about each batch's own assets: over the whole list, or over the wrong
        // slice, it would settle assets this transaction has not detached.
        ArgumentCaptor<List<UUID>> asked = ArgumentCaptor.captor();
        verify(assetRepository, times(2)).orphansAmong(asked.capture());
        assertThat(asked.getAllValues()).containsExactly(List.of(first, second), List.of(third));
    }

    /**
     * The counts are summed across batches, not taken from the last one. Nothing else exercises the accumulation: the
     * default batch size is 100 and every integration test withdraws fewer assets than that, so {@code plus} is only
     * ever called there as {@code NOTHING.plus(done)}, which is identity for any one field.
     */
    @Test
    void theCountsOfEveryBatchAreAddedUp() {
        UUID first = UUID.randomUUID();
        UUID second = UUID.randomUUID();
        pages(1, List.of(first), List.of(second), List.of());
        when(sourceWriter.detachCbom(any(), any())).thenReturn(1);
        when(synchronizer.tryLock(anyString())).thenReturn(true);
        when(assetRepository.orphansAmong(List.of(first)))
                .thenReturn(List.of(new CryptoAssetRepository.OrphanRow(first, false)));
        when(assetRepository.orphansAmong(List.of(second)))
                .thenReturn(List.of(new CryptoAssetRepository.OrphanRow(second, true)));

        CbomAssetDetachService.Withdrawal withdrawal = service(1).withdraw(CBOM);

        assertThat(withdrawal).isEqualTo(new CbomAssetDetachService.Withdrawal(2, 1, 1, true));
    }

    /**
     * A batch that already committed stays committed. The caller is told the unit is incomplete, not that nothing
     * happened -- reporting zero here would understate what this node really did and, for the deletion lifecycle, would
     * present an irreversibly collected orphan as a withdrawal that never ran.
     */
    @Test
    void anAbandonedUnitStillReportsWhatTheCommittedBatchesDid() {
        UUID first = UUID.randomUUID();
        UUID second = UUID.randomUUID();
        pages(1, List.of(first), List.of(second));
        when(sourceWriter.detachCbom(first, CBOM)).thenReturn(1);
        when(synchronizer.tryLock(anyString())).thenReturn(true, false);
        when(assetRepository.orphansAmong(List.of(first)))
                .thenReturn(List.of(new CryptoAssetRepository.OrphanRow(first, false)));

        CbomAssetDetachService.Withdrawal withdrawal = service(1).withdraw(CBOM);

        assertThat(withdrawal).isEqualTo(new CbomAssetDetachService.Withdrawal(1, 1, 0, false));
        verify(sourceWriter, never()).detachCbom(second, CBOM);
    }

    /** An asset another CBOM still sources is not returned as an orphan, so nothing settles it. */
    @Test
    void anAssetThatKeepsASourceIsLeftAlone() {
        UUID asset = sourcedAsset();
        when(synchronizer.tryLock(anyString())).thenReturn(true);
        when(assetRepository.orphansAmong(List.of(asset))).thenReturn(List.of());

        CbomAssetDetachService.Withdrawal withdrawal = service(100).withdraw(CBOM);

        assertThat(withdrawal).isEqualTo(new CbomAssetDetachService.Withdrawal(1, 0, 0, true));
        verify(assetWriter, never()).delete(any());
    }

    /** An orphan no alias points at is collected -- the branch the integration suite proves against a real cascade. */
    @Test
    void anOrphanNoAliasPointsAtIsCollected() {
        UUID asset = sourcedAsset();
        when(synchronizer.tryLock(anyString())).thenReturn(true);
        when(assetRepository.orphansAmong(List.of(asset)))
                .thenReturn(List.of(new CryptoAssetRepository.OrphanRow(asset, false)));

        CbomAssetDetachService.Withdrawal withdrawal = service(100).withdraw(CBOM);

        assertThat(withdrawal).isEqualTo(new CbomAssetDetachService.Withdrawal(1, 1, 0, true));
        verify(assetWriter).delete(asset);
    }

    /** An orphan an alias points at is kept: deleting it would cascade the operator's merge decision away. */
    @Test
    void anOrphanAnAliasPointsAtIsKept() {
        UUID asset = sourcedAsset();
        when(synchronizer.tryLock(anyString())).thenReturn(true);
        when(assetRepository.orphansAmong(List.of(asset)))
                .thenReturn(List.of(new CryptoAssetRepository.OrphanRow(asset, true)));

        CbomAssetDetachService.Withdrawal withdrawal = service(100).withdraw(CBOM);

        assertThat(withdrawal).isEqualTo(new CbomAssetDetachService.Withdrawal(1, 0, 1, true));
        verify(assetWriter, never()).delete(any());
    }

    /** The keyed caller waits instead of skipping, or another node's sync would read as a refused deletion. */
    @Test
    void anOperatorsDeleteWaitsForTheClusterLockRatherThanSkippingTheWithdrawal() {
        UUID asset = sourcedAsset();

        service(100).withdrawWaiting(CBOM);

        verify(synchronizer).lock(CbomAssetIngestService.assetSyncLockKey(CBOM));
        verify(synchronizer, never()).tryLock(anyString());
        verify(sourceWriter).detachCbom(asset, CBOM);
        // The blocking acquisition must be the FIRST lock of the transaction: a waiter that already held
        // ALIAS_DECISION_LOCK would close a cycle against any ingest holding the asset-sync lock. Verifying only that
        // the wait happens would not fail if someone moved the alias lock above it.
        InOrder ranked = inOrder(synchronizer);
        ranked.verify(synchronizer).lock(CbomAssetIngestService.assetSyncLockKey(CBOM));
        ranked.verify(synchronizer).lock(CryptoAssetAliasWriter.ALIAS_DECISION_LOCK);
    }

    /**
     * The work list is read under the lock, so a CBOM that sources nothing still takes it.
     *
     * <p>
     * Read before the lock, the emptiness is a snapshot: an ingest writing that document's first sources is invisible
     * to it, and the withdrawal reports a complete withdrawal of an inventory it never excluded anything from. The
     * delete that follows then meets the RESTRICT foreign key.
     */
    @Test
    void aCbomThatSourcesNothingIsStillWithdrawnUnderTheLock() {
        pages(100, List.of());

        CbomAssetDetachService.Withdrawal withdrawal = service(100).withdrawWaiting(CBOM);

        assertThat(withdrawal).isEqualTo(new CbomAssetDetachService.Withdrawal(0, 0, 0, true));
        InOrder ranked = inOrder(synchronizer, sourceRepository);
        ranked.verify(synchronizer).lock(CbomAssetIngestService.assetSyncLockKey(CBOM));
        ranked.verify(sourceRepository).findAssetUuidsByCbomUuid(CBOM, Limit.of(100));
    }

    /**
     * A page is re-read after every commit, so sources attached in the gap are withdrawn too.
     *
     * <p>
     * The lock is transaction-scoped and released at each batch commit. A withdrawal working through a list it read
     * once would leave every source an ingest of the same document attached after that read -- and still return
     * {@code complete()}, which is the claim the keyed delete rests on.
     */
    @Test
    void aSourceAttachedBetweenTwoBatchesIsWithdrawnTooRatherThanMissed() {
        UUID known = UUID.randomUUID();
        UUID attachedInTheGap = UUID.randomUUID();
        pages(1, List.of(known), List.of(attachedInTheGap), List.of());
        when(sourceWriter.detachCbom(any(), any())).thenReturn(1);
        when(assetRepository.orphansAmong(any())).thenReturn(List.of());

        CbomAssetDetachService.Withdrawal withdrawal = service(1).withdrawWaiting(CBOM);

        assertThat(withdrawal).isEqualTo(new CbomAssetDetachService.Withdrawal(2, 0, 0, true));
        verify(sourceWriter).detachCbom(attachedInTheGap, CBOM);
    }

    /**
     * A failure partway carries what the committed batches did, because "threw" and "withdrew nothing" are not the same
     * thing.
     *
     * <p>
     * The caller uses this to decide whether the CBOM now owes a rebuild. Told only that the call threw, a delete path
     * leaves a row reading {@code SYNCED} that sources part of an inventory already deleted -- on no work list, and
     * rebuilt by nothing.
     */
    @Test
    void aFailurePartwayThroughCarriesWhatTheCommittedBatchesWithdrew() {
        UUID first = UUID.randomUUID();
        UUID second = UUID.randomUUID();
        pages(1, List.of(first), List.of(second));
        when(sourceWriter.detachCbom(first, CBOM)).thenReturn(1);
        when(sourceWriter.detachCbom(second, CBOM)).thenThrow(new IllegalStateException("deadlock victim"));
        when(assetRepository.orphansAmong(List.of(first)))
                .thenReturn(List.of(new CryptoAssetRepository.OrphanRow(first, false)));

        assertThatThrownBy(() -> service(1).withdrawWaiting(CBOM))
                .isInstanceOf(CbomAssetDetachService.WithdrawalFailedException.class)
                .hasCauseInstanceOf(IllegalStateException.class)
                .extracting(e -> ((CbomAssetDetachService.WithdrawalFailedException) e).committed())
                .isEqualTo(new CbomAssetDetachService.Withdrawal(1, 1, 0, true));
    }

    /** A failure before the first commit withdrew nothing, and says so -- the case the carve-out is for. */
    @Test
    void aFailureBeforeTheFirstCommitReportsAnUntouchedInventory() {
        UUID asset = UUID.randomUUID();
        pages(1, List.of(asset));
        when(sourceWriter.detachCbom(asset, CBOM)).thenThrow(new IllegalStateException("connection lost"));

        assertThatThrownBy(() -> service(1).withdrawWaiting(CBOM))
                .isInstanceOf(CbomAssetDetachService.WithdrawalFailedException.class)
                .matches(e -> !((CbomAssetDetachService.WithdrawalFailedException) e).withdrewSomething());
    }

    private UUID sourcedAsset() {
        UUID asset = UUID.randomUUID();
        pages(100, List.of(asset));
        when(sourceWriter.detachCbom(asset, CBOM)).thenReturn(1);
        return asset;
    }

    /**
     * The work list as the withdrawal actually reads it: one page per batch, under the lock that batch holds.
     *
     * <p>
     * Successive stubbed returns rather than one list, because the loop asks again after every commit -- a stub that
     * answered the same page for ever would hang the test, which is the honest shape of the thing being pinned.
     */
    @SafeVarargs
    private void pages(int batchSize, List<UUID>... pages) {
        final List<UUID> first = pages[0];
        final List<UUID>[] rest = java.util.Arrays.copyOfRange(pages, 1, pages.length);
        when(sourceRepository.findAssetUuidsByCbomUuid(CBOM, Limit.of(batchSize))).thenReturn(first, rest);
    }

    private CbomAssetDetachService service(int batchSize) {
        return new CbomAssetDetachService(sourceWriter, assetWriter, sourceRepository, assetRepository, synchronizer,
                new TransactionHandler(), CbomIngestTestFixtures.properties(batchSize));
    }
}
