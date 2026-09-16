package com.otilm.core.cbom.ingest;

import com.otilm.api.exception.PlatformException;
import com.otilm.core.cluster.ClusterOperationSynchronizer;
import com.otilm.core.config.CbomSyncProperties;
import com.otilm.core.dao.repository.cbom.CryptoAssetRepository;
import com.otilm.core.dao.repository.cbom.CryptoAssetSourceRepository;
import com.otilm.core.events.transaction.TransactionHandler;
import com.otilm.core.service.writer.cbom.CryptoAssetAliasWriter;
import com.otilm.core.service.writer.cbom.CryptoAssetSourceWriter;
import com.otilm.core.service.writer.cbom.CryptoAssetWriter;
import java.util.List;
import java.util.UUID;
import lombok.extern.slf4j.Slf4j;
import org.springframework.data.domain.Limit;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Propagation;
import org.springframework.transaction.annotation.Transactional;

/**
 * Withdraws one CBOM's contribution to the cryptographic asset inventory, and settles what that withdrawal leaves
 * behind.
 *
 * <p>
 * The orchestrator half of a bean pair, like {@link CbomAssetIngestService}: it owns the transaction boundaries and
 * composes the writers, and writes nothing itself.
 *
 * <p>
 * <b>The orphan rule.</b> An asset whose last source is withdrawn is deleted, unless an alias is <em>pointed at</em> it
 * -- that is, its key is some alias's canonical key -- in which case the row is kept with {@code source_count} at zero
 * and its payload cleared. The inventory is meant to say what the documents currently say, and a row nothing sources
 * any more says nothing; but an alias is an operator's decision about which assets are the same asset,
 * {@code crypto_asset_alias} cascades from the canonical row, and a sweep no operator asked for must not discard that
 * decision silently. The absorbed side carries no such risk -- the alias table has no foreign key on
 * {@code absorbed_key}, and an absorbed row that no longer exists is its normal state -- so an orphan named only there
 * is collected like any other.
 *
 * <p>
 * <b>A kept orphan is a row state nothing produced before this class.</b> {@code source_count = 0} with no payload is
 * listed, paginated and counted by the cryptographic asset API exactly like a sourced asset, because no read path has a
 * {@code source_count > 0} predicate. That is deliberate for now -- the row is kept precisely so an operator can still
 * see and unmerge the decision that holds it, and hiding it would make the alias unreachable through the API that
 * created it -- but it does mean the inventory's totals count assets no document currently mentions. Recorded as open
 * work on core#2073.
 *
 * <p>
 * <b>Why a batch may be abandoned, and what survives it.</b> Every batch takes
 * {@link CbomAssetIngestService#assetSyncLockKey(UUID) the withdrawn CBOM's asset-sync lock}, exactly as ingest does --
 * the two paths write the same rows, and the lock is what keeps one node at a time on them. The key is the document's,
 * not the operation's, so a withdrawal and an unrelated document's ingest do not contend; the pair that must exclude
 * each other is this withdrawal and an ingest of the same CBOM, which share the key.
 *
 * <p>
 * What a batch does when another node holds that key depends on what its caller was promised. A housekeeping withdrawal
 * ({@link #withdraw(UUID)}) gives up, because its caller learns it from the return value and leaves the CBOM owing the
 * work. A withdrawal whose caller was promised the outcome ({@link #withdrawWaiting(UUID)}) waits instead: an operator
 * deleting a document is told it is gone, and skipping would turn that delete into a refusal for as long as another
 * node happened to be syncing.
 *
 * <p>
 * Each batch commits in its own transaction, so giving up is <b>not</b> all-or-nothing: the batches that already
 * committed stay committed, their orphans included, and deleting an orphan is not reversible. What the caller is
 * promised is only that no more than its own unit of work is lost -- {@link Withdrawal#complete()} says whether the
 * rest was reached, and the counts describe what really happened either way. That is safe because the caller leaves the
 * CBOM owing the work and the next run redoes the whole withdrawal idempotently; it is not safe to ignore, because a
 * revision left half-withdrawn still sources part of an inventory another revision now speaks for.
 *
 * <p>
 * The same reasoning applies to a batch that <em>throws</em>, which is why it does not propagate bare:
 * {@link WithdrawalFailedException} carries what the batches before it committed, so a caller can tell a withdrawal
 * that did nothing from one that half-emptied the inventory and must record the CBOM as owing a rebuild.
 *
 * <p>
 * <b>The work list is read under the lock, one page per batch.</b> Reading it once at entry would make the promise
 * weaker than it looks: the lock is released at every batch commit, so a snapshot taken before the first acquisition --
 * or before the previous commit -- misses every source an ingest of the same document attaches in the gap, and
 * {@code complete()} would still be true. Re-reading under the lock also makes the empty case take the lock at all,
 * which is what excludes an ingest writing a CBOM's first sources while it is being deleted. The loop ends on a page
 * the lock says is empty, so it converges only because an ingest of one document is itself finite.
 */
@Slf4j
@Service
public class CbomAssetDetachService {

    private final CryptoAssetSourceWriter sourceWriter;
    private final CryptoAssetWriter assetWriter;
    private final CryptoAssetSourceRepository sourceRepository;
    private final CryptoAssetRepository assetRepository;
    private final ClusterOperationSynchronizer clusterSynchronizer;
    private final TransactionHandler transactionHandler;
    private final int batchSize;

    public CbomAssetDetachService(CryptoAssetSourceWriter sourceWriter, CryptoAssetWriter assetWriter,
            CryptoAssetSourceRepository sourceRepository, CryptoAssetRepository assetRepository,
            ClusterOperationSynchronizer clusterSynchronizer, TransactionHandler transactionHandler,
            CbomSyncProperties properties) {
        this.sourceWriter = sourceWriter;
        this.assetWriter = assetWriter;
        this.sourceRepository = sourceRepository;
        this.assetRepository = assetRepository;
        this.clusterSynchronizer = clusterSynchronizer;
        this.transactionHandler = transactionHandler;
        this.batchSize = properties.assetBatchSize();
    }

    /**
     * What withdrawing a CBOM's contribution did, for the run report and for the tests that pin the orphan rule.
     *
     * @param complete whether every batch was reached. False means another node held the cluster lock partway through:
     * the counts still describe what this node committed before it stopped, and the CBOM goes on owing the rest.
     */
    public record Withdrawal(int detached, int deleted, int kept, boolean complete) {

        static final Withdrawal NOTHING = new Withdrawal(0, 0, 0, true);

        Withdrawal plus(Withdrawal other) {
            return new Withdrawal(detached + other.detached, deleted + other.deleted, kept + other.kept,
                    complete && other.complete);
        }

        /** The unit stopped here: what this batch committed is nothing, and the rest was left for whoever holds it. */
        static final Withdrawal ABANDONED = new Withdrawal(0, 0, 0, false);
    }

    /**
     * Withdraws every link the given CBOM contributed, applying the orphan rule to each asset it leaves without a
     * source.
     *
     * @return what was withdrawn, and whether the whole CBOM was reached. An incomplete withdrawal is not an empty one:
     * see the class comment. A caller that needs the CBOM fully withdrawn must treat {@code complete == false} as work
     * still owed and repeat the call, not as "nothing happened".
     */
    @Transactional(propagation = Propagation.NOT_SUPPORTED)
    public Withdrawal withdraw(UUID cbomUuid) {
        return withdrawInBatches(cbomUuid, Contention.SKIP);
    }

    /**
     * Withdraws every link the given CBOM contributed, waiting for the cluster lock instead of leaving the work to
     * whoever holds it.
     *
     * <p>
     * For the caller that was promised the outcome: an operator deleting one CBOM is told the document is gone, and the
     * deletion cannot proceed while the inventory still references it -- the foreign key is {@code RESTRICT}. A skipped
     * withdrawal would turn the delete into a refusal for as long as another node happened to be syncing. Waiting is
     * what makes {@link Withdrawal#complete()} true here by construction; the assertion below is the invariant, not a
     * case the caller is expected to handle.
     *
     * <p>
     * Blocking on that key carries a ranking obligation, and this is the only path that takes it blocking: the wait
     * must be the <b>first</b> lock of its transaction, above {@code ALIAS_DECISION_LOCK} and above every
     * {@code crypto_asset} row lock, so that a waiter holds nothing a holder could go on to want. See the lock ranking
     * on {@link CbomAssetIngestService}.
     */
    @Transactional(propagation = Propagation.NOT_SUPPORTED)
    public Withdrawal withdrawWaiting(UUID cbomUuid) {
        final Withdrawal withdrawn = withdrawInBatches(cbomUuid, Contention.WAIT);
        if (!withdrawn.complete()) {
            throw new IllegalStateException("A waiting withdrawal cannot be abandoned");
        }
        return withdrawn;
    }

    /** What a batch does when another node holds the withdrawn CBOM's asset-sync lock. */
    private enum Contention {
        SKIP,
        WAIT
    }

    private Withdrawal withdrawInBatches(UUID cbomUuid, Contention contention) {
        Withdrawal total = Withdrawal.NOTHING;
        while (true) {
            final Batch done;
            try {
                done = transactionHandler
                        .runInNewTransaction(() -> withdrawBatchUnderClusterLock(cbomUuid, contention));
            } catch (RuntimeException e) {
                throw new WithdrawalFailedException(total, e);
            }
            if (done == null) {
                return total.plus(Withdrawal.ABANDONED);
            }
            total = total.plus(done.withdrawn());
            if (done.last()) {
                return total;
            }
        }
    }

    /** One batch's outcome: what it withdrew, and whether the page it read under the lock was the last one. */
    private record Batch(Withdrawal withdrawn, boolean last) {
    }

    /** One batch, inside the transaction that holds the cluster lock. Null when another node holds it. */
    private Batch withdrawBatchUnderClusterLock(UUID cbomUuid, Contention contention) {
        final String lockKey = CbomAssetIngestService.assetSyncLockKey(cbomUuid);
        if (contention == Contention.WAIT) {
            clusterSynchronizer.lock(lockKey);
        } else if (!clusterSynchronizer.tryLock(lockKey)) {
            return null;
        }
        // Under the lock, never once at entry -- see the class comment. An empty page here is the withdrawal's last
        // word, and it is worth what the lock makes it worth: nothing can be attaching sources while it is read.
        final List<UUID> assets = sourceRepository.findAssetUuidsByCbomUuid(cbomUuid, Limit.of(batchSize));
        if (assets.isEmpty()) {
            return new Batch(Withdrawal.NOTHING, true);
        }
        // Before the first crypto_asset row lock, as on the ingest path: deleting an orphan deletes its aliases by
        // cascade, so this transaction may decide about aliases as well as rows.
        clusterSynchronizer.lock(CryptoAssetAliasWriter.ALIAS_DECISION_LOCK);

        int detached = 0;
        for (UUID assetUuid : assets) {
            detached += sourceWriter.detachCbom(assetUuid, cbomUuid);
        }
        // Once for the batch, after every detach: both questions are set-shaped, and asking them per asset would put
        // two more round trips per asset inside the transaction holding the cluster-wide ALIAS_DECISION_LOCK.
        int deleted = 0;
        int kept = 0;
        for (CryptoAssetRepository.OrphanRow orphan : assetRepository.orphansAmong(assets)) {
            if (orphan.namedByAnAlias()) {
                log
                        .debug("CBOM asset withdrawal: asset {} has no source left but an alias points at it; keeping the row",
                                orphan.uuid());
                kept++;
            } else {
                assetWriter.delete(orphan.uuid());
                deleted++;
            }
        }
        return new Batch(new Withdrawal(detached, deleted, kept, true), assets.size() < batchSize);
    }

    /**
     * A withdrawal that stopped on a failure, carrying what the batches before it committed.
     *
     * <p>
     * "Threw" and "withdrew nothing" are not the same thing here, and a caller that treats them as one strands rows.
     * Every batch commits on its own, so a failure on batch <i>k</i> leaves <i>1..k-1</i> withdrawn and their orphan
     * assets irreversibly deleted; a delete path that then leaves the CBOM reading {@code SYNCED} has put it on no work
     * list at all, because the backlog pass selects {@code PENDING} and the retry pass {@code IN_PROGRESS}/
     * {@code FAILED}. {@link #withdrewSomething()} is the question those callers actually need answered.
     *
     * <p>
     * The message is fixed rather than the cause's: it reaches a caller that may put it on the wire, and a database
     * failure's own text quotes the failing row. That is what {@link PlatformException} marks -- text this platform
     * authored, carrying nothing the database said.
     */
    public static class WithdrawalFailedException extends RuntimeException implements PlatformException {

        private final transient Withdrawal committed;

        public WithdrawalFailedException(Withdrawal committed, RuntimeException cause) {
            super("Withdrawing the CBOM's cryptographic assets failed", cause);
            this.committed = committed;
        }

        /** What committed before the failure. */
        public Withdrawal committed() {
            return committed;
        }

        /** Whether the inventory was changed at all, which is what decides if the CBOM now owes a rebuild. */
        public boolean withdrewSomething() {
            return committed.detached() > 0 || committed.deleted() > 0 || committed.kept() > 0;
        }
    }
}
