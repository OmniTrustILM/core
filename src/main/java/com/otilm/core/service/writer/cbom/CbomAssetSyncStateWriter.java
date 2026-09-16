package com.otilm.core.service.writer.cbom;

import com.otilm.api.model.core.cbom.CbomAssetSyncState;
import com.otilm.core.dao.repository.CbomRepository;
import java.time.OffsetDateTime;
import java.util.EnumSet;
import java.util.Set;
import java.util.UUID;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

/**
 * Short transactional writes to a CBOM row's cryptographic-asset ingest state.
 *
 * <p>
 * Kept separate from the header sync that created the row: header sync and asset ingest fail independently, and a CBOM
 * whose header is stored but whose assets could not be parsed must be visibly {@code FAILED} rather than absent -- a
 * promise that holds only if {@link #markFailed} is called from outside the transaction that failed. See its
 * documentation.
 */
@Service
public class CbomAssetSyncStateWriter {

    private final CbomRepository cbomRepository;

    public CbomAssetSyncStateWriter(CbomRepository cbomRepository) {
        this.cbomRepository = cbomRepository;
    }

    /**
     * The states a failure may be written over: everything except {@code SYNCED}.
     *
     * <p>
     * A run selects its work list, reads a document over HTTP, and only then writes. Another node can finish the same
     * CBOM inside that window, and a failure written unconditionally would flip a genuinely synced row to FAILED with
     * an error that is not about it. Success is unconditional in the other direction on purpose: the run that actually
     * ingested the assets is the one entitled to say so.
     */
    private static final Set<CbomAssetSyncState> NOT_YET_SYNCED = EnumSet
            .of(CbomAssetSyncState.PENDING, CbomAssetSyncState.IN_PROGRESS, CbomAssetSyncState.FAILED);

    /**
     * The stand-in for "never attempted", so neither side of the claim's comparison is a bare null.
     *
     * <p>
     * PostgreSQL cannot infer the type of a null bind parameter in that position and the statement fails at the driver.
     * No real attempt carries the epoch.
     */
    private static final OffsetDateTime NEVER_ATTEMPTED = OffsetDateTime.parse("1970-01-01T00:00:00Z");

    /**
     * Claims the CBOM for an ingest attempt, clearing any error from the previous one.
     *
     * <p>
     * Guarded on {@link #NOT_YET_SYNCED} for the same reason {@link #markFailed} is, and it is not the same guard as
     * {@link #claimForIngest}'s. The attempt timestamp is a retry window, never an ownership token: a run whose ingest
     * outlives {@code cbom.sync.ingest-retry-after} loses its claim to another node without being told, and an
     * unconditional write here would then walk a row that node has since finished back from {@code SYNCED} to
     * {@code IN_PROGRESS}. What the two nodes write to {@code crypto_asset} still converges -- every write is an
     * idempotent upsert, and the cluster lock admits one of them at a time -- so the state column is the only thing
     * that needs guarding.
     *
     * @return 1 if the claim was written, 0 if the CBOM had been synced in the meantime
     */
    @Transactional
    public int markInProgress(UUID cbomUuid) {
        return cbomRepository
                .updateAssetSyncState(cbomUuid, CbomAssetSyncState.IN_PROGRESS, null, null, NOT_YET_SYNCED);
    }

    /**
     * Claims a CBOM off the ingest work list, only if it is still as the caller read it.
     *
     * <p>
     * For the backlog pass, which selects its list with a plain read and then spends an HTTP document read on each
     * entry: this is what stops a second node from spending the same read. {@link #markInProgress} is the unconditional
     * claim, for a caller that already holds the document and is entitled to ingest it.
     *
     * @return 1 when the caller may proceed, 0 when another node claimed the row first
     */
    @Transactional
    public int claimForIngest(UUID cbomUuid, CbomAssetSyncState expectedState, OffsetDateTime expectedAttemptedAt) {
        return cbomRepository
                .claimAssetIngest(cbomUuid, CbomAssetSyncState.IN_PROGRESS, expectedState,
                        expectedAttemptedAt == null ? NEVER_ATTEMPTED : expectedAttemptedAt, NEVER_ATTEMPTED);
    }

    /**
     * Undoes a claim whose work never happened, putting the row back in the list it came from.
     *
     * <p>
     * For the one case where the claim buys nothing: the CBOM repository answered no document read of the run at all,
     * which is not a verdict on any document. See {@link #claimForIngest}.
     */
    @Transactional
    public int releaseClaim(UUID cbomUuid, CbomAssetSyncState previousState) {
        return cbomRepository.releaseAssetIngestClaim(cbomUuid, CbomAssetSyncState.IN_PROGRESS, previousState);
    }

    /**
     * The sentence a deletion leaves on a CBOM it withdrew from the inventory but could not remove.
     *
     * <p>
     * It lives here rather than on the delete path because two writers on this class read it: the one that writes it,
     * and {@link #markSynced} -- which must not overwrite it. Operator-visible text, so it says what to do.
     */
    public static final String DELETION_WITHDREW_THE_INVENTORY = "A deletion withdrew this CBOM's cryptographic assets and then failed; they will be ingested again.";

    /**
     * Records a successful ingest -- over any state, but not over a deletion's withdrawal.
     *
     * <p>
     * Unconditional on the state on purpose: the run that actually ingested the assets is the one entitled to say so,
     * and {@link #markInProgress}/{@link #markFailed} carry the guards that stop a stale run from overruling it. The
     * one write it must not overrule is not a state but a fact about the inventory -- see
     * {@link CbomRepository#updateAssetSyncStateUnlessError}.
     *
     * @return 1 if the success was recorded, 0 if a deletion had withdrawn the inventory in the meantime
     */
    @Transactional
    public int markSynced(UUID cbomUuid, OffsetDateTime syncedAt) {
        return cbomRepository
                .updateAssetSyncStateUnlessError(cbomUuid, CbomAssetSyncState.SYNCED, syncedAt,
                        DELETION_WITHDREW_THE_INVENTORY);
    }

    /**
     * Settles a revision a later one has taken the URN from: it owes no ingest, but it did not perform one either.
     *
     * <p>
     * {@code SYNCED} with <b>no</b> {@code assets_synced_at} of its own, which is the difference from
     * {@link #markSynced} and the point of having a second method. That column is not private bookkeeping: the
     * cryptographic asset dashboard serves its maximum over every CBOM as "last completed sync at", the CBOM DTO serves
     * it per row, and {@code CBOM_ASSETS_SYNCED_AT} offers it as a user-facing filter. Stamping it here would let a run
     * that ingested nothing at all advance the dashboard's completion time, and would present a document sourcing no
     * assets as one whose assets were just synced. A null parameter leaves the stored value alone (see
     * {@link CbomRepository#updateAssetSyncState}), so a row that never synced keeps none and one that synced under an
     * earlier revision keeps the time it really did.
     *
     * <p>
     * What this state does <em>not</em> distinguish is a revision that contributed and one that was written off, both
     * of which now read {@code SYNCED} while sourcing nothing. Telling them apart needs a state constant, and
     * {@code CbomAssetSyncState} lives in the {@code interfaces} artifact -- recorded as open work on core#2073.
     */
    @Transactional
    public int markSuperseded(UUID cbomUuid) {
        return cbomRepository.updateAssetSyncState(cbomUuid, CbomAssetSyncState.SYNCED, null, null, null);
    }

    /**
     * The states a withdrawal's failure may be written over: everything except {@code PENDING}.
     *
     * <p>
     * {@code SYNCED} is the point of the method -- see {@link #markWithdrawnButNotDeleted}. {@code PENDING} is the
     * exclusion: a CBOM whose assets were never ingested has nothing to withdraw, so nothing was withdrawn from it, and
     * flipping it to {@code FAILED} would move it off the fast pending list onto the 30-minute retry list under a
     * sentence that is untrue of it.
     */
    private static final Set<CbomAssetSyncState> WITHDRAWABLE = EnumSet
            .of(CbomAssetSyncState.IN_PROGRESS, CbomAssetSyncState.SYNCED, CbomAssetSyncState.FAILED);

    /**
     * Records that a deletion withdrew this CBOM's contribution to the inventory and then failed to remove the record.
     *
     * <p>
     * For the one caller entitled to overrule a success: the withdrawal commits before the header delete, so a deletion
     * that fails in between leaves a row that says SYNCED and sources nothing. The guard {@link #markFailed} applies is
     * there to stop a stale run from overwriting another node's success; here the row genuinely is no longer ingested,
     * and leaving it SYNCED would keep the backlog pass from ever rebuilding it.
     *
     * <p>
     * It is not an ingest attempt, so it leaves the attempt clock alone and is bounded below by {@link #WITHDRAWABLE}.
     * Both are explained on {@link CbomRepository#updateAssetSyncStateKeepingAttempt}.
     *
     * @return 1 if the failure was recorded, 0 if the CBOM owed an ingest it had not started
     */
    @Transactional
    public int markWithdrawnButNotDeleted(UUID cbomUuid) {
        return cbomRepository
                .updateAssetSyncStateKeepingAttempt(cbomUuid, CbomAssetSyncState.FAILED,
                        DELETION_WITHDREW_THE_INVENTORY, WITHDRAWABLE);
    }

    /**
     * Records a failed ingest attempt.
     *
     * <p>
     * Call it only after the ingest transaction has rolled back. Every method on this writer is {@code REQUIRED}, by
     * the rule that a writer joins the transaction it is handed, so calling this one from inside the failing
     * transaction enrolls the FAILED row in that rollback: the state is lost, and nothing reports that it was lost. The
     * class promise above -- that a failure is visibly FAILED rather than absent -- is a promise the caller keeps, not
     * one this bean can enforce. Owning that boundary is the ingest orchestrator's job.
     *
     * @param operatorSafeError text the caller shaped itself. It is stored verbatim and shown to an operator, so a
     * driver or framework message must never be passed here: a constraint violation's {@code DETAIL} line carries the
     * failing row, and for {@code crypto_asset} that row carries the identity key. Use
     * {@code CryptoAssetConstraintTranslator} to derive a safe sentence from a database failure.
     *
     * @return 1 if the failure was recorded, 0 if the CBOM had been synced in the meantime -- see
     * {@link #NOT_YET_SYNCED}
     */
    @Transactional
    public int markFailed(UUID cbomUuid, String operatorSafeError) {
        return cbomRepository
                .updateAssetSyncState(cbomUuid, CbomAssetSyncState.FAILED, operatorSafeError, null, NOT_YET_SYNCED);
    }
}
