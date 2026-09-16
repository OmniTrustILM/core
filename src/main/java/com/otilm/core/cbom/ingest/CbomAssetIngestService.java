package com.otilm.core.cbom.ingest;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.otilm.api.exception.ValidationException;
import com.otilm.api.model.core.cbom.CbomAssetSyncState;
import com.otilm.core.cbom.asset.CryptoAssetIdentityFields;
import com.otilm.core.cbom.asset.CryptoPropertiesDigest;
import com.otilm.core.cbom.asset.identity.CbomAssetExtractor;
import com.otilm.core.cbom.pqc.PqcDecision;
import com.otilm.core.cbom.pqc.PqcEvaluator;
import com.otilm.core.cbom.pqc.PqcRuleset;
import com.otilm.core.cluster.ClusterOperationSynchronizer;
import com.otilm.core.config.CbomSyncProperties;
import com.otilm.core.dao.CryptoAssetConstraintTranslator;
import com.otilm.core.dao.repository.CbomRepository;
import com.otilm.core.dao.repository.cbom.CryptoAssetRepository;
import com.otilm.core.events.transaction.TransactionHandler;
import com.otilm.core.model.cbom.PqcStaleVerdictRow;
import com.otilm.core.serialization.ObjectMapperFactory;
import com.otilm.core.service.writer.cbom.CbomAssetSyncStateWriter;
import com.otilm.core.service.writer.cbom.CryptoAssetAliasWriter;
import com.otilm.core.service.writer.cbom.CryptoAssetSourceWriter;
import com.otilm.core.service.writer.cbom.CryptoAssetWriter;
import io.micrometer.core.instrument.MeterRegistry;
import java.time.OffsetDateTime;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.UUID;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Propagation;
import org.springframework.transaction.annotation.Transactional;

/**
 * Ingests one CBOM's cryptographic assets as a single unit of work.
 *
 * <p>
 * The orchestrator half of the bean pair: it owns the transaction boundaries and composes the writers, and writes
 * nothing itself. {@code NOT_SUPPORTED} because a caller may hand it a document it has just fetched while its own
 * transaction is open, and because the state writes have to commit independently of the asset writes -- see below.
 *
 * <p>
 * <b>The document is a parameter, never a fetch.</b> Every caller has the document already, and taking it as an
 * argument is what keeps the HTTP read outside the transaction that holds the cluster lock.
 *
 * <p>
 * <b>Three boundaries, and why each is its own transaction.</b>
 * <ul>
 * <li>{@code markInProgress} / {@code markSynced} / {@code markFailed} run in their own transactions, because
 * {@link CbomAssetSyncStateWriter} is {@code REQUIRED} and would otherwise enrol the state in the very transaction that
 * is failing -- the failure would then roll back the record of itself, and the operator would see a CBOM that looks
 * untouched.</li>
 * <li>Each batch of asset writes runs in its own transaction and takes {@link #assetSyncLockKey(UUID) this CBOM's
 * asset-sync lock} inside it. That lock is transaction-scoped, so it is released at every batch commit rather than held
 * across the document: a second node can take it in the gap, and the first node then abandons the rest of the document
 * at its next batch. Safe, because every write is an idempotent upsert and the CBOM goes on owing an ingest -- but it
 * is why a batch is bounded by {@code cbom.sync.asset-batch-size} rather than by the document.</li>
 * <li>Inside a batch, {@link CryptoAssetAliasWriter#ALIAS_DECISION_LOCK} is taken <b>before the first asset row
 * lock</b>. That lock outranks every {@code crypto_asset} row lock, so a transaction that upserts a source first and
 * stamps a guard second would deadlock against one doing the reverse.</li>
 * </ul>
 *
 * <p>
 * <b>Lock ranking, third rank included.</b> The asset-sync lock is taken above {@code ALIAS_DECISION_LOCK}, which is
 * above every {@code crypto_asset} row lock. On this path it is acquired with a non-blocking {@code tryLock}, so a node
 * that cannot get it abandons the batch rather than joining a wait chain.
 *
 * <p>
 * It may also be acquired <b>blocking</b> -- {@link CbomAssetDetachService#withdrawWaiting(UUID)} does, for a caller
 * that was promised the outcome, and so does the header delete that follows it -- and what keeps that safe is the
 * ranking, not the non-blocking call: the blocking acquisition is the <b>first</b> lock of its transaction, so the
 * waiter holds nothing any holder could go on to want, and no cycle can close. A path that took
 * {@code ALIAS_DECISION_LOCK} or a {@code crypto_asset} row lock and then waited on the asset-sync lock would close
 * one; that is the thing this ranking forbids.
 */
@Slf4j
@Service
public class CbomAssetIngestService {

    /** Shared: building one per document is measurable on a large inventory. */
    private static final ObjectMapper JSON_COLUMN = ObjectMapperFactory.jsonColumn();

    private final CbomAssetExtractor extractor;
    private final CryptoAssetWriter assetWriter;
    private final CryptoAssetSourceWriter sourceWriter;
    private final CbomAssetDetachService detachService;
    private final CbomAssetSyncStateWriter stateWriter;
    private final CbomRepository cbomRepository;
    private final CryptoAssetRepository assetRepository;
    private final PqcEvaluator evaluator;
    private final ClusterOperationSynchronizer clusterSynchronizer;
    private final TransactionHandler transactionHandler;
    private final MeterRegistry meterRegistry;
    private final boolean enabled;
    private final int batchSize;

    public CbomAssetIngestService(CbomAssetExtractor extractor, CryptoAssetWriter assetWriter,
            CryptoAssetSourceWriter sourceWriter, CbomAssetDetachService detachService,
            CbomAssetSyncStateWriter stateWriter, CbomRepository cbomRepository, CryptoAssetRepository assetRepository,
            PqcEvaluator evaluator, ClusterOperationSynchronizer clusterSynchronizer,
            TransactionHandler transactionHandler, MeterRegistry meterRegistry, CbomSyncProperties properties) {
        this.extractor = extractor;
        this.assetWriter = assetWriter;
        this.sourceWriter = sourceWriter;
        this.detachService = detachService;
        this.stateWriter = stateWriter;
        this.cbomRepository = cbomRepository;
        this.assetRepository = assetRepository;
        this.evaluator = evaluator;
        this.clusterSynchronizer = clusterSynchronizer;
        this.transactionHandler = transactionHandler;
        this.meterRegistry = meterRegistry;
        this.enabled = properties.assetIngestEnabled();
        this.batchSize = properties.assetBatchSize();
    }

    /**
     * The cluster lock this CBOM's asset writes take, one key per document.
     *
     * <p>
     * Per document rather than one key for the operation, because the backlog pass claims a row before it reads the
     * document and a single key would undo that: a node that lost a global lock would have spent the HTTP read and the
     * extraction already, and the cluster would write at one node's rate however many nodes it has. Two nodes working
     * different documents do not contend; two working the same one are what this excludes, which is the case the claim
     * cannot cover on its own -- the inline pass does not claim, and a claim can expire under a long ingest.
     */
    public static String assetSyncLockKey(UUID cbomUuid) {
        return "cbom-asset-sync:" + cbomUuid;
    }

    /** What one document's ingest did, for the run report. */
    public enum IngestOutcome {
        /** Every asset the document yielded is stored and the CBOM reads {@code SYNCED}. */
        INGESTED,
        /** Another node is ingesting this CBOM; it is left as the run found it, still owing an ingest. */
        LOCKED_ELSEWHERE,
        /** The document was refused before anything was written; the CBOM reads {@code FAILED} with the reason. */
        REFUSED,
        /** Writing failed partway; the CBOM reads {@code FAILED} and the next run redoes the unit. */
        FAILED,
        /**
         * {@code cbom.sync.asset-ingest-enabled} is off. Nothing was read and nothing was written, and the CBOM is left
         * exactly as it was found -- so turning the switch back on resumes rather than repairs.
         */
        DISABLED,
        /**
         * A later version of the same serial number has itself been ingested, so this document no longer speaks for its
         * URN. Anything this revision had already contributed is withdrawn and the CBOM reads {@code SYNCED}: it owes
         * no ingest, because the version that supersedes it owns the inventory.
         *
         * <p>
         * {@code assets_synced_at} is deliberately <b>not</b> stamped -- see
         * {@link CbomAssetSyncStateWriter#markSuperseded}.
         */
        SUPERSEDED,
        /**
         * The CBOM header was deleted while this document was being ingested, so there is nothing left to source. The
         * row is gone, so nothing is written and nothing is owed: the tombstone is what keeps the next run from storing
         * the document again.
         */
        DELETED
    }

    /**
     * Ingests the document's assets and leaves the CBOM row saying what happened. Idempotent: every write is an upsert
     * on the arbiters the migration declares, so redoing a unit a crash left half-written converges on the same rows.
     *
     * @param seenAt when this CBOM was observed to say what it says -- one constant for the whole document, because
     * {@link CryptoAssetSourceWriter#upsertSource} elects the newest <em>observation</em> and a per-asset clock would
     * make an arbitrary asset of the same document win
     */
    @Transactional(propagation = Propagation.NOT_SUPPORTED)
    public IngestOutcome ingest(UUID cbomUuid, Map<String, Object> document, OffsetDateTime seenAt) {
        // Ahead of valueToTree, which is the whole reason the check is its own method: both production callers reach
        // this overload -- the inline pass with a Map, the backlog pass with a BomResponseDto, which extends
        // LinkedHashMap -- so a check made only in the JsonNode overload would build the tree of every disabled and
        // every superseded document first.
        return settleWithoutReading(cbomUuid)
                .orElseGet(() -> ingestExtracted(cbomUuid, JSON_COLUMN.valueToTree(document), seenAt));
    }

    /** As {@link #ingest(UUID, Map, OffsetDateTime)}, for a document already parsed into a tree. */
    @Transactional(propagation = Propagation.NOT_SUPPORTED)
    public IngestOutcome ingest(UUID cbomUuid, JsonNode document, OffsetDateTime seenAt) {
        return settleWithoutReading(cbomUuid).orElseGet(() -> ingestExtracted(cbomUuid, document, seenAt));
    }

    /**
     * What this CBOM's ingest is settled as without its document, if anything -- the kill switch, and supersession.
     *
     * <p>
     * Public because a caller that has still to <em>fetch</em> the document should ask first: {@link #ingest} calls it
     * too, as the backstop that makes the answer true of every caller, but by then the HTTP read has been paid for.
     * Calling it changes state (a superseded revision is withdrawn and settled), so its answer is an outcome to count,
     * not a question to ask idly.
     *
     * @return the outcome when there is nothing to read the document for, empty when the ingest should proceed
     */
    @Transactional(propagation = Propagation.NOT_SUPPORTED)
    public Optional<IngestOutcome> settleWithoutReading(UUID cbomUuid) {
        // The authoritative half of the kill switch. Its callers check it too, so that a disabled run does not select
        // a work list or spend a document read; this is what makes "nothing is written" true of every caller, present
        // and future, rather than of the two that remember to ask.
        if (!enabled) {
            return Optional.of(IngestOutcome.DISABLED);
        }
        if (cbomRepository.hasIngestedLaterVersion(cbomUuid)) {
            // Ahead of the claim as well, so a revision nothing will extract never takes one. The callers test it
            // earlier still, before spending the document read; this is the backstop that makes it true of every
            // caller.
            return Optional.of(supersede(cbomUuid, cbomRepository.findAssetSyncState(cbomUuid).orElse(null)));
        }
        return Optional.empty();
    }

    private IngestOutcome ingestExtracted(UUID cbomUuid, JsonNode document, OffsetDateTime seenAt) {
        // Captured before the claim overwrites it, so a unit that finds the lock taken can put the row back in the
        // list it came from rather than leaving it IN_PROGRESS for work no node is doing.
        final CbomAssetSyncState entryState = cbomRepository.findAssetSyncState(cbomUuid).orElse(null);
        runInOwnTransaction(() -> stateWriter.markInProgress(cbomUuid));

        final CbomAssetExtractor.Extraction extraction;
        try {
            extraction = extractor.extract(document);
        } catch (RuntimeException e) {
            log.warn("CBOM asset ingest: extracting the document failed for CBOM {}", cbomUuid, e);
            return refuse(cbomUuid, "the document could not be read for cryptographic assets (see the Core log)");
        }

        if (extraction.documentScopeUnavailable()) {
            // Refused rather than ingested: without the whole-document scope a fabricated placeholder digest is
            // trusted and every certificate's public-key slot empties, which merges rows that are not the same asset.
            // An over-merge cannot be undone without re-keying the inventory; not ingesting can be retried.
            return refuse(cbomUuid,
                    "the document's cross-component scope could not be built, so its assets cannot be keyed safely");
        }

        final List<CbomAssetExtractor.ExtractedAsset> assets = CbomAssetExtractor.ExtractedAsset
                .coalesceByIdentity(extraction.assets(), CbomAssetIngestService::leafCountOf);
        try {
            for (List<CbomAssetExtractor.ExtractedAsset> batch : batches(assets)) {
                final BatchOutcome outcome = transactionHandler
                        .runInNewTransaction(() -> writeBatchUnderClusterLock(cbomUuid, batch, seenAt));
                if (outcome == BatchOutcome.LOCKED_ELSEWHERE) {
                    return lockedElsewhere(cbomUuid, entryState);
                }
                if (outcome == BatchOutcome.SUPERSEDED) {
                    return supersede(cbomUuid, entryState);
                }
                if (outcome == BatchOutcome.DELETED) {
                    log.debug("CBOM asset ingest: CBOM {} was deleted while its assets were being ingested", cbomUuid);
                    return IngestOutcome.DELETED;
                }
            }
            // Once more before the row is called synced, for the version that was on its last batch when a newer one
            // took the URN: nothing after the loop would otherwise look again, and this revision would be recorded as
            // the one speaking for a URN it no longer speaks for.
            if (cbomRepository.hasIngestedLaterVersion(cbomUuid)) {
                return supersede(cbomUuid, entryState);
            }
            if (!withdrawSupersededVersions(cbomUuid)) {
                return lockedElsewhere(cbomUuid, entryState);
            }
        } catch (RuntimeException e) {
            log.warn("CBOM asset ingest: storing the assets failed for CBOM {}", cbomUuid, e);
            return fail(cbomUuid, "storing the cryptographic assets failed: " + safeReason(e));
        }

        runInOwnTransaction(() -> stateWriter.markSynced(cbomUuid, seenAt));
        log
                .debug("CBOM asset ingest: CBOM {} ingested {} assets, {} components skipped", cbomUuid, assets.size(),
                        extraction.skips().size());
        return IngestOutcome.INGESTED;
    }

    /**
     * Hands the URN to this version: every earlier version's links are withdrawn, and the assets they leave without a
     * source are settled by {@link CbomAssetDetachService}'s orphan rule.
     *
     * <p>
     * After the new version's own sources are written, not before. A run that dies in between leaves an asset sourced
     * by two revisions of one document -- a count too high, which the next run corrects -- where the other order would
     * leave the inventory saying nothing about a document that still exists.
     *
     * @return false when another node holds the cluster lock, which leaves the CBOM owing the whole unit: it is not
     * marked synced, and the next run redoes it idempotently
     */
    private boolean withdrawSupersededVersions(UUID cbomUuid) {
        for (UUID superseded : cbomRepository.findSupersededVersionUuids(cbomUuid)) {
            final CbomAssetDetachService.Withdrawal withdrawn = detachService.withdraw(superseded);
            if (withdrawn.detached() > 0) {
                log
                        .debug("CBOM asset ingest: CBOM {} superseded version {}, withdrawing {} links ({} assets deleted, {} kept for an alias)",
                                cbomUuid, superseded, withdrawn.detached(), withdrawn.deleted(), withdrawn.kept());
            }
            if (!withdrawn.complete()) {
                return false;
            }
        }
        return true;
    }

    /** What one batch of asset writes did, for the loop that drives them. */
    private enum BatchOutcome {
        WRITTEN,
        /** Another node is ingesting the same CBOM: a skip, not a failure. The CBOM keeps owing an ingest. */
        LOCKED_ELSEWHERE,
        /** A newer revision took the URN while this document was being written. */
        SUPERSEDED,
        /** An operator deleted the CBOM header while this document was being written. */
        DELETED
    }

    /**
     * One batch, inside the transaction that holds the cluster lock.
     */
    private BatchOutcome writeBatchUnderClusterLock(UUID cbomUuid, List<CbomAssetExtractor.ExtractedAsset> batch,
            OffsetDateTime seenAt) {
        if (!clusterSynchronizer.tryLock(assetSyncLockKey(cbomUuid))) {
            return BatchOutcome.LOCKED_ELSEWHERE;
        }
        // Re-read under the lock, not once at entry. The lock is transaction-scoped, so it is released at every batch
        // commit -- and in that gap a newer revision can be stored, ingested, and withdraw everything this document has
        // written so far. Resuming would then re-attach a superseded revision's links to assets the newer revision now
        // owns, permanently: the newer row is SYNCED and never looks again, and the withdrawal is only ever driven by
        // the ingesting version. One indexed lookup per batch closes it.
        if (cbomRepository.hasIngestedLaterVersion(cbomUuid)) {
            return BatchOutcome.SUPERSEDED;
        }
        // The same reasoning as the supersession re-read, for the other thing that can happen to this CBOM in the gap:
        // a deletion withdraws the inventory and removes the header under this very lock. Writing a source row against
        // a cbom_uuid that is gone violates crypto_asset_source_to_cbom_key -- a noisy failed document whose markFailed
        // then updates no row, because there is no row. One indexed lookup, next to the one already here.
        if (!cbomRepository.existsById(cbomUuid)) {
            return BatchOutcome.DELETED;
        }
        // Before the first crypto_asset row lock any writer below will take. Re-entrant within the transaction, so
        // taking it here costs the writers' own acquisitions nothing.
        clusterSynchronizer.lock(CryptoAssetAliasWriter.ALIAS_DECISION_LOCK);

        // A set, not a list: the verdict pass reads each row back once, after every source of the batch has been
        // merged into it.
        final Set<UUID> written = new LinkedHashSet<>();
        // In uuid order, which is the order CryptoAssetPqcVerdictWriter.applyStaleBatch takes crypto_asset row
        // locks in. Every asset an ingest creates is immediately on the sweep's work list -- upsertIdentity leaves
        // pqc_ruleset_version null -- and the sweep holds a different cluster lock, so the two do run at once; two
        // transactions locking an overlapping row set in opposite orders deadlock, and on this side the loser fails
        // the whole document and waits out cbom.sync.ingest-retry-after. An asset with no row yet sorts last and keeps
        // document order: its uuid is minted by the insert, so there is nothing to order it by and no lock the sweep
        // can be waiting on. The resolution is a plain read, so a row another node inserts in between is ordered as
        // new -- which narrows the window rather than closing it, and is why the sweep's own retry-one-at-a-time path
        // stays the backstop.
        final Map<String, UUID> rows = new LinkedHashMap<>();
        for (CbomAssetExtractor.ExtractedAsset asset : batch) {
            assetRepository
                    .findUuidByIdentityKey(asset.identityKey())
                    .ifPresent(uuid -> rows.put(asset.identityKey(), uuid));
        }
        final List<CbomAssetExtractor.ExtractedAsset> ordered = batch
                .stream()
                .sorted(Comparator
                        .comparing((CbomAssetExtractor.ExtractedAsset asset) -> rows.containsKey(asset.identityKey())
                                ? 0
                                : 1)
                        .thenComparing(asset -> rows.get(asset.identityKey()),
                                Comparator.nullsLast(Comparator.naturalOrder())))
                .toList();
        for (CbomAssetExtractor.ExtractedAsset asset : ordered) {
            final UUID assetUuid = assetWriter.upsertIdentity(asset.identityKey(), fieldsOf(asset), asset.guard());
            sourceWriter
                    .upsertSource(assetUuid, cbomUuid, propertiesOf(asset), asset.evidence(),
                            asset.reportedOccurrences(), seenAt);
            written.add(assetUuid);
        }
        stampVerdicts(written);
        return BatchOutcome.WRITTEN;
    }

    /**
     * Hands this revision's place to the version that supersedes it: whatever it had already written is withdrawn, and
     * the row is settled as synced without claiming a sync of its own.
     *
     * <p>
     * The withdrawal is what makes the write-off safe. A revision can reach this point with part of an inventory
     * already attached -- a run that failed partway, or one a newer revision overtook between batches -- and marking it
     * synced without giving those links back would strand that partial contribution for ever: nothing moves a
     * {@code SYNCED} row back onto a work list, and the withdrawal half of supersession only ever runs from the
     * <em>ingesting</em> version, which has already been and gone.
     *
     * <p>
     * An incomplete withdrawal leaves the row owing the unit rather than marking it synced, so the next run finishes
     * what this one started.
     */
    private IngestOutcome supersede(UUID cbomUuid, CbomAssetSyncState entryState) {
        final CbomAssetDetachService.Withdrawal withdrawn = detachService.withdraw(cbomUuid);
        if (!withdrawn.complete()) {
            return lockedElsewhere(cbomUuid, entryState);
        }
        if (withdrawn.detached() > 0) {
            log
                    .debug("CBOM asset ingest: CBOM {} is superseded; withdrew the {} links it had already contributed",
                            cbomUuid, withdrawn.detached());
        }
        runInOwnTransaction(() -> stateWriter.markSuperseded(cbomUuid));
        return IngestOutcome.SUPERSEDED;
    }

    /**
     * Stamps the PQC verdict of every asset this batch touched, reading each row back after its sources were merged.
     *
     * <p>
     * Read back rather than evaluated from the document: an asset several CBOMs report is evaluated on the payload the
     * merge elected, not on whichever document happened to arrive last. Stamping here rather than leaving the rows to
     * {@code PqcVerdictSweeper} is a latency decision -- a null {@code pqc_ruleset_version} is already stale to the
     * sweep -- and it matters most on the first ingest, when the sweep has the largest backlog it will ever have.
     *
     * <p>
     * Being a latency decision, it must not be able to fail the unit of work. A row the rules cannot evaluate is
     * counted and left unstamped, which is exactly how the sweep finds it later; letting the exception out would roll
     * back the whole batch -- every identity and source write in it -- and fail the document for ever, since the retry
     * would meet the same row.
     */
    private void stampVerdicts(Set<UUID> assetUuids) {
        for (PqcStaleVerdictRow row : assetRepository.verdictRowsByUuids(assetUuids)) {
            try {
                final JsonNode merged = mergedPayload(row);
                final PqcDecision decision = evaluator
                        .evaluate(evaluator.fromStoredRow(row.fields(), merged),
                                PqcEvaluator.nistQuantumSecurityLevel(merged));
                assetWriter
                        .applyPqcVerdict(row.uuid(), decision.verdict(), decision.ruleId(), decision.reason(),
                                PqcRuleset.VERSION, decision.evaluatedFields());
            } catch (RuntimeException e) {
                meterRegistry.counter("crypto_asset.ingest.verdict_failed").increment();
                // The uuid, never the identity key: this line reaches an operator's log aggregator.
                log
                        .warn("CBOM asset ingest: stamping the post-quantum verdict failed for cryptographic asset {}; leaving it to the sweep",
                                row.uuid(), e);
            }
        }
    }

    private static JsonNode mergedPayload(PqcStaleVerdictRow row) {
        try {
            return row.mergedCryptoPropertiesJson() == null
                    ? null
                    : JSON_COLUMN.readTree(row.mergedCryptoPropertiesJson());
        } catch (com.fasterxml.jackson.core.JsonProcessingException e) {
            throw new IllegalStateException("The stored merged cryptographic properties could not be read", e);
        }
    }

    /**
     * Gives the claim back when another node is already ingesting this CBOM. Nothing else records the outcome, so
     * without this the row keeps the {@code IN_PROGRESS} the claim wrote: out of the pending list, into the retry list,
     * and invisible for {@code cbom.sync.ingest-retry-after} -- a whole run skipped over work no node is doing.
     */
    private IngestOutcome lockedElsewhere(UUID cbomUuid, CbomAssetSyncState entryState) {
        if (entryState != null && entryState != CbomAssetSyncState.SYNCED) {
            runInOwnTransaction(() -> stateWriter.releaseClaim(cbomUuid, entryState));
        }
        return IngestOutcome.LOCKED_ELSEWHERE;
    }

    private IngestOutcome refuse(UUID cbomUuid, String reason) {
        runInOwnTransaction(() -> stateWriter.markFailed(cbomUuid, reason));
        return IngestOutcome.REFUSED;
    }

    private IngestOutcome fail(UUID cbomUuid, String reason) {
        runInOwnTransaction(() -> stateWriter.markFailed(cbomUuid, reason));
        return IngestOutcome.FAILED;
    }

    /** Where the state writes get their independence: the writer is {@code REQUIRED} and would otherwise join. */
    private void runInOwnTransaction(Runnable write) {
        transactionHandler.runInNewTransaction(write);
    }

    private List<List<CbomAssetExtractor.ExtractedAsset>> batches(List<CbomAssetExtractor.ExtractedAsset> assets) {
        final List<List<CbomAssetExtractor.ExtractedAsset>> batches = new ArrayList<>();
        for (int from = 0; from < assets.size(); from += batchSize) {
            batches.add(assets.subList(from, Math.min(from + batchSize, assets.size())));
        }
        return batches;
    }

    private static CryptoAssetIdentityFields fieldsOf(CbomAssetExtractor.ExtractedAsset asset) {
        return CryptoAssetIdentityFields
                .of(PqcEvaluator.assetTypeOf(asset.normalized().assetType()), asset.normalized());
    }

    /** The measure the cross-source merge itself elects on, so the fold inside a document agrees with it. */
    private static int leafCountOf(CbomAssetExtractor.ExtractedAsset asset) {
        final Map<String, Object> properties = propertiesOf(asset);
        return properties == null ? 0 : CryptoPropertiesDigest.of(properties).leafCount();
    }

    @SuppressWarnings("unchecked")
    private static Map<String, Object> propertiesOf(CbomAssetExtractor.ExtractedAsset asset) {
        final JsonNode retained = asset.retainedProperties();
        return retained == null || retained.isNull() ? null : JSON_COLUMN.convertValue(retained, Map.class);
    }

    /**
     * The operator-visible half of a failure.
     *
     * <p>
     * A driver message is never it: a constraint violation's DETAIL line carries the failing row, and for
     * {@code crypto_asset} that row carries the identity key. But most of what reaches here is not a constraint
     * violation at all -- a guard refused because an alias already merges the asset, an identity key of the wrong
     * shape, a lock that could not be acquired -- and translating those as "it would violate a database constraint"
     * says something false to the one person who could act on it. A {@link ValidationException} is text the inventory's
     * own writers shaped for an operator, so it is passed through; everything else goes to the translator, which reads
     * the violated constraint's <em>name</em> and never the exception's message.
     */
    private static String safeReason(RuntimeException e) {
        if (e instanceof ValidationException && e.getMessage() != null) {
            return e.getMessage();
        }
        return CryptoAssetConstraintTranslator.describe(e);
    }
}
