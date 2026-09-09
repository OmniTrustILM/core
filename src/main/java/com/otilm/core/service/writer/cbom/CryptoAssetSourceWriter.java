package com.otilm.core.service.writer.cbom;

import com.otilm.core.cbom.asset.CryptoPropertiesDigest;
import com.otilm.core.cbom.asset.JsonColumnText;
import com.otilm.core.cbom.asset.OccurrenceEvidenceCapper;
import com.otilm.core.dao.repository.cbom.CryptoAssetRepository;
import com.otilm.core.dao.repository.cbom.CryptoAssetSourceRepository;
import java.time.OffsetDateTime;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.UUID;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

/**
 * Short transactional writes against {@code crypto_asset_source}, each of which also re-derives the owning asset's
 * merge bookkeeping in the same transaction.
 *
 * <p>
 * The two are inseparable on purpose: {@code crypto_asset.merged_crypto_properties} is one source's retained payload,
 * so a source change that did not re-elect would leave the asset attributing its payload to a source that no longer
 * says that -- or, on removal, to a source that no longer exists.
 *
 * <p>
 * <b>Lock order.</b> The inventory has two lock classes and they are ranked, because a transaction can hold both:
 *
 * <ol>
 * <li>{@link CryptoAssetAliasWriter#ALIAS_DECISION_LOCK}, the cluster advisory lock over alias and guard
 * decisions;</li>
 * <li>the {@code crypto_asset} row lock, then the {@code crypto_asset_source} row.</li>
 * </ol>
 *
 * <p>
 * Both methods here take the asset's row lock before touching a source row. {@code crypto_asset} and
 * {@code crypto_asset_source} reference each other, so a path that locked the source first would deadlock against a
 * concurrent ingest on the same pair; locking asset-then-source closes that cycle. Neither method takes the advisory
 * lock at all, so neither can be the transaction that holds a row and then waits for it.
 *
 * <p>
 * That is the constraint an orchestrator has to preserve, and it is the one this class cannot enforce for its caller.
 * {@link CryptoAssetWriter#upsertIdentity} takes the advisory lock when it stamps a guard. A transaction that upserts a
 * source for one asset and then stamps a guard on another would hold a row lock while waiting for the advisory lock,
 * and a concurrent transaction doing the reverse would deadlock against it. <b>An ingest that may stamp a guard must
 * therefore take the advisory lock once, up front, before its first asset row lock</b> -- it is re-entrant within a
 * transaction, so acquiring it early costs a later acquisition nothing. That wiring belongs to the ingest ticket, which
 * is also what first makes the interleaving reachable: nothing composes these writers today.
 */
@Service
public class CryptoAssetSourceWriter {

    private final CryptoAssetSourceRepository sourceRepository;
    private final CryptoAssetRepository assetRepository;

    public CryptoAssetSourceWriter(CryptoAssetSourceRepository sourceRepository,
            CryptoAssetRepository assetRepository) {
        this.sourceRepository = sourceRepository;
        this.assetRepository = assetRepository;
    }

    /**
     * Records what one CBOM says about one asset -- its payload verbatim, its occurrence evidence capped -- and
     * re-elects the asset's merged payload from the result.
     *
     * <p>
     * The stored content is the newest <em>observation</em>, not the newest arrival: a call carrying a {@code seenAt}
     * older than the one already recorded widens the row's window and leaves the payload, the evidence and the counts
     * alone. Without that, a delayed retry would leave the row attesting a state it never held. A call at the same
     * instant does refresh, so a re-extraction under upgraded code is not locked out.
     *
     * @param seenAt when this CBOM was observed to say it -- the observation time, which must be monotone per CBOM
     * across re-syncs for the recency rule to bite; a per-document constant makes every re-ingest a tie
     * @param occurrences every occurrence the CBOM reported; the unclipped count is stored, so the gap against the
     * retained evidence is the visible record that capping happened
     */
    @Transactional
    public void upsertSource(UUID assetUuid, UUID cbomUuid, Map<String, Object> cryptoProperties,
            List<Map<String, Object>> occurrences, OffsetDateTime seenAt) {
        assetRepository.lockForSourceChange(assetUuid);
        CryptoPropertiesDigest digest = CryptoPropertiesDigest.of(cryptoProperties);
        sourceRepository
                .upsertSource(UUID.randomUUID(), assetUuid, cbomUuid, JsonColumnText.render(cryptoProperties),
                        digest.leafCount(), digest.hash(),
                        JsonColumnText.render(OccurrenceEvidenceCapper.cap(occurrences)), occurrenceCount(occurrences),
                        seenAt);
        assetRepository.recomputeMergeFromSources(assetUuid);
    }

    // A JSON-null array element carries no evidence -- OccurrenceEvidenceCapper#cap filters it out before capping --
    // so counting it here would let occurrence_count overstate what cap() considers an occurrence.
    private static int occurrenceCount(List<Map<String, Object>> occurrences) {
        return occurrences == null ? 0 : (int) occurrences.stream().filter(Objects::nonNull).count();
    }

    /**
     * Removes one CBOM's contribution to one asset and re-elects the asset's merged payload from what is left.
     *
     * <p>
     * An asset left with no sources is retained, with {@code source_count} at zero and its payload cleared, rather than
     * deleted: retention is reversible by a later sweep and deletion is not, and the epic's re-sync semantics have not
     * ratified which one applies.
     *
     * <p>
     * <b>No production caller yet.</b> The delete path in {@code CbomServiceImpl} must call this for every asset a CBOM
     * contributes to before deleting the row, because {@code crypto_asset_source_to_cbom_key} is RESTRICT. That wiring
     * belongs to the ingest ticket, which is also what first makes it reachable: until something writes
     * {@code crypto_asset_source}, every CBOM has zero sources and deletes unimpeded. It is not optional — without it
     * the first CBOM to acquire a source cannot be deleted through the API at all.
     *
     * @return 1 if a source row was removed, 0 if there was none
     */
    @Transactional
    public int detachCbom(UUID assetUuid, UUID cbomUuid) {
        assetRepository.lockForSourceChange(assetUuid);
        int removed = sourceRepository.deleteForAssetAndCbom(assetUuid, cbomUuid);
        assetRepository.recomputeMergeFromSources(assetUuid);
        return removed;
    }
}
