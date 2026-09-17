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
 * transaction, so acquiring it early costs a later acquisition nothing. {@code CbomAssetIngestService} is where that
 * wiring lives, and a unit test asserts the order rather than leaving it to an intermittent deadlock.
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
        upsertSource(assetUuid, cbomUuid, cryptoProperties, occurrences, occurrenceCount(occurrences), seenAt);
    }

    /**
     * Records what one CBOM says about one asset when the caller already knows how many occurrences the document
     * reported, which is the shape extraction hands over: {@code CbomAssetExtractor} caps the evidence as it builds an
     * asset, so the list reaching this method is already clipped and its size is no longer what the producer claimed.
     * Deriving the count from it would erase exactly the gap {@code occurrence_count} exists to record.
     *
     * @param reportedOccurrences how many occurrences the CBOM reported, before any capping
     */
    @Transactional
    public void upsertSource(UUID assetUuid, UUID cbomUuid, Map<String, Object> cryptoProperties,
            List<Map<String, Object>> occurrences, int reportedOccurrences, OffsetDateTime seenAt) {
        assetRepository.lockForSourceChange(assetUuid);
        CryptoPropertiesDigest digest = CryptoPropertiesDigest.of(cryptoProperties);
        sourceRepository
                .upsertSource(UUID.randomUUID(), assetUuid, cbomUuid, JsonColumnText.render(cryptoProperties),
                        digest.leafCount(), digest.hash(),
                        JsonColumnText.render(OccurrenceEvidenceCapper.cap(occurrences)), reportedOccurrences, seenAt);
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
     * This method leaves an asset with no sources behind, cleared and counted at zero; it does not decide what happens
     * to it. That decision is the orphan rule, it belongs to the caller that knows why the source went away, and
     * {@code CbomAssetDetachService} is where it lives: the row is deleted unless an alias points at it as its
     * canonical key, in which case it is kept so that the cascade from {@code crypto_asset_alias} does not collect the
     * operator's merge decision along with it.
     *
     * <p>
     * <b>The API's delete path still does not call this.</b> {@code CbomServiceImpl} must withdraw every asset a CBOM
     * contributes to before deleting the row, because {@code crypto_asset_source_to_cbom_key} is RESTRICT; until it
     * does, a CBOM that has acquired a source cannot be deleted through the API at all. Ingest is what writes those
     * rows, so the exposure is live from core#2073 and {@code cbom.sync.asset-ingest-enabled} is what bounds it:
     * turning ingest off stops any further CBOM acquiring sources. The supersede path here is the first caller of this
     * unit of work, not the deletion lifecycle.
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
