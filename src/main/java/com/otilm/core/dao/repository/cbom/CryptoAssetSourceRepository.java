package com.otilm.core.dao.repository.cbom;

import com.otilm.core.dao.entity.cbom.CryptoAssetSource;
import com.otilm.core.dao.repository.SecurityFilterRepository;
import java.time.OffsetDateTime;
import java.util.List;
import java.util.Optional;
import java.util.UUID;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

/**
 * Queries and guarded writes for the many-to-many link between a cryptographic asset and the CBOMs that report it.
 *
 * <p>
 * Every {@code @Modifying} statement here is called from {@code CryptoAssetSourceWriter} and from nowhere else.
 */
@Repository
public interface CryptoAssetSourceRepository extends SecurityFilterRepository<CryptoAssetSource, UUID> {

    Optional<CryptoAssetSource> findByAssetUuidAndCbomUuid(UUID assetUuid, UUID cbomUuid);

    List<CryptoAssetSource> findByAssetUuidOrderByFirstSeenAt(UUID assetUuid);

    boolean existsByCbomUuid(UUID cbomUuid);

    /**
     * The detail endpoint's source list: every CBOM's contribution with its document header, oldest contribution first,
     * uuid as the deterministic tiebreak. The fetch join loads the read-only {@link CryptoAssetSource#getCbom()}
     * association in the same query, so callers can read header fields without a session.
     */
    @Query("""
            SELECT s FROM CryptoAssetSource s
            JOIN FETCH s.cbom
            WHERE s.assetUuid = :assetUuid
            ORDER BY s.firstSeenAt ASC, s.uuid ASC
            """)
    List<CryptoAssetSource> findWithCbomByAssetUuid(@Param("assetUuid") UUID assetUuid);

    /**
     * The assets a CBOM contributes to -- the work list for detaching that CBOM before its row is deleted, since the
     * foreign key is {@code RESTRICT}.
     */
    @Query("SELECT DISTINCT s.assetUuid FROM CryptoAssetSource s WHERE s.cbomUuid = :cbomUuid ORDER BY s.assetUuid")
    List<UUID> findAssetUuidsByCbomUuid(@Param("cbomUuid") UUID cbomUuid);

    /**
     * Records what one CBOM says about one asset, or refreshes it.
     *
     * <p>
     * <b>Concurrency:</b> atomic on the unique {@code (asset_uuid, cbom_uuid)} -- a re-sync of an unchanged document
     * rewrites the row rather than creating a second one.
     *
     * <p>
     * The seen-at pair is merged with {@code LEAST}/{@code GREATEST} rather than assigned, so the row always holds a
     * real window. Keeping {@code first_seen_at} and overwriting {@code last_seen_at} would look equivalent only while
     * events arrive in order: a retry, a replayed document or two nodes ingesting the same CBOM can present an older
     * {@code seenAt} after a newer one, and a plain assignment would then store a {@code last_seen_at} that precedes
     * {@code first_seen_at}. {@code occurrence_count} is the unclipped count, so the gap against the retained
     * {@code evidence} array records that capping happened.
     *
     * <p>
     * <b>The content follows the newest observation, not the newest arrival.</b> The same out-of-order input the window
     * merge exists for would otherwise leave stale content under a window claiming the newer sync: an arrival carrying
     * an older {@code seenAt} would overwrite the payload, the evidence and the counts, and
     * {@link CryptoAssetRepository#recomputeMergeFromSources} would re-elect on it -- so the row would attest "as of
     * {@code last_seen_at} this CBOM said X" at an instant when it said Y. That is a state that was never true, and the
     * wire calls this payload what the source declared. Every content column is therefore gated on the same recency
     * test, so the ones that must move together -- payload with its hash and leaf count, evidence with its count --
     * cannot come apart. A strictly older arrival widens the window and changes nothing else.
     *
     * <p>
     * The comparison is {@code >=} rather than {@code >} deliberately. If the ingest path ends up deriving
     * {@code seenAt} from the document rather than from the extraction run, every re-ingest is a tie; under {@code >}
     * the content would then freeze forever and a re-extraction under upgraded code could never refresh the row. Under
     * {@code >=} a tie refreshes, which degrades to the previous behaviour rather than to a silent floor.
     */
    @Modifying
    @Query(value = """
            INSERT INTO {h-schema}crypto_asset_source (uuid, asset_uuid, cbom_uuid, original_crypto_properties,
                    properties_leaf_count, properties_hash, evidence, occurrence_count, first_seen_at, last_seen_at)
            VALUES (:uuid, :assetUuid, :cbomUuid, CAST(:properties AS jsonb), :leafCount, :propertiesHash,
                    CAST(:evidence AS jsonb), :occurrenceCount, :seenAt, :seenAt)
            ON CONFLICT (asset_uuid, cbom_uuid) DO UPDATE SET
                original_crypto_properties = CASE
                    WHEN EXCLUDED.last_seen_at >= crypto_asset_source.last_seen_at
                        THEN EXCLUDED.original_crypto_properties
                    ELSE crypto_asset_source.original_crypto_properties END,
                properties_leaf_count = CASE
                    WHEN EXCLUDED.last_seen_at >= crypto_asset_source.last_seen_at
                        THEN EXCLUDED.properties_leaf_count
                    ELSE crypto_asset_source.properties_leaf_count END,
                properties_hash = CASE
                    WHEN EXCLUDED.last_seen_at >= crypto_asset_source.last_seen_at
                        THEN EXCLUDED.properties_hash
                    ELSE crypto_asset_source.properties_hash END,
                evidence = CASE
                    WHEN EXCLUDED.last_seen_at >= crypto_asset_source.last_seen_at
                        THEN EXCLUDED.evidence
                    ELSE crypto_asset_source.evidence END,
                occurrence_count = CASE
                    WHEN EXCLUDED.last_seen_at >= crypto_asset_source.last_seen_at
                        THEN EXCLUDED.occurrence_count
                    ELSE crypto_asset_source.occurrence_count END,
                first_seen_at = LEAST(crypto_asset_source.first_seen_at, EXCLUDED.first_seen_at),
                last_seen_at = GREATEST(crypto_asset_source.last_seen_at, EXCLUDED.last_seen_at)
            """, nativeQuery = true)
    void upsertSource(@Param("uuid") UUID uuid, @Param("assetUuid") UUID assetUuid, @Param("cbomUuid") UUID cbomUuid,
            @Param("properties") String properties, @Param("leafCount") int leafCount,
            @Param("propertiesHash") String propertiesHash, @Param("evidence") String evidence,
            @Param("occurrenceCount") int occurrenceCount, @Param("seenAt") OffsetDateTime seenAt);

    @Modifying
    @Query("DELETE FROM CryptoAssetSource s WHERE s.assetUuid = :assetUuid AND s.cbomUuid = :cbomUuid")
    int deleteForAssetAndCbom(@Param("assetUuid") UUID assetUuid, @Param("cbomUuid") UUID cbomUuid);
}
