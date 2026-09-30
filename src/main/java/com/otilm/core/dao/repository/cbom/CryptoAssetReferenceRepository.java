package com.otilm.core.dao.repository.cbom;

import com.otilm.core.dao.entity.cbom.CryptoAssetReference;
import jakarta.persistence.Tuple;
import java.time.OffsetDateTime;
import java.util.Collection;
import java.util.List;
import java.util.UUID;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

/**
 * The references an asset's sources recorded. Every {@code @Modifying} statement here is called from
 * {@code CryptoAssetReferenceWriter} and from nowhere else.
 *
 * <p>
 * The source is addressed by its {@code (asset_uuid, cbom_uuid)} arbiter, which is what the ingest holds; resolving it
 * inside the statement keeps the lookup and the write in one snapshot. Both writes also require the source to hold this
 * observation's payload: {@code upsertSource} keeps the newer one, and references from an older replay would describe a
 * different revision than the payload beside them.
 */
@Repository
public interface CryptoAssetReferenceRepository extends JpaRepository<CryptoAssetReference, UUID> {

    @Modifying
    @Query(value = """
            DELETE FROM {h-schema}crypto_asset_reference r
            USING {h-schema}crypto_asset_source s
            WHERE r.source_uuid = s.uuid AND s.asset_uuid = :assetUuid AND s.cbom_uuid = :cbomUuid
              AND s.last_seen_at = :seenAt
            """, nativeQuery = true)
    int deleteForSource(@Param("assetUuid") UUID assetUuid, @Param("cbomUuid") UUID cbomUuid,
            @Param("seenAt") OffsetDateTime seenAt);

    /** @return 1, or 0 when the source is gone */
    @Modifying
    @Query(value = """
            INSERT INTO {h-schema}crypto_asset_reference (uuid, source_uuid, kind, ordinal, ref, suite, target_asset_uuid)
            SELECT :uuid, s.uuid, :kind, :ordinal, :ref, :suite, :targetAssetUuid
            FROM {h-schema}crypto_asset_source s
            WHERE s.asset_uuid = :assetUuid AND s.cbom_uuid = :cbomUuid AND s.last_seen_at = :seenAt
            """,
            nativeQuery = true)
    int insertForSource(@Param("uuid") UUID uuid, @Param("assetUuid") UUID assetUuid, @Param("cbomUuid") UUID cbomUuid,
            @Param("seenAt") OffsetDateTime seenAt, @Param("kind") String kind, @Param("ordinal") int ordinal,
            @Param("ref") String ref, @Param("suite") String suite, @Param("targetAssetUuid") UUID targetAssetUuid);

    /**
     * The references of each asset's elected source -- the one whose payload the merge adopted, so the references and
     * the payload the rules read describe the same component -- with each target's stored verdict.
     */
    @Query(value = """
            SELECT a.uuid AS asset_uuid, r.kind, r.ref, r.suite, r.target_asset_uuid,
                   t.asset_type AS target_type, t.pqc_verdict AS target_verdict, t.pqc_rule_id AS target_rule_id,
                   t.primitive AS target_primitive
            FROM {h-schema}crypto_asset a
            JOIN {h-schema}crypto_asset_reference r ON r.source_uuid = a.properties_source_uuid
            LEFT JOIN {h-schema}crypto_asset t ON t.uuid = r.target_asset_uuid
            WHERE a.uuid IN :uuids
            ORDER BY a.uuid, r.kind, r.ordinal
            """, nativeQuery = true)
    List<Tuple> findElectedReferences(@Param("uuids") Collection<UUID> uuids);
}
