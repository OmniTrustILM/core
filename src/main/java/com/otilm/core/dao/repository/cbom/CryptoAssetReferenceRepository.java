package com.otilm.core.dao.repository.cbom;

import com.otilm.core.dao.entity.cbom.CryptoAssetReference;
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
 * inside the statement keeps the lookup and the write in one snapshot.
 */
@Repository
public interface CryptoAssetReferenceRepository extends JpaRepository<CryptoAssetReference, UUID> {

    @Modifying
    @Query(value = """
            DELETE FROM {h-schema}crypto_asset_reference r
            USING {h-schema}crypto_asset_source s
            WHERE r.source_uuid = s.uuid AND s.asset_uuid = :assetUuid AND s.cbom_uuid = :cbomUuid
            """, nativeQuery = true)
    int deleteForSource(@Param("assetUuid") UUID assetUuid, @Param("cbomUuid") UUID cbomUuid);

    /** @return 1, or 0 when the source is gone */
    @Modifying
    @Query(value = """
            INSERT INTO {h-schema}crypto_asset_reference (uuid, source_uuid, kind, ordinal, ref, suite, target_asset_uuid)
            SELECT :uuid, s.uuid, :kind, :ordinal, :ref, :suite, :targetAssetUuid
            FROM {h-schema}crypto_asset_source s
            WHERE s.asset_uuid = :assetUuid AND s.cbom_uuid = :cbomUuid
            """,
            nativeQuery = true)
    int insertForSource(@Param("uuid") UUID uuid, @Param("assetUuid") UUID assetUuid, @Param("cbomUuid") UUID cbomUuid,
            @Param("kind") String kind, @Param("ordinal") int ordinal, @Param("ref") String ref,
            @Param("suite") String suite, @Param("targetAssetUuid") UUID targetAssetUuid);
}
