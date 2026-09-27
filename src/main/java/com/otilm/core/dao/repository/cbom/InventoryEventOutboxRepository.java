package com.otilm.core.dao.repository.cbom;

import com.otilm.core.dao.entity.cbom.InventoryEventOutbox;
import java.time.OffsetDateTime;
import java.util.List;
import java.util.UUID;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

@Repository
public interface InventoryEventOutboxRepository extends JpaRepository<InventoryEventOutbox, UUID> {

    @Modifying(clearAutomatically = true, flushAutomatically = true)
    @Query(value = """
            INSERT INTO {h-schema}inventory_event_outbox
                (cbom_uuid, asset_uuids, cbom_synced, assets_ready, revision, created_at)
            VALUES (:cbomUuid, :assetUuids, FALSE, FALSE, 0, CURRENT_TIMESTAMP)
            ON CONFLICT (cbom_uuid) DO UPDATE SET
                asset_uuids = inventory_event_outbox.asset_uuids || EXCLUDED.asset_uuids,
                assets_ready = FALSE,
                revision = inventory_event_outbox.revision + 1
            """, nativeQuery = true)
    void recordAddedAssets(@Param("cbomUuid") UUID cbomUuid, @Param("assetUuids") UUID[] assetUuids);

    @Modifying(clearAutomatically = true, flushAutomatically = true)
    @Query(value = """
            INSERT INTO {h-schema}inventory_event_outbox
                (cbom_uuid, asset_uuids, cbom_synced, assets_ready, cbom_user_uuid, revision, created_at)
            VALUES (:cbomUuid, ARRAY[]::uuid[], TRUE, FALSE, :userUuid, 0, CURRENT_TIMESTAMP)
            ON CONFLICT (cbom_uuid) DO UPDATE SET
                cbom_synced = TRUE,
                cbom_user_uuid = EXCLUDED.cbom_user_uuid,
                revision = inventory_event_outbox.revision + 1
            """, nativeQuery = true)
    void recordCbomSynced(@Param("cbomUuid") UUID cbomUuid, @Param("userUuid") UUID userUuid);

    @Query(value = """
            SELECT o.cbom_uuid FROM {h-schema}inventory_event_outbox o
            LEFT JOIN {h-schema}cbom c ON c.uuid = o.cbom_uuid
            WHERE (o.cbom_synced OR (o.assets_ready AND c.asset_sync_state <> 'IN_PROGRESS')
                OR (c.asset_sync_state = 'FAILED' AND cardinality(o.asset_uuids) > 0)
                OR c.uuid IS NULL)
              AND (o.claimed_until IS NULL OR o.claimed_until < CURRENT_TIMESTAMP)
            ORDER BY o.created_at
            LIMIT :limit
            """, nativeQuery = true)
    List<UUID> findReadyBatch(@Param("limit") int limit);

    @Modifying(clearAutomatically = true, flushAutomatically = true)
    @Query(value = """
            UPDATE {h-schema}inventory_event_outbox
            SET assets_ready = TRUE, revision = revision + 1
            WHERE cbom_uuid = :cbomUuid AND cbom_synced = FALSE AND cardinality(asset_uuids) > 0
            """, nativeQuery = true)
    void markAssetsReady(@Param("cbomUuid") UUID cbomUuid);

    @Modifying(clearAutomatically = true, flushAutomatically = true)
    @Query(value = """
            UPDATE {h-schema}inventory_event_outbox
            SET claimed_until = :leaseUntil
            WHERE cbom_uuid = :cbomUuid
              AND (claimed_until IS NULL OR claimed_until < CURRENT_TIMESTAMP)
            """, nativeQuery = true)
    int claim(@Param("cbomUuid") UUID cbomUuid, @Param("leaseUntil") OffsetDateTime leaseUntil);

    @Modifying(clearAutomatically = true, flushAutomatically = true)
    @Query("DELETE FROM InventoryEventOutbox o WHERE o.cbomUuid = :cbomUuid AND o.revision = :revision "
            + "AND o.claimedUntil = :leaseUntil")
    int deleteIfUnchanged(@Param("cbomUuid") UUID cbomUuid, @Param("revision") long revision,
            @Param("leaseUntil") OffsetDateTime leaseUntil);

    @Modifying(clearAutomatically = true, flushAutomatically = true)
    @Query(value = """
            UPDATE {h-schema}inventory_event_outbox
            SET asset_uuids = asset_uuids[(:sentCount + 1) : cardinality(asset_uuids)],
                assets_ready = assets_ready AND cardinality(asset_uuids) > :sentCount,
                revision = revision + 1
            WHERE cbom_uuid = :cbomUuid AND claimed_until = :leaseUntil AND revision > :revision
            """, nativeQuery = true)
    int acknowledgeSentPrefix(@Param("cbomUuid") UUID cbomUuid, @Param("revision") long revision,
            @Param("leaseUntil") OffsetDateTime leaseUntil, @Param("sentCount") int sentCount);

    @Modifying(clearAutomatically = true, flushAutomatically = true)
    @Query(value = """
            DELETE FROM {h-schema}inventory_event_outbox
            WHERE cbom_uuid = :cbomUuid AND claimed_until = :leaseUntil
              AND cardinality(asset_uuids) = 0 AND cbom_synced = FALSE
            """, nativeQuery = true)
    void deleteEmpty(@Param("cbomUuid") UUID cbomUuid, @Param("leaseUntil") OffsetDateTime leaseUntil);

    @Modifying(clearAutomatically = true, flushAutomatically = true)
    @Query("UPDATE InventoryEventOutbox o SET o.claimedUntil = null WHERE o.cbomUuid = :cbomUuid "
            + "AND o.claimedUntil = :leaseUntil")
    void release(@Param("cbomUuid") UUID cbomUuid, @Param("leaseUntil") OffsetDateTime leaseUntil);
}
