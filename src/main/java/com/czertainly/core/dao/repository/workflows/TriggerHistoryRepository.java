package com.czertainly.core.dao.repository.workflows;


import com.czertainly.api.model.core.auth.Resource;
import com.czertainly.core.dao.entity.workflows.TriggerHistory;
import com.czertainly.core.dao.repository.SecurityFilterRepository;
import org.springframework.data.jpa.repository.EntityGraph;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;

import java.util.List;
import java.util.UUID;

@Repository
public interface TriggerHistoryRepository extends SecurityFilterRepository<TriggerHistory, UUID> {

    @EntityGraph(attributePaths = {"records"})
    List<TriggerHistory> findAllByTriggerUuidAndTriggerAssociationObjectUuid(UUID triggerUuid, UUID triggerAssociationObjectUuid);

    @EntityGraph(attributePaths = {"records"})
    List<TriggerHistory> findByTriggerAssociationObjectUuidOrderByTriggerUuidAscTriggeredAtAsc(UUID triggerAssociationObjectUuid);

    @Modifying
    @Query("UPDATE TriggerHistory t SET t.triggerAssociationUuid = NULL WHERE t.triggerAssociationUuid = :uuid")
    int removeTriggerAssociation(@Param("uuid") UUID uuid);

    @EntityGraph(attributePaths = {"records", "triggerAssociation", "records.execution", "records.execution.items", "records.execution.items.notificationProfile"})
    Page<TriggerHistory> findByObjectUuidAndObjectResourceOrderByTriggeredAtDesc(UUID objectUuid, Resource objectResource, Pageable pageable);

    /**
     * Returns one row per event history with three counts in a single GROUP BY query,
     * replacing three separate per-row count queries when mapping a page of EventHistory records.
     * Each row is [eventHistoryUuid, objectsEvaluated, objectsMatched, objectsIgnored].
     */
    @Query(value = """
            SELECT t.event_history_uuid,
                   COUNT(DISTINCT t.object_uuid),
                   COUNT(DISTINCT CASE WHEN t.conditions_matched THEN t.object_uuid END),
                   COUNT(DISTINCT CASE WHEN t.conditions_matched AND tr.ignore_trigger THEN t.object_uuid END)
            FROM trigger_history t
            LEFT JOIN trigger tr ON t.trigger_uuid = tr.uuid
            WHERE t.event_history_uuid IN :uuids
            GROUP BY t.event_history_uuid
            """, nativeQuery = true)
    List<Object[]> countStatsByEventHistoryUuids(@Param("uuids") List<UUID> uuids);

    /**
     * Returns paginated (event_history_uuid, object_uuid) pairs for a batch of event histories
     * in a single window-function query, replacing one paginated query per event history row.
     * Offset is zero-based; limit is the page size.
     */
    @Query(value = """
            SELECT event_history_uuid, object_uuid
            FROM (
                SELECT event_history_uuid, object_uuid,
                    ROW_NUMBER() OVER (PARTITION BY event_history_uuid ORDER BY object_uuid) AS rn
                FROM (
                    SELECT DISTINCT event_history_uuid, object_uuid
                    FROM trigger_history
                    WHERE event_history_uuid IN :uuids
                ) distinct_pairs
            ) ranked
            WHERE rn > :offset AND rn <= :offset + :limit
            """, nativeQuery = true)
    List<Object[]> findPaginatedObjectUuidsByEventHistoryUuids(
            @Param("uuids") List<UUID> uuids,
            @Param("offset") int offset,
            @Param("limit") int limit);

    /**
     * Fetches all trigger histories for a set of event histories filtered to specific object UUIDs,
     * replacing one query per event history row. Results are grouped in Java by eventHistoryUuid → objectUuid.
     */
    @EntityGraph(attributePaths = {"records", "triggerAssociation", "records.execution", "records.execution.items", "records.execution.items.notificationProfile"})
    List<TriggerHistory> findByEventHistoryUuidInAndObjectUuidInOrderByEventHistoryUuidAscObjectUuidAscTriggeredAtDesc(
            List<UUID> eventHistoryUuids, List<UUID> objectUuids);

}
