package com.otilm.core.dao.repository;

import com.otilm.api.model.core.auth.Resource;
import com.otilm.core.dao.entity.DiscoveryItem;
import java.time.OffsetDateTime;
import java.util.List;
import java.util.UUID;
import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

/**
 * Staging store for every discovered resource except certificates, which keep their own v1 table.
 */
@Repository
public interface DiscoveryItemRepository extends JpaRepository<DiscoveryItem, UUID> {

    /**
     * Stages one drained item, ignoring a repeat of one already staged for the run.
     *
     * @param payload the item's payload, pre-serialized to JSON text
     * @param meta serialized {@code MetadataAttribute} list, or {@code null}
     */
    // S107: native query binds one parameter per column.
    @SuppressWarnings("java:S107")
    @Modifying
    @Query(value = """
            INSERT INTO {h-schema}discovery_item
                (uuid, discovery_uuid, resource, sequence, unique_ref, payload, discovered_at, newly_discovered, meta)
            VALUES (:uuid, :discoveryUuid, :resource, :sequence, :uniqueRef, CAST(:payload AS jsonb),
                    :discoveredAt, :newlyDiscovered, CAST(:meta AS jsonb))
            ON CONFLICT (discovery_uuid, resource, unique_ref) DO NOTHING
            """, nativeQuery = true)
    void stage(@Param("uuid") UUID uuid, @Param("discoveryUuid") UUID discoveryUuid, @Param("resource") String resource,
            @Param("sequence") long sequence, @Param("uniqueRef") String uniqueRef, @Param("payload") String payload,
            @Param("discoveredAt") OffsetDateTime discoveredAt, @Param("newlyDiscovered") boolean newlyDiscovered,
            @Param("meta") String meta);

    /**
     * One page of everything the run staged, as a union of the two staging stores ({@code DiscoveryDetailCounts} says
     * why there are two). The certificate branch builds its payload at read time, after the limit, so only the page's
     * rows are detoasted.
     *
     * <p>
     * Filters apply inside each branch, and {@code newlyDiscovered} after the certificate numbering, so a row keeps its
     * synthesized number whether or not the caller filtered.
     *
     * <p>
     * {@code processed} and {@code inventoryUuid} on an item row read columns nothing writes until key ingestion lands
     * (core#1965); they are selected so that pipeline needs no change here.
     *
     * <p>
     * {@code i_cre} must be a timestamp for the {@code discovered_at} coalesce to plan; tests build their schema from
     * the entities and cannot catch a regression.
     *
     * @param resource enum member name to restrict to — what both tables store — or null for every resource
     * @param newlyDiscovered tri-state: null means both
     */
    // Aliases on the outer select are quoted: Postgres folds an unquoted one to lower case and the projection binds
    // by exact label. Ordering inside the union is positional -- only the first branch's labels are in scope there --
    // and the outer ORDER BY repeats it by name, since a CTE's ordering need not survive into the query above it.
    @Query(value = """
            WITH page AS (
            SELECT i.uuid AS uuid,
                   i.inventory_uuid AS inventory_uuid,
                   i.sequence AS sequence,
                   i.unique_ref AS unique_ref,
                   i.resource AS resource,
                   i.discovered_at AS discovered_at,
                   i.payload AS staged_payload,
                   NULL::bigint AS content_id,
                   i.newly_discovered AS newly_discovered,
                   (i.processed_at IS NOT NULL) AS processed,
                   i.processed_error AS processed_error,
                   i.meta #>> '{}' AS meta
              FROM {h-schema}discovery_item i
             WHERE i.discovery_uuid = :discoveryUuid
               AND (CAST(:resource AS VARCHAR) IS NULL OR i.resource = CAST(:resource AS VARCHAR))
               AND (CAST(:newlyDiscovered AS BOOLEAN) IS NULL
                    OR i.newly_discovered = CAST(:newlyDiscovered AS BOOLEAN))
            UNION ALL
            SELECT c.uuid, c.inventory_uuid, c.sequence, c.unique_ref, c.resource, c.discovered_at, c.staged_payload,
                   c.content_id, c.newly_discovered, c.processed, c.processed_error, c.meta
              FROM (
                SELECT dc.uuid AS uuid,
                       cert.uuid AS inventory_uuid,
                       COALESCE(dc.sequence,
                                    ROW_NUMBER() OVER (ORDER BY dc.i_cre, dc.uuid)) AS sequence,
                       COALESCE(dc.unique_ref, cc.fingerprint) AS unique_ref,
                       'CERTIFICATE' AS resource,
                       COALESCE(dc.discovered_at, dc.i_cre) AS discovered_at,
                       NULL::jsonb AS staged_payload,
                       dc.certificate_content_id AS content_id,
                       dc.newly_discovered AS newly_discovered,
                       dc.processed AS processed,
                       dc.processed_error AS processed_error,
                       dc.meta #>> '{}' AS meta
                  FROM {h-schema}discovery_certificate dc
                  JOIN {h-schema}certificate_content cc ON cc.id = dc.certificate_content_id
                  LEFT JOIN {h-schema}certificate cert ON cert.certificate_content_id = cc.id
                 WHERE dc.discovery_uuid = :discoveryUuid
                   AND (CAST(:resource AS VARCHAR) IS NULL OR CAST(:resource AS VARCHAR) = 'CERTIFICATE')
              ) c
             WHERE (CAST(:newlyDiscovered AS BOOLEAN) IS NULL
                    OR c.newly_discovered = CAST(:newlyDiscovered AS BOOLEAN))
             ORDER BY 3, 6, 1
             LIMIT :limit OFFSET :offset
            )
            SELECT p.uuid AS "uuid",
                   p.inventory_uuid AS "inventoryUuid",
                   p.sequence AS "sequence",
                   p.unique_ref AS "uniqueRef",
                   p.resource AS "resource",
                   p.discovered_at AS "discoveredAt",
                   COALESCE(p.staged_payload,
                            jsonb_build_object('resource', 'certificates',
                                               'certificateData', cc.content)) #>> '{}' AS "payload",
                   p.newly_discovered AS "newlyDiscovered",
                   p.processed AS "processed",
                   p.processed_error AS "processedError",
                   p.meta AS "meta"
              FROM page p
              LEFT JOIN {h-schema}certificate_content cc ON cc.id = p.content_id
             ORDER BY p.sequence, p.discovered_at, p.uuid
            """, nativeQuery = true)
    List<DiscoveryItemRow> listItems(@Param("discoveryUuid") UUID discoveryUuid, @Param("resource") String resource,
            @Param("newlyDiscovered") Boolean newlyDiscovered, @Param("limit") int limit, @Param("offset") long offset);

    /** Two indexed counts summed — the union itself is never materialized to size a page. */
    @Query(value = """
            SELECT (
                SELECT COUNT(*) FROM {h-schema}discovery_item i
                 WHERE i.discovery_uuid = :discoveryUuid
                   AND (CAST(:resource AS VARCHAR) IS NULL OR i.resource = CAST(:resource AS VARCHAR))
                   AND (CAST(:newlyDiscovered AS BOOLEAN) IS NULL
                        OR i.newly_discovered = CAST(:newlyDiscovered AS BOOLEAN))
            ) + (
                SELECT COUNT(*) FROM {h-schema}discovery_certificate dc
                 WHERE dc.discovery_uuid = :discoveryUuid
                   AND (CAST(:resource AS VARCHAR) IS NULL OR CAST(:resource AS VARCHAR) = 'CERTIFICATE')
                   AND (CAST(:newlyDiscovered AS BOOLEAN) IS NULL
                        OR dc.newly_discovered = CAST(:newlyDiscovered AS BOOLEAN))
            )
            """, nativeQuery = true)
    long countItems(@Param("discoveryUuid") UUID discoveryUuid, @Param("resource") String resource,
            @Param("newlyDiscovered") Boolean newlyDiscovered);

    /** Whether any staged item of this run carries a reason it produced nothing. */
    boolean existsByDiscoveryUuidAndProcessedErrorIsNotNull(UUID discoveryUuid);

    /** One bounded page of key items the import pipeline has not reached yet, oldest first. */
    List<DiscoveryItem> findByDiscoveryUuidAndResourceAndProcessedAtIsNullAndProcessedErrorIsNull(UUID discoveryUuid,
            Resource resource, Pageable pageable);

    /** Stamps the item with the object it became. */
    @Modifying
    @Query(value = """
            UPDATE {h-schema}discovery_item
               SET inventory_uuid = :inventoryUuid, processed_at = :processedAt
             WHERE uuid = :uuid
            """, nativeQuery = true)
    void markImported(@Param("uuid") UUID uuid, @Param("inventoryUuid") UUID inventoryUuid,
            @Param("processedAt") OffsetDateTime processedAt);

    /**
     * Stamps why the item produced nothing. {@code processed_at} is set with it: the item was attempted, and the
     * backlog must not offer it again.
     */
    @Modifying
    @Query(value = """
            UPDATE {h-schema}discovery_item
               SET processed_error = :reason, processed_at = :processedAt
             WHERE uuid = :uuid
            """, nativeQuery = true)
    void markFailed(@Param("uuid") UUID uuid, @Param("reason") String reason,
            @Param("processedAt") OffsetDateTime processedAt);

    /**
     * Key items the import pipeline still owes a verdict. A row carries one either way once it has been through:
     * {@code processed_at} when it became a key, {@code processed_error} when it could not.
     */
    @Query(value = """
            SELECT COUNT(*) FROM {h-schema}discovery_item i
             WHERE i.discovery_uuid = :discoveryUuid
               AND i.resource = 'CRYPTOGRAPHIC_KEY'
               AND i.processed_at IS NULL
               AND i.processed_error IS NULL
            """, nativeQuery = true)
    long countPendingKeys(@Param("discoveryUuid") UUID discoveryUuid);

    /**
     * How many newly discovered items reached the inventory, across both stores. Cleanly imported only: a certificate
     * row carries its reason alongside {@code processed}, so a row stamped with one is an outcome of its own and is
     * counted by {@link #countNewlyDiscoveredFailed} instead.
     *
     * <p>
     * The item branch reads {@code processed_at}, unwritten until key ingestion lands (see {@link #listItems}), so a
     * run staging keys reports none of them imported.
     */
    @Query(value = """
            SELECT (
                SELECT COUNT(*) FROM {h-schema}discovery_item i
                 WHERE i.discovery_uuid = :discoveryUuid
                   AND i.newly_discovered = TRUE
                   AND i.processed_at IS NOT NULL
                   AND i.processed_error IS NULL
            ) + (
                SELECT COUNT(*) FROM {h-schema}discovery_certificate dc
                 WHERE dc.discovery_uuid = :discoveryUuid
                   AND dc.newly_discovered = TRUE
                   AND dc.processed = TRUE
                   AND dc.processed_error IS NULL
            )
            """, nativeQuery = true)
    long countNewlyDiscoveredImported(@Param("discoveryUuid") UUID discoveryUuid);

    /**
     * How many newly discovered items the platform could not import, across both stores. Keyed on the recorded reason
     * rather than on {@code processed}: a row the pipeline never reached carries its reason and nothing else, and it is
     * as finished as one that failed inside it.
     */
    @Query(value = """
            SELECT (
                SELECT COUNT(*) FROM {h-schema}discovery_item i
                 WHERE i.discovery_uuid = :discoveryUuid
                   AND i.newly_discovered = TRUE
                   AND i.processed_error IS NOT NULL
            ) + (
                SELECT COUNT(*) FROM {h-schema}discovery_certificate dc
                 WHERE dc.discovery_uuid = :discoveryUuid
                   AND dc.newly_discovered = TRUE
                   AND dc.processed_error IS NOT NULL
            )
            """, nativeQuery = true)
    long countNewlyDiscoveredFailed(@Param("discoveryUuid") UUID discoveryUuid);
}
