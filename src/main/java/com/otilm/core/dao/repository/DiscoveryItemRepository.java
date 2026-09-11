package com.otilm.core.dao.repository;

import com.otilm.core.dao.entity.DiscoveryItem;
import java.time.OffsetDateTime;
import java.util.List;
import java.util.UUID;
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
     * One page of everything the run staged, certificates included. The two stores are unioned rather than merged:
     * certificate bytes stay deduplicated in {@code certificate_content}, so the certificate branch builds its payload
     * at read time — after the limit, for the page's rows only. Built inside the union it would sit in a windowed
     * subquery's target list, detoasting every certificate in the run on every request.
     *
     * <p>
     * The resource filter is applied inside each branch, so a single-resource query reads one table. The
     * {@code newlyDiscovered} filter is applied to the certificate branch <i>after</i> its numbering, so a row keeps
     * the same synthesized number whether or not the caller filtered.
     *
     * <p>
     * A staged item's {@code processed} and {@code inventoryUuid} read columns nothing writes yet: only certificates
     * have an import pipeline, so an item row answers {@code false} and {@code null} until key ingestion lands
     * (core#1965). They are selected here so that pipeline needs no change to this query.
     *
     * <p>
     * {@code i_cre} must be a timestamp for the {@code discovered_at} coalesce to plan. It is the one audited column
     * declared {@code VARCHAR}, and a regression is invisible to tests, which build their schema from the entities.
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
}
