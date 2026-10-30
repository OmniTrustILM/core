package com.otilm.core.dao.repository.cbom;

import com.otilm.core.dao.entity.cbom.CbomIngestFinding;
import java.time.OffsetDateTime;
import java.util.List;
import java.util.UUID;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

/**
 * What an asset ingest had to report about one CBOM.
 *
 * <p>
 * A plain {@link JpaRepository}: a finding is read through the CBOM it belongs to, which is the resource the security
 * filter already answers for.
 */
@Repository
public interface CbomIngestFindingRepository extends JpaRepository<CbomIngestFinding, UUID> {

    List<CbomIngestFinding> findAllByCbomUuidOrderByKindAscDetailAsc(UUID cbomUuid);

    /**
     * Records one rolled-up line of the report.
     *
     * <p>
     * Upsert on {@code (cbom_uuid, kind, detail)}, so redoing a unit a crash left half-written converges on the same
     * rows rather than reporting the same finding twice. The count is replaced rather than added to: a redone ingest
     * read the whole document again, so its count is the whole count.
     */
    @Modifying(flushAutomatically = true)
    @Query(value = """
            INSERT INTO {h-schema}cbom_ingest_finding
                (uuid, cbom_uuid, kind, component_name, detail, occurrences, recorded_at)
            VALUES (:uuid, :cbomUuid, :kind, :componentName, :detail, :occurrences, :recordedAt)
            ON CONFLICT ON CONSTRAINT uq_cbom_ingest_finding DO UPDATE
               SET component_name = EXCLUDED.component_name,
                   occurrences    = EXCLUDED.occurrences,
                   recorded_at    = EXCLUDED.recorded_at
            """, nativeQuery = true)
    void recordFinding(@Param("uuid") UUID uuid, @Param("cbomUuid") UUID cbomUuid, @Param("kind") String kind,
            @Param("componentName") String componentName, @Param("detail") String detail,
            @Param("occurrences") int occurrences, @Param("recordedAt") OffsetDateTime recordedAt);

    /**
     * Drops the previous run's report for this CBOM.
     *
     * <p>
     * The upsert above cannot do it: a re-ingest that no longer raises a finding leaves the old row standing otherwise,
     * and the operator reads a complaint the current document does not make.
     */
    @Modifying(flushAutomatically = true)
    @Query(value = "DELETE FROM {h-schema}cbom_ingest_finding WHERE cbom_uuid = :cbomUuid", nativeQuery = true)
    int deleteForCbom(@Param("cbomUuid") UUID cbomUuid);
}
