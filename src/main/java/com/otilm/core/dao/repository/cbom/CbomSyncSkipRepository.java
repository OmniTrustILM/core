package com.otilm.core.dao.repository.cbom;

import com.otilm.api.model.core.cbom.CbomSyncSkipState;
import com.otilm.core.dao.entity.cbom.CbomSyncSkip;
import com.otilm.core.model.cbom.CbomHeaderCounts;
import java.time.OffsetDateTime;
import java.util.List;
import java.util.Optional;
import java.util.UUID;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.JpaSpecificationExecutor;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

/**
 * Feed entries the header sync could not store, kept for a bounded retry.
 *
 * <p>
 * A plain {@link JpaRepository} with {@link JpaSpecificationExecutor} for the operator list: the rows are platform
 * bookkeeping listed under the CBOM inventory's own permissions, never a secured resource of their own, so there is no
 * security filter to apply. Writes go through {@code CbomSyncSkipWriter} and, for the retention sweep's batches,
 * {@code CbomSyncSkipRetentionWriter}.
 */
@Repository
public interface CbomSyncSkipRepository
        extends
            JpaRepository<CbomSyncSkip, UUID>,
            JpaSpecificationExecutor<CbomSyncSkip> {

    /**
     * The rows in one state, oldest failure first, {@code uuid} as the tie-break so the order is total. The sync loads
     * the {@code RETRYING} rows only: a written-off row leaves the table only through the retention sweep or an
     * operator's retry, so loading every row would grow with the retention window rather than with the live retry set.
     */
    List<CbomSyncSkip> findAllByStateOrderByFirstSkippedAtAscUuidAsc(CbomSyncSkipState state);

    Optional<CbomSyncSkip> findBySerialNumberAndVersion(String serialNumber, int version);

    /**
     * Counts one more failed attempt for an identity, creating the row on the first failure.
     *
     * <p>
     * <b>Concurrency:</b> two runs failing on the same entry at once both count -- the unique constraint is the
     * arbiter, so neither insert fails. The attempt budget is spent a run early in that case, which is the safe
     * direction. A row already written off stays written off here: this statement only ever moves {@code state} to
     * {@code PERMANENTLY_SKIPPED}, when the new attempt count reaches {@code maxAttempts}; {@link #requestRetry} is the
     * one way back.
     */
    @Modifying(clearAutomatically = true, flushAutomatically = true)
    @Query(value = """
            INSERT INTO {h-schema}cbom_sync_skip (uuid, serial_number, version, reason, attempts, first_skipped_at,
                last_attempt_at, state, algorithms_count, certificates_count, protocols_count, crypto_material_count,
                total_assets_count)
            VALUES (:uuid, :serialNumber, :version, :reason, 1, :now, :now,
                CASE WHEN 1 >= :maxAttempts THEN 'PERMANENTLY_SKIPPED' ELSE 'RETRYING' END,
                :#{#counts.algorithms()}, :#{#counts.certificates()}, :#{#counts.protocols()},
                :#{#counts.cryptoMaterial()}, :#{#counts.totalAssets()})
            ON CONFLICT (serial_number, version) DO UPDATE SET
                reason = EXCLUDED.reason,
                attempts = cbom_sync_skip.attempts + 1,
                last_attempt_at = EXCLUDED.last_attempt_at,
                state = CASE WHEN cbom_sync_skip.attempts + 1 >= :maxAttempts THEN 'PERMANENTLY_SKIPPED'
                             ELSE cbom_sync_skip.state END,
                algorithms_count = EXCLUDED.algorithms_count,
                certificates_count = EXCLUDED.certificates_count,
                protocols_count = EXCLUDED.protocols_count,
                crypto_material_count = EXCLUDED.crypto_material_count,
                total_assets_count = EXCLUDED.total_assets_count
            """, nativeQuery = true)
    void upsertAttempt(@Param("uuid") UUID uuid, @Param("serialNumber") String serialNumber,
            @Param("version") int version, @Param("reason") String reason, @Param("now") OffsetDateTime now,
            @Param("maxAttempts") int maxAttempts, @Param("counts") CbomHeaderCounts counts);

    @Modifying(clearAutomatically = true, flushAutomatically = true)
    @Query("DELETE FROM CbomSyncSkip s WHERE s.serialNumber = :serialNumber AND s.version = :version")
    int deleteBySerialNumberAndVersion(@Param("serialNumber") String serialNumber, @Param("version") int version);

    /**
     * An operator's retry: a written-off row goes back to retrying with its attempts reset, so the next run tries it
     * with a full budget. A row already retrying is left alone. Returns the number of rows changed, so the caller can
     * tell a no-op from a reset.
     */
    @Modifying(clearAutomatically = true, flushAutomatically = true)
    @Query("""
            UPDATE CbomSyncSkip s SET s.state = :retrying, s.attempts = 0
            WHERE s.uuid = :uuid AND s.state = :writtenOff
            """)
    int requestRetry(@Param("uuid") UUID uuid, @Param("retrying") CbomSyncSkipState retrying,
            @Param("writtenOff") CbomSyncSkipState writtenOff);

    /**
     * One batch of the retention sweep: the oldest written-off rows whose last attempt lies before the cutoff, at most
     * {@code limit} of them. Native, because JPQL has no {@code LIMIT} on a delete; the subquery orders by
     * {@code last_attempt_at}, then {@code uuid} for a total order, so each batch takes the oldest rows the index on
     * {@code (state, last_attempt_at)} finds first.
     */
    @Modifying(clearAutomatically = true, flushAutomatically = true)
    @Query(value = """
            DELETE FROM {h-schema}cbom_sync_skip
            WHERE uuid IN (
                SELECT uuid FROM {h-schema}cbom_sync_skip
                WHERE state = 'PERMANENTLY_SKIPPED' AND last_attempt_at < :cutoff
                ORDER BY last_attempt_at, uuid
                LIMIT :limit)
            """, nativeQuery = true)
    int deleteWrittenOffBefore(@Param("cutoff") OffsetDateTime cutoff, @Param("limit") int limit);
}
