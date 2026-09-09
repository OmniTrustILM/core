package com.otilm.core.dao.repository.cbom;

import com.otilm.core.dao.entity.cbom.CbomSyncSkip;
import com.otilm.core.model.cbom.CbomHeaderCounts;
import com.otilm.core.model.cbom.CbomSyncSkipState;
import java.time.OffsetDateTime;
import java.util.List;
import java.util.Optional;
import java.util.UUID;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

/**
 * Feed entries the header sync could not store, kept for a bounded retry.
 *
 * <p>
 * A plain {@link JpaRepository}: platform bookkeeping, never a listed resource. Writes go through
 * {@code CbomSyncSkipWriter}.
 */
@Repository
public interface CbomSyncSkipRepository extends JpaRepository<CbomSyncSkip, UUID> {

    /**
     * The rows in one state, oldest failure first, {@code uuid} as the tie-break so the order is total. The sync loads
     * the {@code RETRYING} rows only: a written-off row never leaves the table on its own, so loading every row would
     * grow with every document ever written off rather than with the live retry set.
     */
    List<CbomSyncSkip> findAllByStateOrderByFirstSkippedAtAscUuidAsc(CbomSyncSkipState state);

    Optional<CbomSyncSkip> findBySerialNumberAndVersion(String serialNumber, int version);

    /**
     * Counts one more failed attempt for an identity, creating the row on the first failure.
     *
     * <p>
     * <b>Concurrency:</b> two runs failing on the same entry at once both count -- the unique constraint is the
     * arbiter, so neither insert fails. The attempt budget is spent a run early in that case, which is the safe
     * direction. A row already written off stays written off: {@code state} only ever moves to
     * {@code PERMANENTLY_SKIPPED}, when the new attempt count reaches {@code maxAttempts}.
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
}
