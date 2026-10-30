package com.otilm.core.dao.repository.cbom;

import com.otilm.core.dao.entity.cbom.CbomTombstone;
import java.time.OffsetDateTime;
import java.util.UUID;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

/**
 * Deleted CBOMs, remembered.
 *
 * <p>
 * A plain {@link JpaRepository}: a tombstone is platform bookkeeping, never a listed resource.
 */
@Repository
public interface CbomTombstoneRepository extends JpaRepository<CbomTombstone, UUID> {

    boolean existsBySerialNumberAndVersion(String serialNumber, int version);

    /**
     * Records that a CBOM was deleted.
     *
     * <p>
     * <b>Concurrency:</b> {@code DO NOTHING} with no arbiter, so <em>every</em> constraint on this table makes the
     * insert a no-op rather than a violation. Naming {@code (uuid)} covered only a retried deletion of the same row; it
     * left the other case failing. A CBOM can be deleted, uploaded again under a new uuid with the same serial number
     * and version -- {@code createCbom} looks only at the live table, so that is legal -- and deleted again, and the
     * second tombstone then collides with {@code uq_cbom_tombstone_serial_version}. Because this writer is REQUIRED,
     * that violation rolled back the deletion that was calling it, leaving the re-created CBOM undeletable through the
     * API until someone removed the old tombstone by hand.
     *
     * <p>
     * Either way the first record of a deletion is the true one and a second attempt has nothing to add, so swallowing
     * both conflicts says what is meant. The table carries only those two constraints, so there is no third conflict
     * being hidden.
     */
    @Modifying
    @Query(value = """
            INSERT INTO {h-schema}cbom_tombstone (uuid, serial_number, version, deleted_at, deleted_by)
            VALUES (:uuid, :serialNumber, :version, :deletedAt, :deletedBy)
            ON CONFLICT DO NOTHING
            """, nativeQuery = true)
    void recordTombstone(@Param("uuid") UUID uuid, @Param("serialNumber") String serialNumber,
            @Param("version") int version, @Param("deletedAt") OffsetDateTime deletedAt,
            @Param("deletedBy") String deletedBy);
}
