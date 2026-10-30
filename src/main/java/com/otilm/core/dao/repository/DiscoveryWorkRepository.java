package com.otilm.core.dao.repository;

import com.otilm.core.dao.entity.DiscoveryWork;
import com.otilm.core.model.discovery.DiscoveryWorkType;
import java.time.OffsetDateTime;
import java.util.List;
import java.util.UUID;
import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

@Repository
public interface DiscoveryWorkRepository extends JpaRepository<DiscoveryWork, UUID> {

    /**
     * Rows due for a tick, soonest first. No row locking: the sweep's cluster-wide advisory lock already serializes
     * access.
     */
    List<DiscoveryWork> findByNextDueAtLessThanEqualOrderByNextDueAt(OffsetDateTime cutoff, Pageable pageable);

    /**
     * Inserts the pending row for a run and work type, or re-arms an existing one.
     */
    @Modifying
    @Query(value = """
            INSERT INTO {h-schema}discovery_work (uuid, discovery_uuid, work_type, attempt, next_due_at)
            VALUES (:uuid, :discoveryUuid, :workType, 0, :nextDueAt)
            ON CONFLICT (discovery_uuid, work_type) DO UPDATE SET next_due_at = EXCLUDED.next_due_at, attempt = 0
            """, nativeQuery = true)
    void schedule(@Param("uuid") UUID uuid, @Param("discoveryUuid") UUID discoveryUuid,
            @Param("workType") String workType, @Param("nextDueAt") OffsetDateTime nextDueAt);

    /**
     * Brings a row forward to {@code nextDueAt} without resetting its attempt counter.
     */
    @Modifying
    @Query(value = """
            INSERT INTO {h-schema}discovery_work (uuid, discovery_uuid, work_type, attempt, next_due_at)
            VALUES (:uuid, :discoveryUuid, :workType, 0, :nextDueAt)
            ON CONFLICT (discovery_uuid, work_type) DO UPDATE SET next_due_at = EXCLUDED.next_due_at
            """, nativeQuery = true)
    void expedite(@Param("uuid") UUID uuid, @Param("discoveryUuid") UUID discoveryUuid,
            @Param("workType") String workType, @Param("nextDueAt") OffsetDateTime nextDueAt);

    @Modifying
    @Query("UPDATE DiscoveryWork w SET w.attempt = :attempt, w.nextDueAt = :nextDueAt "
            + "WHERE w.discoveryUuid = :discoveryUuid AND w.workType = :workType")
    void reschedule(@Param("discoveryUuid") UUID discoveryUuid, @Param("workType") DiscoveryWorkType workType,
            @Param("attempt") int attempt, @Param("nextDueAt") OffsetDateTime nextDueAt);

    /**
     * Lowers an agenda row's attempt counter to {@code attempt} when it is currently above it.
     */
    @Modifying
    @Query("UPDATE DiscoveryWork w SET w.attempt = :attempt "
            + "WHERE w.discoveryUuid = :discoveryUuid AND w.workType = :workType AND w.attempt > :attempt")
    void resetAttemptTo(@Param("discoveryUuid") UUID discoveryUuid, @Param("workType") DiscoveryWorkType workType,
            @Param("attempt") int attempt);

    boolean existsByDiscoveryUuid(UUID discoveryUuid);

    @Modifying
    @Query("DELETE FROM DiscoveryWork w WHERE w.discoveryUuid = :discoveryUuid")
    void deleteByDiscoveryUuid(@Param("discoveryUuid") UUID discoveryUuid);

    /**
     * Drops one kind of pending work, leaving the run's other rows alone.
     */
    @Modifying
    @Query("DELETE FROM DiscoveryWork w WHERE w.discoveryUuid = :discoveryUuid AND w.workType = :workType")
    void deleteByDiscoveryUuidAndWorkType(@Param("discoveryUuid") UUID discoveryUuid,
            @Param("workType") DiscoveryWorkType workType);
}
