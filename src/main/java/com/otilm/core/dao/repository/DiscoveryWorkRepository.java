package com.otilm.core.dao.repository;

import com.otilm.core.dao.entity.DiscoveryWork;
import com.otilm.core.model.discovery.DiscoveryWorkType;
import java.time.OffsetDateTime;
import java.util.List;
import java.util.Optional;
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
     * Rows due for a tick that no tick holds, soonest first: never leased, or leased by a tick whose lease has run out.
     * No row locking: the advisory lock serializes sweeps, and {@link #claim} checks each row again.
     */
    @Query("SELECT w FROM DiscoveryWork w WHERE w.nextDueAt <= :dueCutoff "
            + "AND (w.leaseToken IS NULL OR w.leaseExpiresAt <= :now) ORDER BY w.nextDueAt")
    List<DiscoveryWork> findClaimable(@Param("dueCutoff") OffsetDateTime dueCutoff, @Param("now") OffsetDateTime now,
            Pageable pageable);

    /**
     * Leases a row to a new tick: a fresh token, the attempt it is charged at, and a due time no earlier than the
     * lease's end, so the row comes due again only once the lease could have run out. The row must still be due and
     * free when the update runs: a tick admitted after the sweep read it keeps it.
     *
     * @return 1 when the row was claimed, 0 when it is no longer due or a live lease now holds it
     */
    @Modifying
    @Query("UPDATE DiscoveryWork w SET w.leaseToken = :leaseToken, w.leaseExpiresAt = :leasedUntil, "
            + "w.attempt = :attempt, w.nextDueAt = :leasedUntil "
            + "WHERE w.discoveryUuid = :discoveryUuid AND w.workType = :workType AND w.nextDueAt <= :dueCutoff "
            + "AND (w.leaseToken IS NULL OR w.leaseExpiresAt <= :now)")
    int claim(@Param("discoveryUuid") UUID discoveryUuid, @Param("workType") DiscoveryWorkType workType,
            @Param("leaseToken") UUID leaseToken, @Param("attempt") int attempt,
            @Param("dueCutoff") OffsetDateTime dueCutoff, @Param("now") OffsetDateTime now,
            @Param("leasedUntil") OffsetDateTime leasedUntil);

    /**
     * Passes the lease from the message carrying {@code leaseToken} to the tick it admits, under {@code tickToken}, and
     * extends it. A second copy of the same message then finds its token gone.
     *
     * @return 1 while the row still held {@code leaseToken}, 0 once a copy, a reclaim, a lifecycle change or the row's
     * deletion took it
     */
    @Modifying
    @Query("UPDATE DiscoveryWork w SET w.leaseToken = :tickToken, w.leaseExpiresAt = :leasedUntil "
            + "WHERE w.discoveryUuid = :discoveryUuid AND w.workType = :workType AND w.leaseToken = :leaseToken")
    int swapLease(@Param("discoveryUuid") UUID discoveryUuid, @Param("workType") DiscoveryWorkType workType,
            @Param("leaseToken") UUID leaseToken, @Param("tickToken") UUID tickToken,
            @Param("leasedUntil") OffsetDateTime leasedUntil);

    /**
     * Extends the lease of the tick holding {@code leaseToken}.
     *
     * @return 1 while the row still holds the token, 0 once a reclaim, a lifecycle change or the row's deletion took it
     */
    @Modifying
    @Query("UPDATE DiscoveryWork w SET w.leaseExpiresAt = :leasedUntil "
            + "WHERE w.discoveryUuid = :discoveryUuid AND w.workType = :workType AND w.leaseToken = :leaseToken")
    int renewLease(@Param("discoveryUuid") UUID discoveryUuid, @Param("workType") DiscoveryWorkType workType,
            @Param("leaseToken") UUID leaseToken, @Param("leasedUntil") OffsetDateTime leasedUntil);

    /**
     * Leases a row no tick holds to {@code leaseToken}, leaving its schedule alone.
     *
     * @return 1 when the row was free and is now leased, 0 when a live lease holds it or the row is gone
     */
    @Modifying
    @Query("UPDATE DiscoveryWork w SET w.leaseToken = :leaseToken, w.leaseExpiresAt = :leasedUntil "
            + "WHERE w.discoveryUuid = :discoveryUuid AND w.workType = :workType "
            + "AND (w.leaseToken IS NULL OR w.leaseExpiresAt <= :now)")
    int leaseIfFree(@Param("discoveryUuid") UUID discoveryUuid, @Param("workType") DiscoveryWorkType workType,
            @Param("leaseToken") UUID leaseToken, @Param("leasedUntil") OffsetDateTime leasedUntil,
            @Param("now") OffsetDateTime now);

    /**
     * Schedules the row's next tick and frees it, if the tick holding {@code leaseToken} still holds it.
     */
    @Modifying
    @Query("UPDATE DiscoveryWork w SET w.attempt = :attempt, w.nextDueAt = :nextDueAt, w.leaseToken = NULL, "
            + "w.leaseExpiresAt = NULL "
            + "WHERE w.discoveryUuid = :discoveryUuid AND w.workType = :workType AND w.leaseToken = :leaseToken")
    int rescheduleLeased(@Param("discoveryUuid") UUID discoveryUuid, @Param("workType") DiscoveryWorkType workType,
            @Param("leaseToken") UUID leaseToken, @Param("attempt") int attempt,
            @Param("nextDueAt") OffsetDateTime nextDueAt);

    /**
     * Schedules the row's next tick at {@code attempt} and frees it, if the tick holding {@code leaseToken} still holds
     * it, and starts the row's busy clock at {@code now} unless it is already running.
     */
    @Modifying
    @Query("UPDATE DiscoveryWork w SET w.attempt = :attempt, w.nextDueAt = :nextDueAt, w.leaseToken = NULL, "
            + "w.leaseExpiresAt = NULL, w.busySince = COALESCE(w.busySince, :now) "
            + "WHERE w.discoveryUuid = :discoveryUuid AND w.workType = :workType AND w.leaseToken = :leaseToken")
    int deferBusyLeased(@Param("discoveryUuid") UUID discoveryUuid, @Param("workType") DiscoveryWorkType workType,
            @Param("leaseToken") UUID leaseToken, @Param("attempt") int attempt,
            @Param("nextDueAt") OffsetDateTime nextDueAt, @Param("now") OffsetDateTime now);

    /** Stops the row's busy clock: its connector answered. */
    @Modifying
    @Query("UPDATE DiscoveryWork w SET w.busySince = NULL "
            + "WHERE w.discoveryUuid = :discoveryUuid AND w.workType = :workType AND w.busySince IS NOT NULL")
    int clearBusySince(@Param("discoveryUuid") UUID discoveryUuid, @Param("workType") DiscoveryWorkType workType);

    @Query("SELECT w.busySince FROM DiscoveryWork w WHERE w.discoveryUuid = :discoveryUuid AND w.workType = :workType")
    Optional<OffsetDateTime> findBusySince(@Param("discoveryUuid") UUID discoveryUuid,
            @Param("workType") DiscoveryWorkType workType);

    /**
     * Frees the row, if the tick holding {@code leaseToken} still holds it, and makes it due no later than {@code now}:
     * while a tick holds the row, its due time is only the claim's fallback for the lease.
     */
    @Modifying
    @Query("UPDATE DiscoveryWork w SET w.leaseToken = NULL, w.leaseExpiresAt = NULL, "
            + "w.nextDueAt = CASE WHEN w.nextDueAt > :now THEN :now ELSE w.nextDueAt END "
            + "WHERE w.discoveryUuid = :discoveryUuid AND w.workType = :workType AND w.leaseToken = :leaseToken")
    int releaseLease(@Param("discoveryUuid") UUID discoveryUuid, @Param("workType") DiscoveryWorkType workType,
            @Param("leaseToken") UUID leaseToken, @Param("now") OffsetDateTime now);

    /**
     * Passes the row from the tick holding {@code leaseToken} straight to its continuation under {@code nextToken}: a
     * fresh budget, and due again only once the continuation's lease could have run out.
     */
    @Modifying
    @Query("UPDATE DiscoveryWork w SET w.leaseToken = :nextToken, w.leaseExpiresAt = :leasedUntil, w.attempt = 0, "
            + "w.nextDueAt = :leasedUntil "
            + "WHERE w.discoveryUuid = :discoveryUuid AND w.workType = :workType AND w.leaseToken = :leaseToken")
    int handOverLease(@Param("discoveryUuid") UUID discoveryUuid, @Param("workType") DiscoveryWorkType workType,
            @Param("leaseToken") UUID leaseToken, @Param("nextToken") UUID nextToken,
            @Param("leasedUntil") OffsetDateTime leasedUntil);

    /**
     * Inserts the pending row for a run and work type, or re-arms an existing one, already leased to the tick about to
     * be published for it: a fresh budget, and due again only once that tick's lease could have run out.
     */
    @Modifying
    @Query(value = """
            INSERT INTO {h-schema}discovery_work
                (uuid, discovery_uuid, work_type, attempt, next_due_at, lease_token, lease_expires_at)
            VALUES (:uuid, :discoveryUuid, :workType, 0, :leasedUntil, :leaseToken, :leasedUntil)
            ON CONFLICT (discovery_uuid, work_type) DO UPDATE SET attempt = 0, next_due_at = EXCLUDED.next_due_at,
                lease_token = EXCLUDED.lease_token, lease_expires_at = EXCLUDED.lease_expires_at
            """, nativeQuery = true)
    void scheduleLeased(@Param("uuid") UUID uuid, @Param("discoveryUuid") UUID discoveryUuid,
            @Param("workType") String workType, @Param("leaseToken") UUID leaseToken,
            @Param("leasedUntil") OffsetDateTime leasedUntil);

    /**
     * Inserts the pending row for a run and work type, or re-arms an existing one. Re-arming frees the row: a tick
     * still holding it worked the run as it was before, and its writes must not land.
     */
    @Modifying
    @Query(value = """
            INSERT INTO {h-schema}discovery_work (uuid, discovery_uuid, work_type, attempt, next_due_at)
            VALUES (:uuid, :discoveryUuid, :workType, 0, :nextDueAt)
            ON CONFLICT (discovery_uuid, work_type) DO UPDATE SET next_due_at = EXCLUDED.next_due_at, attempt = 0,
                lease_token = NULL, lease_expires_at = NULL
            """, nativeQuery = true)
    void schedule(@Param("uuid") UUID uuid, @Param("discoveryUuid") UUID discoveryUuid,
            @Param("workType") String workType, @Param("nextDueAt") OffsetDateTime nextDueAt);

    /**
     * Brings a row forward to {@code nextDueAt} without resetting its attempt counter, and frees it, so the next sweep
     * claims it even while a tick from before the change still holds it.
     */
    @Modifying
    @Query(value = """
            INSERT INTO {h-schema}discovery_work (uuid, discovery_uuid, work_type, attempt, next_due_at)
            VALUES (:uuid, :discoveryUuid, :workType, 0, :nextDueAt)
            ON CONFLICT (discovery_uuid, work_type) DO UPDATE SET next_due_at = EXCLUDED.next_due_at,
                lease_token = NULL, lease_expires_at = NULL
            """, nativeQuery = true)
    void expedite(@Param("uuid") UUID uuid, @Param("discoveryUuid") UUID discoveryUuid,
            @Param("workType") String workType, @Param("nextDueAt") OffsetDateTime nextDueAt);

    @Modifying
    @Query("UPDATE DiscoveryWork w SET w.attempt = :attempt, w.nextDueAt = :nextDueAt "
            + "WHERE w.discoveryUuid = :discoveryUuid AND w.workType = :workType")
    void reschedule(@Param("discoveryUuid") UUID discoveryUuid, @Param("workType") DiscoveryWorkType workType,
            @Param("attempt") int attempt, @Param("nextDueAt") OffsetDateTime nextDueAt);

    /**
     * Lowers an agenda row's attempt counter to {@code attempt} when it is currently above it, and frees the row.
     */
    @Modifying
    @Query("UPDATE DiscoveryWork w SET w.attempt = CASE WHEN w.attempt > :attempt THEN :attempt ELSE w.attempt END, "
            + "w.leaseToken = NULL, w.leaseExpiresAt = NULL "
            + "WHERE w.discoveryUuid = :discoveryUuid AND w.workType = :workType")
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
