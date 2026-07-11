package com.otilm.core.dao.repository;

import com.otilm.core.dao.entity.CertificateStatusPoll;
import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

import java.time.OffsetDateTime;
import java.util.List;
import java.util.UUID;

@Repository
public interface CertificateStatusPollRepository extends JpaRepository<CertificateStatusPoll, UUID> {

    /**
     * Returns rows due for polling ({@code next_poll_at} reached), soonest-due first. No row locking:
     * cross-node mutual exclusion is provided by the cluster-wide advisory lock held by the status-poll
     * sweep, so a plain ordered read is enough.
     */
    List<CertificateStatusPoll> findByNextPollAtLessThanEqualOrderByNextPollAt(OffsetDateTime cutoff, Pageable pageable);

    /**
     * Inserts a new in-flight poll, or does nothing if one already exists for the certificate. Atomic on the
     * unique {@code certificate_uuid} — unlike an exists-check-then-insert, a concurrent loser is a clean no-op
     * (no constraint violation, no aborted transaction).
     */
    @Modifying
    @Query(value = """
            INSERT INTO {h-schema}certificate_status_poll (uuid, certificate_uuid, operation, attempt, next_poll_at)
            VALUES (:uuid, :certificateUuid, :operation, 0, :nextPollAt)
            ON CONFLICT (certificate_uuid) DO NOTHING
            """, nativeQuery = true)
    void scheduleIfAbsent(@Param("uuid") UUID uuid,
                          @Param("certificateUuid") UUID certificateUuid,
                          @Param("operation") String operation,
                          @Param("nextPollAt") OffsetDateTime nextPollAt);

    @Modifying
    @Query("UPDATE CertificateStatusPoll p SET p.attempt = :attempt, p.nextPollAt = :nextPollAt WHERE p.certificateUuid = :certificateUuid")
    void reschedule(@Param("certificateUuid") UUID certificateUuid,
                    @Param("attempt") int attempt,
                    @Param("nextPollAt") OffsetDateTime nextPollAt);

    /**
     * Lowers a poll row's attempt counter to {@code attempt} when it is currently above it.
     */
    @Modifying
    @Query("UPDATE CertificateStatusPoll p SET p.attempt = :attempt WHERE p.certificateUuid = :certificateUuid AND p.attempt > :attempt")
    void resetAttemptTo(@Param("certificateUuid") UUID certificateUuid, @Param("attempt") int attempt);

    @Modifying
    @Query("DELETE FROM CertificateStatusPoll p WHERE p.certificateUuid = :certificateUuid")
    void deleteByCertificateUuid(@Param("certificateUuid") UUID certificateUuid);
}
