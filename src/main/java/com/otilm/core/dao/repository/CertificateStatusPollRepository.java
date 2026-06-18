package com.otilm.core.dao.repository;

import com.otilm.core.dao.entity.CertificateStatusPoll;
import com.otilm.core.messaging.jms.listeners.poll.CertificateStatusPollSweeper;
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
     * cross-node mutual exclusion is provided by the cluster-wide advisory lock held by
     * {@link CertificateStatusPollSweeper}, so a plain ordered read is enough.
     */
    List<CertificateStatusPoll> findByNextPollAtLessThanEqualOrderByNextPollAt(OffsetDateTime cutoff, Pageable pageable);

    boolean existsByCertificateUuid(UUID certificateUuid);

    @Modifying
    @Query("UPDATE CertificateStatusPoll p SET p.attempt = :attempt, p.nextPollAt = :nextPollAt WHERE p.certificateUuid = :certificateUuid")
    void reschedule(@Param("certificateUuid") UUID certificateUuid,
                    @Param("attempt") int attempt,
                    @Param("nextPollAt") OffsetDateTime nextPollAt);

    @Modifying
    @Query("DELETE FROM CertificateStatusPoll p WHERE p.certificateUuid = :certificateUuid")
    void deleteByCertificateUuid(@Param("certificateUuid") UUID certificateUuid);
}
