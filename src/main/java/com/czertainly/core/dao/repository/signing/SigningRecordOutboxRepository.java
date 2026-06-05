package com.czertainly.core.dao.repository.signing;

import com.czertainly.core.dao.entity.signing.SigningRecordOutbox;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

import java.time.Instant;
import java.util.List;
import java.util.Optional;
import java.util.UUID;

@Repository
public interface SigningRecordOutboxRepository extends JpaRepository<SigningRecordOutbox, UUID> {

    /**
     * Returns the oldest drainable rows (attempts still below the poison threshold), oldest first. No row
     * locking: cross-node mutual exclusion for the drain is provided by a cluster-wide advisory lock held by
     * {@link com.czertainly.core.signing.record.SigningRecordOutboxDrainer}, so a plain ordered read is
     * enough and avoids holding row locks across the per-row drain transactions.
     *
     * <p>Only the {@code uuid} is projected: the drainer re-fetches each row as a managed entity inside its own
     * per-row transaction, so materializing the multi-MB {@code signed_document}/{@code dtbs}/
     * {@code signature_value} BYTEA columns for the whole batch here would be wasted I/O on the hot path.
     */
    @Query(value = """
            SELECT uuid FROM signing_record_outbox
            WHERE attempts < :poisonThreshold
            ORDER BY signing_time
            LIMIT :batchSize
            """, nativeQuery = true)
    List<UUID> findDrainableBatch(@Param("poisonThreshold") int poisonThreshold,
                                  @Param("batchSize") int batchSize);

    @Query("SELECT MIN(o.signingTime) FROM SigningRecordOutbox o WHERE o.attempts < :poisonThreshold")
    Optional<Instant> findOldestSigningTimeBelowPoisonThreshold(@Param("poisonThreshold") int poisonThreshold);

    @Query("SELECT COUNT(o) FROM SigningRecordOutbox o WHERE o.attempts >= :poisonThreshold")
    long countPoisoned(@Param("poisonThreshold") int poisonThreshold);

    @Modifying
    @Query("UPDATE SigningRecordOutbox o SET o.attempts = o.attempts + 1, o.lastError = :err WHERE o.uuid IN :uuids")
    void recordFailure(@Param("uuids") List<UUID> uuids, @Param("err") String err);
}
