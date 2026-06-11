package com.otilm.core.dao.repository.signing;

import com.otilm.core.dao.entity.signing.SigningRecordOutbox;
import com.otilm.core.signing.record.SigningRecordOutboxDrainer;
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
     * {@link SigningRecordOutboxDrainer}, so a plain ordered read is
     * enough and avoids holding row locks across the per-row drain transactions.
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

    /**
     * Deletes the outbox row by its UUID with a bare {@code DELETE … WHERE uuid = ?}. Unlike the inherited
     * {@code delete(entity)} / {@code deleteById(...)} — which load the row first and, for a detached entity,
     * re-SELECT its multi-MB {@code signed_document}/{@code dtbs}/{@code signature_value} BYTEA columns to merge
     * it into the persistence context before removal — this issues no SELECT, so the drain never reads those
     * blobs a second time just to delete the row it already copied.
     */
    @Modifying
    @Query("DELETE FROM SigningRecordOutbox o WHERE o.uuid = :uuid")
    void deleteByUuid(@Param("uuid") UUID uuid);
}
