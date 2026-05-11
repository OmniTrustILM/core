package com.czertainly.core.dao.repository.signing;

import com.czertainly.core.dao.entity.signing.SigningRecordOutbox;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

import java.time.OffsetDateTime;
import java.util.List;
import java.util.Optional;
import java.util.UUID;

@Repository
public interface SigningRecordOutboxRepository extends JpaRepository<SigningRecordOutbox, UUID> {

    @Query(value = """
            SELECT * FROM signing_record_outbox
            ORDER BY created_at
            FOR UPDATE SKIP LOCKED
            LIMIT :batchSize
            """, nativeQuery = true)
    List<SigningRecordOutbox> claimBatchSkipLocked(@Param("batchSize") int batchSize);

    @Query("SELECT MIN(o.createdAt) FROM SigningRecordOutbox o")
    Optional<OffsetDateTime> findOldestCreatedAt();

    @Modifying
    @Query("UPDATE SigningRecordOutbox o SET o.attempts = o.attempts + 1, o.lastError = :err WHERE o.uuid IN :uuids")
    void recordFailure(@Param("uuids") List<UUID> uuids, @Param("err") String err);
}
