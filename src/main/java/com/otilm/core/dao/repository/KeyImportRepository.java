package com.otilm.core.dao.repository;

import com.otilm.core.dao.entity.KeyImport;
import com.otilm.core.dao.entity.KeyImportState;
import jakarta.persistence.LockModeType;
import java.time.OffsetDateTime;
import java.util.Collection;
import java.util.List;
import java.util.Optional;
import java.util.UUID;
import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Lock;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

@Repository
public interface KeyImportRepository extends JpaRepository<KeyImport, UUID> {

    @Lock(LockModeType.PESSIMISTIC_WRITE)
    @Query("SELECT i FROM KeyImport i WHERE i.uuid = :uuid")
    Optional<KeyImport> findForUpdateByUuid(@Param("uuid") UUID uuid);

    Optional<KeyImport> findFirstByIdempotencyKeyAndStateInOrderByCreatedAtDesc(String idempotencyKey,
            Collection<KeyImportState> states);

    /**
     * The attempts in the given states that are due for a look, the longest waiting first, locked: an attempt a retry
     * is sending again meanwhile is read as the retry leaves it.
     */
    @Lock(LockModeType.PESSIMISTIC_WRITE)
    List<KeyImport> findForUpdateByStateInAndNextCheckAtLessThanEqualOrderByNextCheckAt(
            Collection<KeyImportState> states, OffsetDateTime now, Pageable page);

    /**
     * Deletes the attempts that completed, failed or were compensated before the cutoff, at most {@code limit} of them
     * and the oldest first, in one statement. An attempt another transaction holds, as another node's delete does, is
     * skipped rather than waited for.
     *
     * @return how many attempts were deleted
     */
    @Modifying
    @Query(value = """
            DELETE FROM {h-schema}key_import
            WHERE uuid IN (
                SELECT uuid FROM {h-schema}key_import
                WHERE state IN ('COMPLETED', 'FAILED', 'COMPENSATED') AND updated_at < :cutoff
                ORDER BY updated_at
                LIMIT :limit
                FOR UPDATE SKIP LOCKED)
            """, nativeQuery = true)
    int deleteFinishedBefore(@Param("cutoff") OffsetDateTime cutoff, @Param("limit") int limit);
}
