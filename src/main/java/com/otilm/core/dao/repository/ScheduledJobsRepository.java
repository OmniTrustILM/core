package com.otilm.core.dao.repository;

import com.otilm.core.dao.entity.ScheduledJob;
import java.time.OffsetDateTime;
import java.util.Optional;
import java.util.UUID;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

@Repository
public interface ScheduledJobsRepository extends SecurityFilterRepository<ScheduledJob, UUID> {
    Optional<ScheduledJob> findByJobName(String jobName);

    /**
     * Records a declined run on the job in one statement, in place. The row count is the point: a job deleted while its
     * run was being skipped shows as 0, where a detached-entity save would write nothing and say nothing. A skip older
     * than the stored one still counts the row but changes neither field, so skips recorded out of order never replace
     * a newer one; both conditions read the row as it was before the statement.
     */
    @Modifying(clearAutomatically = true, flushAutomatically = true)
    @Query("""
            UPDATE ScheduledJob j SET
                j.lastSkippedAt = CASE WHEN j.lastSkippedAt IS NULL OR j.lastSkippedAt <= :at
                    THEN :at ELSE j.lastSkippedAt END,
                j.lastSkipReason = CASE WHEN j.lastSkippedAt IS NULL OR j.lastSkippedAt <= :at
                    THEN :reason ELSE j.lastSkipReason END
            WHERE j.uuid = :uuid
            """)
    int recordSkip(@Param("uuid") UUID uuid, @Param("at") OffsetDateTime at, @Param("reason") String reason);
}
