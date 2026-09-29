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
     * run was being skipped shows as 0, where a detached-entity save would write nothing and say nothing.
     */
    @Modifying(clearAutomatically = true, flushAutomatically = true)
    @Query("UPDATE ScheduledJob j SET j.lastSkippedAt = :at, j.lastSkipReason = :reason WHERE j.uuid = :uuid")
    int recordSkip(@Param("uuid") UUID uuid, @Param("at") OffsetDateTime at, @Param("reason") String reason);
}
