package com.otilm.core.dao.repository;

import com.otilm.api.model.core.auth.Resource;
import com.otilm.api.model.scheduler.SchedulerJobExecutionStatus;
import com.otilm.core.dao.entity.ScheduledJobHistory;
import java.util.Date;
import java.util.Optional;
import java.util.UUID;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

@Repository
public interface ScheduledJobHistoryRepository extends SecurityFilterRepository<ScheduledJobHistory, UUID> {
    ScheduledJobHistory findTopByScheduledJobUuidOrderByJobExecutionDesc(UUID scheduledJobUuid);

    boolean existsByScheduledJobUuid(UUID scheduledJobUuid);

    boolean existsByScheduledJobUuidAndSchedulerExecutionStatusAndJobEndTimeIsNull(UUID scheduledJobUuid,
            SchedulerJobExecutionStatus schedulerExecutionStatus);

    Optional<ScheduledJobHistory> findFirstByScheduledJobJobNameAndSchedulerExecutionStatusOrderByJobExecutionDesc(
            String jobName, SchedulerJobExecutionStatus status);

    /**
     * Closes a run in one statement. The row count is the point: a row that vanished (the job was deleted, cascading
     * its history) shows as 0, where a detached-entity save would write nothing and say nothing.
     */
    @Modifying(clearAutomatically = true, flushAutomatically = true)
    @Query("""
            UPDATE ScheduledJobHistory h
               SET h.jobEndTime = :endTime,
                   h.schedulerExecutionStatus = :status,
                   h.resultMessage = :message,
                   h.resultObjectType = :objectType,
                   h.resultObjectIdentification = :objectIdentification
             WHERE h.uuid = :uuid
            """)
    int closeRun(@Param("uuid") UUID uuid, @Param("endTime") Date endTime,
            @Param("status") SchedulerJobExecutionStatus status, @Param("message") String message,
            @Param("objectType") Resource objectType, @Param("objectIdentification") String objectIdentification);

    /** Removes a run's row in one statement; 0 when it is already gone. */
    @Modifying(clearAutomatically = true, flushAutomatically = true)
    @Query("DELETE FROM ScheduledJobHistory h WHERE h.uuid = :uuid")
    int removeRun(@Param("uuid") UUID uuid);
}
