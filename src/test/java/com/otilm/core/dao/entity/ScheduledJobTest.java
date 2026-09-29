package com.otilm.core.dao.entity;

import com.otilm.api.model.core.scheduler.ScheduledJobDetailDto;
import com.otilm.api.model.core.scheduler.ScheduledJobDto;
import com.otilm.api.model.core.scheduler.ScheduledJobScheduleState;
import com.otilm.api.model.scheduler.SchedulerJobExecutionStatus;
import com.otilm.core.model.scheduler.ObservedSchedule;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.Date;
import java.util.UUID;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;

/**
 * The DTO is the operator's only view of the job; each of its three sources -- scheduler, history, the job row --
 * lands.
 */
class ScheduledJobTest {

    private static final Instant NEXT = Instant.parse("2026-09-29T12:30:00Z");
    private static final Instant PREVIOUS = Instant.parse("2026-09-29T11:30:00Z");
    private static final Instant STARTED = Instant.parse("2026-09-29T10:30:00Z");
    private static final Instant SKIPPED = Instant.parse("2026-09-29T11:30:00Z");
    private static final ObservedSchedule LIVE = new ObservedSchedule(ScheduledJobScheduleState.SCHEDULED, NEXT,
            PREVIOUS);

    @Test
    void mapToDto_carriesTheObservedSchedule() {
        ScheduledJobDto dto = anHourlyJob().mapToDto(null, LIVE);

        assertEquals(ScheduledJobScheduleState.SCHEDULED, dto.getScheduleState());
        assertEquals(NEXT, dto.getNextFireTime());
        assertEquals(PREVIOUS, dto.getPreviousFireTime());
    }

    @Test
    void mapToDto_carriesAnUnreadSchedulerAsUnknownWithoutFireTimes() {
        ScheduledJobDto dto = anHourlyJob().mapToDto(null, ObservedSchedule.UNKNOWN);

        assertEquals(ScheduledJobScheduleState.UNKNOWN, dto.getScheduleState());
        assertNull(dto.getNextFireTime());
        assertNull(dto.getPreviousFireTime());
    }

    @Test
    void mapToDto_carriesTheLastDeclinedRun() {
        ScheduledJob job = anHourlyJob();
        job.setLastSkippedAt(SKIPPED.atOffset(ZoneOffset.UTC));
        job.setLastSkipReason("No stale cryptographic asset to re-evaluate");

        ScheduledJobDto dto = job.mapToDto(null, LIVE);

        assertEquals(SKIPPED, dto.getLastSkippedAt());
        assertEquals("No stale cryptographic asset to re-evaluate", dto.getLastSkipReason());
    }

    @Test
    void mapToDto_carriesTheLastRunFromTheHistory() {
        ScheduledJobDto dto = anHourlyJob().mapToDto(aRun(SchedulerJobExecutionStatus.FAILED, STARTED), LIVE);

        assertEquals(SchedulerJobExecutionStatus.FAILED, dto.getLastExecutionStatus());
        assertEquals(STARTED, dto.getLastExecutionStartTime());
    }

    @Test
    void mapToDto_leavesTheLastRunAbsentWithoutHistory() {
        ScheduledJobDto dto = anHourlyJob().mapToDto(null, LIVE);

        assertNull(dto.getLastExecutionStatus());
        assertNull(dto.getLastExecutionStartTime());
        assertNull(dto.getLastSkippedAt());
        assertNull(dto.getLastSkipReason());
    }

    @Test
    void mapToDetailDto_carriesTheSameFieldsAndTheUser() {
        ScheduledJob job = anHourlyJob();
        UUID user = UUID.randomUUID();
        job.setUserUuid(user);
        job.setLastSkippedAt(SKIPPED.atOffset(ZoneOffset.UTC));
        job.setLastSkipReason("Nothing past the retention window");

        ScheduledJobDetailDto dto = job.mapToDetailDto(aRun(SchedulerJobExecutionStatus.SUCCESS, STARTED), LIVE);

        assertEquals(user, dto.getUserUuid());
        assertEquals("CryptoAssetPqcSweepTask", dto.getJobType());
        assertEquals(ScheduledJobScheduleState.SCHEDULED, dto.getScheduleState());
        assertEquals(NEXT, dto.getNextFireTime());
        assertEquals(STARTED, dto.getLastExecutionStartTime());
        assertEquals(SKIPPED, dto.getLastSkippedAt());
        assertEquals("Nothing past the retention window", dto.getLastSkipReason());
    }

    private static ScheduledJob anHourlyJob() {
        ScheduledJob job = new ScheduledJob();
        job.setUuid(UUID.randomUUID());
        job.setJobName("hourly-job");
        job.setJobClassName("com.otilm.core.tasks.CryptoAssetPqcSweepTask");
        job.setCronExpression("0 30 * ? * *");
        job.setEnabled(true);
        return job;
    }

    private static ScheduledJobHistory aRun(SchedulerJobExecutionStatus status, Instant startedAt) {
        ScheduledJobHistory history = new ScheduledJobHistory();
        history.setSchedulerExecutionStatus(status);
        history.setJobExecution(Date.from(startedAt));
        return history;
    }
}
