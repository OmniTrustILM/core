package com.otilm.core.dao.entity;

import com.otilm.api.model.core.scheduler.ScheduledJobDetailDto;
import com.otilm.api.model.core.scheduler.ScheduledJobDto;
import com.otilm.api.model.scheduler.SchedulerJobExecutionStatus;
import java.time.Instant;
import java.util.UUID;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

class ScheduledJobTest {

    @Test
    void mapToDto_carriesTheNextFireTime_forAnEnabledJob() {
        // given
        Instant before = Instant.now();
        ScheduledJob job = anHourlyJob();

        // when
        ScheduledJobDto dto = job.mapToDto(null);

        // then
        assertNotNull(dto.getNextFireTime());
        assertTrue(dto.getNextFireTime().isAfter(before));
    }

    @Test
    void mapToDetailDto_carriesTheNextFireTime_forAnEnabledJob() {
        // given
        Instant before = Instant.now();
        ScheduledJob job = anHourlyJob();

        // when
        ScheduledJobDetailDto dto = job.mapToDetailDto(null);

        // then
        assertNotNull(dto.getNextFireTime());
        assertTrue(dto.getNextFireTime().isAfter(before));
    }

    @Test
    void mapping_carriesNoNextFireTime_forADisabledJob() {
        // given
        ScheduledJob job = anHourlyJob();
        job.setEnabled(false);

        // then
        assertNull(job.mapToDto(null).getNextFireTime());
        assertNull(job.mapToDetailDto(null).getNextFireTime());
    }

    @Test
    void mapping_carriesNoNextFireTime_forAOneTimeJobThatHasSucceeded() {
        // given a one-time job whose trigger the scheduler has already dropped
        ScheduledJob job = anHourlyJob();
        job.setOneTime(true);
        ScheduledJobHistory lastRun = aRunWith(SchedulerJobExecutionStatus.SUCCESS);

        // then
        assertNull(job.mapToDto(lastRun).getNextFireTime());
        assertNull(job.mapToDetailDto(lastRun).getNextFireTime());
    }

    @Test
    void mapping_keepsTheNextFireTime_forAOneTimeJobWhoseLastRunFailed() {
        // given: the trigger is only removed on SUCCESS; after a failure it is still registered and fires again
        ScheduledJob job = anHourlyJob();
        job.setOneTime(true);

        // then
        assertNotNull(job.mapToDto(aRunWith(SchedulerJobExecutionStatus.FAILED)).getNextFireTime());
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

    private static ScheduledJobHistory aRunWith(SchedulerJobExecutionStatus status) {
        ScheduledJobHistory history = new ScheduledJobHistory();
        history.setSchedulerExecutionStatus(status);
        return history;
    }
}
