package com.otilm.core.integration.dao.repository;

import com.otilm.api.model.scheduler.SchedulerJobExecutionStatus;
import com.otilm.core.dao.entity.ScheduledJob;
import com.otilm.core.dao.entity.ScheduledJobHistory;
import com.otilm.core.dao.repository.ScheduledJobHistoryRepository;
import com.otilm.core.dao.repository.ScheduledJobsRepository;
import com.otilm.core.tasks.CbomSyncTask;
import com.otilm.core.util.BaseSpringBootTest;
import java.time.Instant;
import java.util.Date;
import java.util.Optional;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;

import static org.assertj.core.api.Assertions.assertThat;

class ScheduledJobHistoryRepositoryITest extends BaseSpringBootTest {

    @Autowired
    private ScheduledJobsRepository scheduledJobsRepository;

    @Autowired
    private ScheduledJobHistoryRepository historyRepository;

    @Test
    void findsLatestSuccessOfTheJob_whenCurrentExecutionIsExcluded() {
        // given
        var job = createJob("nightly-discovery");
        var otherJob = createJob("other-discovery");
        createRun(job, SchedulerJobExecutionStatus.SUCCESS, "2026-11-18T09:00:00Z");
        var latestSuccess = createRun(job, SchedulerJobExecutionStatus.SUCCESS, "2026-11-18T10:00:00Z");
        createRun(job, SchedulerJobExecutionStatus.FAILED, "2026-11-18T11:00:00Z");
        createRun(otherJob, SchedulerJobExecutionStatus.SUCCESS, "2026-11-18T11:30:00Z");
        var currentRun = createRun(job, SchedulerJobExecutionStatus.SUCCESS, "2026-11-18T12:00:00Z");

        // when
        Optional<ScheduledJobHistory> found = historyRepository
                .findFirstByScheduledJobUuidAndSchedulerExecutionStatusAndUuidNotOrderByJobExecutionDesc(job.getUuid(),
                        SchedulerJobExecutionStatus.SUCCESS, currentRun.getUuid());

        // then
        assertThat(found).map(ScheduledJobHistory::getUuid).contains(latestSuccess.getUuid());
    }

    // ── Helpers ───────────────────────────────────────────────────────────────

    private ScheduledJob createJob(String jobName) {
        var job = new ScheduledJob();
        job.setJobName(jobName);
        job.setJobClassName(CbomSyncTask.class.getName());
        job.setCronExpression("0 0 * ? * *");
        job.setEnabled(true);
        job.setOneTime(false);
        job.setSystem(true);
        return scheduledJobsRepository.save(job);
    }

    private ScheduledJobHistory createRun(ScheduledJob job, SchedulerJobExecutionStatus status, String startedAt) {
        var run = new ScheduledJobHistory();
        run.setScheduledJobUuid(job.getUuid());
        run.setSchedulerExecutionStatus(status);
        run.setJobExecution(Date.from(Instant.parse(startedAt)));
        return historyRepository.save(run);
    }
}
