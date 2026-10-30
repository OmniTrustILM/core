package com.otilm.core.integration.service;

import com.otilm.api.model.scheduler.SchedulerJobExecutionStatus;
import com.otilm.core.dao.entity.ScheduledJob;
import com.otilm.core.dao.entity.ScheduledJobHistory;
import com.otilm.core.dao.repository.ScheduledJobHistoryRepository;
import com.otilm.core.dao.repository.ScheduledJobsRepository;
import com.otilm.core.events.transaction.ScheduledJobFinishedEvent;
import com.otilm.core.model.ScheduledTaskResult;
import com.otilm.core.service.writer.scheduler.ScheduledJobHistoryWriter;
import com.otilm.core.tasks.ScheduledJobInfo;
import com.otilm.core.util.BaseSpringBootTest;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.ApplicationEventPublisher;
import org.springframework.transaction.PlatformTransactionManager;
import org.springframework.transaction.support.TransactionTemplate;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;

/**
 * The asynchronous finish, end to end: a task that returned {@code null} leaves its STARTED row, and the
 * {@code ScheduledJobFinishedEvent} published from inside another transaction closes it once that transaction commits.
 * This is the path the event handler's {@code NOT_SUPPORTED} exists for -- with the publishing transaction still
 * registered in the {@code AFTER_COMMIT} phase, a write that joined it would be lost and the row would stay STARTED.
 */
class ScheduledJobFinishedEventITest extends BaseSpringBootTest {

    @Autowired
    private ScheduledJobHistoryWriter writer;

    @Autowired
    private ScheduledJobsRepository scheduledJobsRepository;

    @Autowired
    private ScheduledJobHistoryRepository scheduledJobHistoryRepository;

    @Autowired
    private ApplicationEventPublisher eventPublisher;

    @Autowired
    private PlatformTransactionManager transactionManager;

    @Test
    void anEventPublishedInsideATransactionClosesTheRowAfterThatTransactionCommits() {
        ScheduledJob job = new ScheduledJob();
        job.setJobName("AsyncFinishingJob");
        job.setJobClassName("com.otilm.core.tasks.DiscoveryCertificateTask");
        job.setCronExpression("0 0 * ? * *");
        job.setEnabled(true);
        job.setOneTime(false);
        job.setSystem(true);
        scheduledJobsRepository.save(job);
        ScheduledJobHistory started = writer.recordStarted(job);
        ScheduledJobFinishedEvent event = new ScheduledJobFinishedEvent(
                new ScheduledJobInfo(job.getJobName(), job.getUuid(), started.getUuid()),
                new ScheduledTaskResult(SchedulerJobExecutionStatus.SUCCESS, "closed by the event"));

        new TransactionTemplate(transactionManager).executeWithoutResult(status -> eventPublisher.publishEvent(event));

        ScheduledJobHistory row = scheduledJobHistoryRepository.findById(started.getUuid()).orElseThrow();
        assertEquals(SchedulerJobExecutionStatus.SUCCESS, row.getSchedulerExecutionStatus());
        assertEquals("closed by the event", row.getResultMessage());
        assertNotNull(row.getJobEndTime());
    }
}
