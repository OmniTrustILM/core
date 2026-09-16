package com.otilm.core.integration.service;

import com.otilm.api.model.core.auth.Resource;
import com.otilm.api.model.scheduler.SchedulerJobExecutionStatus;
import com.otilm.core.dao.entity.ScheduledJob;
import com.otilm.core.dao.entity.ScheduledJobHistory;
import com.otilm.core.dao.repository.ScheduledJobHistoryRepository;
import com.otilm.core.dao.repository.ScheduledJobsRepository;
import com.otilm.core.model.ScheduledTaskResult;
import com.otilm.core.service.writer.scheduler.ScheduledJobHistoryWriter;
import com.otilm.core.tasks.CbomSyncTask;
import com.otilm.core.util.BaseSpringBootTest;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.transaction.PlatformTransactionManager;
import org.springframework.transaction.TransactionDefinition;
import org.springframework.transaction.support.TransactionTemplate;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/** The writer against a real database: each call commits on its own, and a vanished row is reported, not ignored. */
class ScheduledJobHistoryWriterITest extends BaseSpringBootTest {

    @Autowired
    private ScheduledJobHistoryWriter writer;

    @Autowired
    private ScheduledJobsRepository scheduledJobsRepository;

    @Autowired
    private ScheduledJobHistoryRepository scheduledJobHistoryRepository;

    @Autowired
    private PlatformTransactionManager transactionManager;

    private ScheduledJob scheduledJob;

    @BeforeEach
    void setUp() {
        scheduledJob = new ScheduledJob();
        scheduledJob.setJobName(CbomSyncTask.NAME);
        scheduledJob.setJobClassName(CbomSyncTask.class.getName());
        scheduledJob.setCronExpression("0 0 * ? * *");
        scheduledJob.setEnabled(true);
        scheduledJob.setOneTime(false);
        scheduledJob.setSystem(true);
        scheduledJobsRepository.save(scheduledJob);
    }

    @Test
    void recordStarted_isCommittedWhenItReturns() {
        ScheduledJobHistory started = writer.recordStarted(scheduledJob);

        TransactionTemplate otherTransaction = new TransactionTemplate(transactionManager);
        otherTransaction.setPropagationBehavior(TransactionDefinition.PROPAGATION_REQUIRES_NEW);
        Boolean visible = otherTransaction
                .execute(status -> scheduledJobHistoryRepository
                        .existsByScheduledJobUuidAndSchedulerExecutionStatusAndJobEndTimeIsNull(scheduledJob.getUuid(),
                                SchedulerJobExecutionStatus.STARTED));

        assertNotNull(started.getUuid());
        assertEquals(Boolean.TRUE, visible, "a STARTED row must be visible to another transaction at once");
    }

    @Test
    void recordFinished_writesEveryResultColumn() {
        ScheduledJobHistory started = writer.recordStarted(scheduledJob);

        writer
                .recordFinished(started.getUuid(), new ScheduledTaskResult(SchedulerJobExecutionStatus.SUCCESS, "done",
                        Resource.SCHEDULED_JOB, "object-1"));

        ScheduledJobHistory row = scheduledJobHistoryRepository.findById(started.getUuid()).orElseThrow();
        assertEquals(SchedulerJobExecutionStatus.SUCCESS, row.getSchedulerExecutionStatus());
        assertEquals("done", row.getResultMessage());
        assertEquals(Resource.SCHEDULED_JOB, row.getResultObjectType());
        assertEquals("object-1", row.getResultObjectIdentification());
        assertNotNull(row.getJobEndTime());
    }

    @Test
    void recordFailed_closesTheRowWithTheShapedMessage() {
        ScheduledJobHistory started = writer.recordStarted(scheduledJob);

        writer.recordFailed(started.getUuid(), "The job failed unexpectedly; see the Core log");

        ScheduledJobHistory row = scheduledJobHistoryRepository.findById(started.getUuid()).orElseThrow();
        assertEquals(SchedulerJobExecutionStatus.FAILED, row.getSchedulerExecutionStatus());
        assertEquals("The job failed unexpectedly; see the Core log", row.getResultMessage());
        assertNull(row.getResultObjectType());
        assertNotNull(row.getJobEndTime());
    }

    @Test
    void recordUnknownTask_isTerminalWithAnEndTime() {
        ScheduledJobHistory row = writer.recordUnknownTask(scheduledJob, "Unknown scheduled task");

        ScheduledJobHistory stored = scheduledJobHistoryRepository.findById(row.getUuid()).orElseThrow();
        assertEquals(SchedulerJobExecutionStatus.FAILED, stored.getSchedulerExecutionStatus());
        assertNotNull(stored.getJobEndTime(), "a terminal row without an end time reads as a run still in flight");
    }

    @Test
    void removeSkipped_deletesTheRow() {
        ScheduledJobHistory started = writer.recordStarted(scheduledJob);

        writer.removeSkipped(started.getUuid());

        assertFalse(scheduledJobHistoryRepository.existsByScheduledJobUuid(scheduledJob.getUuid()));
    }

    @Test
    void aVanishedRow_isReportedByEveryFinalizer() {
        ScheduledJobHistory started = writer.recordStarted(scheduledJob);
        scheduledJobHistoryRepository.deleteById(started.getUuid());
        ScheduledTaskResult result = new ScheduledTaskResult(SchedulerJobExecutionStatus.SUCCESS, "done");

        assertThrows(IllegalStateException.class, () -> writer.recordFinished(started.getUuid(), result));
        assertThrows(IllegalStateException.class, () -> writer.recordFailed(started.getUuid(), "failed"));
        assertThrows(IllegalStateException.class, () -> writer.removeSkipped(started.getUuid()));
        assertTrue(scheduledJobHistoryRepository.findById(started.getUuid()).isEmpty());
    }
}
