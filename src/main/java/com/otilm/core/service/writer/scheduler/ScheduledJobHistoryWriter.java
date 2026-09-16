package com.otilm.core.service.writer.scheduler;

import com.otilm.api.model.scheduler.SchedulerJobExecutionStatus;
import com.otilm.core.dao.entity.ScheduledJob;
import com.otilm.core.dao.entity.ScheduledJobHistory;
import com.otilm.core.dao.repository.ScheduledJobHistoryRepository;
import com.otilm.core.model.ScheduledTaskResult;
import java.util.Date;
import java.util.UUID;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

/**
 * Short transactional writes to {@code scheduled_job_history}, so a job's bookkeeping never shares a transaction with
 * the job.
 *
 * <p>
 * Every method is {@code REQUIRED} (Rule D of {@code TransactionalBoundaryArchTest}) and relies on its two callers
 * running with no transaction: {@code SchedulerServiceImpl.runScheduledJob} and {@code handleScheduledJobFinishedEvent}
 * are both {@code NOT_SUPPORTED}, the latter because it runs in the {@code AFTER_COMMIT} phase of the publishing
 * transaction, which is committed but still registered -- a write that joined it would be lost. Each call therefore
 * starts and commits a transaction of its own, which is what makes STARTED visible while the job runs and a run's final
 * status durable before any external call reports it.
 *
 * <p>
 * Each close is one {@code @Modifying} statement, as the writer convention asks, and its row count is what tells a
 * vanished row apart: the three finalizers all name the row {@link #recordStarted} committed moments earlier on the
 * same thread, so a missing row means the same thing to each of them.
 */
@Service
public class ScheduledJobHistoryWriter {

    private final ScheduledJobHistoryRepository repository;

    public ScheduledJobHistoryWriter(ScheduledJobHistoryRepository repository) {
        this.repository = repository;
    }

    /** The run has started; the row is visible to every other transaction the moment this returns. */
    @Transactional
    public ScheduledJobHistory recordStarted(ScheduledJob job) {
        return repository.save(newRow(job, SchedulerJobExecutionStatus.STARTED, null));
    }

    /**
     * A run that could not start because its task class is unknown: one FAILED row, no STARTED before it, already ended
     * -- a terminal row without an end time would read as a run still in flight.
     */
    @Transactional
    public ScheduledJobHistory recordUnknownTask(ScheduledJob job, String message) {
        ScheduledJobHistory row = newRow(job, SchedulerJobExecutionStatus.FAILED, message);
        row.setJobEndTime(row.getJobExecution());
        return repository.save(row);
    }

    /** The task returned a result: closes the row with it. */
    @Transactional
    public void recordFinished(UUID historyUuid, ScheduledTaskResult result) {
        close(historyUuid, result);
    }

    /**
     * The task threw: closes the row as FAILED, so it never stays STARTED forever.
     *
     * @param operatorSafeMessage text the caller shaped; it reaches the scheduler API, so never a raw exception message
     */
    @Transactional
    public void recordFailed(UUID historyUuid, String operatorSafeMessage) {
        close(historyUuid, new ScheduledTaskResult(SchedulerJobExecutionStatus.FAILED, operatorSafeMessage));
    }

    /** The task declined the run ({@code ScheduledJobSkippedException}): a skipped run leaves no history. */
    @Transactional
    public void removeSkipped(UUID historyUuid) {
        if (repository.removeRun(historyUuid) == 0) {
            throw vanished(historyUuid);
        }
    }

    private void close(UUID historyUuid, ScheduledTaskResult result) {
        int closed = repository
                .closeRun(historyUuid, new Date(), result.getStatus(), result.getResultMessage(),
                        result.getResultObjectType(), result.getResultObjectIdentification());
        if (closed == 0) {
            throw vanished(historyUuid);
        }
    }

    private static IllegalStateException vanished(UUID historyUuid) {
        return new IllegalStateException(
                "scheduled_job_history row " + historyUuid + " vanished before its run was finalized");
    }

    private static ScheduledJobHistory newRow(ScheduledJob job, SchedulerJobExecutionStatus status, String message) {
        ScheduledJobHistory row = new ScheduledJobHistory();
        row.setScheduledJobUuid(job.getUuid());
        row.setJobExecution(new Date());
        row.setSchedulerExecutionStatus(status);
        row.setResultMessage(message);
        return row;
    }
}
