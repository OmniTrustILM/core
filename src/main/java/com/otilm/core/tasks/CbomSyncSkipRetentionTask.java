package com.otilm.core.tasks;

import com.otilm.api.model.core.auth.Resource;
import com.otilm.api.model.scheduler.SchedulerJobExecutionStatus;
import com.otilm.core.api.ScheduledJobSkippedException;
import com.otilm.core.cbom.sync.CbomSyncPolicy;
import com.otilm.core.cbom.sync.CbomSyncSkipRetentionSweeper;
import com.otilm.core.model.ScheduledTaskResult;
import lombok.NoArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

/**
 * The retention sweep's schedule, and nothing else: daily, at a quiet hour, after the hourly sync at :00.
 *
 * <p>
 * A system {@code ScheduledJobTask} rather than {@code @Scheduled}, as {@code CryptoAssetPqcSweepTask} is: under SaaS
 * an operator cannot touch yml, and registered here enable and disable work through the Scheduler API while the cron
 * stays fixed. The retention itself is read from the platform settings at the start of each run.
 *
 * <p>
 * Not {@code @Transactional}: {@code SchedulerListener} runs a job with no transaction, and
 * {@code CbomSyncSkipRetentionSweeper.sweep()} opens its own ({@code REQUIRES_NEW}).
 */
@Slf4j
@Component
@NoArgsConstructor
public class CbomSyncSkipRetentionTask implements ScheduledJobTask {

    public static final String NAME = "CbomSyncSkipRetentionTask";

    /** Daily at 03:15, clear of the hourly sync at :00, the PQC sweep at :30 and the Sunday reconcile at 02:30. */
    private static final String CRON_EXPRESSION = "0 15 3 ? * *";

    private CbomSyncSkipRetentionSweeper sweeper;

    @Autowired
    public void setSweeper(CbomSyncSkipRetentionSweeper sweeper) {
        this.sweeper = sweeper;
    }

    @Override
    public String getDefaultJobName() {
        return NAME;
    }

    @Override
    public String getDefaultCronExpression() {
        return CRON_EXPRESSION;
    }

    @Override
    public boolean isDefaultOneTimeJob() {
        return false;
    }

    @Override
    public boolean isSystemJob() {
        return true;
    }

    /**
     * A run that removed nothing is a skip, as for the PQC sweep: a SUCCESS row a day saying so would bury the runs
     * that did something. The catch names the failure with fixed text, because a message here reaches the scheduler
     * API.
     */
    @Override
    public ScheduledTaskResult performJob(final ScheduledJobInfo scheduledJobInfo, final Object taskData) {
        final int retentionDays;
        final CbomSyncSkipRetentionSweeper.SweepOutcome outcome;
        try {
            retentionDays = CbomSyncPolicy.fromSettingsCache().skipRetentionDays();
            outcome = sweeper.sweep(retentionDays);
        } catch (RuntimeException e) {
            log.error("CBOM sync skip retention sweep failed before it could report its outcome", e);
            return new ScheduledTaskResult(SchedulerJobExecutionStatus.FAILED,
                    "The sweep failed before it could report its outcome; see the application log", Resource.CBOM,
                    null);
        }
        if (!outcome.ran() || (outcome.deleted() == 0 && !outcome.aborted())) {
            throw new ScheduledJobSkippedException();
        }
        String message = "Removed %d record(s) of documents the sync gave up on more than %d day(s) ago, in %d batch(es)"
                .formatted(outcome.deleted(), retentionDays, outcome.batches());
        if (outcome.aborted()) {
            return new ScheduledTaskResult(SchedulerJobExecutionStatus.FAILED,
                    "The sweep stopped before completing. " + message, Resource.CBOM, null);
        }
        if (outcome.capped()) {
            message += "; stopped at the per-run cap, anything left goes on the next run";
        }
        return new ScheduledTaskResult(SchedulerJobExecutionStatus.SUCCESS, message, Resource.CBOM, null);
    }
}
