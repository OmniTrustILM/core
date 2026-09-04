package com.otilm.core.tasks;

import com.otilm.api.model.core.auth.Resource;
import com.otilm.api.model.scheduler.SchedulerJobExecutionStatus;
import com.otilm.core.api.ScheduledJobSkippedException;
import com.otilm.core.cbom.pqc.PqcVerdictSweeper;
import com.otilm.core.model.ScheduledTaskResult;
import lombok.NoArgsConstructor;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

/**
 * The re-evaluation sweep's schedule, and nothing else.
 *
 * <p>
 * <b>A system {@code ScheduledJobTask} rather than a {@code @Scheduled} class, and the difference is a customer's.</b>
 * Every cluster-locked sweep shipped so far uses {@code @Scheduled}, which is simpler and reaches nobody: under SaaS an
 * operator cannot touch yml, so a {@code @Scheduled} sweep can never be paused. Registered here it is reachable through
 * the Scheduler API -- {@code SchedulerServiceImpl.changeScheduledJobState} carries no {@code isSystem} guard, so
 * enable and disable work on a system job, while {@code updateScheduledJob} refuses to let its cron be edited. That is
 * the shape wanted: pause and resume yes, re-tune the cadence no, since "which rows are due" is a shipped constant
 * rather than a preference. The cost of the route is that it needs the external scheduler service, which is not a new
 * dependency -- {@code SystemScheduledJobs.registerJobs} already calls it for {@code CbomSyncTask}, and without ingest
 * there is no inventory to sweep.
 *
 * <p>
 * <b>Deliberately not {@code @Transactional}.</b> {@code SchedulerListener} is already class-level transactional, so
 * the sweeper's own {@code REQUIRES_NEW} is the second transaction in the chain and a third here would hold a
 * connection idle for the whole run for no reason. All orchestration lives in {@link PqcVerdictSweeper}, which is what
 * lets it be tested without standing up the scheduling machinery.
 */
@Component
@NoArgsConstructor
public class CryptoAssetPqcSweepTask implements ScheduledJobTask {

    public static final String NAME = "CryptoAssetPqcSweepTask";

    /** Hourly, on the half hour -- offset from {@code CbomSyncTask}'s top of the hour so the two do not contend. */
    private static final String CRON_EXPRESSION = "0 30 * ? * *";

    private PqcVerdictSweeper sweeper;

    @Autowired
    public void setSweeper(PqcVerdictSweeper sweeper) {
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
    public String getJobClassName() {
        return this.getClass().getName();
    }

    @Override
    public boolean isSystemJob() {
        return true;
    }

    /**
     * A run that swept nothing is a skip, not a success.
     *
     * <p>
     * The job fires hourly and, until ingest gains a caller, will find nothing to do on nearly every run. Reporting
     * those as SUCCESS would write a history row an hour into {@code scheduled_job_history} forever and bury the runs
     * that did something. {@code CbomSyncTask} takes the same route when its repository client is unconfigured.
     */
    @Override
    public ScheduledTaskResult performJob(final ScheduledJobInfo scheduledJobInfo, final Object taskData) {
        PqcVerdictSweeper.SweepOutcome outcome = sweeper.sweep();
        if (!outcome.ran() || outcome.evaluated() == 0) {
            throw new ScheduledJobSkippedException();
        }
        String message = "Re-evaluated %d cryptographic asset(s) in %d batch(es); %d verdict(s) written, %d skipped after a failure"
                .formatted(outcome.evaluated(), outcome.batches(), outcome.written(), outcome.failed());
        return new ScheduledTaskResult(SchedulerJobExecutionStatus.SUCCESS, message, Resource.CRYPTO_ASSET, null);
    }
}
