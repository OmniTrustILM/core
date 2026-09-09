package com.otilm.core.tasks;

import com.otilm.api.model.core.auth.Resource;
import com.otilm.api.model.scheduler.SchedulerJobExecutionStatus;
import com.otilm.core.api.ScheduledJobSkippedException;
import com.otilm.core.cbom.pqc.PqcVerdictSweeper;
import com.otilm.core.model.ScheduledTaskResult;
import lombok.NoArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

/**
 * The sweep's schedule, and nothing else.
 *
 * <p>
 * A system {@code ScheduledJobTask} rather than {@code @Scheduled}, which reaches nobody: under SaaS an operator cannot
 * touch yml. Registered here, enable and disable work through the Scheduler API while the cron stays fixed -- pause
 * yes, re-tune no. It needs the external scheduler, which {@code CbomSyncTask} already needs.
 *
 * <p>
 * Not {@code @Transactional}: {@code SchedulerListener} already opens one, and the sweeper's own is the second.
 */
@Slf4j
@Component
@NoArgsConstructor
public class CryptoAssetPqcSweepTask implements ScheduledJobTask {

    public static final String NAME = "CryptoAssetPqcSweepTask";

    /** Hourly at :30, offset from {@code CbomSyncTask} so the two do not contend. */
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
     * A run that read nothing is a skip: until ingest gains a caller this fires hourly and finds nothing, and a SUCCESS
     * row an hour would bury the runs that did something.
     *
     * <p>
     * The history row is the only place an operator learns what happened, so it distinguishes the three ways a row can
     * leave the work list unwritten. A refused row is ordinary -- another writer reached it first -- and the next sweep
     * retries it, so it is reported and does not fail the run. A row whose own write transaction failed, or a sweep
     * that stopped early, is not ordinary. Only rows whose {@code EVALUATION-FAILED} stamp actually landed are reported
     * as recorded: the sweep counts the stamps that committed, not the ones it built.
     *
     * <p>
     * The catch is what stops a failure of the sweep's own connection -- a failover, a pooler restart, an
     * {@code idle_in_transaction_session_timeout} -- from leaving no history row at all. It runs on the listener's
     * transaction, which is still live, and its text is fixed: an exception message here reaches the scheduler API.
     */
    @Override
    public ScheduledTaskResult performJob(final ScheduledJobInfo scheduledJobInfo, final Object taskData) {
        PqcVerdictSweeper.SweepOutcome outcome;
        try {
            outcome = sweeper.sweep();
        } catch (RuntimeException e) {
            log.error("PQC verdict sweep failed before it could report its outcome", e);
            return new ScheduledTaskResult(SchedulerJobExecutionStatus.FAILED,
                    "The sweep failed before it could report its outcome; see the application log",
                    Resource.CRYPTO_ASSET, null);
        }
        if (!outcome.ran() || (outcome.read() == 0 && !outcome.aborted())) {
            throw new ScheduledJobSkippedException();
        }
        String message = ("Read %d stale cryptographic asset(s) in %d batch(es); %d verdict(s) written, of which %d "
                + "recorded as UNKNOWN because the rule set could not be evaluated; %d refused and left for the next "
                + "sweep; %d could not be written")
                .formatted(outcome.read(), outcome.batches(), outcome.written(), outcome.unevaluated(),
                        outcome.refused(), outcome.writeFailures());
        if (outcome.aborted()) {
            return new ScheduledTaskResult(SchedulerJobExecutionStatus.FAILED,
                    "The sweep stopped before completing. " + message, Resource.CRYPTO_ASSET, null);
        }
        if (outcome.unevaluated() > 0 || outcome.writeFailures() > 0) {
            return new ScheduledTaskResult(SchedulerJobExecutionStatus.FAILED, message, Resource.CRYPTO_ASSET, null);
        }
        return new ScheduledTaskResult(SchedulerJobExecutionStatus.SUCCESS, message, Resource.CRYPTO_ASSET, null);
    }
}
