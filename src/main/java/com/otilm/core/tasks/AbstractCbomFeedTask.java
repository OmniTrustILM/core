package com.otilm.core.tasks;

import com.otilm.api.exception.CbomRepositoryException;
import com.otilm.api.exception.PlatformException;
import com.otilm.api.model.core.auth.Resource;
import com.otilm.api.model.scheduler.SchedulerJobExecutionStatus;
import com.otilm.core.api.ScheduledJobSkippedException;
import com.otilm.core.model.ScheduledTaskResult;
import com.otilm.core.service.CbomInternalService;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.transaction.annotation.Propagation;
import org.springframework.transaction.annotation.Transactional;

/**
 * What the two passes over the CBOM repository's feed have in common.
 *
 * <p>
 * They differ in one thing each: how far back the listing reaches, and how often it runs. Everything else -- the
 * unconfigured-repository skip, the outage skip, the operator-visible failure text -- is the same, and was the same
 * thirty lines twice before the reconciliation pass existed.
 */
public abstract class AbstractCbomFeedTask implements ScheduledJobTask {

    private static final Logger logger = LoggerFactory.getLogger(AbstractCbomFeedTask.class);

    private final String jobName;
    private final String cronExpression;

    private CbomInternalService cbomService;

    protected AbstractCbomFeedTask(String jobName, String cronExpression) {
        this.jobName = jobName;
        this.cronExpression = cronExpression;
    }

    @Override
    public String getDefaultJobName() {
        return jobName;
    }

    @Override
    public String getDefaultCronExpression() {
        return cronExpression;
    }

    @Autowired
    public void setCbomService(CbomInternalService cbomService) {
        this.cbomService = cbomService;
    }

    protected CbomInternalService cbomService() {
        return cbomService;
    }

    /** The pass itself, answering with the run report an operator reads in the job history. */
    protected abstract String runPass() throws CbomRepositoryException;

    @Override
    public boolean isDefaultOneTimeJob() {
        return false;
    }

    @Override
    public boolean isSystemJob() {
        return true;
    }

    /**
     * Runs without a transaction of its own: the run pages an external service and reads one document per entry, and
     * the service method it calls is {@code NOT_SUPPORTED} for that reason. Opening a transaction here only to have it
     * suspended for the whole run would keep it open, unused, for as long as the run takes.
     */
    @Override
    @Transactional(propagation = Propagation.NOT_SUPPORTED)
    public ScheduledTaskResult performJob(final ScheduledJobInfo scheduledJobInfo, final Object taskData) {
        if (!cbomService.isCbomRepositoryClientConfigured()) {
            throw new ScheduledJobSkippedException();
        }

        String runResultMessage;
        try {
            runResultMessage = runPass();
        } catch (Exception e) {
            if (e instanceof CbomRepositoryException ex && ex.getProblemDetail() != null
                    && ex.getProblemDetail().getStatus() == HttpStatus.SERVICE_UNAVAILABLE.value()) {
                throw new ScheduledJobSkippedException();
            }

            // Only a shaped domain exception's own message is operator-safe; anything else (JPA, the WebClient
            // stack, a bare RuntimeException) could quote driver or framework internals, so it is replaced with the
            // fallback below. The stack trace itself is still logged, for the Core log.
            final String safeReason = PlatformException.safeMessage(e, "unexpected error, see the Core log");
            final String errorMessage = String
                    .format("Unable to sync CBOMs for job %s. Error: %s",
                            scheduledJobInfo == null ? "" : scheduledJobInfo.jobName(), safeReason);
            logger.error(errorMessage, e);
            return new ScheduledTaskResult(SchedulerJobExecutionStatus.FAILED, errorMessage, Resource.CBOM, null);
        }

        return new ScheduledTaskResult(SchedulerJobExecutionStatus.SUCCESS, runResultMessage, Resource.CBOM, null);
    }
}
