package com.otilm.core.messaging.jms.listeners;

import com.otilm.api.exception.NotFoundException;
import com.otilm.api.exception.SchedulerException;
import com.otilm.api.model.scheduler.SchedulerJobExecutionMessage;
import com.otilm.core.service.SchedulerInternalService;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;
import org.springframework.transaction.annotation.Propagation;
import org.springframework.transaction.annotation.Transactional;

/**
 * Runs a scheduled job with no ambient transaction, like the platform's other listeners. A job's history rows are
 * written by {@code ScheduledJobHistoryWriter} in short transactions of their own, so a job that outlives
 * {@code spring.transaction.default-timeout} still ends with a history row, and a task that opens its own transaction
 * ({@code UpdateCertificateStatusTask}, {@code UpdateIntuneRevocationRequestsTask}) starts its clock at
 * {@code performJob} rather than at the message.
 */
@Component
@Transactional(propagation = Propagation.NOT_SUPPORTED)
public class SchedulerListener implements MessageProcessor<SchedulerJobExecutionMessage> {

    private static final Logger logger = LoggerFactory.getLogger(SchedulerListener.class);

    private SchedulerInternalService schedulerService;

    @Autowired
    public void setSchedulerService(SchedulerInternalService schedulerService) {
        this.schedulerService = schedulerService;
    }

    @Override
    public void processMessage(SchedulerJobExecutionMessage schedulerMessage) {
        logger.debug("Received scheduler message: {}", schedulerMessage);
        try {
            schedulerService.runScheduledJob(schedulerMessage.getJobName());
        } catch (SchedulerException | NotFoundException e) {
            logger.error("Unable to process the job {}. Error: {}", schedulerMessage.getJobName(), e.getMessage(), e);
        } catch (RuntimeException e) {
            // Deliberately swallowed, so the endpoint acknowledges the message: a redelivery would run the job again.
            // Whatever the run recorded stands -- a FAILED row when the task threw, SUCCESS or FAILED when a side
            // effect after the status failed, nothing at all when the failure came before the STARTED row -- and this
            // line names the job for whoever has to look. An Error is not caught, here or below: runScheduledJob
            // closes its row all the same, and whether the message is redelivered is the JMS retry policy's call -- a
            // deterministic one exhausts it, a transient one (memory that comes back, a class that appears after a
            // redeploy) gets its retry.
            logger.error("Scheduled job '{}' did not run to completion", schedulerMessage.getJobName(), e);
        }
    }
}
