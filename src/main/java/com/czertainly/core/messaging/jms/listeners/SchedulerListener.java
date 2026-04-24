package com.czertainly.core.messaging.jms.listeners;

import com.czertainly.api.exception.NotFoundException;
import com.czertainly.api.exception.SchedulerException;
import com.czertainly.api.model.scheduler.SchedulerJobExecutionMessage;
import com.czertainly.core.service.SchedulerService;
import jakarta.transaction.Transactional;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

@Component
@Transactional
public class SchedulerListener implements MessageProcessor<SchedulerJobExecutionMessage> {

    private static final Logger logger = LoggerFactory.getLogger(SchedulerListener.class);

    private SchedulerService schedulerService;

    @Autowired
    public void setSchedulerService(SchedulerService schedulerService) {
        this.schedulerService = schedulerService;
    }

    @Override
    public void processMessage(SchedulerJobExecutionMessage schedulerMessage) {
        logger.debug("Received scheduler message: {}", schedulerMessage);
        try {
            schedulerService.runScheduledJob(schedulerMessage.getJobName());
        } catch (SchedulerException | NotFoundException e) {
            logger.error("Unable to process the job {}. Error: {}", schedulerMessage.getJobName(), e.getMessage(), e);
        }
    }
}
