package com.otilm.core.service;

import com.otilm.api.exception.NotFoundException;
import com.otilm.api.exception.SchedulerException;
import com.otilm.api.model.core.scheduler.ScheduledJobDetailDto;
import com.otilm.core.tasks.ScheduledJobTask;

public interface SchedulerInternalService {

    ScheduledJobDetailDto registerScheduledJob(Class<? extends ScheduledJobTask> scheduledJobTaskClass) throws SchedulerException;

    void runScheduledJob(String jobName) throws SchedulerException, NotFoundException;
}
