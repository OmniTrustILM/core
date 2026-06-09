package com.czertainly.core.service;

import com.czertainly.api.exception.NotFoundException;
import com.czertainly.api.exception.SchedulerException;
import com.czertainly.api.model.core.scheduler.PaginationRequestDto;
import com.czertainly.api.model.core.scheduler.ScheduledJobDetailDto;
import com.czertainly.api.model.core.scheduler.ScheduledJobHistoryResponseDto;
import com.czertainly.api.model.core.scheduler.ScheduledJobsResponseDto;
import com.czertainly.api.model.scheduler.UpdateScheduledJob;
import com.czertainly.core.security.authz.SecurityFilter;
import com.czertainly.core.tasks.ScheduledJobTask;

public interface SchedulerExternalService {

    ScheduledJobsResponseDto listScheduledJobs(SecurityFilter filter, PaginationRequestDto pagination);

    ScheduledJobDetailDto getScheduledJobDetail(String uuid) throws NotFoundException;

    void deleteScheduledJob(String uuid);

    ScheduledJobHistoryResponseDto getScheduledJobHistory(SecurityFilter filter, PaginationRequestDto pagination, String uuid);

    void enableScheduledJob(String uuid) throws SchedulerException, NotFoundException;

    void disableScheduledJob(String uuid) throws SchedulerException, NotFoundException;

    ScheduledJobDetailDto updateScheduledJob(String uuid, UpdateScheduledJob request) throws NotFoundException, SchedulerException;

    ScheduledJobDetailDto registerScheduledJob(Class<? extends ScheduledJobTask> scheduledJobTaskClass, String jobName, String cronExpression, boolean oneTime, Object taskData) throws SchedulerException;
}
