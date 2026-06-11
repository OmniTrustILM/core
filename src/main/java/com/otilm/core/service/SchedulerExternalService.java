package com.otilm.core.service;

import com.otilm.api.exception.NotFoundException;
import com.otilm.api.exception.SchedulerException;
import com.otilm.api.model.core.scheduler.PaginationRequestDto;
import com.otilm.api.model.core.scheduler.ScheduledJobDetailDto;
import com.otilm.api.model.core.scheduler.ScheduledJobHistoryResponseDto;
import com.otilm.api.model.core.scheduler.ScheduledJobsResponseDto;
import com.otilm.api.model.scheduler.UpdateScheduledJob;
import com.otilm.core.security.authz.SecurityFilter;
import com.otilm.core.tasks.ScheduledJobTask;

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
