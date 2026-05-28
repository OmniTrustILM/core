package com.czertainly.core.api.web;

import com.czertainly.api.exception.NotFoundException;
import com.czertainly.api.exception.SchedulerException;
import com.czertainly.api.interfaces.core.web.SchedulerController;
import com.czertainly.api.model.core.auth.Resource;
import com.czertainly.api.model.core.logging.enums.Module;
import com.czertainly.api.model.core.logging.enums.Operation;
import com.czertainly.api.model.core.scheduler.PaginationRequestDto;
import com.czertainly.api.model.core.scheduler.ScheduledJobDetailDto;
import com.czertainly.api.model.core.scheduler.ScheduledJobHistoryResponseDto;
import com.czertainly.api.model.core.scheduler.ScheduledJobsResponseDto;
import com.czertainly.api.model.scheduler.UpdateScheduledJob;
import com.czertainly.core.aop.AuditLogged;
import com.czertainly.core.logging.LogResource;
import com.czertainly.core.security.authz.SecurityFilter;
import com.czertainly.core.service.SchedulerExternalService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class SchedulerControllerImpl implements SchedulerController {

    private SchedulerExternalService schedulerService;

    @Override
    @AuditLogged(module = Module.SCHEDULER, resource = Resource.SCHEDULED_JOB, operation = Operation.LIST)
    public ScheduledJobsResponseDto listScheduledJobs(final PaginationRequestDto pagination) {
        return schedulerService.listScheduledJobs(SecurityFilter.create(), pagination);
    }

    @Override
    @AuditLogged(module = Module.SCHEDULER, resource = Resource.SCHEDULED_JOB, operation = Operation.DETAIL)
    public ScheduledJobDetailDto getScheduledJobDetail(@LogResource(uuid = true) final String uuid) throws NotFoundException {
        return schedulerService.getScheduledJobDetail(uuid);
    }

    @Override
    @AuditLogged(module = Module.SCHEDULER, resource = Resource.SCHEDULED_JOB, operation = Operation.UPDATE)
    public ScheduledJobDetailDto updateScheduledJob(@LogResource(uuid = true) String uuid, UpdateScheduledJob request) throws NotFoundException, SchedulerException {
        return schedulerService.updateScheduledJob(uuid, request);
    }

    @Override
    @AuditLogged(module = Module.SCHEDULER, resource = Resource.SCHEDULED_JOB, operation = Operation.DELETE)
    public void deleteScheduledJob(@LogResource(uuid = true) final String uuid) {
        schedulerService.deleteScheduledJob(uuid);
    }

    @Override
    @AuditLogged(module = Module.SCHEDULER, resource = Resource.SCHEDULED_JOB, operation = Operation.HISTORY)
    public ScheduledJobHistoryResponseDto getScheduledJobHistory(final PaginationRequestDto pagination, @LogResource(uuid = true) String uuid) {
        return schedulerService.getScheduledJobHistory(SecurityFilter.create(), pagination, uuid);
    }

    @Override
    @AuditLogged(module = Module.SCHEDULER, resource = Resource.SCHEDULED_JOB, operation = Operation.ENABLE)
    public void enableScheduledJob(@LogResource(uuid = true) String uuid) throws SchedulerException, NotFoundException {
        schedulerService.enableScheduledJob(uuid);
    }

    @Override
    @AuditLogged(module = Module.SCHEDULER, resource = Resource.SCHEDULED_JOB, operation = Operation.DISABLE)
    public void disableScheduledJob(@LogResource(uuid = true) String uuid) throws SchedulerException, NotFoundException {
        schedulerService.disableScheduledJob(uuid);
    }

    // SETTERs

    @Autowired
    public void setSchedulerService(SchedulerExternalService schedulerService) {
        this.schedulerService = schedulerService;
    }
}
