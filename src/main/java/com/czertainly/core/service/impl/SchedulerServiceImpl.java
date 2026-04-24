package com.czertainly.core.service.impl;

import com.czertainly.api.clients.SchedulerApiClient;
import com.czertainly.api.exception.NotFoundException;
import com.czertainly.api.exception.SchedulerException;
import com.czertainly.api.exception.ValidationError;
import com.czertainly.api.exception.ValidationException;
import com.czertainly.api.model.core.auth.Resource;
import com.czertainly.api.model.core.scheduler.*;
import com.czertainly.api.model.scheduler.SchedulerJobDto;
import com.czertainly.api.model.scheduler.SchedulerJobExecutionStatus;
import com.czertainly.api.model.scheduler.SchedulerRequestDto;
import com.czertainly.api.model.scheduler.UpdateScheduledJob;
import com.czertainly.core.api.ScheduledJobSkippedException;
import com.czertainly.core.dao.entity.ScheduledJob;
import com.czertainly.core.dao.entity.ScheduledJobHistory;
import com.czertainly.core.dao.repository.ScheduledJobHistoryRepository;
import com.czertainly.core.dao.repository.ScheduledJobsRepository;
import com.czertainly.core.events.handlers.ScheduledJobFinishedEventHandler;
import com.czertainly.core.events.transaction.ScheduledJobFinishedEvent;
import com.czertainly.core.messaging.jms.producers.EventProducer;
import com.czertainly.core.model.ScheduledTaskResult;
import com.czertainly.core.model.auth.ResourceAction;
import com.czertainly.core.security.authz.ExternalAuthorization;
import com.czertainly.core.security.authz.SecuredUUID;
import com.czertainly.core.security.authz.SecurityFilter;
import com.czertainly.core.service.SchedulerService;
import com.czertainly.core.tasks.ScheduledJobInfo;
import com.czertainly.core.tasks.ScheduledJobTask;
import com.czertainly.core.util.AuthHelper;
import com.czertainly.core.util.FilterPredicatesBuilder;
import com.czertainly.core.util.RequestValidatorHelper;
import jakarta.persistence.criteria.CriteriaBuilder;
import jakarta.persistence.criteria.CriteriaQuery;
import jakarta.persistence.criteria.Predicate;
import jakarta.persistence.criteria.Root;
import org.apache.commons.lang3.function.TriFunction;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.ApplicationContext;
import org.springframework.data.domain.PageRequest;
import org.springframework.data.domain.Pageable;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Isolation;
import org.springframework.transaction.annotation.Propagation;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.transaction.event.TransactionPhase;
import org.springframework.transaction.event.TransactionalEventListener;

import java.util.Date;
import java.util.List;
import java.util.Optional;
import java.util.UUID;

@Service
public class SchedulerServiceImpl implements SchedulerService {

    private static final Logger logger = LoggerFactory.getLogger(SchedulerServiceImpl.class);

    private AuthHelper authHelper;

    private ApplicationContext applicationContext;

    private EventProducer eventProducer;

    private SchedulerApiClient schedulerApiClient;

    private ScheduledJobsRepository scheduledJobsRepository;

    private ScheduledJobHistoryRepository scheduledJobHistoryRepository;

    @Autowired
    public void setAuthHelper(AuthHelper authHelper) {
        this.authHelper = authHelper;
    }

    @Autowired
    public void setApplicationContext(ApplicationContext applicationContext) {
        this.applicationContext = applicationContext;
    }

    @Autowired
    public void setEventProducer(EventProducer eventProducer) {
        this.eventProducer = eventProducer;
    }

    @Autowired
    public void setScheduledJobsRepository(ScheduledJobsRepository scheduledJobsRepository) {
        this.scheduledJobsRepository = scheduledJobsRepository;
    }

    @Autowired
    public void setSchedulerApiClient(SchedulerApiClient schedulerApiClient) {
        this.schedulerApiClient = schedulerApiClient;
    }

    @Autowired
    public void setScheduledJobHistoryRepository(ScheduledJobHistoryRepository scheduledJobHistoryRepository) {
        this.scheduledJobHistoryRepository = scheduledJobHistoryRepository;
    }

    @Override
    @ExternalAuthorization(resource = Resource.SCHEDULED_JOB, action = ResourceAction.LIST)
    public ScheduledJobsResponseDto listScheduledJobs(final SecurityFilter filter, final PaginationRequestDto paginationRequestDto) {
        RequestValidatorHelper.revalidatePaginationRequestDto(paginationRequestDto);
        final Pageable pageable = PageRequest.of(paginationRequestDto.getPageNumber() - 1, paginationRequestDto.getItemsPerPage());
        final List<ScheduledJob> scheduledJobList = scheduledJobsRepository.findUsingSecurityFilter(filter, List.of(), null, pageable, null);

        final Long maxItems = scheduledJobsRepository.countUsingSecurityFilter(filter, null);
        final ScheduledJobsResponseDto responseDto = new ScheduledJobsResponseDto();
        responseDto.setScheduledJobs(scheduledJobList.stream()
                .map(job -> job.mapToDto(scheduledJobHistoryRepository.findTopByScheduledJobUuidOrderByJobExecutionDesc(job.getUuid())))
                .toList());
        responseDto.setItemsPerPage(paginationRequestDto.getItemsPerPage());
        responseDto.setPageNumber(paginationRequestDto.getPageNumber());
        responseDto.setTotalItems(maxItems);
        responseDto.setTotalPages((int) Math.ceil((double) maxItems / paginationRequestDto.getItemsPerPage()));
        return responseDto;
    }

    @Override
    @ExternalAuthorization(resource = Resource.SCHEDULED_JOB, action = ResourceAction.DETAIL)
    public ScheduledJobDetailDto getScheduledJobDetail(final String uuid) throws NotFoundException {
        final ScheduledJob scheduledJob = scheduledJobsRepository.findByUuid(SecuredUUID.fromString(uuid)).orElseThrow(() -> new NotFoundException(ScheduledJob.class, uuid));
        return scheduledJob.mapToDetailDto(scheduledJobHistoryRepository.findTopByScheduledJobUuidOrderByJobExecutionDesc(UUID.fromString(uuid)));
    }

    @Override
    @ExternalAuthorization(resource = Resource.SCHEDULED_JOB, action = ResourceAction.DELETE)
    public void deleteScheduledJob(final String uuid) {
        final Optional<ScheduledJob> scheduledJobOptional = scheduledJobsRepository.findByUuid(SecuredUUID.fromString(uuid));
        if (scheduledJobOptional.isPresent()) {
            final ScheduledJob scheduledJob = scheduledJobOptional.get();

            if (scheduledJob.isSystem()) {
                logger.warn("Unable to delete system job.");
                throw new ValidationException(ValidationError.create("Unable to delete system job."));
            }

            if (scheduledJobHistoryRepository.existsByScheduledJobUuid(UUID.fromString(uuid))) {
                logger.warn("Unable to delete job with existing history.");
                throw new ValidationException(ValidationError.create("Unable to delete job with existing history."));
            }

            try {
                schedulerApiClient.deleteScheduledJob(scheduledJob.getJobName());
                scheduledJobsRepository.deleteById(UUID.fromString(uuid));
            } catch (SchedulerException e) {
                logger.error("Unable to delete job {}: {}", scheduledJob.getJobName(), e.getMessage());
            }
        }
    }

    @Override
    @ExternalAuthorization(resource = Resource.SCHEDULED_JOB, action = ResourceAction.DETAIL)
    public ScheduledJobHistoryResponseDto getScheduledJobHistory(final SecurityFilter filter, final PaginationRequestDto paginationRequestDto, final String uuid) {
        final TriFunction<Root<ScheduledJobHistory>, CriteriaBuilder, CriteriaQuery<?>, Predicate> additionalWhereClause = (root, cb, cr) -> FilterPredicatesBuilder.constructFilterForJobHistory(cb, root, UUID.fromString(uuid));

        RequestValidatorHelper.revalidatePaginationRequestDto(paginationRequestDto);
        final Pageable pageable = PageRequest.of(paginationRequestDto.getPageNumber() - 1, paginationRequestDto.getItemsPerPage());
        final List<ScheduledJobHistory> scheduledJobHistoryList = scheduledJobHistoryRepository.findUsingSecurityFilter(filter, List.of(), additionalWhereClause, pageable, (root, cb) -> cb.desc(root.get("jobExecution")));

        final Long maxItems = scheduledJobHistoryRepository.countUsingSecurityFilter(filter, additionalWhereClause);
        final ScheduledJobHistoryResponseDto responseDto = new ScheduledJobHistoryResponseDto();
        responseDto.setScheduledJobHistory(scheduledJobHistoryList.stream().map(ScheduledJobHistory::mapToDto).toList());
        responseDto.setItemsPerPage(paginationRequestDto.getItemsPerPage());
        responseDto.setPageNumber(paginationRequestDto.getPageNumber());
        responseDto.setTotalItems(maxItems);
        responseDto.setTotalPages((int) Math.ceil((double) maxItems / paginationRequestDto.getItemsPerPage()));

        return responseDto;
    }

    @Override
    @ExternalAuthorization(resource = Resource.SCHEDULED_JOB, action = ResourceAction.ENABLE)
    public void enableScheduledJob(final String uuid) throws SchedulerException, NotFoundException {
        changeScheduledJobState(uuid, true);
    }

    @Override
    @ExternalAuthorization(resource = Resource.SCHEDULED_JOB, action = ResourceAction.ENABLE)
    public void disableScheduledJob(final String uuid) throws SchedulerException, NotFoundException {
        changeScheduledJobState(uuid, false);
    }

    @Override
    public ScheduledJobDetailDto updateScheduledJob(String uuid, UpdateScheduledJob request) throws NotFoundException, SchedulerException {
        ScheduledJob scheduledJob = scheduledJobsRepository.findByUuid(SecuredUUID.fromString(uuid)).orElseThrow(() -> new NotFoundException(ScheduledJob.class, uuid));
        if (scheduledJob.isSystem()) throw new ValidationException("Cannot updated system job.");
        SchedulerRequestDto schedulerRequestDto = new SchedulerRequestDto(
                new SchedulerJobDto(scheduledJob.getUuid(), scheduledJob.getJobName(), request.getCronExpression(), scheduledJob.getJobClassName())
        );
        schedulerApiClient.updateScheduledJob(schedulerRequestDto);
        if (!scheduledJob.isEnabled()) disableScheduledJob(uuid);

        scheduledJob.setCronExpression(request.getCronExpression());
        scheduledJobsRepository.save(scheduledJob);

        return scheduledJob.mapToDetailDto(scheduledJobHistoryRepository.findTopByScheduledJobUuidOrderByJobExecutionDesc(UUID.fromString(uuid)));
    }

    private void changeScheduledJobState(final String uuid, final boolean enabled) throws SchedulerException, NotFoundException {
        final Optional<ScheduledJob> scheduledJobOptional = scheduledJobsRepository.findByUuid(SecuredUUID.fromString(uuid));
        if (scheduledJobOptional.isPresent()) {
            final ScheduledJob scheduledJob = scheduledJobOptional.get();
            if (enabled) {
                schedulerApiClient.enableScheduledJob(scheduledJob.getJobName());
                scheduledJob.setEnabled(true);
            } else {
                schedulerApiClient.disableScheduledJob(scheduledJob.getJobName());
                scheduledJob.setEnabled(false);
            }
            scheduledJobsRepository.save(scheduledJob);
        } else {
            throw new NotFoundException("There is no such scheduled job {}", uuid);
        }
    }

    // Scheduled job processing

    @Override
    public ScheduledJobDetailDto registerScheduledJob(final Class<? extends ScheduledJobTask> scheduledJobTaskClass) throws SchedulerException {
        final ScheduledJobTask scheduledJobTask = applicationContext.getBean(scheduledJobTaskClass);
        return registerScheduler(scheduledJobTask, scheduledJobTask.getDefaultJobName(), scheduledJobTask.getDefaultCronExpression(), scheduledJobTask.isDefaultOneTimeJob(), null);
    }

    @Override
    public ScheduledJobDetailDto registerScheduledJob(final Class<? extends ScheduledJobTask> scheduledJobTaskClass, final String jobName, final String cronExpression, final boolean oneTime, final Object taskData) throws SchedulerException {
        final ScheduledJobTask scheduledJobTask = applicationContext.getBean(scheduledJobTaskClass);
        return registerScheduler(scheduledJobTask, jobName, cronExpression, oneTime, taskData);
    }

    @Override
    public void runScheduledJob(final String jobName) throws NotFoundException {
        final ScheduledJob scheduledJob = scheduledJobsRepository.findByJobName(jobName).orElseThrow(() -> new NotFoundException(ScheduledJobHistory.class, jobName));

        ScheduledJobTask scheduledJobTask;
        try {
            final Class<?> clazz = Class.forName(scheduledJob.getJobClassName());
            final Object clazzObject = applicationContext.getBean(clazz);
            if (clazzObject instanceof ScheduledJobTask task) {
                scheduledJobTask = task;
            } else {
                scheduledJobTask = null;
            }
        } catch (ClassNotFoundException ignored) {
            scheduledJobTask = null;
        }

        if (scheduledJobTask == null) {
            String errorMessage = "Unknown scheduled task '%s' for job '%s'".formatted(scheduledJob.getJobClassName(), scheduledJob.getJobName());
            registerJobHistory(scheduledJob, SchedulerJobExecutionStatus.FAILED, errorMessage);
            logger.error(errorMessage);
            return;
        }

        final ScheduledJobHistory scheduledJobHistory = registerJobHistory(scheduledJob, SchedulerJobExecutionStatus.STARTED, null);

        if (scheduledJob.getUserUuid() != null) {
            authHelper.authenticateAsUser(scheduledJob.getUserUuid());
        }


        boolean skipped = false;
        ScheduledTaskResult result = null;
        try {
            result = scheduledJobTask.performJob(new ScheduledJobInfo(scheduledJob.getJobName(), scheduledJob.getUuid(), scheduledJobHistory.getUuid()), scheduledJob.getObjectData());
        } catch (ScheduledJobSkippedException e) {
            skipped = true;
        } finally {
            if (skipped || result != null) {
                finalizeFinishedScheduledJob(scheduledJob, scheduledJobHistory, result, skipped);
            }
        }
    }

    @Transactional(propagation = Propagation.REQUIRES_NEW, isolation = Isolation.DEFAULT)
    @TransactionalEventListener(phase = TransactionPhase.AFTER_COMMIT)
    public void handleScheduledJobFinishedEvent(ScheduledJobFinishedEvent event) throws NotFoundException {
        logger.debug("ScheduledJobFinished event handler: {}", event.scheduledJobInfo().jobUuid());
        final ScheduledJob scheduledJob = scheduledJobsRepository.findByUuid(SecuredUUID.fromUUID(event.scheduledJobInfo().jobUuid())).orElseThrow(() -> new NotFoundException(ScheduledJob.class, event.scheduledJobInfo().jobUuid()));
        final ScheduledJobHistory scheduledJobHistory = scheduledJobHistoryRepository.findByUuid(SecuredUUID.fromUUID(event.scheduledJobInfo().jobHistoryUuid())).orElseThrow(() -> new NotFoundException(ScheduledJobHistory.class, event.scheduledJobInfo().jobHistoryUuid()));
        finalizeFinishedScheduledJob(scheduledJob, scheduledJobHistory, event.result(), false);
    }

    private void finalizeFinishedScheduledJob(ScheduledJob scheduledJob, ScheduledJobHistory scheduledJobHistory, ScheduledTaskResult result, boolean skipped) {
        logger.debug("Finalizing finished scheduled job '{}'", scheduledJob.getJobName());

        // update job history
        if (result != null) {
            scheduledJobHistory.setJobEndTime(new Date());
            scheduledJobHistory.setSchedulerExecutionStatus(result.getStatus());
            scheduledJobHistory.setResultMessage(result.getResultMessage());
            scheduledJobHistory.setResultObjectType(result.getResultObjectType());
            scheduledJobHistory.setResultObjectIdentification(result.getResultObjectIdentification());
            scheduledJobHistoryRepository.save(scheduledJobHistory);
        } else if (skipped) {
            logger.debug("Skipping scheduled job '{}', removing history entry", scheduledJob.getJobName());
            scheduledJobHistoryRepository.delete(scheduledJobHistory);
        }

        // deregister one-time job
        if (result != null && SchedulerJobExecutionStatus.SUCCESS.equals(result.getStatus()) && scheduledJob.isOneTime()) {
            try {
                schedulerApiClient.deleteScheduledJob(scheduledJob.getJobName());
                logger.info("Scheduled job '{}' was deleted/unscheduled because it was one-time job only.", scheduledJob.getJobName());
            } catch (SchedulerException e) {
                logger.error("Failed to delete/unschedule finished one-time job '{}'", scheduledJob.getJobName());
            }
        }

        // raise event for non-system job
        if (!scheduledJob.isSystem() && result != null) {
            eventProducer.produceMessage(ScheduledJobFinishedEventHandler.constructEventMessage(scheduledJob.getUuid(), result));
        }

        logger.info("Scheduled job '{}' has finished", scheduledJob.getJobName());
    }

    private ScheduledJobDetailDto registerScheduler(ScheduledJobTask scheduledJobTask, final String jobName, final String cronExpression, final boolean oneTime, final Object taskData) throws SchedulerException {
        if (scheduledJobTask == null) {
            throw new SchedulerException("Unknown scheduled task for job: " + jobName);
        }

        final SchedulerJobDto schedulerDetail = new SchedulerJobDto(jobName, cronExpression, scheduledJobTask.getJobClassName());
        schedulerApiClient.schedulerCreate(new SchedulerRequestDto(schedulerDetail));

        Optional<ScheduledJob> scheduledJob = scheduledJobsRepository.findByJobName(jobName);
        if (scheduledJob.isPresent()) {
            logger.info("Scheduled job '{}' was already registered.", jobName);
            return scheduledJob.get().mapToDetailDto(null);
        }

        ScheduledJob scheduledJobEntity = new ScheduledJob();
        scheduledJobEntity.setJobName(jobName);
        scheduledJobEntity.setCronExpression(cronExpression);
        scheduledJobEntity.setObjectData(taskData);
        scheduledJobEntity.setOneTime(oneTime);
        scheduledJobEntity.setEnabled(true);
        scheduledJobEntity.setSystem(scheduledJobTask.isSystemJob());
        scheduledJobEntity.setJobClassName(scheduledJobTask.getJobClassName());

        try {
            scheduledJobEntity.setUserUuid(UUID.fromString(AuthHelper.getUserIdentification().getUuid()));
        } catch (ValidationException ignored) {
            scheduledJobEntity.setUserUuid(null);
        }

        scheduledJobsRepository.save(scheduledJobEntity);

        logger.info("Scheduled job '{}' was registered.", jobName);
        return scheduledJobEntity.mapToDetailDto(null);
    }

    private ScheduledJobHistory registerJobHistory(final ScheduledJob scheduledJob, SchedulerJobExecutionStatus status, String message) {
        final ScheduledJobHistory scheduledJobHistory = new ScheduledJobHistory();
        scheduledJobHistory.setScheduledJobUuid(scheduledJob.getUuid());
        scheduledJobHistory.setJobExecution(new Date());
        scheduledJobHistory.setSchedulerExecutionStatus(status);
        scheduledJobHistory.setResultMessage(message);
        return scheduledJobHistoryRepository.save(scheduledJobHistory);
    }

}
