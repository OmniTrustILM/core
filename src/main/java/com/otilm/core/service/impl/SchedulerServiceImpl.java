package com.otilm.core.service.impl;

import com.otilm.api.clients.SchedulerApiClient;
import com.otilm.api.exception.NotFoundException;
import com.otilm.api.exception.PlatformException;
import com.otilm.api.exception.SchedulerException;
import com.otilm.api.exception.ValidationError;
import com.otilm.api.exception.ValidationException;
import com.otilm.api.model.core.auth.Resource;
import com.otilm.api.model.core.scheduler.PaginationRequestDto;
import com.otilm.api.model.core.scheduler.ScheduledJobDetailDto;
import com.otilm.api.model.core.scheduler.ScheduledJobHistoryResponseDto;
import com.otilm.api.model.core.scheduler.ScheduledJobsResponseDto;
import com.otilm.api.model.scheduler.SchedulerJobDto;
import com.otilm.api.model.scheduler.SchedulerJobExecutionStatus;
import com.otilm.api.model.scheduler.SchedulerRequestDto;
import com.otilm.api.model.scheduler.UpdateScheduledJob;
import com.otilm.core.api.ScheduledJobSkippedException;
import com.otilm.core.dao.entity.ScheduledJob;
import com.otilm.core.dao.entity.ScheduledJobHistory;
import com.otilm.core.dao.repository.ScheduledJobHistoryRepository;
import com.otilm.core.dao.repository.ScheduledJobsRepository;
import com.otilm.core.events.handlers.ScheduledJobFinishedEventHandler;
import com.otilm.core.events.transaction.ScheduledJobFinishedEvent;
import com.otilm.core.messaging.jms.producers.EventProducer;
import com.otilm.core.model.ScheduledTaskResult;
import com.otilm.core.model.auth.ResourceAction;
import com.otilm.core.security.authz.ExternalAuthorization;
import com.otilm.core.security.authz.SecuredUUID;
import com.otilm.core.security.authz.SecurityFilter;
import com.otilm.core.service.SchedulerExternalService;
import com.otilm.core.service.SchedulerInternalService;
import com.otilm.core.service.writer.scheduler.ScheduledJobHistoryWriter;
import com.otilm.core.tasks.ScheduledJobInfo;
import com.otilm.core.tasks.ScheduledJobTask;
import com.otilm.core.util.AuthHelper;
import com.otilm.core.util.FilterPredicatesBuilder;
import com.otilm.core.util.RequestValidatorHelper;
import jakarta.persistence.criteria.CriteriaBuilder;
import jakarta.persistence.criteria.CriteriaQuery;
import jakarta.persistence.criteria.Predicate;
import jakarta.persistence.criteria.Root;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import java.util.UUID;
import org.apache.commons.lang3.function.TriFunction;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.ApplicationContext;
import org.springframework.data.domain.PageRequest;
import org.springframework.data.domain.Pageable;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Propagation;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.transaction.event.TransactionPhase;
import org.springframework.transaction.event.TransactionalEventListener;

@Service
public class SchedulerServiceImpl implements SchedulerExternalService, SchedulerInternalService {

    private static final Logger logger = LoggerFactory.getLogger(SchedulerServiceImpl.class);

    private AuthHelper authHelper;

    private ApplicationContext applicationContext;

    private EventProducer eventProducer;

    private SchedulerApiClient schedulerApiClient;

    private ScheduledJobsRepository scheduledJobsRepository;

    private ScheduledJobHistoryRepository scheduledJobHistoryRepository;

    private ScheduledJobHistoryWriter historyWriter;

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

    @Autowired
    public void setHistoryWriter(ScheduledJobHistoryWriter historyWriter) {
        this.historyWriter = historyWriter;
    }

    @Override
    @ExternalAuthorization(resource = Resource.SCHEDULED_JOB, action = ResourceAction.LIST)
    public ScheduledJobsResponseDto listScheduledJobs(final SecurityFilter filter,
            final PaginationRequestDto paginationRequestDto) {
        RequestValidatorHelper.revalidatePaginationRequestDto(paginationRequestDto);
        final Pageable pageable = PageRequest
                .of(paginationRequestDto.getPageNumber() - 1, paginationRequestDto.getItemsPerPage());
        final List<ScheduledJob> scheduledJobList = scheduledJobsRepository
                .findUsingSecurityFilter(filter, List.of(), null, pageable, null);

        final Long maxItems = scheduledJobsRepository.countUsingSecurityFilter(filter, null);
        final ScheduledJobsResponseDto responseDto = new ScheduledJobsResponseDto();
        responseDto
                .setScheduledJobs(scheduledJobList
                        .stream()
                        .map(job -> job
                                .mapToDto(scheduledJobHistoryRepository
                                        .findTopByScheduledJobUuidOrderByJobExecutionDesc(job.getUuid())))
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
        final ScheduledJob scheduledJob = scheduledJobsRepository
                .findByUuid(SecuredUUID.fromString(uuid))
                .orElseThrow(() -> new NotFoundException(ScheduledJob.class, uuid));
        return scheduledJob
                .mapToDetailDto(scheduledJobHistoryRepository
                        .findTopByScheduledJobUuidOrderByJobExecutionDesc(UUID.fromString(uuid)));
    }

    @Override
    @ExternalAuthorization(resource = Resource.SCHEDULED_JOB, action = ResourceAction.DELETE)
    public void deleteScheduledJob(final String uuid) {
        final Optional<ScheduledJob> scheduledJobOptional = scheduledJobsRepository
                .findByUuid(SecuredUUID.fromString(uuid));
        if (scheduledJobOptional.isPresent()) {
            final ScheduledJob scheduledJob = scheduledJobOptional.get();

            if (scheduledJob.isSystem()) {
                logger.warn("Unable to delete system job.");
                throw new ValidationException(ValidationError.create("Unable to delete system job."));
            }

            if (scheduledJobHistoryRepository
                    .existsByScheduledJobUuidAndSchedulerExecutionStatusAndJobEndTimeIsNull(UUID.fromString(uuid),
                            SchedulerJobExecutionStatus.STARTED)) {
                logger.warn("Unable to delete scheduled job '{}' while it is executing.", scheduledJob.getJobName());
                throw new ValidationException(ValidationError
                        .create("Unable to delete scheduled job while it is executing. Wait for the current run to finish."));
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
    public ScheduledJobHistoryResponseDto getScheduledJobHistory(final SecurityFilter filter,
            final PaginationRequestDto paginationRequestDto, final String uuid) {
        final TriFunction<Root<ScheduledJobHistory>, CriteriaBuilder, CriteriaQuery<?>, Predicate> additionalWhereClause = (
                root, cb, cr) -> FilterPredicatesBuilder.constructFilterForJobHistory(cb, root, UUID.fromString(uuid));

        RequestValidatorHelper.revalidatePaginationRequestDto(paginationRequestDto);
        final Pageable pageable = PageRequest
                .of(paginationRequestDto.getPageNumber() - 1, paginationRequestDto.getItemsPerPage());
        final List<ScheduledJobHistory> scheduledJobHistoryList = scheduledJobHistoryRepository
                .findUsingSecurityFilter(filter, List.of(), additionalWhereClause, pageable,
                        (root, cb) -> cb.desc(root.get("jobExecution")));

        final Long maxItems = scheduledJobHistoryRepository.countUsingSecurityFilter(filter, additionalWhereClause);
        final ScheduledJobHistoryResponseDto responseDto = new ScheduledJobHistoryResponseDto();
        responseDto
                .setScheduledJobHistory(scheduledJobHistoryList.stream().map(ScheduledJobHistory::mapToDto).toList());
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
    @ExternalAuthorization(resource = Resource.SCHEDULED_JOB, action = ResourceAction.UPDATE)
    public ScheduledJobDetailDto updateScheduledJob(String uuid, UpdateScheduledJob request)
            throws NotFoundException, SchedulerException {
        ScheduledJob scheduledJob = scheduledJobsRepository
                .findByUuid(SecuredUUID.fromString(uuid))
                .orElseThrow(() -> new NotFoundException(ScheduledJob.class, uuid));
        if (scheduledJob.isSystem()) {
            throw new ValidationException("Cannot updated system job.");
        }
        SchedulerRequestDto schedulerRequestDto = new SchedulerRequestDto(new SchedulerJobDto(scheduledJob.getUuid(),
                scheduledJob.getJobName(), request.getCronExpression(), scheduledJob.getJobClassName()));
        schedulerApiClient.updateScheduledJob(schedulerRequestDto);
        if (!scheduledJob.isEnabled()) {
            disableScheduledJob(uuid);
        }

        scheduledJob.setCronExpression(request.getCronExpression());
        scheduledJobsRepository.save(scheduledJob);

        return scheduledJob
                .mapToDetailDto(scheduledJobHistoryRepository
                        .findTopByScheduledJobUuidOrderByJobExecutionDesc(UUID.fromString(uuid)));
    }

    private void changeScheduledJobState(final String uuid, final boolean enabled)
            throws SchedulerException, NotFoundException {
        final Optional<ScheduledJob> scheduledJobOptional = scheduledJobsRepository
                .findByUuid(SecuredUUID.fromString(uuid));
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
    public ScheduledJobDetailDto registerScheduledJob(final Class<? extends ScheduledJobTask> scheduledJobTaskClass)
            throws SchedulerException {
        final ScheduledJobTask scheduledJobTask = applicationContext.getBean(scheduledJobTaskClass);
        return registerScheduler(scheduledJobTask, scheduledJobTask.getDefaultJobName(),
                scheduledJobTask.getDefaultCronExpression(), scheduledJobTask.isDefaultOneTimeJob(), null);
    }

    @Override
    @ExternalAuthorization(resource = Resource.SCHEDULED_JOB, action = ResourceAction.CREATE)
    public ScheduledJobDetailDto registerScheduledJob(final Class<? extends ScheduledJobTask> scheduledJobTaskClass,
            final String jobName, final String cronExpression, final boolean oneTime, final Object taskData)
            throws SchedulerException {
        final ScheduledJobTask scheduledJobTask = applicationContext.getBean(scheduledJobTaskClass);
        return registerScheduler(scheduledJobTask, jobName, cronExpression, oneTime, taskData);
    }

    /**
     * Runs with no transaction of its own, whoever calls it: a caller's transaction would put the job back under
     * {@code spring.transaction.default-timeout} (core#2251). Every history write is the writer's own short
     * transaction; the only repository call made here directly is a read.
     */
    @Override
    @Transactional(propagation = Propagation.NOT_SUPPORTED)
    public void runScheduledJob(final String jobName) throws NotFoundException {
        final ScheduledJob scheduledJob = scheduledJobsRepository
                .findByJobName(jobName)
                .orElseThrow(() -> new NotFoundException(ScheduledJobHistory.class, jobName));

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
            String errorMessage = "Unknown scheduled task '%s' for job '%s'"
                    .formatted(scheduledJob.getJobClassName(), scheduledJob.getJobName());
            historyWriter.recordUnknownTask(scheduledJob, errorMessage);
            logger.error(errorMessage);
            return;
        }

        // Committed before the task runs: the history shows the run while it runs, and nothing the task does --
        // however long it takes -- can roll this row back. Runs with no transaction of its own (see
        // SchedulerListener); every write below is the writer's own short transaction.
        final ScheduledJobHistory history = historyWriter.recordStarted(scheduledJob);
        final ScheduledJobInfo jobInfo = new ScheduledJobInfo(scheduledJob.getJobName(), scheduledJob.getUuid(),
                history.getUuid());

        final ScheduledTaskResult result;
        boolean outcomeHandled = false;
        try {
            if (scheduledJob.getUserUuid() != null) {
                authHelper.authenticateAsUser(scheduledJob.getUserUuid());
            }
            result = scheduledJobTask.performJob(jobInfo, scheduledJob.getObjectData());
            outcomeHandled = true;
        } catch (ScheduledJobSkippedException e) {
            outcomeHandled = true;
            logger.debug("Skipping scheduled job '{}', removing history entry", scheduledJob.getJobName());
            try {
                historyWriter.removeSkipped(history.getUuid());
            } catch (RuntimeException bookkeeping) {
                // A skip is not a failure; the row that should have gone is named so an operator can remove it.
                logger
                        .error("Scheduled job '{}' was skipped but its history row {} could not be removed",
                                scheduledJob.getJobName(), history.getUuid(), bookkeeping);
            }
            return;
        } catch (RuntimeException e) {
            outcomeHandled = true;
            // Threw, as opposed to returned null: without this the row would stay STARTED forever and
            // deleteScheduledJob would refuse the job as "executing". The text is shaped: an exception's own message
            // can quote driver or framework internals, and this one reaches the scheduler API.
            try {
                historyWriter
                        .recordFailed(history.getUuid(),
                                PlatformException.safeMessage(e, "The job failed unexpectedly; see the Core log"));
            } catch (RuntimeException bookkeeping) {
                // The task's own failure is the one to surface; the bookkeeping failure rides along.
                e.addSuppressed(bookkeeping);
            }
            throw e;
        } finally {
            if (!outcomeHandled) {
                // Only an Error gets here (performJob declares no checked exception). It is not caught -- whether the
                // message is redelivered is the JMS retry policy's call -- but the row it would leave behind is closed,
                // or deleteScheduledJob would refuse the job as "executing" forever.
                try {
                    historyWriter.recordFailed(history.getUuid(), "The job failed with an error; see the Core log");
                } catch (RuntimeException bookkeeping) {
                    logger
                            .error("Scheduled job '{}' failed with an error and its history row {} could not be closed",
                                    scheduledJob.getJobName(), history.getUuid(), bookkeeping);
                }
            }
        }

        if (result == null) {
            // Finishes asynchronously (DiscoveryCertificateTask while the discovery is PROCESSING);
            // handleScheduledJobFinishedEvent closes the row later.
            return;
        }
        finalizeFinishedScheduledJob(scheduledJob, history.getUuid(), result);
    }

    /**
     * {@code NOT_SUPPORTED}: this runs in the {@code AFTER_COMMIT} phase of the publishing transaction, which is
     * committed but still registered, so a {@code REQUIRED} write made here would join it and be lost. Suspending it
     * lets the writer's {@code REQUIRED} methods start transactions of their own, and keeps the deregistration call to
     * the scheduler and the finished-job event outside any database transaction. The status commits first, then the
     * outside is told: the order the history has to be able to vouch for.
     */
    @Transactional(propagation = Propagation.NOT_SUPPORTED)
    @TransactionalEventListener(phase = TransactionPhase.AFTER_COMMIT)
    public void handleScheduledJobFinishedEvent(ScheduledJobFinishedEvent event) throws NotFoundException {
        logger.debug("ScheduledJobFinished event handler: {}", event.scheduledJobInfo().jobUuid());
        final ScheduledTaskResult result = Objects
                .requireNonNull(event.result(), "a ScheduledJobFinishedEvent carries the run's result");
        final ScheduledJob scheduledJob = scheduledJobsRepository
                .findByUuid(SecuredUUID.fromUUID(event.scheduledJobInfo().jobUuid()))
                .orElseThrow(() -> new NotFoundException(ScheduledJob.class, event.scheduledJobInfo().jobUuid()));
        finalizeFinishedScheduledJob(scheduledJob, event.scheduledJobInfo().jobHistoryUuid(), result);
    }

    /**
     * Closes the run: the final status is committed first, and only then are the outside parties told -- the scheduler
     * for a one-time job, the event consumers for a non-system one -- so nothing is ever reported that the history
     * cannot confirm.
     */
    private void finalizeFinishedScheduledJob(ScheduledJob scheduledJob, UUID historyUuid, ScheduledTaskResult result) {
        logger.debug("Finalizing finished scheduled job '{}'", scheduledJob.getJobName());

        try {
            historyWriter.recordFinished(historyUuid, result);
        } catch (RuntimeException e) {
            // The close write failed -- a failover, a pooler restart. The row must not stay STARTED, so a second close
            // marks it FAILED and names the real outcome; the outside is told nothing the history cannot confirm, and
            // a missing SUCCESS row only makes the next sync re-list, which is safe.
            try {
                historyWriter
                        .recordFailed(historyUuid, "The run finished with " + result.getStatus()
                                + " but its history could not be closed; see the Core log");
            } catch (RuntimeException again) {
                e.addSuppressed(again);
            }
            throw e;
        }

        // deregister one-time job
        if (SchedulerJobExecutionStatus.SUCCESS.equals(result.getStatus()) && scheduledJob.isOneTime()) {
            try {
                schedulerApiClient.deleteScheduledJob(scheduledJob.getJobName());
                logger
                        .info("Scheduled job '{}' was deleted/unscheduled because it was one-time job only.",
                                scheduledJob.getJobName());
            } catch (SchedulerException | RuntimeException e) {
                // The client surfaces transport and status failures unchecked; either way the status is committed
                // and the finished-job event below must still go out.
                logger.error("Failed to delete/unschedule finished one-time job '{}'", scheduledJob.getJobName(), e);
            }
        }

        // raise event for non-system job
        if (!scheduledJob.isSystem()) {
            try {
                eventProducer
                        .produceMessage(
                                ScheduledJobFinishedEventHandler.constructEventMessage(scheduledJob.getUuid(), result));
            } catch (RuntimeException e) {
                // The status is committed and a redelivery would run the job again, so the event is what is lost.
                logger
                        .error("Scheduled job '{}' finished with {}, but its finished-job event could not be sent",
                                scheduledJob.getJobName(), result.getStatus(), e);
            }
        }

        logger.info("Scheduled job '{}' has finished", scheduledJob.getJobName());
    }

    private ScheduledJobDetailDto registerScheduler(ScheduledJobTask scheduledJobTask, final String jobName,
            final String cronExpression, final boolean oneTime, final Object taskData) throws SchedulerException {
        if (scheduledJobTask == null) {
            throw new SchedulerException("Unknown scheduled task for job: " + jobName);
        }

        final SchedulerJobDto schedulerDetail = new SchedulerJobDto(jobName, cronExpression,
                scheduledJobTask.getJobClassName());
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

}
