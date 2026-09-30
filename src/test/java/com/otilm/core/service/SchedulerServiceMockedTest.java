package com.otilm.core.service;

import ch.qos.logback.classic.Level;
import ch.qos.logback.classic.Logger;
import ch.qos.logback.classic.spi.ILoggingEvent;
import ch.qos.logback.core.read.ListAppender;
import com.otilm.api.clients.SchedulerApiClient;
import com.otilm.api.exception.ConnectionServiceException;
import com.otilm.api.exception.NotFoundException;
import com.otilm.api.exception.SchedulerException;
import com.otilm.api.exception.ValidationException;
import com.otilm.api.model.core.scheduler.PaginationRequestDto;
import com.otilm.api.model.core.scheduler.ScheduledJobDetailDto;
import com.otilm.api.model.core.scheduler.ScheduledJobHistoryResponseDto;
import com.otilm.api.model.core.scheduler.ScheduledJobScheduleState;
import com.otilm.api.model.core.scheduler.ScheduledJobsResponseDto;
import com.otilm.api.model.scheduler.SchedulerJobDto;
import com.otilm.api.model.scheduler.SchedulerJobExecutionStatus;
import com.otilm.api.model.scheduler.SchedulerResponseDto;
import com.otilm.api.model.scheduler.SchedulerStatus;
import com.otilm.api.model.scheduler.SchedulerTriggerState;
import com.otilm.api.model.scheduler.UpdateScheduledJob;
import com.otilm.core.api.ScheduledJobSkippedException;
import com.otilm.core.dao.entity.ScheduledJob;
import com.otilm.core.dao.entity.ScheduledJobHistory;
import com.otilm.core.dao.repository.ScheduledJobHistoryRepository;
import com.otilm.core.dao.repository.ScheduledJobsRepository;
import com.otilm.core.events.transaction.ScheduledJobFinishedEvent;
import com.otilm.core.messaging.jms.producers.EventProducer;
import com.otilm.core.model.ScheduledTaskResult;
import com.otilm.core.security.authz.SecuredUUID;
import com.otilm.core.security.authz.SecurityFilter;
import com.otilm.core.service.impl.SchedulerServiceImpl;
import com.otilm.core.service.writer.scheduler.ScheduledJobHistoryWriter;
import com.otilm.core.service.writer.scheduler.ScheduledJobWriter;
import com.otilm.core.tasks.ScheduledJobInfo;
import com.otilm.core.tasks.ScheduledJobTask;
import com.otilm.core.util.AuthHelper;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;
import java.util.Optional;
import java.util.UUID;
import java.util.function.Supplier;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.EnumSource;
import org.mockito.ArgumentCaptor;
import org.mockito.InOrder;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.MockedStatic;
import org.mockito.junit.jupiter.MockitoExtension;
import org.slf4j.LoggerFactory;
import org.springframework.context.ApplicationContext;
import org.springframework.data.domain.Pageable;
import org.springframework.http.HttpStatus;
import reactor.core.Exceptions;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.argThat;
import static org.mockito.ArgumentMatchers.contains;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.ArgumentMatchers.isNull;
import static org.mockito.Mockito.atLeastOnce;
import static org.mockito.Mockito.doReturn;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.inOrder;
import static org.mockito.Mockito.mockStatic;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.spy;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class SchedulerServiceMockedTest {

    @Mock
    private ScheduledJobsRepository scheduledJobsRepository;

    @Mock
    private ScheduledJobHistoryRepository scheduledJobHistoryRepository;

    @Mock
    private ScheduledJobHistoryWriter historyWriter;

    @Mock
    private ScheduledJobWriter scheduledJobWriter;

    @Mock
    private ApplicationContext applicationContext;

    @Mock
    private AuthHelper authHelper;

    @Mock
    private SchedulerApiClient schedulerApiClient;

    @Mock
    private EventProducer eventProducer;

    @InjectMocks
    private SchedulerServiceImpl schedulerService;

    private ScheduledJob scheduledJob;
    private ScheduledJobHistory scheduledJobHistory;

    private static final String JOB_NAME = "TestScheduledJob";
    private static final UUID JOB_UUID = UUID.randomUUID();
    private static final UUID HISTORY_UUID = UUID.randomUUID();

    @BeforeEach
    void setUp() {
        scheduledJob = new ScheduledJob();
        scheduledJob.setUuid(JOB_UUID);
        scheduledJob.setJobName(JOB_NAME);
        scheduledJob.setCronExpression("0 0 * * * ?");
        scheduledJob.setJobClassName(TestTask.class.getName());
        scheduledJob.setEnabled(true);
        scheduledJob.setSystem(false);
        scheduledJob.setOneTime(false);

        scheduledJobHistory = new ScheduledJobHistory();
        scheduledJobHistory.setUuid(HISTORY_UUID);
        scheduledJobHistory.setScheduledJobUuid(JOB_UUID);
        scheduledJobHistory.setJobExecution(new Date());
        scheduledJobHistory.setSchedulerExecutionStatus(SchedulerJobExecutionStatus.STARTED);
    }

    @Test
    void testListScheduledJobs_ReturnsPagedResponse() {
        PaginationRequestDto pagination = new PaginationRequestDto();
        pagination.setPageNumber(1);
        pagination.setItemsPerPage(10);

        when(scheduledJobsRepository
                .findUsingSecurityFilter(any(), eq(List.of()), isNull(), any(Pageable.class), isNull()))
                .thenReturn(List.of(scheduledJob));
        when(scheduledJobsRepository.countUsingSecurityFilter(any(), isNull())).thenReturn(1L);
        when(scheduledJobHistoryRepository.findTopByScheduledJobUuidOrderByJobExecutionDesc(JOB_UUID))
                .thenReturn(scheduledJobHistory);

        ScheduledJobsResponseDto response = schedulerService.listScheduledJobs(SecurityFilter.create(), pagination);

        assertEquals(1, response.getScheduledJobs().size());
        assertEquals(1L, response.getTotalItems());
        assertEquals(1, response.getTotalPages());
        assertEquals(10, response.getItemsPerPage());
        assertEquals(1, response.getPageNumber());
    }

    @Test
    void testListScheduledJobs_ReadsTheSchedulerOncePerPage() {
        PaginationRequestDto pagination = new PaginationRequestDto();
        ScheduledJob other = new ScheduledJob();
        other.setUuid(UUID.randomUUID());
        other.setJobName("OtherJob");
        other.setJobClassName(TestTask.class.getName());
        other.setCronExpression("0 0 * * * ?");
        when(scheduledJobsRepository
                .findUsingSecurityFilter(any(), eq(List.of()), isNull(), any(Pageable.class), isNull()))
                .thenReturn(List.of(scheduledJob, other));
        when(scheduledJobsRepository.countUsingSecurityFilter(any(), isNull())).thenReturn(2L);
        when(schedulerApiClient.listScheduledJobs()).thenReturn(schedulerHolding(JOB_NAME));

        ScheduledJobsResponseDto response = schedulerService.listScheduledJobs(SecurityFilter.create(), pagination);

        verify(schedulerApiClient, times(1)).listScheduledJobs();
        assertEquals(ScheduledJobScheduleState.SCHEDULED, response.getScheduledJobs().get(0).getScheduleState());
        assertEquals(Instant.parse("2026-09-29T12:30:00Z"), response.getScheduledJobs().get(0).getNextFireTime());
        assertEquals(ScheduledJobScheduleState.NOT_SCHEDULED, response.getScheduledJobs().get(1).getScheduleState());
    }

    /**
     * An outage must not fail the page, and must not print a trace per listing either: one WARN, without the trace and
     * without the exception's own text, which for an error status is the scheduler's response body.
     */
    @Test
    void testListScheduledJobs_WhenTheSchedulerCannotBeRead_ServesUnknown() {
        PaginationRequestDto pagination = new PaginationRequestDto();
        when(scheduledJobsRepository
                .findUsingSecurityFilter(any(), eq(List.of()), isNull(), any(Pageable.class), isNull()))
                .thenReturn(List.of(scheduledJob));
        when(scheduledJobsRepository.countUsingSecurityFilter(any(), isNull())).thenReturn(1L);
        when(schedulerApiClient.listScheduledJobs())
                .thenThrow(new IllegalStateException("Timeout on blocking read for 5000000000 NS"));
        List<ILoggingEvent> warnings = new ArrayList<>();

        ScheduledJobsResponseDto response = capturingWarnings(warnings, () -> assertDoesNotThrow(
                () -> schedulerService.listScheduledJobs(SecurityFilter.create(), pagination)));

        assertEquals(1, response.getScheduledJobs().size());
        assertEquals(ScheduledJobScheduleState.UNKNOWN, response.getScheduledJobs().get(0).getScheduleState());
        assertNull(response.getScheduledJobs().get(0).getNextFireTime());
        assertEquals(1, warnings.size());
        assertNull(warnings.get(0).getThrowableProxy());
        assertFalse(warnings.get(0).getFormattedMessage().contains("Timeout on blocking read"));
    }

    /**
     * An error status names its status on the WARN, so that a scheduler that predates the list (500), a base URL that
     * points elsewhere (404) and a proxy that refuses core (401, 403) read apart. The body stays out: it is the
     * answering server's own text, and it is also the exception's message.
     */
    @ParameterizedTest
    @EnumSource(value = HttpStatus.class, names = {"UNAUTHORIZED", "FORBIDDEN", "NOT_FOUND", "INTERNAL_SERVER_ERROR"})
    void testListScheduledJobs_WhenTheSchedulerAnswersAnErrorStatus_WarnsOnceWithTheStatusOnly(HttpStatus status) {
        PaginationRequestDto pagination = new PaginationRequestDto();
        when(scheduledJobsRepository
                .findUsingSecurityFilter(any(), eq(List.of()), isNull(), any(Pageable.class), isNull()))
                .thenReturn(List.of(scheduledJob));
        when(scheduledJobsRepository.countUsingSecurityFilter(any(), isNull())).thenReturn(1L);
        // As the client throws it: the checked exception wrapped by reactor on the blocking read. Thrown from an
        // answer, since thenThrow would throw the checked cause itself (the wrapper's fillInStackTrace returns it).
        when(schedulerApiClient.listScheduledJobs()).thenAnswer(invocation -> {
            throw Exceptions.propagate(new ConnectionServiceException("scheduler-node-7 stack", status));
        });
        List<ILoggingEvent> warnings = new ArrayList<>();

        ScheduledJobsResponseDto response = capturingWarnings(warnings, () -> assertDoesNotThrow(
                () -> schedulerService.listScheduledJobs(SecurityFilter.create(), pagination)));

        assertEquals(ScheduledJobScheduleState.UNKNOWN, response.getScheduledJobs().get(0).getScheduleState());
        assertEquals(1, warnings.size());
        assertNull(warnings.get(0).getThrowableProxy());
        String warning = warnings.get(0).getFormattedMessage();
        assertTrue(warning.contains("ConnectionServiceException"), warning);
        assertTrue(warning.contains("HTTP " + status.value()), warning);
        assertFalse(warning.contains("scheduler-node-7"), warning);
    }

    /** An answer without a usable job list is as unread as an outage, and is reported the same way: by its status. */
    @Test
    void testListScheduledJobs_WhenTheAnswerIsNotOk_ServesUnknownAndWarnsOnce() {
        PaginationRequestDto pagination = new PaginationRequestDto();
        when(scheduledJobsRepository
                .findUsingSecurityFilter(any(), eq(List.of()), isNull(), any(Pageable.class), isNull()))
                .thenReturn(List.of(scheduledJob));
        when(scheduledJobsRepository.countUsingSecurityFilter(any(), isNull())).thenReturn(1L);
        when(schedulerApiClient.listScheduledJobs())
                .thenReturn(new SchedulerResponseDto(SchedulerStatus.ERROR, "scheduler-node-7"));
        List<ILoggingEvent> warnings = new ArrayList<>();

        ScheduledJobsResponseDto response = capturingWarnings(warnings,
                () -> schedulerService.listScheduledJobs(SecurityFilter.create(), pagination));

        assertEquals(ScheduledJobScheduleState.UNKNOWN, response.getScheduledJobs().get(0).getScheduleState());
        assertEquals(1, warnings.size());
        assertNull(warnings.get(0).getThrowableProxy());
        assertTrue(warnings.get(0).getFormattedMessage().contains("schedulerStatus ERROR"));
        assertFalse(warnings.get(0).getFormattedMessage().contains("scheduler-node-7"));
    }

    /**
     * A scheduler that predates the trigger fields answers OK with a job list and no states. Every job is unknown, and
     * the one WARN says why: the list is there, the states are not.
     */
    @Test
    void testListScheduledJobs_WhenTheAnswerCarriesNoTriggerState_ServesUnknownAndWarnsOnce() {
        PaginationRequestDto pagination = new PaginationRequestDto();
        ScheduledJob omitted = new ScheduledJob();
        omitted.setUuid(UUID.randomUUID());
        omitted.setJobName("OmittedJob");
        omitted.setJobClassName(TestTask.class.getName());
        omitted.setCronExpression("0 0 * * * ?");
        when(scheduledJobsRepository
                .findUsingSecurityFilter(any(), eq(List.of()), isNull(), any(Pageable.class), isNull()))
                .thenReturn(List.of(scheduledJob, omitted));
        when(scheduledJobsRepository.countUsingSecurityFilter(any(), isNull())).thenReturn(2L);
        SchedulerResponseDto answer = schedulerHolding(JOB_NAME);
        answer.getSchedulerJobList().getFirst().setTriggerState(null);
        when(schedulerApiClient.listScheduledJobs()).thenReturn(answer);
        List<ILoggingEvent> warnings = new ArrayList<>();

        ScheduledJobsResponseDto response = capturingWarnings(warnings,
                () -> schedulerService.listScheduledJobs(SecurityFilter.create(), pagination));

        assertEquals(ScheduledJobScheduleState.UNKNOWN, response.getScheduledJobs().get(0).getScheduleState());
        assertEquals(ScheduledJobScheduleState.UNKNOWN, response.getScheduledJobs().get(1).getScheduleState());
        assertEquals(1, warnings.size());
        assertNull(warnings.get(0).getThrowableProxy());
        assertTrue(warnings.get(0).getFormattedMessage().contains("no trigger state"),
                warnings.get(0).getFormattedMessage());
    }

    @Test
    void testGetScheduledJobDetail_WhenTheSchedulerAnswersAnEmptyBody_ServesUnknownAndWarnsOnce() {
        when(scheduledJobsRepository.findByUuid(any(SecuredUUID.class))).thenReturn(Optional.of(scheduledJob));
        when(schedulerApiClient.listScheduledJobs()).thenReturn(null);
        List<ILoggingEvent> warnings = new ArrayList<>();

        ScheduledJobDetailDto response = capturingWarnings(warnings,
                () -> assertDoesNotThrow(() -> schedulerService.getScheduledJobDetail(JOB_UUID.toString())));

        assertEquals(ScheduledJobScheduleState.UNKNOWN, response.getScheduleState());
        assertEquals(1, warnings.size());
        assertTrue(warnings.get(0).getFormattedMessage().contains("empty body"));
    }

    @Test
    void testListScheduledJobs_WhenThePageIsEmpty_DoesNotReadTheScheduler() {
        PaginationRequestDto pagination = new PaginationRequestDto();
        when(scheduledJobsRepository
                .findUsingSecurityFilter(any(), eq(List.of()), isNull(), any(Pageable.class), isNull()))
                .thenReturn(List.of());
        when(scheduledJobsRepository.countUsingSecurityFilter(any(), isNull())).thenReturn(0L);

        schedulerService.listScheduledJobs(SecurityFilter.create(), pagination);

        verify(schedulerApiClient, never()).listScheduledJobs();
    }

    @Test
    void testGetScheduledJobDetail_CarriesTheObservedSchedule() throws Exception {
        when(scheduledJobsRepository.findByUuid(any(SecuredUUID.class))).thenReturn(Optional.of(scheduledJob));
        when(schedulerApiClient.listScheduledJobs()).thenReturn(schedulerHolding(JOB_NAME));

        ScheduledJobDetailDto response = schedulerService.getScheduledJobDetail(JOB_UUID.toString());

        assertEquals(ScheduledJobScheduleState.SCHEDULED, response.getScheduleState());
        assertEquals(Instant.parse("2026-09-29T11:30:00Z"), response.getPreviousFireTime());
    }

    @Test
    void testGetScheduledJobDetail_ReturnsDetail() throws Exception {
        when(scheduledJobsRepository.findByUuid(any(SecuredUUID.class))).thenReturn(Optional.of(scheduledJob));
        when(scheduledJobHistoryRepository.findTopByScheduledJobUuidOrderByJobExecutionDesc(JOB_UUID))
                .thenReturn(scheduledJobHistory);

        ScheduledJobDetailDto response = schedulerService.getScheduledJobDetail(JOB_UUID.toString());

        assertNotNull(response);
        verify(scheduledJobsRepository).findByUuid(any(SecuredUUID.class));
        verify(scheduledJobHistoryRepository).findTopByScheduledJobUuidOrderByJobExecutionDesc(JOB_UUID);
    }

    @Test
    void testGetScheduledJobDetail_WhenNotFound_ThrowsNotFoundException() {
        when(scheduledJobsRepository.findByUuid(any(SecuredUUID.class))).thenReturn(Optional.empty());

        assertThrows(NotFoundException.class, () -> schedulerService.getScheduledJobDetail(JOB_UUID.toString()));
    }

    @Test
    void testDeleteScheduledJob_WhenJobDoesNotExist_DoesNothing() throws SchedulerException {
        when(scheduledJobsRepository.findByUuid(any(SecuredUUID.class))).thenReturn(Optional.empty());

        assertDoesNotThrow(() -> schedulerService.deleteScheduledJob(JOB_UUID.toString()));

        verify(schedulerApiClient, never()).deleteScheduledJob(anyString());
        verify(scheduledJobsRepository, never()).deleteById(any());
    }

    @Test
    void testDeleteScheduledJob_WhenSystemJob_ThrowsValidationException() throws SchedulerException {
        scheduledJob.setSystem(true);
        when(scheduledJobsRepository.findByUuid(any(SecuredUUID.class))).thenReturn(Optional.of(scheduledJob));

        assertThrows(ValidationException.class, () -> schedulerService.deleteScheduledJob(JOB_UUID.toString()));

        verify(schedulerApiClient, never()).deleteScheduledJob(anyString());
        verify(scheduledJobsRepository, never()).deleteById(any());
    }

    @Test
    void testDeleteScheduledJob_WhenExecutionInFlight_ThrowsValidationException() throws SchedulerException {
        when(scheduledJobsRepository.findByUuid(any(SecuredUUID.class))).thenReturn(Optional.of(scheduledJob));
        when(scheduledJobHistoryRepository
                .existsByScheduledJobUuidAndSchedulerExecutionStatusAndJobEndTimeIsNull(JOB_UUID,
                        SchedulerJobExecutionStatus.STARTED))
                .thenReturn(true);

        assertThrows(ValidationException.class, () -> schedulerService.deleteScheduledJob(JOB_UUID.toString()));

        verify(schedulerApiClient, never()).deleteScheduledJob(anyString());
        verify(scheduledJobsRepository, never()).deleteById(any());
    }

    @Test
    void testDeleteScheduledJob_WhenSchedulerDeleteSucceeds_DeletesRepositoryRecord() throws Exception {
        when(scheduledJobsRepository.findByUuid(any(SecuredUUID.class))).thenReturn(Optional.of(scheduledJob));
        when(scheduledJobHistoryRepository
                .existsByScheduledJobUuidAndSchedulerExecutionStatusAndJobEndTimeIsNull(JOB_UUID,
                        SchedulerJobExecutionStatus.STARTED))
                .thenReturn(false);

        schedulerService.deleteScheduledJob(JOB_UUID.toString());

        verify(schedulerApiClient).deleteScheduledJob(JOB_NAME);
        verify(scheduledJobsRepository).deleteById(JOB_UUID);
    }

    @Test
    void testDeleteScheduledJob_WhenSchedulerDeleteFails_SwallowsException() throws Exception {
        when(scheduledJobsRepository.findByUuid(any(SecuredUUID.class))).thenReturn(Optional.of(scheduledJob));
        when(scheduledJobHistoryRepository
                .existsByScheduledJobUuidAndSchedulerExecutionStatusAndJobEndTimeIsNull(JOB_UUID,
                        SchedulerJobExecutionStatus.STARTED))
                .thenReturn(false);
        doThrow(new SchedulerException("boom")).when(schedulerApiClient).deleteScheduledJob(JOB_NAME);

        assertDoesNotThrow(() -> schedulerService.deleteScheduledJob(JOB_UUID.toString()));

        verify(scheduledJobsRepository, never()).deleteById(any());
    }

    @Test
    void testGetScheduledJobHistory_ReturnsPagedResponse() {
        PaginationRequestDto pagination = new PaginationRequestDto();
        pagination.setPageNumber(1);
        pagination.setItemsPerPage(10);

        when(scheduledJobHistoryRepository
                .findUsingSecurityFilter(any(), eq(List.of()), any(), any(Pageable.class), any()))
                .thenReturn(List.of(scheduledJobHistory));
        when(scheduledJobHistoryRepository.countUsingSecurityFilter(any(), any())).thenReturn(1L);

        ScheduledJobHistoryResponseDto response = schedulerService
                .getScheduledJobHistory(SecurityFilter.create(), pagination, JOB_UUID.toString());

        assertEquals(1, response.getScheduledJobHistory().size());
        assertEquals(1L, response.getTotalItems());
        assertEquals(1, response.getTotalPages());
    }

    @Test
    void testEnableScheduledJob_EnablesAndSavesJob() throws Exception {
        scheduledJob.setEnabled(false);
        when(scheduledJobsRepository.findByUuid(any(SecuredUUID.class))).thenReturn(Optional.of(scheduledJob));

        schedulerService.enableScheduledJob(JOB_UUID.toString());

        assertTrue(scheduledJob.isEnabled());
        verify(schedulerApiClient).enableScheduledJob(JOB_NAME);
        verify(scheduledJobsRepository).save(scheduledJob);
    }

    @Test
    void testDisableScheduledJob_DisablesAndSavesJob() throws Exception {
        scheduledJob.setEnabled(true);
        when(scheduledJobsRepository.findByUuid(any(SecuredUUID.class))).thenReturn(Optional.of(scheduledJob));

        schedulerService.disableScheduledJob(JOB_UUID.toString());

        assertFalse(scheduledJob.isEnabled());
        verify(schedulerApiClient).disableScheduledJob(JOB_NAME);
        verify(scheduledJobsRepository).save(scheduledJob);
    }

    @Test
    void testEnableScheduledJob_WhenNotFound_ThrowsNotFoundException() {
        when(scheduledJobsRepository.findByUuid(any(SecuredUUID.class))).thenReturn(Optional.empty());

        assertThrows(NotFoundException.class, () -> schedulerService.enableScheduledJob(JOB_UUID.toString()));
    }

    @Test
    void testUpdateScheduledJob_WhenNotFound_ThrowsNotFoundException() {
        when(scheduledJobsRepository.findByUuid(any(SecuredUUID.class))).thenReturn(Optional.empty());

        UpdateScheduledJob request = new UpdateScheduledJob();
        request.setCronExpression("0 15 * * * ?");

        assertThrows(NotFoundException.class, () -> schedulerService.updateScheduledJob(JOB_UUID.toString(), request));
    }

    @Test
    void testUpdateScheduledJob_WhenSystemJob_ThrowsValidationException() {
        scheduledJob.setSystem(true);
        when(scheduledJobsRepository.findByUuid(any(SecuredUUID.class))).thenReturn(Optional.of(scheduledJob));

        UpdateScheduledJob request = new UpdateScheduledJob();
        request.setCronExpression("0 15 * * * ?");

        assertThrows(ValidationException.class,
                () -> schedulerService.updateScheduledJob(JOB_UUID.toString(), request));
    }

    @Test
    void testUpdateScheduledJob_WhenEnabled_UpdatesCronAndDoesNotDisableAgain() throws Exception {
        scheduledJob.setEnabled(true);
        when(scheduledJobsRepository.findByUuid(any(SecuredUUID.class))).thenReturn(Optional.of(scheduledJob));
        when(scheduledJobHistoryRepository.findTopByScheduledJobUuidOrderByJobExecutionDesc(JOB_UUID))
                .thenReturn(scheduledJobHistory);

        when(schedulerApiClient.listScheduledJobs()).thenReturn(schedulerHolding(JOB_NAME));

        UpdateScheduledJob request = new UpdateScheduledJob();
        request.setCronExpression("0 15 * * * ?");

        ScheduledJobDetailDto response = schedulerService.updateScheduledJob(JOB_UUID.toString(), request);

        assertNotNull(response);
        assertEquals(ScheduledJobScheduleState.SCHEDULED, response.getScheduleState());
        assertEquals("0 15 * * * ?", scheduledJob.getCronExpression());
        verify(schedulerApiClient).updateScheduledJob(any());
        verify(schedulerApiClient, never()).disableScheduledJob(anyString());
        verify(scheduledJobsRepository).save(scheduledJob);
    }

    @Test
    void testUpdateScheduledJob_WhenDisabled_UpdatesCronAndReDisablesJob() throws Exception {
        scheduledJob.setEnabled(false);
        when(scheduledJobsRepository.findByUuid(any(SecuredUUID.class))).thenReturn(Optional.of(scheduledJob));
        when(scheduledJobHistoryRepository.findTopByScheduledJobUuidOrderByJobExecutionDesc(JOB_UUID))
                .thenReturn(scheduledJobHistory);

        UpdateScheduledJob request = new UpdateScheduledJob();
        request.setCronExpression("0 30 * * * ?");

        schedulerService.updateScheduledJob(JOB_UUID.toString(), request);

        verify(schedulerApiClient).updateScheduledJob(any());
        verify(schedulerApiClient).disableScheduledJob(JOB_NAME);
        verify(scheduledJobsRepository, atLeastOnce()).save(scheduledJob);
        assertFalse(scheduledJob.isEnabled());
    }

    @Test
    void testRegisterScheduledJob_WithDefaults_WhenAlreadyRegistered_ReturnsExistingDetail() throws Exception {
        TestTask task = new TestTask(new ScheduledTaskResult(SchedulerJobExecutionStatus.SUCCESS, "ok"));
        when(applicationContext.getBean(TestTask.class)).thenReturn(task);
        when(scheduledJobsRepository.findByJobName(task.getDefaultJobName())).thenReturn(Optional.of(scheduledJob));
        when(schedulerApiClient.listScheduledJobs()).thenReturn(schedulerHolding(JOB_NAME));

        ScheduledJobDetailDto response = schedulerService.registerScheduledJob(TestTask.class);

        assertNotNull(response);
        assertEquals(ScheduledJobScheduleState.SCHEDULED, response.getScheduleState());
        verify(schedulerApiClient).schedulerCreate(any());
        verify(scheduledJobsRepository, never()).save(any());
    }

    @Test
    void testRegisterScheduledJob_WithExplicitValues_SavesNewJob() throws Exception {
        TestTask task = new TestTask(new ScheduledTaskResult(SchedulerJobExecutionStatus.SUCCESS, "ok"));
        when(applicationContext.getBean(TestTask.class)).thenReturn(task);
        when(scheduledJobsRepository.findByJobName("CustomJob")).thenReturn(Optional.empty());

        try (MockedStatic<AuthHelper> authHelperMock = mockStatic(AuthHelper.class)) {
            authHelperMock.when(AuthHelper::getUserIdentification).thenThrow(new ValidationException("no auth"));

            ScheduledJobDetailDto response = schedulerService
                    .registerScheduledJob(TestTask.class, "CustomJob", "0 10 * * * ?", true, "payload");

            assertNotNull(response);
            // The mocked client answers no body: the scheduler could not be read.
            assertEquals(ScheduledJobScheduleState.UNKNOWN, response.getScheduleState());

            ArgumentCaptor<ScheduledJob> jobCaptor = ArgumentCaptor.forClass(ScheduledJob.class);
            verify(scheduledJobsRepository).save(jobCaptor.capture());

            ScheduledJob savedJob = jobCaptor.getValue();
            assertEquals("CustomJob", savedJob.getJobName());
            assertEquals("0 10 * * * ?", savedJob.getCronExpression());
            assertEquals("payload", savedJob.getObjectData());
            assertTrue(savedJob.isOneTime());
            assertTrue(savedJob.isEnabled());
            assertNull(savedJob.getUserUuid());
            assertEquals(TestTask.class.getName(), savedJob.getJobClassName());
        }
    }

    @Test
    void testRunScheduledJob_WhenJobNotFound_ThrowsNotFoundException() {
        when(scheduledJobsRepository.findByJobName(JOB_NAME)).thenReturn(Optional.empty());

        assertThrows(NotFoundException.class, () -> schedulerService.runScheduledJob(JOB_NAME));
    }

    @Test
    void testRunScheduledJob_WhenTaskClassNotFound_RegistersFailedHistory() throws Exception {
        scheduledJob.setJobClassName("com.nonexistent.UnknownTask");
        when(scheduledJobsRepository.findByJobName(JOB_NAME)).thenReturn(Optional.of(scheduledJob));

        schedulerService.runScheduledJob(JOB_NAME);

        verify(historyWriter).recordUnknownTask(eq(scheduledJob), contains("Unknown scheduled task"));
        verify(historyWriter, never()).recordStarted(any());
    }

    @Test
    void testRunScheduledJob_WhenTaskIsNotScheduledJobTask_RegistersFailedHistory() throws Exception {
        when(scheduledJobsRepository.findByJobName(JOB_NAME)).thenReturn(Optional.of(scheduledJob));

        Object notATask = new Object();
        doReturn(notATask).when(applicationContext).getBean(eq(TestTask.class));

        schedulerService.runScheduledJob(JOB_NAME);

        verify(historyWriter).recordUnknownTask(eq(scheduledJob), contains("Unknown scheduled task"));
        verify(historyWriter, never()).recordStarted(any());
    }

    @Test
    void testRunScheduledJob_WhenJobSucceeds_UpdatesHistoryAndProducesEvent() throws Exception {
        TestTask testTask = spy(new TestTask(
                new ScheduledTaskResult(SchedulerJobExecutionStatus.SUCCESS, "Job completed successfully")));

        when(scheduledJobsRepository.findByJobName(JOB_NAME)).thenReturn(Optional.of(scheduledJob));
        when(historyWriter.recordStarted(scheduledJob)).thenReturn(scheduledJobHistory);
        when(applicationContext.getBean(eq(TestTask.class))).thenReturn(testTask);

        schedulerService.runScheduledJob(JOB_NAME);

        verify(testTask).performJob(any(ScheduledJobInfo.class), any());

        ArgumentCaptor<ScheduledTaskResult> resultCaptor = ArgumentCaptor.forClass(ScheduledTaskResult.class);
        verify(historyWriter).recordFinished(eq(HISTORY_UUID), resultCaptor.capture());
        assertEquals(SchedulerJobExecutionStatus.SUCCESS, resultCaptor.getValue().getStatus());
        assertEquals("Job completed successfully", resultCaptor.getValue().getResultMessage());

        verify(eventProducer).produceMessage(any());
    }

    @Test
    void testRunScheduledJob_WhenJobFails_UpdatesHistoryWithFailedStatus() throws Exception {
        TestTask testTask = spy(
                new TestTask(new ScheduledTaskResult(SchedulerJobExecutionStatus.FAILED, "Job failed with error")));

        when(scheduledJobsRepository.findByJobName(JOB_NAME)).thenReturn(Optional.of(scheduledJob));
        when(historyWriter.recordStarted(scheduledJob)).thenReturn(scheduledJobHistory);
        when(applicationContext.getBean(eq(TestTask.class))).thenReturn(testTask);

        schedulerService.runScheduledJob(JOB_NAME);

        ArgumentCaptor<ScheduledTaskResult> resultCaptor = ArgumentCaptor.forClass(ScheduledTaskResult.class);
        verify(historyWriter).recordFinished(eq(HISTORY_UUID), resultCaptor.capture());
        assertEquals(SchedulerJobExecutionStatus.FAILED, resultCaptor.getValue().getStatus());
        assertEquals("Job failed with error", resultCaptor.getValue().getResultMessage());

        verify(eventProducer).produceMessage(any());
    }

    @Test
    void testRunScheduledJob_WhenJobThrowsScheduledJobSkippedException_RecordsTheSkipAndDeletesHistory()
            throws Exception {
        TestTask testTask = spy(new TestTask(new ScheduledJobSkippedException("nothing to do")));

        when(scheduledJobsRepository.findByJobName(JOB_NAME)).thenReturn(Optional.of(scheduledJob));
        when(historyWriter.recordStarted(scheduledJob)).thenReturn(scheduledJobHistory);
        when(applicationContext.getBean(eq(TestTask.class))).thenReturn(testTask);

        schedulerService.runScheduledJob(JOB_NAME);

        verify(testTask).performJob(any(ScheduledJobInfo.class), any());
        // The skip first: should the run stop between the two writes, the signal that matters is the one kept.
        InOrder bookkeeping = inOrder(scheduledJobWriter, historyWriter);
        bookkeeping.verify(scheduledJobWriter).recordSkipped(JOB_UUID, "nothing to do");
        bookkeeping.verify(historyWriter).removeSkipped(HISTORY_UUID);
        verify(historyWriter, never()).recordFinished(any(), any());
        verify(historyWriter, never()).recordFailed(any(), any());
        verify(eventProducer, never()).produceMessage(any());
    }

    /** A skip is not a failure: bookkeeping that fails is logged, and the other write still happens. */
    @Test
    void testRunScheduledJob_WhenTheSkipCannotBeRecorded_StillRemovesTheHistoryRow() throws Exception {
        TestTask testTask = spy(new TestTask(new ScheduledJobSkippedException("nothing to do")));

        when(scheduledJobsRepository.findByJobName(JOB_NAME)).thenReturn(Optional.of(scheduledJob));
        when(historyWriter.recordStarted(scheduledJob)).thenReturn(scheduledJobHistory);
        when(applicationContext.getBean(eq(TestTask.class))).thenReturn(testTask);
        doThrow(new IllegalStateException("vanished"))
                .when(scheduledJobWriter)
                .recordSkipped(JOB_UUID, "nothing to do");

        assertDoesNotThrow(() -> schedulerService.runScheduledJob(JOB_NAME));

        verify(historyWriter).removeSkipped(HISTORY_UUID);
    }

    @Test
    void testRunScheduledJob_WhenTheHistoryRowCannotBeRemoved_TheSkipIsStillRecorded() throws Exception {
        TestTask testTask = spy(new TestTask(new ScheduledJobSkippedException("nothing to do")));

        when(scheduledJobsRepository.findByJobName(JOB_NAME)).thenReturn(Optional.of(scheduledJob));
        when(historyWriter.recordStarted(scheduledJob)).thenReturn(scheduledJobHistory);
        when(applicationContext.getBean(eq(TestTask.class))).thenReturn(testTask);
        doThrow(new IllegalStateException("vanished")).when(historyWriter).removeSkipped(HISTORY_UUID);

        assertDoesNotThrow(() -> schedulerService.runScheduledJob(JOB_NAME));

        verify(scheduledJobWriter).recordSkipped(JOB_UUID, "nothing to do");
    }

    @Test
    void testRunScheduledJob_WhenJobHasUserUuid_AuthenticatesAsUser() throws Exception {
        UUID userUuid = UUID.randomUUID();
        scheduledJob.setUserUuid(userUuid);

        TestTask testTask = spy(new TestTask(
                new ScheduledTaskResult(SchedulerJobExecutionStatus.SUCCESS, "Job completed successfully")));

        when(scheduledJobsRepository.findByJobName(JOB_NAME)).thenReturn(Optional.of(scheduledJob));
        when(historyWriter.recordStarted(scheduledJob)).thenReturn(scheduledJobHistory);
        when(applicationContext.getBean(eq(TestTask.class))).thenReturn(testTask);

        schedulerService.runScheduledJob(JOB_NAME);

        verify(authHelper).authenticateAsUser(userUuid);
    }

    @Test
    void testRunScheduledJob_WhenJobHasObjectData_PassesItToTask() throws Exception {
        Object taskData = new Object();
        scheduledJob.setObjectData(taskData);

        TestTask testTask = spy(new TestTask(
                new ScheduledTaskResult(SchedulerJobExecutionStatus.SUCCESS, "Job completed successfully")));

        when(scheduledJobsRepository.findByJobName(JOB_NAME)).thenReturn(Optional.of(scheduledJob));
        when(historyWriter.recordStarted(scheduledJob)).thenReturn(scheduledJobHistory);
        when(applicationContext.getBean(eq(TestTask.class))).thenReturn(testTask);

        schedulerService.runScheduledJob(JOB_NAME);

        ArgumentCaptor<Object> dataCaptor = ArgumentCaptor.forClass(Object.class);
        verify(testTask).performJob(any(ScheduledJobInfo.class), dataCaptor.capture());
        assertSame(taskData, dataCaptor.getValue());
    }

    @Test
    void testRunScheduledJob_CreatesHistoryWithCorrectScheduledJobInfo() throws Exception {
        TestTask testTask = spy(new TestTask(
                new ScheduledTaskResult(SchedulerJobExecutionStatus.SUCCESS, "Job completed successfully")));

        when(scheduledJobsRepository.findByJobName(JOB_NAME)).thenReturn(Optional.of(scheduledJob));
        when(historyWriter.recordStarted(scheduledJob)).thenReturn(scheduledJobHistory);
        when(applicationContext.getBean(eq(TestTask.class))).thenReturn(testTask);

        schedulerService.runScheduledJob(JOB_NAME);

        ArgumentCaptor<ScheduledJobInfo> infoCaptor = ArgumentCaptor.forClass(ScheduledJobInfo.class);
        verify(testTask).performJob(infoCaptor.capture(), any());

        ScheduledJobInfo jobInfo = infoCaptor.getValue();
        assertEquals(JOB_NAME, jobInfo.jobName());
        assertEquals(JOB_UUID, jobInfo.jobUuid());
        assertEquals(HISTORY_UUID, jobInfo.jobHistoryUuid());
    }

    @Test
    void testRunScheduledJob_WhenOneTimeSuccessful_DeletesScheduledJob() throws Exception {
        scheduledJob.setOneTime(true);

        TestTask testTask = spy(new TestTask(new ScheduledTaskResult(SchedulerJobExecutionStatus.SUCCESS, "done")));

        when(scheduledJobsRepository.findByJobName(JOB_NAME)).thenReturn(Optional.of(scheduledJob));
        when(historyWriter.recordStarted(scheduledJob)).thenReturn(scheduledJobHistory);
        when(applicationContext.getBean(eq(TestTask.class))).thenReturn(testTask);

        schedulerService.runScheduledJob(JOB_NAME);

        verify(schedulerApiClient).deleteScheduledJob(JOB_NAME);
    }

    @Test
    void testRunScheduledJob_WhenOneTimeSuccessfulAndDeleteFails_SwallowsException() throws Exception {
        scheduledJob.setOneTime(true);

        TestTask testTask = spy(new TestTask(new ScheduledTaskResult(SchedulerJobExecutionStatus.SUCCESS, "done")));

        when(scheduledJobsRepository.findByJobName(JOB_NAME)).thenReturn(Optional.of(scheduledJob));
        when(historyWriter.recordStarted(scheduledJob)).thenReturn(scheduledJobHistory);
        when(applicationContext.getBean(eq(TestTask.class))).thenReturn(testTask);
        doThrow(new SchedulerException("boom")).when(schedulerApiClient).deleteScheduledJob(JOB_NAME);

        assertDoesNotThrow(() -> schedulerService.runScheduledJob(JOB_NAME));

        verify(eventProducer).produceMessage(any());
    }

    @Test
    void testRunScheduledJob_WhenSystemJobSuccessful_DoesNotProduceEvent() throws Exception {
        scheduledJob.setSystem(true);

        TestTask testTask = spy(new TestTask(new ScheduledTaskResult(SchedulerJobExecutionStatus.SUCCESS, "done")));

        when(scheduledJobsRepository.findByJobName(JOB_NAME)).thenReturn(Optional.of(scheduledJob));
        when(historyWriter.recordStarted(scheduledJob)).thenReturn(scheduledJobHistory);
        when(applicationContext.getBean(eq(TestTask.class))).thenReturn(testTask);

        schedulerService.runScheduledJob(JOB_NAME);

        verify(eventProducer, never()).produceMessage(any());
    }

    @Test
    void testHandleScheduledJobFinishedEvent_FinalizesExistingHistory() throws Exception {
        ScheduledTaskResult result = new ScheduledTaskResult(SchedulerJobExecutionStatus.SUCCESS, "event-finished");
        ScheduledJobFinishedEvent event = new ScheduledJobFinishedEvent(
                new ScheduledJobInfo(JOB_NAME, JOB_UUID, HISTORY_UUID), result);

        when(scheduledJobsRepository.findByUuid(any(SecuredUUID.class))).thenReturn(Optional.of(scheduledJob));

        schedulerService.handleScheduledJobFinishedEvent(event);

        ArgumentCaptor<ScheduledTaskResult> resultCaptor = ArgumentCaptor.forClass(ScheduledTaskResult.class);
        verify(historyWriter).recordFinished(eq(HISTORY_UUID), resultCaptor.capture());
        assertEquals(SchedulerJobExecutionStatus.SUCCESS, resultCaptor.getValue().getStatus());
        assertEquals("event-finished", resultCaptor.getValue().getResultMessage());
        verify(eventProducer).produceMessage(any());
    }

    @Test
    void testHandleScheduledJobFinishedEvent_WhenJobNotFound_ThrowsNotFoundException() {
        ScheduledJobFinishedEvent event = new ScheduledJobFinishedEvent(
                new ScheduledJobInfo(JOB_NAME, JOB_UUID, HISTORY_UUID),
                new ScheduledTaskResult(SchedulerJobExecutionStatus.SUCCESS, "done"));

        when(scheduledJobsRepository.findByUuid(any(SecuredUUID.class))).thenReturn(Optional.empty());

        assertThrows(NotFoundException.class, () -> schedulerService.handleScheduledJobFinishedEvent(event));
    }

    @Test
    void testRunScheduledJob_WhenTaskThrowsRuntimeException_RecordsFailedAndRethrows() throws Exception {
        TestTask testTask = spy(new TestTask(new ScheduledTaskResult(SchedulerJobExecutionStatus.SUCCESS, "never")));
        doThrow(new IllegalStateException("boom")).when(testTask).performJob(any(ScheduledJobInfo.class), any());

        when(scheduledJobsRepository.findByJobName(JOB_NAME)).thenReturn(Optional.of(scheduledJob));
        when(historyWriter.recordStarted(scheduledJob)).thenReturn(scheduledJobHistory);
        when(applicationContext.getBean(eq(TestTask.class))).thenReturn(testTask);

        assertThrows(IllegalStateException.class, () -> schedulerService.runScheduledJob(JOB_NAME));

        // Threw, so the row is closed as FAILED -- with a shaped message, never the exception's own text.
        verify(historyWriter).recordFailed(eq(HISTORY_UUID), argThat(message -> !message.contains("boom")));
        verify(historyWriter, never()).recordFinished(any(), any());
        verify(eventProducer, never()).produceMessage(any());
    }

    @Test
    void testRunScheduledJob_WhenTaskReturnsNull_LeavesTheStartedRowOpen() throws Exception {
        TestTask testTask = spy(new TestTask((ScheduledTaskResult) null));

        when(scheduledJobsRepository.findByJobName(JOB_NAME)).thenReturn(Optional.of(scheduledJob));
        when(historyWriter.recordStarted(scheduledJob)).thenReturn(scheduledJobHistory);
        when(applicationContext.getBean(eq(TestTask.class))).thenReturn(testTask);

        schedulerService.runScheduledJob(JOB_NAME);

        // Returned null, so it finishes later through handleScheduledJobFinishedEvent: the STARTED row stays open.
        verify(historyWriter, never()).recordFinished(any(), any());
        verify(historyWriter, never()).recordFailed(any(), any());
        verify(eventProducer, never()).produceMessage(any());
    }

    @Test
    void testRunScheduledJob_WhenTaskThrowsError_RecordsFailedAndRethrows() throws Exception {
        TestTask testTask = spy(new TestTask(new ScheduledTaskResult(SchedulerJobExecutionStatus.SUCCESS, "never")));
        doThrow(new AssertionError("optional class missing"))
                .when(testTask)
                .performJob(any(ScheduledJobInfo.class), any());

        when(scheduledJobsRepository.findByJobName(JOB_NAME)).thenReturn(Optional.of(scheduledJob));
        when(historyWriter.recordStarted(scheduledJob)).thenReturn(scheduledJobHistory);
        when(applicationContext.getBean(eq(TestTask.class))).thenReturn(testTask);

        assertThrows(AssertionError.class, () -> schedulerService.runScheduledJob(JOB_NAME));

        // An Error closes the row as well; otherwise it would stay STARTED and block deleting the job.
        verify(historyWriter).recordFailed(eq(HISTORY_UUID), any());
    }

    @Test
    void testRunScheduledJob_WhenRecordingTheFailureFails_StillThrowsTheTasksOwnException() throws Exception {
        TestTask testTask = spy(new TestTask(new ScheduledTaskResult(SchedulerJobExecutionStatus.SUCCESS, "never")));
        doThrow(new IllegalStateException("task broke")).when(testTask).performJob(any(ScheduledJobInfo.class), any());

        when(scheduledJobsRepository.findByJobName(JOB_NAME)).thenReturn(Optional.of(scheduledJob));
        when(historyWriter.recordStarted(scheduledJob)).thenReturn(scheduledJobHistory);
        when(applicationContext.getBean(eq(TestTask.class))).thenReturn(testTask);
        doThrow(new IllegalStateException("database gone")).when(historyWriter).recordFailed(any(), any());

        IllegalStateException thrown = assertThrows(IllegalStateException.class,
                () -> schedulerService.runScheduledJob(JOB_NAME));

        assertEquals("task broke", thrown.getMessage());
        assertEquals(1, thrown.getSuppressed().length);
        assertEquals("database gone", thrown.getSuppressed()[0].getMessage());
    }

    @Test
    void testRunScheduledJob_WhenTheFinishedEventCannotBeSent_TheRunStillCountsAsFinished() throws Exception {
        TestTask testTask = spy(new TestTask(new ScheduledTaskResult(SchedulerJobExecutionStatus.SUCCESS, "done")));

        when(scheduledJobsRepository.findByJobName(JOB_NAME)).thenReturn(Optional.of(scheduledJob));
        when(historyWriter.recordStarted(scheduledJob)).thenReturn(scheduledJobHistory);
        when(applicationContext.getBean(eq(TestTask.class))).thenReturn(testTask);
        doThrow(new IllegalStateException("broker down")).when(eventProducer).produceMessage(any());

        assertDoesNotThrow(() -> schedulerService.runScheduledJob(JOB_NAME));

        verify(historyWriter).recordFinished(eq(HISTORY_UUID), any());
    }

    @Test
    void testRunScheduledJob_WhenOneTimeDeregistrationFailsUnchecked_TheFinishedEventIsStillSent() throws Exception {
        scheduledJob.setOneTime(true);
        TestTask testTask = spy(new TestTask(new ScheduledTaskResult(SchedulerJobExecutionStatus.SUCCESS, "done")));

        when(scheduledJobsRepository.findByJobName(JOB_NAME)).thenReturn(Optional.of(scheduledJob));
        when(historyWriter.recordStarted(scheduledJob)).thenReturn(scheduledJobHistory);
        when(applicationContext.getBean(eq(TestTask.class))).thenReturn(testTask);
        // The scheduler client surfaces transport and status failures unchecked, not as SchedulerException.
        doThrow(new IllegalStateException("scheduler returned 500"))
                .when(schedulerApiClient)
                .deleteScheduledJob(JOB_NAME);

        assertDoesNotThrow(() -> schedulerService.runScheduledJob(JOB_NAME));

        verify(historyWriter).recordFinished(eq(HISTORY_UUID), any());
        verify(eventProducer).produceMessage(any());
    }

    @Test
    void testRunScheduledJob_WhenTheCloseWriteFails_ClosesTheRowAsFailedAndRethrows() throws Exception {
        TestTask testTask = spy(new TestTask(new ScheduledTaskResult(SchedulerJobExecutionStatus.SUCCESS, "done")));

        when(scheduledJobsRepository.findByJobName(JOB_NAME)).thenReturn(Optional.of(scheduledJob));
        when(historyWriter.recordStarted(scheduledJob)).thenReturn(scheduledJobHistory);
        when(applicationContext.getBean(eq(TestTask.class))).thenReturn(testTask);
        doThrow(new IllegalStateException("pooler restarted")).when(historyWriter).recordFinished(any(), any());

        assertThrows(IllegalStateException.class, () -> schedulerService.runScheduledJob(JOB_NAME));

        // The row must not stay STARTED: a second close marks it FAILED and names the real outcome.
        verify(historyWriter).recordFailed(eq(HISTORY_UUID), contains("SUCCESS"));
        verify(eventProducer, never()).produceMessage(any());
    }

    /** Runs {@code action} with the service's log captured, adding to {@code warnings} what it logged at WARN. */
    private static <T> T capturingWarnings(List<ILoggingEvent> warnings, Supplier<T> action) {
        ListAppender<ILoggingEvent> logs = new ListAppender<>();
        Logger serviceLogger = (Logger) LoggerFactory.getLogger(SchedulerServiceImpl.class);
        logs.start();
        serviceLogger.addAppender(logs);
        try {
            return action.get();
        } finally {
            serviceLogger.detachAppender(logs);
            logs.list.stream().filter(event -> event.getLevel() == Level.WARN).forEach(warnings::add);
        }
    }

    private static SchedulerResponseDto schedulerHolding(String jobName) {
        SchedulerJobDto job = new SchedulerJobDto(jobName, "0 0 * * * ?", TestTask.class.getName());
        job.setTriggerState(SchedulerTriggerState.NORMAL);
        job.setNextFireTime(Instant.parse("2026-09-29T12:30:00Z"));
        job.setPreviousFireTime(Instant.parse("2026-09-29T11:30:00Z"));
        SchedulerResponseDto response = new SchedulerResponseDto(SchedulerStatus.OK);
        response.setSchedulerJobList(List.of(job));
        return response;
    }

    // Inner test class to simulate a ScheduledJobTask
    public static class TestTask implements ScheduledJobTask {
        private final ScheduledTaskResult result;
        private final ScheduledJobSkippedException exception;

        public TestTask(ScheduledTaskResult result) {
            this.result = result;
            this.exception = null;
        }

        public TestTask(ScheduledJobSkippedException exception) {
            this.result = null;
            this.exception = exception;
        }

        @Override
        public ScheduledTaskResult performJob(ScheduledJobInfo scheduledJobInfo, Object data) {
            if (exception != null) {
                throw exception;
            }
            return result;
        }

        @Override
        public String getJobClassName() {
            return TestTask.class.getName();
        }

        @Override
        public String getDefaultJobName() {
            return "TestTask";
        }

        @Override
        public String getDefaultCronExpression() {
            return "0 0 * * * ?";
        }

        @Override
        public boolean isDefaultOneTimeJob() {
            return false;
        }

        @Override
        public boolean isSystemJob() {
            return false;
        }
    }
}
