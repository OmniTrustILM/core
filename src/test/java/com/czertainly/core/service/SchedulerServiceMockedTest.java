package com.czertainly.core.service;

import com.czertainly.api.clients.SchedulerApiClient;
import com.czertainly.api.exception.NotFoundException;
import com.czertainly.api.exception.SchedulerException;
import com.czertainly.api.exception.ValidationException;
import com.czertainly.api.model.core.scheduler.PaginationRequestDto;
import com.czertainly.api.model.core.scheduler.ScheduledJobDetailDto;
import com.czertainly.api.model.core.scheduler.ScheduledJobHistoryResponseDto;
import com.czertainly.api.model.core.scheduler.ScheduledJobsResponseDto;
import com.czertainly.api.model.scheduler.SchedulerJobExecutionStatus;
import com.czertainly.api.model.scheduler.UpdateScheduledJob;
import com.czertainly.core.api.ScheduledJobSkippedException;
import com.czertainly.core.dao.entity.ScheduledJob;
import com.czertainly.core.dao.entity.ScheduledJobHistory;
import com.czertainly.core.dao.repository.ScheduledJobHistoryRepository;
import com.czertainly.core.dao.repository.ScheduledJobsRepository;
import com.czertainly.core.events.transaction.ScheduledJobFinishedEvent;
import com.czertainly.core.messaging.jms.producers.EventProducer;
import com.czertainly.core.model.ScheduledTaskResult;
import com.czertainly.core.security.authz.SecuredUUID;
import com.czertainly.core.security.authz.SecurityFilter;
import com.czertainly.core.service.impl.SchedulerServiceImpl;
import com.czertainly.core.tasks.ScheduledJobInfo;
import com.czertainly.core.tasks.ScheduledJobTask;
import com.czertainly.core.util.AuthHelper;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.MockedStatic;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.context.ApplicationContext;
import org.springframework.data.domain.Pageable;

import java.util.Date;
import java.util.List;
import java.util.Optional;
import java.util.UUID;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
class SchedulerServiceMockedTest {

    @Mock
    private ScheduledJobsRepository scheduledJobsRepository;

    @Mock
    private ScheduledJobHistoryRepository scheduledJobHistoryRepository;

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

        when(scheduledJobsRepository.findUsingSecurityFilter(any(), eq(List.of()), isNull(), any(Pageable.class), isNull()))
                .thenReturn(List.of(scheduledJob));
        when(scheduledJobsRepository.countUsingSecurityFilter(any(), isNull())).thenReturn(1L);
        when(scheduledJobHistoryRepository.findTopByScheduledJobUuidOrderByJobExecutionDesc(JOB_UUID)).thenReturn(scheduledJobHistory);

        ScheduledJobsResponseDto response = schedulerService.listScheduledJobs(SecurityFilter.create(), pagination);

        assertEquals(1, response.getScheduledJobs().size());
        assertEquals(1L, response.getTotalItems());
        assertEquals(1, response.getTotalPages());
        assertEquals(10, response.getItemsPerPage());
        assertEquals(1, response.getPageNumber());
    }

    @Test
    void testGetScheduledJobDetail_ReturnsDetail() throws Exception {
        when(scheduledJobsRepository.findByUuid(any(SecuredUUID.class))).thenReturn(Optional.of(scheduledJob));
        when(scheduledJobHistoryRepository.findTopByScheduledJobUuidOrderByJobExecutionDesc(JOB_UUID)).thenReturn(scheduledJobHistory);

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
    void testDeleteScheduledJob_WhenHistoryExists_ThrowsValidationException() throws SchedulerException {
        when(scheduledJobsRepository.findByUuid(any(SecuredUUID.class))).thenReturn(Optional.of(scheduledJob));
        when(scheduledJobHistoryRepository.existsByScheduledJobUuid(JOB_UUID)).thenReturn(true);

        assertThrows(ValidationException.class, () -> schedulerService.deleteScheduledJob(JOB_UUID.toString()));

        verify(schedulerApiClient, never()).deleteScheduledJob(anyString());
        verify(scheduledJobsRepository, never()).deleteById(any());
    }

    @Test
    void testDeleteScheduledJob_WhenSchedulerDeleteSucceeds_DeletesRepositoryRecord() throws Exception {
        when(scheduledJobsRepository.findByUuid(any(SecuredUUID.class))).thenReturn(Optional.of(scheduledJob));
        when(scheduledJobHistoryRepository.existsByScheduledJobUuid(JOB_UUID)).thenReturn(false);

        schedulerService.deleteScheduledJob(JOB_UUID.toString());

        verify(schedulerApiClient).deleteScheduledJob(JOB_NAME);
        verify(scheduledJobsRepository).deleteById(JOB_UUID);
    }

    @Test
    void testDeleteScheduledJob_WhenSchedulerDeleteFails_SwallowsException() throws Exception {
        when(scheduledJobsRepository.findByUuid(any(SecuredUUID.class))).thenReturn(Optional.of(scheduledJob));
        when(scheduledJobHistoryRepository.existsByScheduledJobUuid(JOB_UUID)).thenReturn(false);
        doThrow(new SchedulerException("boom")).when(schedulerApiClient).deleteScheduledJob(JOB_NAME);

        assertDoesNotThrow(() -> schedulerService.deleteScheduledJob(JOB_UUID.toString()));

        verify(scheduledJobsRepository, never()).deleteById(any());
    }

    @Test
    void testGetScheduledJobHistory_ReturnsPagedResponse() {
        PaginationRequestDto pagination = new PaginationRequestDto();
        pagination.setPageNumber(1);
        pagination.setItemsPerPage(10);

        when(scheduledJobHistoryRepository.findUsingSecurityFilter(any(), eq(List.of()), any(), any(Pageable.class), any()))
                .thenReturn(List.of(scheduledJobHistory));
        when(scheduledJobHistoryRepository.countUsingSecurityFilter(any(), any())).thenReturn(1L);

        ScheduledJobHistoryResponseDto response = schedulerService.getScheduledJobHistory(SecurityFilter.create(), pagination, JOB_UUID.toString());

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

        assertThrows(ValidationException.class, () -> schedulerService.updateScheduledJob(JOB_UUID.toString(), request));
    }

    @Test
    void testUpdateScheduledJob_WhenEnabled_UpdatesCronAndDoesNotDisableAgain() throws Exception {
        scheduledJob.setEnabled(true);
        when(scheduledJobsRepository.findByUuid(any(SecuredUUID.class))).thenReturn(Optional.of(scheduledJob));
        when(scheduledJobHistoryRepository.findTopByScheduledJobUuidOrderByJobExecutionDesc(JOB_UUID)).thenReturn(scheduledJobHistory);

        UpdateScheduledJob request = new UpdateScheduledJob();
        request.setCronExpression("0 15 * * * ?");

        ScheduledJobDetailDto response = schedulerService.updateScheduledJob(JOB_UUID.toString(), request);

        assertNotNull(response);
        assertEquals("0 15 * * * ?", scheduledJob.getCronExpression());
        verify(schedulerApiClient).updateScheduledJob(any());
        verify(schedulerApiClient, never()).disableScheduledJob(anyString());
        verify(scheduledJobsRepository).save(scheduledJob);
    }

    @Test
    void testUpdateScheduledJob_WhenDisabled_UpdatesCronAndReDisablesJob() throws Exception {
        scheduledJob.setEnabled(false);
        when(scheduledJobsRepository.findByUuid(any(SecuredUUID.class))).thenReturn(Optional.of(scheduledJob));
        when(scheduledJobHistoryRepository.findTopByScheduledJobUuidOrderByJobExecutionDesc(JOB_UUID)).thenReturn(scheduledJobHistory);

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

        ScheduledJobDetailDto response = schedulerService.registerScheduledJob(TestTask.class);

        assertNotNull(response);
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

            ScheduledJobDetailDto response = schedulerService.registerScheduledJob(
                    TestTask.class,
                    "CustomJob",
                    "0 10 * * * ?",
                    true,
                    "payload"
            );

            assertNotNull(response);

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
        when(scheduledJobHistoryRepository.save(any(ScheduledJobHistory.class))).thenReturn(scheduledJobHistory);

        schedulerService.runScheduledJob(JOB_NAME);

        ArgumentCaptor<ScheduledJobHistory> historyCaptor = ArgumentCaptor.forClass(ScheduledJobHistory.class);
        verify(scheduledJobHistoryRepository).save(historyCaptor.capture());

        ScheduledJobHistory savedHistory = historyCaptor.getValue();
        assertEquals(SchedulerJobExecutionStatus.FAILED, savedHistory.getSchedulerExecutionStatus());
        assertTrue(savedHistory.getResultMessage().contains("Unknown scheduled task"));
    }
    @Test
    void testRunScheduledJob_WhenTaskIsNotScheduledJobTask_RegistersFailedHistory() throws Exception {
        when(scheduledJobsRepository.findByJobName(JOB_NAME)).thenReturn(Optional.of(scheduledJob));
        when(scheduledJobHistoryRepository.save(any(ScheduledJobHistory.class))).thenReturn(scheduledJobHistory);

        Object notATask = new Object();
        doReturn(notATask).when(applicationContext).getBean(eq(TestTask.class));

        schedulerService.runScheduledJob(JOB_NAME);

        ArgumentCaptor<ScheduledJobHistory> historyCaptor = ArgumentCaptor.forClass(ScheduledJobHistory.class);
        verify(scheduledJobHistoryRepository).save(historyCaptor.capture());

        ScheduledJobHistory savedHistory = historyCaptor.getValue();
        assertEquals(SchedulerJobExecutionStatus.FAILED, savedHistory.getSchedulerExecutionStatus());
        assertTrue(savedHistory.getResultMessage().contains("Unknown scheduled task"));
    }

    @Test
    void testRunScheduledJob_WhenJobSucceeds_UpdatesHistoryAndProducesEvent() throws Exception {
        TestTask testTask = spy(new TestTask(
                new ScheduledTaskResult(SchedulerJobExecutionStatus.SUCCESS, "Job completed successfully")
        ));

        when(scheduledJobsRepository.findByJobName(JOB_NAME)).thenReturn(Optional.of(scheduledJob));
        when(scheduledJobHistoryRepository.save(any(ScheduledJobHistory.class))).thenReturn(scheduledJobHistory);
        when(applicationContext.getBean(eq(TestTask.class))).thenReturn(testTask);

        schedulerService.runScheduledJob(JOB_NAME);

        verify(testTask).performJob(any(ScheduledJobInfo.class), any());

        ArgumentCaptor<ScheduledJobHistory> historyCaptor = ArgumentCaptor.forClass(ScheduledJobHistory.class);
        verify(scheduledJobHistoryRepository, atLeast(2)).save(historyCaptor.capture());

        ScheduledJobHistory finalHistory = historyCaptor.getAllValues().getLast();
        assertEquals(SchedulerJobExecutionStatus.SUCCESS, finalHistory.getSchedulerExecutionStatus());
        assertEquals("Job completed successfully", finalHistory.getResultMessage());
        assertNotNull(finalHistory.getJobEndTime());

        verify(eventProducer).produceMessage(any());
    }

    @Test
    void testRunScheduledJob_WhenJobFails_UpdatesHistoryWithFailedStatus() throws Exception {
        TestTask testTask = spy(new TestTask(
                new ScheduledTaskResult(SchedulerJobExecutionStatus.FAILED, "Job failed with error")
        ));

        when(scheduledJobsRepository.findByJobName(JOB_NAME)).thenReturn(Optional.of(scheduledJob));
        when(scheduledJobHistoryRepository.save(any(ScheduledJobHistory.class))).thenReturn(scheduledJobHistory);
        when(applicationContext.getBean(eq(TestTask.class))).thenReturn(testTask);

        schedulerService.runScheduledJob(JOB_NAME);

        ArgumentCaptor<ScheduledJobHistory> historyCaptor = ArgumentCaptor.forClass(ScheduledJobHistory.class);
        verify(scheduledJobHistoryRepository, atLeast(2)).save(historyCaptor.capture());

        ScheduledJobHistory finalHistory = historyCaptor.getAllValues().getLast();
        assertEquals(SchedulerJobExecutionStatus.FAILED, finalHistory.getSchedulerExecutionStatus());
        assertEquals("Job failed with error", finalHistory.getResultMessage());

        verify(eventProducer).produceMessage(any());
    }

    @Test
    void testRunScheduledJob_WhenJobThrowsScheduledJobSkippedException_DeletesHistory() throws Exception {
        TestTask testTask = spy(new TestTask(new ScheduledJobSkippedException()));

        when(scheduledJobsRepository.findByJobName(JOB_NAME)).thenReturn(Optional.of(scheduledJob));
        when(scheduledJobHistoryRepository.save(any(ScheduledJobHistory.class))).thenReturn(scheduledJobHistory);
        when(applicationContext.getBean(eq(TestTask.class))).thenReturn(testTask);

        schedulerService.runScheduledJob(JOB_NAME);

        verify(testTask).performJob(any(ScheduledJobInfo.class), any());
        verify(scheduledJobHistoryRepository).delete(scheduledJobHistory);
        verify(eventProducer, never()).produceMessage(any());
    }

    @Test
    void testRunScheduledJob_WhenJobHasUserUuid_AuthenticatesAsUser() throws Exception {
        UUID userUuid = UUID.randomUUID();
        scheduledJob.setUserUuid(userUuid);

        TestTask testTask = spy(new TestTask(
                new ScheduledTaskResult(SchedulerJobExecutionStatus.SUCCESS, "Job completed successfully")
        ));

        when(scheduledJobsRepository.findByJobName(JOB_NAME)).thenReturn(Optional.of(scheduledJob));
        when(scheduledJobHistoryRepository.save(any(ScheduledJobHistory.class))).thenReturn(scheduledJobHistory);
        when(applicationContext.getBean(eq(TestTask.class))).thenReturn(testTask);

        schedulerService.runScheduledJob(JOB_NAME);

        verify(authHelper).authenticateAsUser(userUuid);
    }

    @Test
    void testRunScheduledJob_WhenJobHasObjectData_PassesItToTask() throws Exception {
        Object taskData = new Object();
        scheduledJob.setObjectData(taskData);

        TestTask testTask = spy(new TestTask(
                new ScheduledTaskResult(SchedulerJobExecutionStatus.SUCCESS, "Job completed successfully")
        ));

        when(scheduledJobsRepository.findByJobName(JOB_NAME)).thenReturn(Optional.of(scheduledJob));
        when(scheduledJobHistoryRepository.save(any(ScheduledJobHistory.class))).thenReturn(scheduledJobHistory);
        when(applicationContext.getBean(eq(TestTask.class))).thenReturn(testTask);

        schedulerService.runScheduledJob(JOB_NAME);

        ArgumentCaptor<Object> dataCaptor = ArgumentCaptor.forClass(Object.class);
        verify(testTask).performJob(any(ScheduledJobInfo.class), dataCaptor.capture());
        assertSame(taskData, dataCaptor.getValue());
    }

    @Test
    void testRunScheduledJob_CreatesHistoryWithCorrectScheduledJobInfo() throws Exception {
        TestTask testTask = spy(new TestTask(
                new ScheduledTaskResult(SchedulerJobExecutionStatus.SUCCESS, "Job completed successfully")
        ));

        when(scheduledJobsRepository.findByJobName(JOB_NAME)).thenReturn(Optional.of(scheduledJob));
        when(scheduledJobHistoryRepository.save(any(ScheduledJobHistory.class))).thenReturn(scheduledJobHistory);
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

        TestTask testTask = spy(new TestTask(
                new ScheduledTaskResult(SchedulerJobExecutionStatus.SUCCESS, "done")
        ));

        when(scheduledJobsRepository.findByJobName(JOB_NAME)).thenReturn(Optional.of(scheduledJob));
        when(scheduledJobHistoryRepository.save(any(ScheduledJobHistory.class))).thenReturn(scheduledJobHistory);
        when(applicationContext.getBean(eq(TestTask.class))).thenReturn(testTask);

        schedulerService.runScheduledJob(JOB_NAME);

        verify(schedulerApiClient).deleteScheduledJob(JOB_NAME);
    }

    @Test
    void testRunScheduledJob_WhenOneTimeSuccessfulAndDeleteFails_SwallowsException() throws Exception {
        scheduledJob.setOneTime(true);

        TestTask testTask = spy(new TestTask(
                new ScheduledTaskResult(SchedulerJobExecutionStatus.SUCCESS, "done")
        ));

        when(scheduledJobsRepository.findByJobName(JOB_NAME)).thenReturn(Optional.of(scheduledJob));
        when(scheduledJobHistoryRepository.save(any(ScheduledJobHistory.class))).thenReturn(scheduledJobHistory);
        when(applicationContext.getBean(eq(TestTask.class))).thenReturn(testTask);
        doThrow(new SchedulerException("boom")).when(schedulerApiClient).deleteScheduledJob(JOB_NAME);

        assertDoesNotThrow(() -> schedulerService.runScheduledJob(JOB_NAME));

        verify(eventProducer).produceMessage(any());
    }

    @Test
    void testRunScheduledJob_WhenSystemJobSuccessful_DoesNotProduceEvent() throws Exception {
        scheduledJob.setSystem(true);

        TestTask testTask = spy(new TestTask(
                new ScheduledTaskResult(SchedulerJobExecutionStatus.SUCCESS, "done")
        ));

        when(scheduledJobsRepository.findByJobName(JOB_NAME)).thenReturn(Optional.of(scheduledJob));
        when(scheduledJobHistoryRepository.save(any(ScheduledJobHistory.class))).thenReturn(scheduledJobHistory);
        when(applicationContext.getBean(eq(TestTask.class))).thenReturn(testTask);

        schedulerService.runScheduledJob(JOB_NAME);

        verify(eventProducer, never()).produceMessage(any());
    }

    @Test
    void testHandleScheduledJobFinishedEvent_FinalizesExistingHistory() throws Exception {
        ScheduledTaskResult result = new ScheduledTaskResult(
                SchedulerJobExecutionStatus.SUCCESS,
                "event-finished"
        );
        ScheduledJobFinishedEvent event = new ScheduledJobFinishedEvent(
                new ScheduledJobInfo(JOB_NAME, JOB_UUID, HISTORY_UUID),
                result
        );

        when(scheduledJobsRepository.findByUuid(any(SecuredUUID.class))).thenReturn(Optional.of(scheduledJob));
        when(scheduledJobHistoryRepository.findByUuid(any(SecuredUUID.class))).thenReturn(Optional.of(scheduledJobHistory));

        schedulerService.handleScheduledJobFinishedEvent(event);

        verify(scheduledJobHistoryRepository).save(scheduledJobHistory);
        assertEquals(SchedulerJobExecutionStatus.SUCCESS, scheduledJobHistory.getSchedulerExecutionStatus());
        assertEquals("event-finished", scheduledJobHistory.getResultMessage());
        verify(eventProducer).produceMessage(any());
    }

    @Test
    void testHandleScheduledJobFinishedEvent_WhenJobNotFound_ThrowsNotFoundException() {
        ScheduledJobFinishedEvent event = new ScheduledJobFinishedEvent(
                new ScheduledJobInfo(JOB_NAME, JOB_UUID, HISTORY_UUID),
                new ScheduledTaskResult(SchedulerJobExecutionStatus.SUCCESS, "done")
        );

        when(scheduledJobsRepository.findByUuid(any(SecuredUUID.class))).thenReturn(Optional.empty());

        assertThrows(NotFoundException.class, () -> schedulerService.handleScheduledJobFinishedEvent(event));
    }

    @Test
    void testHandleScheduledJobFinishedEvent_WhenHistoryNotFound_ThrowsNotFoundException() {
        ScheduledJobFinishedEvent event = new ScheduledJobFinishedEvent(
                new ScheduledJobInfo(JOB_NAME, JOB_UUID, HISTORY_UUID),
                new ScheduledTaskResult(SchedulerJobExecutionStatus.SUCCESS, "done")
        );

        when(scheduledJobsRepository.findByUuid(any(SecuredUUID.class))).thenReturn(Optional.of(scheduledJob));
        when(scheduledJobHistoryRepository.findByUuid(any(SecuredUUID.class))).thenReturn(Optional.empty());

        assertThrows(NotFoundException.class, () -> schedulerService.handleScheduledJobFinishedEvent(event));
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
