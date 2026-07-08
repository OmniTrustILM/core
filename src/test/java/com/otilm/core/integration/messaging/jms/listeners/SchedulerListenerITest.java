package com.otilm.core.integration.messaging.jms.listeners;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import com.otilm.api.exception.CbomRepositoryException;
import com.otilm.core.dao.repository.ScheduledJobHistoryRepository;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ProblemDetail;
import org.springframework.security.access.method.P;
import org.springframework.test.context.bean.override.mockito.MockitoBean;

import com.otilm.api.model.scheduler.SchedulerJobExecutionMessage;
import com.otilm.core.dao.entity.ScheduledJob;
import com.otilm.core.dao.repository.ScheduledJobsRepository;
import com.otilm.core.messaging.jms.listeners.SchedulerListener;
import com.otilm.core.service.impl.CbomServiceImpl;
import com.otilm.core.tasks.CbomSyncTask;
import com.otilm.core.util.BaseSpringBootTest;

class SchedulerListenerITest extends BaseSpringBootTest {

    @MockitoBean
    private CbomServiceImpl cbomService;

    @Autowired
    private SchedulerListener schedulerListener;

    @Autowired
    private ScheduledJobsRepository scheduledJobsRepository;

    @Autowired
    private ScheduledJobHistoryRepository scheduledJobHistoryRepository;

    @Test
    void testProcessMessage_CbomSyncTaskSkipped_DoesNotThrowUnexpectedRollbackException() throws CbomRepositoryException {
        ScheduledJob scheduledJob = new ScheduledJob();
        scheduledJob.setJobName(CbomSyncTask.NAME);
        scheduledJob.setJobClassName(CbomSyncTask.class.getName());
        scheduledJob.setCronExpression("0 0 * ? * *");
        scheduledJob.setEnabled(true);
        scheduledJob.setOneTime(false);
        scheduledJob.setSystem(true);
        scheduledJobsRepository.save(scheduledJob);

        when(cbomService.isCbomRepositoryClientConfigured()).thenReturn(false);

        SchedulerJobExecutionMessage message = new SchedulerJobExecutionMessage(CbomSyncTask.NAME, CbomSyncTask.class.getName());

        assertDoesNotThrow(() -> schedulerListener.processMessage(message));
        verify(cbomService).isCbomRepositoryClientConfigured();
        assertFalse(scheduledJobHistoryRepository.existsByScheduledJobUuid(scheduledJob.getUuid()));

        // Mock path when cbom is configured
        when(cbomService.isCbomRepositoryClientConfigured()).thenReturn(true);
        when(cbomService.sync()).thenThrow(new CbomRepositoryException(ProblemDetail.forStatus(HttpStatus.SERVICE_UNAVAILABLE)));

        assertDoesNotThrow(() -> schedulerListener.processMessage(message));
        verify(cbomService).sync();
        assertFalse(scheduledJobHistoryRepository.existsByScheduledJobUuid(scheduledJob.getUuid()));
    }
}
