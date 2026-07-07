package com.otilm.core.integration.messaging.jms.listeners;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;

import org.junit.jupiter.api.Test;
import org.mockito.Mockito;
import org.springframework.beans.factory.annotation.Autowired;
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

    @Test
    void testProcessMessage_CbomSyncTaskSkipped_DoesNotThrowUnexpectedRollbackException() {
        ScheduledJob scheduledJob = new ScheduledJob();
        scheduledJob.setJobName(CbomSyncTask.NAME);
        scheduledJob.setJobClassName(CbomSyncTask.class.getName());
        scheduledJob.setCronExpression("0 0 * ? * *");
        scheduledJob.setEnabled(true);
        scheduledJob.setOneTime(false);
        scheduledJob.setSystem(true);
        scheduledJobsRepository.save(scheduledJob);

        Mockito.when(cbomService.isCbomRepositoryClientConfigured()).thenReturn(false);

        SchedulerJobExecutionMessage message = new SchedulerJobExecutionMessage(CbomSyncTask.NAME, CbomSyncTask.class.getName());

        assertDoesNotThrow(() -> schedulerListener.processMessage(message));
    }
}
