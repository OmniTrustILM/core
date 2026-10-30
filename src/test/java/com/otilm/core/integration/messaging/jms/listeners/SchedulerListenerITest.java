package com.otilm.core.integration.messaging.jms.listeners;

import com.otilm.api.exception.CbomRepositoryException;
import com.otilm.api.model.scheduler.SchedulerJobExecutionMessage;
import com.otilm.api.model.scheduler.SchedulerJobExecutionStatus;
import com.otilm.core.dao.entity.ScheduledJob;
import com.otilm.core.dao.entity.ScheduledJobHistory;
import com.otilm.core.dao.repository.ScheduledJobHistoryRepository;
import com.otilm.core.dao.repository.ScheduledJobsRepository;
import com.otilm.core.messaging.jms.listeners.SchedulerListener;
import com.otilm.core.service.impl.CbomServiceImpl;
import com.otilm.core.tasks.CbomSyncTask;
import com.otilm.core.util.BaseSpringBootTest;
import java.util.List;
import java.util.concurrent.atomic.AtomicBoolean;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ProblemDetail;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import org.springframework.transaction.PlatformTransactionManager;
import org.springframework.transaction.TransactionDefinition;
import org.springframework.transaction.support.TransactionTemplate;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

class SchedulerListenerITest extends BaseSpringBootTest {

    @MockitoBean
    private CbomServiceImpl cbomService;

    @Autowired
    private SchedulerListener schedulerListener;

    @Autowired
    private ScheduledJobsRepository scheduledJobsRepository;

    @Autowired
    private ScheduledJobHistoryRepository scheduledJobHistoryRepository;

    @Autowired
    private PlatformTransactionManager transactionManager;

    private ScheduledJob scheduledJob;

    @BeforeEach
    void setUp() {
        scheduledJob = new ScheduledJob();
        scheduledJob.setJobName(CbomSyncTask.NAME);
        scheduledJob.setJobClassName(CbomSyncTask.class.getName());
        scheduledJob.setCronExpression("0 0 * ? * *");
        scheduledJob.setEnabled(true);
        scheduledJob.setOneTime(false);
        scheduledJob.setSystem(true);
        scheduledJobsRepository.save(scheduledJob);
    }

    @Test
    void testProcessMessage_CbomClientNotConfigured_DoesNotThrowUnexpectedRollbackException() {
        when(cbomService.isCbomRepositoryClientConfigured()).thenReturn(false);

        SchedulerJobExecutionMessage message = new SchedulerJobExecutionMessage(CbomSyncTask.NAME,
                CbomSyncTask.class.getName());

        assertDoesNotThrow(() -> schedulerListener.processMessage(message));
        verify(cbomService).isCbomRepositoryClientConfigured();
        assertFalse(scheduledJobHistoryRepository.existsByScheduledJobUuid(scheduledJob.getUuid()));
    }

    @Test
    void testProcessMessage_CbomSyncTaskThrowsException_DoesNotThrowUnexpectedRollbackException()
            throws CbomRepositoryException {
        when(cbomService.isCbomRepositoryClientConfigured()).thenReturn(true);
        when(cbomService.sync())
                .thenThrow(new CbomRepositoryException(ProblemDetail.forStatus(HttpStatus.SERVICE_UNAVAILABLE)));

        SchedulerJobExecutionMessage message = new SchedulerJobExecutionMessage(CbomSyncTask.NAME,
                CbomSyncTask.class.getName());

        assertDoesNotThrow(() -> schedulerListener.processMessage(message));
        verify(cbomService).sync();
        assertFalse(scheduledJobHistoryRepository.existsByScheduledJobUuid(scheduledJob.getUuid()));
    }

    /**
     * A second connection and a second transaction: what another node, or the job-history UI, would see. A plain
     * repository read would join whatever transaction the listener holds and prove nothing.
     */
    private TransactionTemplate otherTransaction() {
        TransactionTemplate template = new TransactionTemplate(transactionManager);
        template.setPropagationBehavior(TransactionDefinition.PROPAGATION_REQUIRES_NEW);
        return template;
    }

    @Test
    void testProcessMessage_StartedRowIsVisibleToAnotherTransactionWhileTheJobRuns() throws Exception {
        when(cbomService.isCbomRepositoryClientConfigured()).thenReturn(true);
        AtomicBoolean seenWhileRunning = new AtomicBoolean(false);
        when(cbomService.sync()).thenAnswer(invocation -> {
            seenWhileRunning
                    .set(Boolean.TRUE
                            .equals(otherTransaction()
                                    .execute(status -> scheduledJobHistoryRepository
                                            .existsByScheduledJobUuidAndSchedulerExecutionStatusAndJobEndTimeIsNull(
                                                    scheduledJob.getUuid(), SchedulerJobExecutionStatus.STARTED))));
            return "synced";
        });

        schedulerListener
                .processMessage(new SchedulerJobExecutionMessage(CbomSyncTask.NAME, CbomSyncTask.class.getName()));

        assertTrue(seenWhileRunning.get(), "the STARTED row must be committed before the job runs");
    }

    @Test
    void testProcessMessage_TaskThrowsRuntimeException_LeavesExactlyOneFailedRow() {
        when(cbomService.isCbomRepositoryClientConfigured())
                .thenThrow(new IllegalStateException("driver text that must not be served"));

        assertDoesNotThrow(() -> schedulerListener
                .processMessage(new SchedulerJobExecutionMessage(CbomSyncTask.NAME, CbomSyncTask.class.getName())));

        List<ScheduledJobHistory> rows = scheduledJobHistoryRepository.findAll();
        assertEquals(1, rows.size(), "a run that threw leaves exactly one history row");
        assertEquals(SchedulerJobExecutionStatus.FAILED, rows.getFirst().getSchedulerExecutionStatus());
        assertNotNull(rows.getFirst().getJobEndTime());
        assertFalse(rows.getFirst().getResultMessage().contains("driver text"),
                "a raw exception message must not reach the history row");
    }

    @Test
    void testProcessMessage_Success_LeavesTheSuccessRowTheWatermarkLookupReads() throws Exception {
        when(cbomService.isCbomRepositoryClientConfigured()).thenReturn(true);
        when(cbomService.sync()).thenReturn("synced");

        schedulerListener
                .processMessage(new SchedulerJobExecutionMessage(CbomSyncTask.NAME, CbomSyncTask.class.getName()));

        assertTrue(scheduledJobHistoryRepository
                .findFirstByScheduledJobJobNameAndSchedulerExecutionStatusOrderByJobExecutionDesc(CbomSyncTask.NAME,
                        SchedulerJobExecutionStatus.SUCCESS)
                .isPresent(), "the watermark lookup must find the SUCCESS row");
    }
}
