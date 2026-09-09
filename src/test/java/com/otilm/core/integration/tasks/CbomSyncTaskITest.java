package com.otilm.core.integration.tasks;

import com.otilm.api.exception.CbomRepositoryException;
import com.otilm.api.model.scheduler.SchedulerJobExecutionStatus;
import com.otilm.core.api.ScheduledJobSkippedException;
import com.otilm.core.model.ScheduledTaskResult;
import com.otilm.core.service.impl.CbomServiceImpl;
import com.otilm.core.tasks.CbomSyncTask;
import com.otilm.core.tasks.ScheduledJobInfo;
import com.otilm.core.util.BaseSpringBootTest;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ProblemDetail;
import org.springframework.test.context.bean.override.mockito.MockitoBean;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

class CbomSyncTaskITest extends BaseSpringBootTest {

    @MockitoBean
    private CbomServiceImpl cbomService;

    @Autowired
    private CbomSyncTask cbomSyncTask;

    @Test
    void testPerformJob_Success() throws Exception {
        ScheduledJobInfo scheduledJobInfo = new ScheduledJobInfo(CbomSyncTask.NAME);
        Object taskData = new Object();
        when(cbomService.isCbomRepositoryClientConfigured()).thenReturn(true);

        ScheduledTaskResult result = cbomSyncTask.performJob(scheduledJobInfo, taskData);

        assertEquals(SchedulerJobExecutionStatus.SUCCESS, result.getStatus());
        verify(cbomService, times(1)).isCbomRepositoryClientConfigured();
        verify(cbomService, times(1)).sync();
    }

    @Test
    void testPerformJob_Failure() throws Exception {
        ScheduledJobInfo scheduledJobInfo = new ScheduledJobInfo(CbomSyncTask.NAME);
        when(cbomService.isCbomRepositoryClientConfigured()).thenReturn(true);
        doThrow(new RuntimeException("Sync failed")).when(cbomService).sync();

        ScheduledTaskResult result = cbomSyncTask.performJob(scheduledJobInfo, new Object());

        assertEquals(SchedulerJobExecutionStatus.FAILED, result.getStatus());
        // A bare RuntimeException is not a PlatformException, so its raw message must not reach the operator-visible
        // result -- only the fallback text may.
        assertTrue(result.getResultMessage().contains("unexpected error, see the Core log"));
        assertFalse(result.getResultMessage().contains("Sync failed"));
        verify(cbomService, times(1)).isCbomRepositoryClientConfigured();
        verify(cbomService, times(1)).sync();
    }

    @Test
    void testPerformJob_Failure_PlatformExceptionMessageIsSurfaced() throws Exception {
        ScheduledJobInfo scheduledJobInfo = new ScheduledJobInfo(CbomSyncTask.NAME);
        when(cbomService.isCbomRepositoryClientConfigured()).thenReturn(true);
        ProblemDetail problemDetail = ProblemDetail
                .forStatusAndDetail(HttpStatus.BAD_GATEWAY, "CBOM Repository repeated the page cursor");
        doThrow(new CbomRepositoryException(problemDetail)).when(cbomService).sync();

        ScheduledTaskResult result = cbomSyncTask.performJob(scheduledJobInfo, new Object());

        assertEquals(SchedulerJobExecutionStatus.FAILED, result.getStatus());
        // CbomRepositoryException is a PlatformException with a Core-shaped message, so it is surfaced verbatim.
        assertTrue(result.getResultMessage().contains("CBOM Repository repeated the page cursor"));
        verify(cbomService, times(1)).isCbomRepositoryClientConfigured();
        verify(cbomService, times(1)).sync();
    }

    @Test
    void testPerformJob_Skip() throws Exception {
        ScheduledJobInfo scheduledJobInfo = new ScheduledJobInfo(CbomSyncTask.NAME);
        when(cbomService.isCbomRepositoryClientConfigured()).thenReturn(false);

        Object triggerObject = new Object();
        assertThrows(ScheduledJobSkippedException.class,
                () -> cbomSyncTask.performJob(scheduledJobInfo, triggerObject));

        verify(cbomService, times(1)).isCbomRepositoryClientConfigured();
        verify(cbomService, times(0)).sync();
    }

    @Test
    void testGetDefaultJobName() {
        assertEquals(CbomSyncTask.NAME, cbomSyncTask.getDefaultJobName());
    }

    @Test
    void testGetDefaultCronExpression() {
        assertEquals("0 0 * ? * *", cbomSyncTask.getDefaultCronExpression());
    }

    @Test
    void testIsDefaultOneTimeJob() {
        assertFalse(cbomSyncTask.isDefaultOneTimeJob());
    }

    @Test
    void testGetJobClassName() {
        assertEquals(CbomSyncTask.class.getName(), cbomSyncTask.getJobClassName());
    }

    @Test
    void testPerformJob_WhenSyncThrowsCbomRepositoryExceptionWith503_ThrowsScheduledJobSkippedException()
            throws CbomRepositoryException {
        // Arrange
        when(cbomService.isCbomRepositoryClientConfigured()).thenReturn(true);

        ProblemDetail problemDetail = ProblemDetail.forStatus(HttpStatus.SERVICE_UNAVAILABLE.value());
        CbomRepositoryException cbomException = new CbomRepositoryException(problemDetail);

        when(cbomService.sync()).thenThrow(cbomException);

        // Act & Assert
        assertThrows(ScheduledJobSkippedException.class, () -> cbomSyncTask.performJob(null, null));

        verify(cbomService).sync();
    }

}
