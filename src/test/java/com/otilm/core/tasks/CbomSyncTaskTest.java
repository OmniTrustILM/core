package com.otilm.core.tasks;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.Mockito.when;
import static org.mockito.Mockito.verify;

import org.junit.jupiter.api.Test;
import org.mockito.Mockito;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ProblemDetail;
import org.springframework.test.context.bean.override.mockito.MockitoBean;

import com.otilm.api.exception.CbomRepositoryException;
import com.otilm.api.model.scheduler.SchedulerJobExecutionStatus;
import com.otilm.core.api.ScheduledJobSkippedException;
import com.otilm.core.model.ScheduledTaskResult;
import com.otilm.core.service.CbomService;
import com.otilm.core.util.BaseSpringBootTest;

class CbomSyncTaskTest extends BaseSpringBootTest {

    @MockitoBean
    private CbomService cbomService;

    @Autowired
    private CbomSyncTask cbomSyncTask;


    @Test
    void testPerformJob_Success() throws Exception {
        ScheduledJobInfo scheduledJobInfo = new ScheduledJobInfo(CbomSyncTask.NAME);
        Object taskData = new Object();
        Mockito.when(cbomService.isCbomRepositoryClientConfigured()).thenReturn(true);

        ScheduledTaskResult result = cbomSyncTask.performJob(scheduledJobInfo, taskData);

        assertEquals(SchedulerJobExecutionStatus.SUCCESS, result.getStatus());
        Mockito.verify(cbomService, Mockito.times(1)).isCbomRepositoryClientConfigured();
        Mockito.verify(cbomService, Mockito.times(1)).sync();
    }

    @Test
    void testPerformJob_Failure() throws Exception {
        ScheduledJobInfo scheduledJobInfo = new ScheduledJobInfo(CbomSyncTask.NAME);
        Mockito.when(cbomService.isCbomRepositoryClientConfigured()).thenReturn(true);
        Mockito.doThrow(new RuntimeException("Sync failed")).when(cbomService).sync();

        ScheduledTaskResult result = cbomSyncTask.performJob(scheduledJobInfo, new Object());

        assertEquals(SchedulerJobExecutionStatus.FAILED, result.getStatus());
        assertTrue(result.getResultMessage().contains("Sync failed"));
        Mockito.verify(cbomService, Mockito.times(1)).isCbomRepositoryClientConfigured();
        Mockito.verify(cbomService, Mockito.times(1)).sync();
    }

    @Test
    void testPerformJob_Skip() throws Exception {
        ScheduledJobInfo scheduledJobInfo = new ScheduledJobInfo(CbomSyncTask.NAME);
        Mockito.when(cbomService.isCbomRepositoryClientConfigured()).thenReturn(false);

        assertThrows(ScheduledJobSkippedException.class, () ->
            cbomSyncTask.performJob(scheduledJobInfo, new Object())
        );

        Mockito.verify(cbomService, Mockito.times(1)).isCbomRepositoryClientConfigured();
        Mockito.verify(cbomService, Mockito.times(0)).sync();
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
    void testPerformJob_WhenSyncThrowsCbomRepositoryExceptionWith503_ThrowsScheduledJobSkippedException() throws CbomRepositoryException {
        // Arrange
        when(cbomService.isCbomRepositoryClientConfigured()).thenReturn(true);
        
        ProblemDetail problemDetail = ProblemDetail.forStatus(HttpStatus.SERVICE_UNAVAILABLE.value());
        CbomRepositoryException cbomException = new CbomRepositoryException(problemDetail);
        
        when(cbomService.sync()).thenThrow(cbomException);

        // Act & Assert
        assertThrows(ScheduledJobSkippedException.class, () -> 
            cbomSyncTask.performJob(null, null)
        );
        
        verify(cbomService).sync();
    }

}
