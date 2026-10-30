package com.otilm.core.tasks;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.otilm.api.model.client.discovery.DiscoveryDto;
import com.otilm.api.model.scheduler.SchedulerJobExecutionStatus;
import com.otilm.core.model.ScheduledTaskResult;
import com.otilm.core.service.DiscoveryExternalService;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.dao.DataIntegrityViolationException;
import org.springframework.transaction.PlatformTransactionManager;
import org.springframework.transaction.TransactionStatus;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class DiscoveryCertificateTaskTest {

    @Mock
    private DiscoveryExternalService discoveryService;

    @Mock
    private PlatformTransactionManager transactionManager;

    @Mock
    private TransactionStatus transactionStatus;

    /** The FAILED result's message reaches the scheduler API through the history row; a driver's text must not. */
    @Test
    void aFailedDiscoveryCreationReportsAShapedMessageNotTheDriversText() throws Exception {
        DiscoveryCertificateTask task = new DiscoveryCertificateTask();
        task.setMapper(new ObjectMapper());
        task.setTransactionManager(transactionManager);
        task.setDiscoveryService(discoveryService);
        when(transactionManager.getTransaction(any())).thenReturn(transactionStatus);
        when(discoveryService.createDiscovery(any(DiscoveryDto.class), eq(true)))
                .thenThrow(new DataIntegrityViolationException(
                        "ERROR: duplicate key value violates unique constraint \"discovery_name_key\""));
        DiscoveryDto request = new DiscoveryDto();
        request.setName("nightly");

        ScheduledTaskResult result = task.performJob(new ScheduledJobInfo("nightly-job"), request);

        assertEquals(SchedulerJobExecutionStatus.FAILED, result.getStatus());
        assertTrue(result.getResultMessage().startsWith("Unable to create discovery nightly"),
                result.getResultMessage());
        assertFalse(result.getResultMessage().contains("duplicate key"), result.getResultMessage());
    }
}
