package com.otilm.core.model.discovery;

import com.otilm.api.model.core.discovery.DiscoveryMessageSeverity;
import com.otilm.api.model.core.discovery.DiscoveryStatus;
import com.otilm.api.model.scheduler.SchedulerJobExecutionStatus;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;

class DiscoveryRunLifecycleTest {

    @Test
    void aCancelSomeoneAskedForIsRecordedAsInformationAndTheirJobRunAsCancelled() {
        assertEquals(DiscoveryMessageSeverity.INFO, DiscoveryRunLifecycle.severityOf(DiscoveryStatus.CANCELLED, true));
        assertEquals(SchedulerJobExecutionStatus.CANCELLED,
                DiscoveryRunLifecycle.executionStatusOf(DiscoveryStatus.CANCELLED, true));
    }

    @Test
    void aCancelNobodyAskedForLostWorkWithoutFailingAndFailsTheSchedule() {
        assertEquals(DiscoveryMessageSeverity.WARNING,
                DiscoveryRunLifecycle.severityOf(DiscoveryStatus.CANCELLED, false));
        assertEquals(SchedulerJobExecutionStatus.FAILED,
                DiscoveryRunLifecycle.executionStatusOf(DiscoveryStatus.CANCELLED, false));
    }

    @Test
    void theOtherEndingsKeepTheirMeaning() {
        assertEquals(DiscoveryMessageSeverity.INFO, DiscoveryRunLifecycle.severityOf(DiscoveryStatus.COMPLETED, false));
        assertEquals(DiscoveryMessageSeverity.WARNING,
                DiscoveryRunLifecycle.severityOf(DiscoveryStatus.WARNING, false));
        assertEquals(DiscoveryMessageSeverity.ERROR, DiscoveryRunLifecycle.severityOf(DiscoveryStatus.FAILED, false));

        assertEquals(SchedulerJobExecutionStatus.SUCCESS,
                DiscoveryRunLifecycle.executionStatusOf(DiscoveryStatus.COMPLETED, false));
        assertEquals(SchedulerJobExecutionStatus.SUCCESS,
                DiscoveryRunLifecycle.executionStatusOf(DiscoveryStatus.WARNING, false));
        assertEquals(SchedulerJobExecutionStatus.FAILED,
                DiscoveryRunLifecycle.executionStatusOf(DiscoveryStatus.FAILED, false));
    }
}
