package com.otilm.core.model.discovery;

import com.otilm.api.model.core.discovery.DiscoveryMessageSeverity;
import com.otilm.api.model.core.discovery.DiscoveryStatus;
import com.otilm.api.model.scheduler.SchedulerJobExecutionStatus;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

class DiscoveryRunLifecycleTest {

    @Test
    void aCancelSomeoneAskedForIsRecordedAsInformationAndTheirJobRunAsCancelled() {
        assertThat(DiscoveryRunLifecycle.severityOf(DiscoveryStatus.CANCELLED, true))
                .isEqualTo(DiscoveryMessageSeverity.INFO);
        assertThat(DiscoveryRunLifecycle.executionStatusOf(DiscoveryStatus.CANCELLED, true))
                .isEqualTo(SchedulerJobExecutionStatus.CANCELLED);
    }

    @Test
    void aCancelNobodyAskedForLostWorkWithoutFailingAndFailsTheSchedule() {
        assertThat(DiscoveryRunLifecycle.severityOf(DiscoveryStatus.CANCELLED, false))
                .isEqualTo(DiscoveryMessageSeverity.WARNING);
        assertThat(DiscoveryRunLifecycle.executionStatusOf(DiscoveryStatus.CANCELLED, false))
                .isEqualTo(SchedulerJobExecutionStatus.FAILED);
    }

    @Test
    void theOtherEndingsKeepTheirMeaning() {
        assertThat(DiscoveryRunLifecycle.severityOf(DiscoveryStatus.COMPLETED, false))
                .isEqualTo(DiscoveryMessageSeverity.INFO);
        assertThat(DiscoveryRunLifecycle.severityOf(DiscoveryStatus.WARNING, false))
                .isEqualTo(DiscoveryMessageSeverity.WARNING);
        assertThat(DiscoveryRunLifecycle.severityOf(DiscoveryStatus.FAILED, false))
                .isEqualTo(DiscoveryMessageSeverity.ERROR);

        assertThat(DiscoveryRunLifecycle.executionStatusOf(DiscoveryStatus.COMPLETED, false))
                .isEqualTo(SchedulerJobExecutionStatus.SUCCESS);
        assertThat(DiscoveryRunLifecycle.executionStatusOf(DiscoveryStatus.WARNING, false))
                .isEqualTo(SchedulerJobExecutionStatus.SUCCESS);
        assertThat(DiscoveryRunLifecycle.executionStatusOf(DiscoveryStatus.FAILED, false))
                .isEqualTo(SchedulerJobExecutionStatus.FAILED);
    }
}
