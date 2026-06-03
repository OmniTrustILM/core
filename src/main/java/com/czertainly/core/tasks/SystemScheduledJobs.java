package com.czertainly.core.tasks;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.scheduling.annotation.EnableScheduling;

import com.czertainly.api.exception.SchedulerException;
import com.czertainly.core.service.SchedulerInternalService;

@Configuration
@EnableScheduling
public class SystemScheduledJobs {

    private SchedulerInternalService schedulerService;

    @Autowired
    public void setSchedulerService(SchedulerInternalService schedulerService) {
        this.schedulerService = schedulerService;
    }

    @Bean
    @ConditionalOnProperty(value = "scheduled-tasks.enabled", matchIfMissing = true, havingValue = "true")
    public Void registerJobs() throws SchedulerException {
        schedulerService.registerScheduledJob(UpdateCertificateStatusTask.class);
        schedulerService.registerScheduledJob(UpdateIntuneRevocationRequestsTask.class);
        schedulerService.registerScheduledJob(CbomSyncTask.class);
        return null;
    }
}
