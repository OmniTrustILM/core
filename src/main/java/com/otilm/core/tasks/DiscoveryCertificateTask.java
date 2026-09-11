package com.otilm.core.tasks;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.otilm.api.model.client.discovery.DiscoveryDetailDto;
import com.otilm.api.model.client.discovery.DiscoveryDto;
import com.otilm.api.model.core.auth.Resource;
import com.otilm.api.model.core.discovery.DiscoveryStatus;
import com.otilm.api.model.scheduler.SchedulerJobExecutionStatus;
import com.otilm.core.model.ScheduledTaskResult;
import com.otilm.core.model.discovery.DiscoveryRunLifecycle;
import com.otilm.core.service.DiscoveryExternalService;
import com.otilm.core.service.DiscoveryInternalService;
import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.UUID;
import lombok.NoArgsConstructor;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;
import org.springframework.transaction.PlatformTransactionManager;
import org.springframework.transaction.TransactionStatus;
import org.springframework.transaction.annotation.Propagation;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.transaction.support.DefaultTransactionDefinition;

@Component
@NoArgsConstructor
@Transactional
public class DiscoveryCertificateTask implements ScheduledJobTask {

    private static final Logger logger = LoggerFactory.getLogger(DiscoveryCertificateTask.class);

    private DiscoveryExternalService discoveryService;

    private DiscoveryInternalService discoveryInternalService;

    private ObjectMapper mapper;

    private PlatformTransactionManager transactionManager;

    private final SimpleDateFormat sdf = new SimpleDateFormat("yyyy-MM-dd_HH-mm-ss.FFF");

    @Autowired
    public void setMapper(ObjectMapper mapper) {
        this.mapper = mapper;
    }

    @Autowired
    public void setTransactionManager(PlatformTransactionManager transactionManager) {
        this.transactionManager = transactionManager;
    }

    @Autowired
    public void setDiscoveryService(DiscoveryExternalService discoveryService) {
        this.discoveryService = discoveryService;
    }

    @Autowired
    public void setDiscoveryInternalService(DiscoveryInternalService discoveryInternalService) {
        this.discoveryInternalService = discoveryInternalService;
    }

    public String getDefaultJobName() {
        return "DiscoveryCertificateTask";
    }

    public String getDefaultCronExpression() {
        return null;
    }

    public boolean isDefaultOneTimeJob() {
        return false;
    }

    public String getJobClassName() {
        return this.getClass().getName();
    }

    public boolean isSystemJob() {
        return false;
    }

    @Override
    @Transactional(propagation = Propagation.NOT_SUPPORTED)
    public ScheduledTaskResult performJob(final ScheduledJobInfo scheduledJobInfo, final Object taskData) {
        final DiscoveryDto discoveryDto = mapper.convertValue(taskData, DiscoveryDto.class);
        discoveryDto.setName(discoveryDto.getName() + prepareTimeSuffix());

        // Define a new transaction
        DiscoveryDetailDto discovery = null;
        TransactionStatus status = transactionManager.getTransaction(new DefaultTransactionDefinition());
        try {
            discovery = discoveryService.createDiscovery(discoveryDto, true);
            transactionManager.commit(status);
        } catch (Exception e) {
            transactionManager.rollback(status);
            final String errorMessage = String
                    .format("Unable to create discovery %s for job %s. Error: %s", discoveryDto.getName(),
                            scheduledJobInfo == null ? "" : scheduledJobInfo.jobName(), e.getMessage());
            logger.error(errorMessage);
            return new ScheduledTaskResult(SchedulerJobExecutionStatus.FAILED, errorMessage,
                    discovery != null ? Resource.DISCOVERY : null, discovery != null ? discovery.getUuid() : null);
        }

        // After the discovery is created and commited, run discovery
        discovery = discoveryInternalService.runDiscovery(UUID.fromString(discovery.getUuid()), scheduledJobInfo);
        // Only a run that has already finished reports here. Anything still running -- v1 post-processing, or a v2
        // run that has just been handed to its tick workers -- reports when it ends, through DISCOVERY_FINISHED.
        // Returning a result now would close the job as succeeded before the run had discovered anything.
        if (DiscoveryRunLifecycle.isTerminal(discovery.getStatus())) {
            return new ScheduledTaskResult(
                    discovery.getStatus() == DiscoveryStatus.FAILED
                            || discovery.getStatus() == DiscoveryStatus.CANCELLED
                                    ? SchedulerJobExecutionStatus.FAILED
                                    : SchedulerJobExecutionStatus.SUCCESS,
                    discovery.getMessage(), Resource.DISCOVERY, discovery.getUuid());
        }

        return null;
    }

    private String prepareTimeSuffix() {
        return "_" + sdf.format(new Date());
    }
}
