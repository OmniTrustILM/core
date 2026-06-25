package com.otilm.core.service;

import com.otilm.api.model.client.discovery.DiscoveryHistoryDetailDto;
import com.otilm.core.security.authz.SecurityFilter;
import com.otilm.core.tasks.ScheduledJobInfo;

import java.util.UUID;

public interface DiscoveryInternalService extends ResourceExtensionService {

    DiscoveryHistoryDetailDto runDiscovery(UUID discoveryUuid, ScheduledJobInfo scheduledJobInfo);

    /**
     * Get the number of discoveries per user for dashboard
     *
     * @return Number of discoveries
     */
    Long statisticsDiscoveryCount(SecurityFilter filter);
}
