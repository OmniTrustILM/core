package com.otilm.core.messaging.jms.configuration;

import com.otilm.core.messaging.jms.configuration.StatusPollProperties.PollSchedule;
import com.otilm.core.model.discovery.DiscoveryWorkType;
import java.util.Map;
import org.springframework.boot.context.properties.ConfigurationProperties;

/**
 * Backoff ladders for discovery v2 work ticks, per {@link DiscoveryWorkType}. The sweep cadence and batch knobs under
 * the same {@code discovery.work} prefix are plain {@code @Value} properties on their consumers.
 */
@ConfigurationProperties("discovery.work")
public record DiscoveryWorkProperties(PollSchedule defaults, Map<DiscoveryWorkType, PollSchedule> byType) {

    public PollSchedule scheduleFor(DiscoveryWorkType type) {
        if (byType != null && byType.containsKey(type)) {
            return byType.get(type);
        }
        return defaults;
    }
}
