package com.otilm.core.messaging.jms.configuration;

import com.otilm.core.messaging.jms.configuration.StatusPollProperties.PollSchedule;
import com.otilm.core.model.discovery.DiscoveryWorkType;
import java.time.Duration;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;

class DiscoveryWorkPropertiesTest {

    @Test
    void scheduleForFallsBackToDefaultsWhenTypeNotOverridden() {
        PollSchedule defaults = new PollSchedule(List.of(Duration.ofSeconds(1)), 720);
        DiscoveryWorkProperties props = new DiscoveryWorkProperties(defaults, Map.of());
        assertEquals(defaults, props.scheduleFor(DiscoveryWorkType.STATUS));
    }

    @Test
    void scheduleForUsesByTypeWhenPresent() {
        PollSchedule defaults = new PollSchedule(List.of(Duration.ofSeconds(1)), 720);
        PollSchedule drain = new PollSchedule(List.of(Duration.ZERO, Duration.ofSeconds(1)), 100);
        DiscoveryWorkProperties props = new DiscoveryWorkProperties(defaults, Map.of(DiscoveryWorkType.DRAIN, drain));
        assertEquals(drain, props.scheduleFor(DiscoveryWorkType.DRAIN));
        assertEquals(defaults, props.scheduleFor(DiscoveryWorkType.STATUS));
    }

    @Test
    void scheduleForToleratesAbsentByTypeBlock() {
        PollSchedule defaults = new PollSchedule(List.of(Duration.ofSeconds(1)), 720);
        DiscoveryWorkProperties props = new DiscoveryWorkProperties(defaults, null);
        assertEquals(defaults, props.scheduleFor(DiscoveryWorkType.PROCESS));
    }
}
