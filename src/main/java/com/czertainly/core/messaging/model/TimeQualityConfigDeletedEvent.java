package com.czertainly.core.messaging.model;

import org.springframework.context.ApplicationEvent;

import java.util.UUID;

public class TimeQualityConfigDeletedEvent extends ApplicationEvent {

    private final UUID configurationId;

    public TimeQualityConfigDeletedEvent(Object source, UUID configurationId) {
        super(source);
        this.configurationId = configurationId;
    }

    public UUID getConfigurationId() {
        return configurationId;
    }
}
