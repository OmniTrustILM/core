package com.otilm.core.messaging.model;

import java.util.UUID;
import org.springframework.context.ApplicationEvent;

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
