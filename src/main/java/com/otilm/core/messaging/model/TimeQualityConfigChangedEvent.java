package com.otilm.core.messaging.model;

import org.springframework.context.ApplicationEvent;

public class TimeQualityConfigChangedEvent extends ApplicationEvent {

    public TimeQualityConfigChangedEvent(Object source) {
        super(source);
    }
}
