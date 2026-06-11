package com.otilm.core.tasks;

import ch.qos.logback.classic.spi.ILoggingEvent;
import ch.qos.logback.core.filter.Filter;
import ch.qos.logback.core.spi.FilterReply;

public class ScheduledLoggingFilter extends Filter<ILoggingEvent> {


    @Override
    public FilterReply decide(ILoggingEvent iLoggingEvent) {
        String threadName = Thread.currentThread().getName();
        if (threadName.startsWith("scheduling-")) {
            return iLoggingEvent.getMarkerList() != null && !iLoggingEvent.getMarkerList().isEmpty() ? FilterReply.ACCEPT : FilterReply.DENY;
        }
        return FilterReply.ACCEPT;
    }
}
