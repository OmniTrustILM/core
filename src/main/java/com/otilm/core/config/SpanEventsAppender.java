package com.otilm.core.config;

import ch.qos.logback.classic.spi.LoggingEvent;
import ch.qos.logback.core.AppenderBase;
import io.opentelemetry.api.common.Attributes;
import io.opentelemetry.api.common.AttributesBuilder;
import io.opentelemetry.api.trace.Span;
import org.slf4j.Marker;

import java.util.List;
import java.util.concurrent.TimeUnit;

/**
 * Logback appender which adds a log to current trace span event
 */
public class SpanEventsAppender extends AppenderBase<LoggingEvent> {
    @Override
    protected void append(LoggingEvent event) {
        Span span = Span.current();

        AttributesBuilder attributesBuilder = Attributes.builder();
        // copy all MDC properties, you can leave it out or take only useful information to avoid storing unnecessary data
        event.getMDCPropertyMap().forEach(attributesBuilder::put);

        List<Marker> markers = event.getMarkerList();
        Marker marker = markers == null || markers.isEmpty() ? null : markers.get(0);
        attributesBuilder.put("marker", marker != null ? marker.getName() : null);

        Attributes attributes = attributesBuilder.build();
        span.addEvent(event.getFormattedMessage(), attributes, event.getTimeStamp(), TimeUnit.MILLISECONDS);
    }
}
