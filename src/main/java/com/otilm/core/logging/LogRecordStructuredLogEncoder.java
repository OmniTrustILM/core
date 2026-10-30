package com.otilm.core.logging;

import ch.qos.logback.classic.Level;
import ch.qos.logback.classic.spi.ILoggingEvent;
import ch.qos.logback.classic.spi.IThrowableProxy;
import ch.qos.logback.classic.spi.LoggerContextVO;
import java.time.Instant;
import java.util.List;
import java.util.Map;
import org.slf4j.Marker;
import org.slf4j.event.KeyValuePair;
import org.springframework.boot.logging.logback.StructuredLogEncoder;
import org.springframework.util.Assert;

/**
 * Structured encoder that gives an event carrying a {@link SerializedLogRecord} a readable message in place of the
 * record's JSON. The record itself is written once, as the nested {@value SerializedLogRecord#KEY} member.
 *
 * <p>
 * Done here rather than in a JSON members customizer because a customizer cannot see the event when the message member
 * is written, and rather than in {@link LoggerWrapper} because the text pattern and the OpenTelemetry appender still
 * need the JSON message.
 */
public class LogRecordStructuredLogEncoder extends StructuredLogEncoder {

    private static final String GELF = "gelf";

    private String format;

    @Override
    public void setFormat(String format) {
        this.format = format;
        super.setFormat(format);
    }

    /**
     * Refuses GELF: its additional fields hold only strings and numbers, so the nested {@value SerializedLogRecord#KEY}
     * object would make every audit and event line invalid GELF.
     */
    @Override
    public void start() {
        Assert
                .state(!GELF.equalsIgnoreCase(format),
                        "Log format 'gelf' cannot carry the nested log_record object; use 'ecs' or 'logstash'");
        super.start();
    }

    @Override
    public byte[] encode(ILoggingEvent event) {
        SerializedLogRecord logRecord = findLogRecord(event);
        return super.encode(logRecord == null ? event : new SummarizedEvent(event, logRecord.summary()));
    }

    private static SerializedLogRecord findLogRecord(ILoggingEvent event) {
        List<KeyValuePair> pairs = event.getKeyValuePairs();
        if (pairs == null) {
            return null;
        }
        for (KeyValuePair pair : pairs) {
            if (SerializedLogRecord.KEY.equals(pair.key) && pair.value instanceof SerializedLogRecord logRecord) {
                return logRecord;
            }
        }
        return null;
    }

    record SummarizedEvent(ILoggingEvent event, String summary) implements ILoggingEvent {

        @Override
        public String getFormattedMessage() {
            return summary;
        }

        @Override
        public String getMessage() {
            return summary;
        }

        @Override
        public Object[] getArgumentArray() {
            return new Object[0];
        }

        @Override
        public String getThreadName() {
            return event.getThreadName();
        }

        @Override
        public Level getLevel() {
            return event.getLevel();
        }

        @Override
        public String getLoggerName() {
            return event.getLoggerName();
        }

        @Override
        public LoggerContextVO getLoggerContextVO() {
            return event.getLoggerContextVO();
        }

        @Override
        public IThrowableProxy getThrowableProxy() {
            return event.getThrowableProxy();
        }

        @Override
        public StackTraceElement[] getCallerData() {
            return event.getCallerData();
        }

        @Override
        public boolean hasCallerData() {
            return event.hasCallerData();
        }

        @Override
        public List<Marker> getMarkerList() {
            return event.getMarkerList();
        }

        @Override
        public Map<String, String> getMDCPropertyMap() {
            return event.getMDCPropertyMap();
        }

        @Override
        @SuppressWarnings("deprecation")
        public Map<String, String> getMdc() {
            return event.getMDCPropertyMap();
        }

        @Override
        public long getTimeStamp() {
            return event.getTimeStamp();
        }

        @Override
        public int getNanoseconds() {
            return event.getNanoseconds();
        }

        @Override
        public Instant getInstant() {
            return event.getInstant();
        }

        @Override
        public long getSequenceNumber() {
            return event.getSequenceNumber();
        }

        @Override
        public List<KeyValuePair> getKeyValuePairs() {
            return event.getKeyValuePairs();
        }

        @Override
        public void prepareForDeferredProcessing() {
            event.prepareForDeferredProcessing();
        }
    }
}
