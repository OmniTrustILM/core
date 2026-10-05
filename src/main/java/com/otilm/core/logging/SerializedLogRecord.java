package com.otilm.core.logging;

import com.otilm.api.model.core.logging.records.LogRecord;
import java.io.IOException;
import java.util.ArrayList;
import java.util.List;
import org.springframework.boot.json.WritableJson;
import org.springframework.util.StringUtils;

/**
 * A {@link LogRecord} serialized once and attached to its log event as a key-value pair. The text pattern and the
 * OpenTelemetry appender ignore key-value pairs and keep printing the JSON message; a structured encoder writes this
 * pair as a nested object, so the record is not escaped into a string a log pipeline has to parse a second time.
 */
public record SerializedLogRecord(LogRecord logRecord, String json) implements WritableJson {

    public static final String KEY = "log_record";

    /**
     * The record's own message, or its operation, resource and result codes when it has none. Only a structured encoder
     * asks for it, so text mode never builds it, and a record with a missing field still gets a line message rather
     * than failing the logging call.
     */
    public String summary() {
        if (StringUtils.hasText(logRecord.message())) {
            return logRecord.message();
        }
        List<String> codes = new ArrayList<>(3);
        if (logRecord.operation() != null) {
            codes.add(logRecord.operation().getCode());
        }
        if (logRecord.resource() != null && logRecord.resource().type() != null) {
            codes.add(logRecord.resource().type().getCode());
        }
        if (logRecord.operationResult() != null) {
            codes.add(logRecord.operationResult().getCode());
        }
        return String.join(" ", codes);
    }

    @Override
    public void to(Appendable out) throws IOException {
        out.append(json);
    }

    @Override
    public String toString() {
        return json;
    }
}
