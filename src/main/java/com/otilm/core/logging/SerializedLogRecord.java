package com.otilm.core.logging;

import com.otilm.api.model.core.logging.records.LogRecord;
import java.io.IOException;
import org.springframework.boot.json.WritableJson;

/**
 * A {@link LogRecord} serialized once and attached to its log event as a key-value pair. The text pattern and the
 * OpenTelemetry appender ignore key-value pairs and keep printing the JSON message; a structured encoder writes this
 * pair as a nested object, so the record is not escaped into a string a log pipeline has to parse a second time.
 */
public record SerializedLogRecord(String json, String summary) implements WritableJson {

    public static final String KEY = "log_record";

    public static SerializedLogRecord of(LogRecord logRecord, String json) {
        String summary = logRecord.message() != null
                ? logRecord.message()
                : "%s %s %s"
                        .formatted(logRecord.operation().getCode(), logRecord.resource().type().getCode(),
                                logRecord.operationResult().getCode());
        return new SerializedLogRecord(json, summary);
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
