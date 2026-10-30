package com.otilm.core.logging;

import com.otilm.api.model.core.auth.Resource;
import com.otilm.api.model.core.logging.enums.Operation;
import com.otilm.api.model.core.logging.enums.OperationResult;
import com.otilm.api.model.core.logging.records.LogRecord;
import com.otilm.api.model.core.logging.records.ResourceRecord;
import java.util.List;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.NullAndEmptySource;
import org.junit.jupiter.params.provider.ValueSource;

import static org.assertj.core.api.Assertions.assertThat;

class SerializedLogRecordTest {

    @Test
    void theRecordsOwnMessageIsTheSummary() {
        LogRecord logRecord = complete().message("Connector refused the export").build();

        assertThat(new SerializedLogRecord(logRecord, "{}").summary()).isEqualTo("Connector refused the export");
    }

    @ParameterizedTest
    @NullAndEmptySource
    @ValueSource(strings = " ")
    void aRecordWithoutAMessageIsSummarizedByItsCodes(String message) {
        LogRecord logRecord = complete().message(message).build();

        assertThat(new SerializedLogRecord(logRecord, "{}").summary()).isEqualTo("export keyItems success");
    }

    @Test
    void aMissingFieldIsLeftOutOfTheSummary() {
        LogRecord logRecord = LogRecord.builder().operation(Operation.EXPORT).build();

        assertThat(new SerializedLogRecord(logRecord, "{}").summary()).isEqualTo("export");
    }

    @Test
    void theJsonIsWrittenAsItIs() {
        SerializedLogRecord serialized = new SerializedLogRecord(complete().build(), "{\"version\":\"1.1\"}");

        assertThat(serialized.toJsonString()).isEqualTo("{\"version\":\"1.1\"}");
        assertThat(serialized).hasToString("{\"version\":\"1.1\"}");
    }

    private static LogRecord.LogRecordBuilder complete() {
        return LogRecord
                .builder()
                .operation(Operation.EXPORT)
                .resource(new ResourceRecord(Resource.CRYPTOGRAPHIC_KEY_ITEM, List.of()))
                .operationResult(OperationResult.SUCCESS);
    }
}
