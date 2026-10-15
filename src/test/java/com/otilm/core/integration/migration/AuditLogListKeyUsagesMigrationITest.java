package com.otilm.core.integration.migration;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.otilm.api.model.core.auth.Resource;
import com.otilm.api.model.core.logging.enums.ActorType;
import com.otilm.api.model.core.logging.enums.AuthMethod;
import com.otilm.api.model.core.logging.enums.Module;
import com.otilm.api.model.core.logging.enums.Operation;
import com.otilm.api.model.core.logging.enums.OperationResult;
import com.otilm.api.model.core.logging.records.ActorRecord;
import com.otilm.api.model.core.logging.records.LogRecord;
import com.otilm.api.model.core.logging.records.ResourceRecord;
import com.otilm.core.serialization.ObjectMapperFactory;
import com.otilm.core.util.BaseSpringBootTest;
import java.nio.charset.StandardCharsets;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;
import java.time.OffsetDateTime;
import javax.sql.DataSource;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.core.io.ClassPathResource;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Runs {@code V202610161200__audit_log_list_key_usages_unknown.sql} in a scratch schema over an audit row recorded
 * under the removed {@code LIST_KEY_USAGES} operation, and reads both stored forms back the way the entity does. The
 * entity-generated schema checks the column against the current enum, so it cannot hold such a row.
 */
class AuditLogListKeyUsagesMigrationITest extends BaseSpringBootTest {

    private static final String MIGRATION_RESOURCE = "db/migration/V202610161200__audit_log_list_key_usages_unknown.sql";
    private static final String SCRATCH_SCHEMA = "audit_log_list_key_usages_migration_check";
    private static final String TABLE_STUB = """
            CREATE TABLE "audit_log" ("id" BIGINT PRIMARY KEY, "operation" TEXT NOT NULL, "log_record" JSONB NOT NULL)
            """;
    private static final long REMOVED = 1;
    private static final long KEPT = 2;

    private final ObjectMapper jsonColumn = ObjectMapperFactory.jsonColumn();

    @Autowired
    private DataSource dataSource;

    @Test
    void aRowOfTheRemovedOperationLoadsAsUnknown_andOtherRowsKeepTheirs() throws Exception {
        try (Connection connection = dataSource.getConnection()) {
            try (Statement statement = connection.createStatement()) {
                statement.execute("DROP SCHEMA IF EXISTS " + SCRATCH_SCHEMA + " CASCADE");
                statement.execute("CREATE SCHEMA " + SCRATCH_SCHEMA);
                statement.execute("SET search_path TO " + SCRATCH_SCHEMA);
                statement.execute(TABLE_STUB);
                insertListRow(connection, REMOVED);
                insertListRow(connection, KEPT);
                statement.execute("""
                        UPDATE audit_log
                           SET operation = 'LIST_KEY_USAGES',
                               log_record = jsonb_set(log_record, '{operation}', '"listKeyUsages"')
                         WHERE id = %d
                        """.formatted(REMOVED));

                statement.execute(new ClassPathResource(MIGRATION_RESOURCE).getContentAsString(StandardCharsets.UTF_8));

                assertThat(columnOperation(statement, REMOVED)).isEqualTo(Operation.UNKNOWN);
                assertThat(logRecordOperation(statement, REMOVED)).isEqualTo(Operation.UNKNOWN);
                assertThat(columnOperation(statement, KEPT)).isEqualTo(Operation.LIST);
                assertThat(logRecordOperation(statement, KEPT)).isEqualTo(Operation.LIST);
            } finally {
                try (Statement statement = connection.createStatement()) {
                    // The connection goes back to a pool shared with the rest of the suite: the session's search_path
                    // must not point at the schema this drops.
                    statement.execute("RESET search_path");
                    statement.execute("DROP SCHEMA IF EXISTS " + SCRATCH_SCHEMA + " CASCADE");
                }
            }
        }
    }

    private void insertListRow(Connection connection, long id) throws Exception {
        LogRecord logRecord = LogRecord
                .builder()
                .version("1.0")
                .module(Module.CRYPTOGRAPHIC_KEYS)
                .actor(new ActorRecord(ActorType.USER, AuthMethod.NONE, null, null))
                .resource(new ResourceRecord(Resource.TOKEN_PROFILE, null))
                .operation(Operation.LIST)
                .operationResult(OperationResult.SUCCESS)
                .timestamp(OffsetDateTime.now())
                .build();
        try (PreparedStatement insert = connection.prepareStatement("INSERT INTO audit_log VALUES (?, ?, ?::jsonb)")) {
            insert.setLong(1, id);
            insert.setString(2, Operation.LIST.name());
            insert.setString(3, jsonColumn.writeValueAsString(logRecord));
            insert.executeUpdate();
        }
    }

    private static Operation columnOperation(Statement statement, long id) throws SQLException {
        return Operation.valueOf(queryOne(statement, "SELECT operation FROM audit_log WHERE id = " + id));
    }

    private Operation logRecordOperation(Statement statement, long id) throws Exception {
        String logRecord = queryOne(statement, "SELECT log_record::text FROM audit_log WHERE id = " + id);
        return jsonColumn.readValue(logRecord, LogRecord.class).operation();
    }

    private static String queryOne(Statement statement, String sql) throws SQLException {
        try (ResultSet rows = statement.executeQuery(sql)) {
            assertThat(rows.next()).describedAs(sql).isTrue();
            return rows.getString(1);
        }
    }
}
