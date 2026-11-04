package com.otilm.core.integration.migration;

import com.otilm.core.util.BaseSpringBootTest;
import java.nio.charset.StandardCharsets;
import java.sql.Connection;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;
import javax.sql.DataSource;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.core.io.ClassPathResource;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Applies {@code V202611041500__trigger_history_event_history_index.sql} to a table shaped as in production and asserts
 * that the index answers the lookup of a trigger history by its event history. The suite's schema is generated from the
 * entities, which declare no such index, so nothing else would notice it renamed, reordered or dropped.
 */
class TriggerHistoryEventHistoryIndexMigrationITest extends BaseSpringBootTest {

    private static final String MIGRATION_RESOURCE = "db/migration/V202611041500__trigger_history_event_history_index.sql";

    private static final String SCRATCH_SCHEMA = "trigger_history_index_check";

    private static final String SOME_UUID = "5f0a3c5e-9c0b-4f7e-8d8b-2b6f1c9e4a11";

    @Autowired
    private DataSource dataSource;

    @Test
    void answersLookupByEventHistory_whenMigrationIsApplied() throws Exception {
        // given
        var lookup = "SELECT uuid FROM trigger_history WHERE event_history_uuid = '%s'".formatted(SOME_UUID);
        try (Connection connection = dataSource.getConnection()) {
            try {
                createTableWithRows(connection);

                // when
                applyMigration(connection);
                String plan = planFor(connection, lookup);

                // then
                assertThat(plan).contains("idx_trigger_history_event_history");
            } finally {
                dropScratchSchema(connection);
            }
        }
    }

    // ── Helpers ───────────────────────────────────────────────────────────────

    private void createTableWithRows(Connection connection) throws SQLException {
        try (Statement statement = connection.createStatement()) {
            statement.execute("DROP SCHEMA IF EXISTS " + SCRATCH_SCHEMA + " CASCADE");
            statement.execute("CREATE SCHEMA " + SCRATCH_SCHEMA);
            // Only the scratch schema is on the path, so an unqualified name cannot resolve to the entity-generated
            // core schema instead.
            statement.execute("SET search_path TO " + SCRATCH_SCHEMA);
            statement.execute("""
                    CREATE TABLE "trigger_history" (
                        "uuid" UUID PRIMARY KEY,
                        "event_history_uuid" UUID
                    );
                    INSERT INTO trigger_history (uuid, event_history_uuid)
                    SELECT gen_random_uuid(), gen_random_uuid() FROM generate_series(1, 500) g;
                    ANALYZE trigger_history;
                    """);
        }
    }

    private void applyMigration(Connection connection) throws Exception {
        try (Statement statement = connection.createStatement()) {
            statement.execute(new ClassPathResource(MIGRATION_RESOURCE).getContentAsString(StandardCharsets.UTF_8));
        }
    }

    /**
     * Sequential scans are disabled for the check: on a table this size the planner would pick one on cost alone, and
     * the question is whether the index answers the lookup at all.
     */
    private String planFor(Connection connection, String query) throws SQLException {
        StringBuilder plan = new StringBuilder();
        try (Statement statement = connection.createStatement()) {
            statement.execute("SET enable_seqscan = off");
            try (ResultSet rows = statement.executeQuery("EXPLAIN " + query)) {
                while (rows.next()) {
                    plan.append(rows.getString(1)).append('\n');
                }
            }
        }
        return plan.toString();
    }

    private void dropScratchSchema(Connection connection) throws SQLException {
        try (Statement statement = connection.createStatement()) {
            statement.execute("DROP SCHEMA IF EXISTS " + SCRATCH_SCHEMA + " CASCADE");
        } finally {
            // The connection goes back to a pool shared with the rest of the suite.
            try (Statement reset = connection.createStatement()) {
                reset.execute("RESET search_path");
                reset.execute("RESET enable_seqscan");
            }
        }
    }
}
