package com.otilm.core.integration.migration;

import com.otilm.core.util.BaseSpringBootTest;
import java.nio.charset.StandardCharsets;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.Statement;
import java.util.ArrayList;
import java.util.List;
import javax.sql.DataSource;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.core.io.ClassPathResource;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Runs {@code V202609171500__cbom_sync_skip_retention.sql} as Flyway will, in a scratch schema holding a stub of the
 * table it indexes, and asserts the catalogue then carries the index the retention sweep and the operator list rely on.
 * The regular test bootstrap generates its schema from the entities, so nothing else executes this file.
 */
class CbomSyncSkipRetentionMigrationITest extends BaseSpringBootTest {

    private static final String MIGRATION_RESOURCE = "db/migration/V202609171500__cbom_sync_skip_retention.sql";
    private static final String SCRATCH_SCHEMA = "cbom_sync_skip_retention_migration_check";
    private static final String TABLE_STUB = """
            CREATE TABLE "cbom_sync_skip" (
                "uuid" UUID PRIMARY KEY,
                "state" TEXT NOT NULL,
                "last_attempt_at" TIMESTAMP WITH TIME ZONE NOT NULL
            )
            """;

    @Autowired
    private DataSource dataSource;

    @Test
    void theMigrationAddsTheStateAndLastAttemptIndex() throws Exception {
        try (Connection connection = dataSource.getConnection()) {
            try {
                try (Statement statement = connection.createStatement()) {
                    statement.execute("DROP SCHEMA IF EXISTS " + SCRATCH_SCHEMA + " CASCADE");
                    statement.execute("CREATE SCHEMA " + SCRATCH_SCHEMA);
                    statement.execute("SET search_path TO " + SCRATCH_SCHEMA);
                    statement.execute(TABLE_STUB);
                    String sql = new String(new ClassPathResource(MIGRATION_RESOURCE).getInputStream().readAllBytes(),
                            StandardCharsets.UTF_8);
                    statement.execute(sql);
                }
                List<String> indexed = new ArrayList<>();
                try (PreparedStatement query = connection
                        .prepareStatement("SELECT indexdef FROM pg_indexes WHERE schemaname = ? AND indexname = ?")) {
                    query.setString(1, SCRATCH_SCHEMA);
                    query.setString(2, "idx_cbom_sync_skip_state_last_attempt");
                    try (ResultSet rows = query.executeQuery()) {
                        while (rows.next()) {
                            indexed.add(rows.getString(1));
                        }
                    }
                }
                assertThat(indexed).hasSize(1);
                assertThat(indexed.get(0)).contains("(state, last_attempt_at)");
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
}
