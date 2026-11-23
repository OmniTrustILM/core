package com.otilm.core.integration.migration;

import com.otilm.core.util.BaseSpringBootTest;
import java.nio.file.Files;
import java.nio.file.Path;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;
import java.util.UUID;
import javax.sql.DataSource;
import org.flywaydb.core.Flyway;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.core.io.ClassPathResource;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class AiRuntimeControlMigrationITest extends BaseSpringBootTest {
    private static final String SCHEMA = "ai_runtime_control_migration_check";
    private static final String MIGRATION = "V202611231200__ai_runtime.sql";

    @Autowired
    private DataSource dataSource;

    @Test
    void seedsDisabledUnpinnedControl_whenMigrationIsApplied() throws Exception {
        // given — an isolated schema migrated by Flyway, with no rows written afterwards

        // when
        withMigratedSchema(connection -> {

            // then
            try (Statement statement = connection.createStatement(); ResultSet row = statement.executeQuery("""
                    SELECT generation, enabled, image_digest, evidence_id, observation_sequence
                    FROM ai_runtime_control
                    """)) {
                assertThat(row.next()).isTrue();
                assertThat(row.getLong("generation")).isEqualTo(1);
                assertThat(row.getBoolean("enabled")).isFalse();
                assertThat(row.getObject("image_digest")).isNull();
                assertThat(row.getObject("evidence_id")).isNull();
                assertThat(row.getLong("observation_sequence")).isZero();
                assertThat(row.next()).isFalse();
            }
        });
    }

    @Test
    void rejectsEnablingControl_whenNoPinsAreStored() throws Exception {
        // given — the seeded control row has no pins
        String enableControl = "UPDATE ai_runtime_control SET enabled = true";

        // when
        withMigratedSchema(connection -> {

            // then
            assertRejected(connection, enableControl, "23514");
        });
    }

    @Test
    void rejectsSecondControlRow_whenOneRowIsSeeded() throws Exception {
        // given
        String secondControlRow = """
                INSERT INTO ai_runtime_control (id, generation, created_at, updated_at)
                VALUES (2, 1, clock_timestamp(), clock_timestamp())
                """;

        // when
        withMigratedSchema(connection -> {

            // then
            assertRejected(connection, secondControlRow, "23514");
        });
    }

    @Test
    void rejectsNegativeControlGeneration_whenRunIsStored() throws Exception {
        // given
        String negativeGeneration = "UPDATE ai_runtime_run SET control_generation = -1";

        // when
        withMigratedSchema(connection -> {
            insertRunWithAttempt(connection, UUID.randomUUID(), UUID.randomUUID());

            // then
            assertRejected(connection, negativeGeneration, "23514");
        });
    }

    @Test
    void rejectsAttemptGeneration_whenItDiffersFromItsRun() throws Exception {
        // given
        String foreignGeneration = "UPDATE ai_runtime_attempt SET control_generation = 1";

        // when
        withMigratedSchema(connection -> {
            insertRunWithAttempt(connection, UUID.randomUUID(), UUID.randomUUID());

            // then
            assertRejected(connection, foreignGeneration, "23503");
        });
    }

    // ── Helpers ───────────────────────────────────────────────────────────────

    private void withMigratedSchema(SqlWork work) throws Exception {
        Path directory = Files.createTempDirectory("ai-runtime-control-migration-");
        Path script = directory.resolve(MIGRATION);
        try (Connection connection = dataSource.getConnection()) {
            try {
                try (Statement statement = connection.createStatement()) {
                    statement.execute("DROP SCHEMA IF EXISTS " + SCHEMA + " CASCADE");
                    statement.execute("CREATE SCHEMA " + SCHEMA);
                }
                Files.write(script, new ClassPathResource("db/migration/" + MIGRATION).getContentAsByteArray());
                Flyway flyway = Flyway
                        .configure()
                        .dataSource(dataSource)
                        .defaultSchema(SCHEMA)
                        .schemas(SCHEMA)
                        .locations("filesystem:" + directory)
                        .load();
                assertThat(flyway.migrate().migrationsExecuted).isEqualTo(1);
                assertThat(flyway.migrate().migrationsExecuted).isZero();
                connection.setSchema(SCHEMA);
                work.run(connection);
            } finally {
                connection.setAutoCommit(true);
                connection.setSchema(dbSchema);
                try (Statement statement = connection.createStatement()) {
                    statement.execute("DROP SCHEMA IF EXISTS " + SCHEMA + " CASCADE");
                }
            }
        } finally {
            Files.deleteIfExists(script);
            Files.deleteIfExists(directory);
        }
    }

    private static void insertRunWithAttempt(Connection connection, UUID run, UUID attempt) throws SQLException {
        connection.setAutoCommit(false);
        try (PreparedStatement statement = connection.prepareStatement("""
                INSERT INTO ai_runtime_run (uuid, actor_uuid, scope_marker, state, revision, fence, attempts_used,
                    attempt_limit, current_attempt_uuid, run_deadline, lease_seconds, pod_limit, created_at,
                    updated_at, control_generation)
                VALUES (?, ?, 'synthetic', 'QUEUED', 1, 1, 1, 2, ?, clock_timestamp() + interval '120 seconds',
                    5, 2, clock_timestamp(), clock_timestamp(), 0)
                """)) {
            statement.setObject(1, run);
            statement.setObject(2, UUID.randomUUID());
            statement.setObject(3, attempt);
            statement.executeUpdate();
        }
        try (PreparedStatement statement = connection.prepareStatement("""
                INSERT INTO ai_runtime_attempt (uuid, run_uuid, attempt_no, state, fence, image_digest,
                    profile_revision, security_revision, trust_revision, protocol, launch_deadline, max_deadline,
                    created_at, updated_at, control_generation)
                VALUES (?, ?, 1, 'LAUNCHING', 1, 'sha256:' || repeat('a',64), 1, 1, 1, 'v1',
                    clock_timestamp() + interval '30 seconds', clock_timestamp() + interval '60 seconds',
                    clock_timestamp(), clock_timestamp(), 0)
                """)) {
            statement.setObject(1, attempt);
            statement.setObject(2, run);
            statement.executeUpdate();
        }
        connection.commit();
        connection.setAutoCommit(true);
    }

    private static void assertRejected(Connection connection, String sql, String sqlState) throws SQLException {
        try (Statement statement = connection.createStatement()) {
            assertThatThrownBy(() -> statement.executeUpdate(sql))
                    .isInstanceOf(SQLException.class)
                    .satisfies(failure -> assertThat(((SQLException) failure).getSQLState()).isEqualTo(sqlState));
        }
    }

    @FunctionalInterface
    private interface SqlWork {
        void run(Connection connection) throws Exception;
    }
}
