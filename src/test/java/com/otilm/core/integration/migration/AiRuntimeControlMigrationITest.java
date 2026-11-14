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
    private static final String KERNEL = "V202610261200__ai_runtime_kernel.sql";
    private static final String CONTROL = "V202611041200__ai_runtime_control.sql";
    @Autowired
    private DataSource dataSource;

    @Test
    void actualFlywayUpgradeLeavesLegacyRowsUnboundAndControlDisabled() throws Exception {
        Path directory = Files.createTempDirectory("ai-runtime-control-migration-");
        Path kernel = directory.resolve(KERNEL);
        Path control = directory.resolve(CONTROL);
        UUID run = UUID.randomUUID();
        UUID attempt = UUID.randomUUID();
        try (Connection connection = dataSource.getConnection()) {
            try {
                try (Statement statement = connection.createStatement()) {
                    statement.execute("DROP SCHEMA IF EXISTS " + SCHEMA + " CASCADE");
                    statement.execute("CREATE SCHEMA " + SCHEMA);
                }
                Files.write(kernel, new ClassPathResource("db/migration/" + KERNEL).getContentAsByteArray());
                Flyway flyway = Flyway
                        .configure()
                        .dataSource(dataSource)
                        .defaultSchema(SCHEMA)
                        .schemas(SCHEMA)
                        .locations("filesystem:" + directory)
                        .load();
                assertThat(flyway.migrate().migrationsExecuted).isEqualTo(1);
                connection.setSchema(SCHEMA);
                insertLegacy(connection, run, attempt);

                Files.write(control, new ClassPathResource("db/migration/" + CONTROL).getContentAsByteArray());
                assertThat(flyway.migrate().migrationsExecuted).isEqualTo(1);
                assertThat(flyway.migrate().migrationsExecuted).isZero();

                try (Statement statement = connection.createStatement(); ResultSet row = statement.executeQuery("""
                        SELECT r.control_generation AS run_generation, a.control_generation AS attempt_generation,
                            r.scope_marker, c.generation, c.enabled, c.image_digest, c.evidence_id,
                            c.observation_sequence
                        FROM ai_runtime_run r JOIN ai_runtime_attempt a ON a.run_uuid = r.uuid
                        CROSS JOIN ai_runtime_control c
                        """)) {
                    assertThat(row.next()).isTrue();
                    assertThat(row.getLong("run_generation")).isZero();
                    assertThat(row.getLong("attempt_generation")).isZero();
                    assertThat(row.getString("scope_marker")).isEqualTo("synthetic-legacy");
                    assertThat(row.getLong("generation")).isEqualTo(1);
                    assertThat(row.getBoolean("enabled")).isFalse();
                    assertThat(row.getObject("image_digest")).isNull();
                    assertThat(row.getObject("evidence_id")).isNull();
                    assertThat(row.getLong("observation_sequence")).isZero();
                    assertThat(row.next()).isFalse();
                }
                assertRejected(connection, "UPDATE ai_runtime_control SET enabled = true", "23514");
                assertRejected(connection, "UPDATE ai_runtime_run SET control_generation = -1", "23514");
                assertRejected(connection, "UPDATE ai_runtime_attempt SET control_generation = 1", "23503");
                assertRejected(connection, """
                        INSERT INTO ai_runtime_control (id, generation, created_at, updated_at)
                        VALUES (2, 1, clock_timestamp(), clock_timestamp())
                        """, "23514");
            } finally {
                connection.setAutoCommit(true);
                connection.setSchema(dbSchema);
                try (Statement statement = connection.createStatement()) {
                    statement.execute("DROP SCHEMA IF EXISTS " + SCHEMA + " CASCADE");
                }
            }
        } finally {
            Files.deleteIfExists(control);
            Files.deleteIfExists(kernel);
            Files.deleteIfExists(directory);
        }
    }

    private static void insertLegacy(Connection connection, UUID run, UUID attempt) throws SQLException {
        connection.setAutoCommit(false);
        try (PreparedStatement statement = connection.prepareStatement("""
                INSERT INTO ai_runtime_run (uuid, actor_uuid, scope_marker, state, revision, fence, attempts_used,
                    attempt_limit, current_attempt_uuid, run_deadline, lease_seconds, pod_limit, created_at, updated_at)
                VALUES (?, ?, 'synthetic-legacy', 'QUEUED', 1, 1, 1, 2, ?, clock_timestamp() + interval '120 seconds',
                    5, 2, clock_timestamp(), clock_timestamp())
                """)) {
            statement.setObject(1, run);
            statement.setObject(2, UUID.randomUUID());
            statement.setObject(3, attempt);
            statement.executeUpdate();
        }
        try (PreparedStatement statement = connection.prepareStatement("""
                INSERT INTO ai_runtime_attempt (uuid, run_uuid, attempt_no, state, fence, image_digest,
                    profile_revision, security_revision, trust_revision, protocol, launch_deadline, max_deadline,
                    created_at, updated_at)
                VALUES (?, ?, 1, 'LAUNCHING', 1, 'sha256:' || repeat('a',64), 1, 1, 1, 'v1',
                    clock_timestamp() + interval '30 seconds', clock_timestamp() + interval '60 seconds',
                    clock_timestamp(), clock_timestamp())
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
}
