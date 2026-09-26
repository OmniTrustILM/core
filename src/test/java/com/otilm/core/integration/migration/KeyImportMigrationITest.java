package com.otilm.core.integration.migration;

import com.otilm.core.util.BaseSpringBootTest;
import java.nio.charset.StandardCharsets;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;
import javax.sql.DataSource;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.core.io.ClassPathResource;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/**
 * Runs {@code V202609261200__key_import.sql} as Flyway will. The test bootstrap generates its schema from the entities,
 * which cannot express a partial index, so this is where the one-open-attempt rule is proven.
 */
class KeyImportMigrationITest extends BaseSpringBootTest {

    private static final String MIGRATION_RESOURCE = "db/migration/V202609261200__key_import.sql";

    private static final String SCRATCH_SCHEMA = "key_import_migration_check";

    private static final String INSERT_ATTEMPT = """
            INSERT INTO key_import (uuid, key_reference, idempotency_key, requester_uuid, requester_name,
                token_instance_uuid, token_profile_uuid, key_request_type, key_algorithm, spki_fingerprint, name,
                exportable, state, secret_digests, created_at, updated_at)
            VALUES (gen_random_uuid(), gen_random_uuid(), 'retry', gen_random_uuid(), 'requester', gen_random_uuid(),
                gen_random_uuid(), 'KEY_PAIR', 'RSA', 'fingerprint', 'key', false, ?, '[]', now(), now())
            """;

    @Autowired
    private DataSource dataSource;

    @Test
    void aKeyHasAtMostOneImportWhoseOutcomeIsOpen() throws Exception {
        try (Connection connection = dataSource.getConnection()) {
            try {
                // given
                applyMigration(connection);
                insertAttempt(connection, "REQUESTED");

                // when
                // then
                assertThatThrownBy(() -> insertAttempt(connection, "ACCEPTED"))
                        .isInstanceOf(SQLException.class)
                        .hasMessageContaining("uq_key_import_open_attempt");
            } finally {
                dropScratchSchema(connection);
            }
        }
    }

    @Test
    void settledImportsLeaveRoomForAnother() throws Exception {
        try (Connection connection = dataSource.getConnection()) {
            try {
                // given
                applyMigration(connection);
                insertAttempt(connection, "FAILED");
                insertAttempt(connection, "COMPLETED");

                // when
                insertAttempt(connection, "REQUESTED");

                // then
                try (Statement statement = connection.createStatement();
                        ResultSet count = statement.executeQuery("SELECT count(*) FROM key_import")) {
                    assertThat(count.next()).isTrue();
                    assertThat(count.getInt(1)).isEqualTo(3);
                }
            } finally {
                dropScratchSchema(connection);
            }
        }
    }

    private void applyMigration(Connection connection) throws Exception {
        String migration = new ClassPathResource(MIGRATION_RESOURCE).getContentAsString(StandardCharsets.UTF_8);
        try (Statement statement = connection.createStatement()) {
            statement.execute("DROP SCHEMA IF EXISTS " + SCRATCH_SCHEMA + " CASCADE");
            statement.execute("CREATE SCHEMA " + SCRATCH_SCHEMA);
            statement.execute("SET search_path TO " + SCRATCH_SCHEMA);
            statement.execute(migration);
        }
    }

    private static void insertAttempt(Connection connection, String state) throws SQLException {
        try (PreparedStatement insert = connection.prepareStatement(INSERT_ATTEMPT)) {
            insert.setString(1, state);
            insert.executeUpdate();
        }
    }

    private void dropScratchSchema(Connection connection) throws SQLException {
        try (Statement statement = connection.createStatement()) {
            statement.execute("DROP SCHEMA IF EXISTS " + SCRATCH_SCHEMA + " CASCADE");
        } finally {
            // The connection goes back to a pool shared with the rest of the suite.
            try (Statement reset = connection.createStatement()) {
                reset.execute("RESET search_path");
            }
        }
    }
}
