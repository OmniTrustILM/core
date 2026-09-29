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
 * Runs the key import migrations as Flyway will. The test bootstrap generates its schema from the entities, which
 * cannot express a partial index or a backfill, so this is where the one-open-attempt rule and the reconciliation
 * schedule are proven.
 */
class KeyImportMigrationITest extends BaseSpringBootTest {

    private static final String MIGRATION_RESOURCE = "db/migration/V202609261200__key_import.sql";

    private static final String RECONCILIATION_RESOURCE = "db/migration/V202609261800__key_import_reconciliation.sql";

    private static final String SECRET_KEY_RESOURCE = "db/migration/V202609271300__key_import_secret_key.sql";

    private static final String SCRATCH_SCHEMA = "key_import_migration_check";

    private static final String INSERT_SECRET_KEY_ATTEMPT = """
            INSERT INTO key_import (uuid, key_reference, idempotency_key, requester_uuid, requester_name,
                token_instance_uuid, token_profile_uuid, key_request_type, key_algorithm, spki_fingerprint, name,
                exportable, state, secret_digests, created_at, updated_at)
            VALUES (gen_random_uuid(), gen_random_uuid(), 'retry', gen_random_uuid(), 'requester', gen_random_uuid(),
                gen_random_uuid(), 'SECRET', 'AES', NULL, 'key', false, ?, '[]', now(), now())
            """;

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

    /** Another import of a key the reconciliation is undoing would put a second copy in the token meanwhile. */
    @Test
    void aKeyBeingUndoneTakesNoOtherImport() throws Exception {
        try (Connection connection = dataSource.getConnection()) {
            try {
                // given
                applyMigration(connection);
                runMigration(connection, RECONCILIATION_RESOURCE);
                insertAttempt(connection, "COMPENSATING");

                // when
                // then
                assertThatThrownBy(() -> insertAttempt(connection, "REQUESTED"))
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

    /** An import open when the reconciliation arrives is looked at once its requester had the retry window to retry. */
    @Test
    void anOpenImportIsLookedAtOnceItsRetryWindowPassed() throws Exception {
        try (Connection connection = dataSource.getConnection()) {
            try {
                // given
                applyMigration(connection);
                insertAttempt(connection, "ACCEPTED");
                insertAttempt(connection, "FAILED");

                // when
                runMigration(connection, RECONCILIATION_RESOURCE);

                // then
                try (Statement statement = connection.createStatement();
                        ResultSet rows = statement
                                .executeQuery(
                                        "SELECT state, next_check_at - created_at FROM key_import ORDER BY state")) {
                    assertThat(rows.next()).isTrue();
                    assertThat(rows.getString(1)).isEqualTo("ACCEPTED");
                    assertThat(rows.getString(2)).isEqualTo("00:15:00");
                    assertThat(rows.next()).isTrue();
                    assertThat(rows.getString(1)).isEqualTo("FAILED");
                    assertThat(rows.getString(2)).isNull();
                }
            } finally {
                dropScratchSchema(connection);
            }
        }
    }

    /** An instance that does not know the schedule yet records imports the reconciliation still looks at. */
    @Test
    void anImportRecordedWithoutItsScheduleIsLookedAtOnceItsRetryWindowPassed() throws Exception {
        try (Connection connection = dataSource.getConnection()) {
            try {
                // given
                applyMigration(connection);
                runMigration(connection, RECONCILIATION_RESOURCE);

                // when
                insertAttempt(connection, "REQUESTED");

                // then
                try (Statement statement = connection.createStatement();
                        ResultSet rows = statement.executeQuery("SELECT next_check_at - created_at FROM key_import")) {
                    assertThat(rows.next()).isTrue();
                    assertThat(rows.getString(1)).isEqualTo("00:15:00");
                }
            } finally {
                dropScratchSchema(connection);
            }
        }
    }

    /** An open import last changed when it was last sent, so one sent again before the upgrade keeps its window. */
    @Test
    void anOpenImportIsScheduledFromItsLastSend() throws Exception {
        try (Connection connection = dataSource.getConnection()) {
            try {
                // given
                applyMigration(connection);
                insertAttempt(connection, "REQUESTED");
                try (Statement statement = connection.createStatement()) {
                    statement
                            .executeUpdate("UPDATE key_import SET created_at = now() - interval '21 hours', "
                                    + "updated_at = now() - interval '10 minutes'");
                }

                // when
                runMigration(connection, RECONCILIATION_RESOURCE);

                // then
                try (Statement statement = connection.createStatement();
                        ResultSet rows = statement
                                .executeQuery("SELECT last_sent_at = updated_at, next_check_at - updated_at "
                                        + "FROM key_import")) {
                    assertThat(rows.next()).isTrue();
                    assertThat(rows.getBoolean(1)).isTrue();
                    assertThat(rows.getString(2)).isEqualTo("00:15:00");
                }
            } finally {
                dropScratchSchema(connection);
            }
        }
    }

    /** The reconciliation gives up on an import a while after it was last sent, so every import knows when that was. */
    @Test
    void everyImportKnowsWhenItWasLastSent() throws Exception {
        try (Connection connection = dataSource.getConnection()) {
            try {
                // given
                applyMigration(connection);
                insertAttempt(connection, "FAILED");

                // when
                runMigration(connection, RECONCILIATION_RESOURCE);
                insertAttempt(connection, "REQUESTED");

                // then
                try (Statement statement = connection.createStatement();
                        ResultSet rows = statement
                                .executeQuery("SELECT count(*) FROM key_import WHERE last_sent_at = created_at")) {
                    assertThat(rows.next()).isTrue();
                    assertThat(rows.getInt(1)).isEqualTo(2);
                }
            } finally {
                dropScratchSchema(connection);
            }
        }
    }

    @Test
    void theReconciliationLooksOnlyAtImportsItHasToSettle() throws Exception {
        try (Connection connection = dataSource.getConnection()) {
            try {
                // given
                applyMigration(connection);

                // when
                runMigration(connection, RECONCILIATION_RESOURCE);

                // then
                try (Statement statement = connection.createStatement();
                        ResultSet index = statement
                                .executeQuery("SELECT indexdef FROM pg_indexes WHERE schemaname = '" + SCRATCH_SCHEMA
                                        + "' AND indexname = 'idx_key_import_next_check_at'")) {
                    assertThat(index.next()).isTrue();
                    assertThat(index.getString(1)).contains("REQUESTED", "ACCEPTED", "COMPENSATING");
                }
            } finally {
                dropScratchSchema(connection);
            }
        }
    }

    /** A secret key has no public key, so its import is recorded without a fingerprint. */
    @Test
    void aSecretKeyImportIsRecordedWithoutAFingerprint() throws Exception {
        try (Connection connection = dataSource.getConnection()) {
            try {
                // given
                applyMigration(connection);
                runMigration(connection, RECONCILIATION_RESOURCE);
                runMigration(connection, SECRET_KEY_RESOURCE);

                // when
                insertSecretKeyAttempt(connection, "REQUESTED");

                // then
                try (Statement statement = connection.createStatement();
                        ResultSet rows = statement
                                .executeQuery("SELECT count(*) FROM key_import WHERE spki_fingerprint IS NULL")) {
                    assertThat(rows.next()).isTrue();
                    assertThat(rows.getInt(1)).isEqualTo(1);
                }
            } finally {
                dropScratchSchema(connection);
            }
        }
    }

    /** A retry while the reconciliation undoes a secret key's import would put a second copy in the token meanwhile. */
    @Test
    void aSecretKeyImportBeingUndoneTakesNoOtherAttempt() throws Exception {
        try (Connection connection = dataSource.getConnection()) {
            try {
                // given
                applyMigration(connection);
                runMigration(connection, RECONCILIATION_RESOURCE);
                runMigration(connection, SECRET_KEY_RESOURCE);
                insertSecretKeyAttempt(connection, "COMPENSATING");

                // when
                // then
                assertThatThrownBy(() -> insertSecretKeyAttempt(connection, "REQUESTED"))
                        .isInstanceOf(SQLException.class)
                        .hasMessageContaining("uq_key_import_open_secret_attempt");
            } finally {
                dropScratchSchema(connection);
            }
        }
    }

    private void applyMigration(Connection connection) throws Exception {
        try (Statement statement = connection.createStatement()) {
            statement.execute("DROP SCHEMA IF EXISTS " + SCRATCH_SCHEMA + " CASCADE");
            statement.execute("CREATE SCHEMA " + SCRATCH_SCHEMA);
            statement.execute("SET search_path TO " + SCRATCH_SCHEMA);
        }
        runMigration(connection, MIGRATION_RESOURCE);
    }

    private static void runMigration(Connection connection, String resource) throws Exception {
        String migration = new ClassPathResource(resource).getContentAsString(StandardCharsets.UTF_8);
        try (Statement statement = connection.createStatement()) {
            statement.execute(migration);
        }
    }

    private static void insertAttempt(Connection connection, String state) throws SQLException {
        insert(connection, INSERT_ATTEMPT, state);
    }

    private static void insertSecretKeyAttempt(Connection connection, String state) throws SQLException {
        insert(connection, INSERT_SECRET_KEY_ATTEMPT, state);
    }

    private static void insert(Connection connection, String attempt, String state) throws SQLException {
        try (PreparedStatement insert = connection.prepareStatement(attempt)) {
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
