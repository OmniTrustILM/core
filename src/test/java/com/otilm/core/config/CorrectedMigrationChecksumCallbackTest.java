package com.otilm.core.config;

import com.otilm.core.config.CorrectedMigrationChecksumCallback.CorrectedMigration;
import com.otilm.core.util.DatabaseMigration;
import java.io.File;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;
import java.util.List;
import java.util.UUID;
import org.assertj.core.api.ThrowableAssert.ThrowingCallable;
import org.flywaydb.core.Flyway;
import org.flywaydb.core.api.output.MigrateResult;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;
import org.testcontainers.containers.PostgreSQLContainer;
import org.testcontainers.junit.jupiter.Container;
import org.testcontainers.junit.jupiter.Testcontainers;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

@Testcontainers
class CorrectedMigrationChecksumCallbackTest {

    private static final String SCHEMA = "core";
    private static final String HISTORY_TABLE = "core_schema_history";
    private static final String MIGRATIONS = "classpath:db/corrected-migration-checksum";
    private static final String MIGRATIONS_DIRECTORY = "src/main/resources/db/migration/";

    @Container
    private static final PostgreSQLContainer<?> POSTGRES = new PostgreSQLContainer<>(
            FlywaySearchPathCallbackTest.minimumSupportedPostgres());

    @ParameterizedTest
    @MethodSource("correctedMigrations")
    void holdsChecksumOfCurrentScript(CorrectedMigration migration) throws Exception {
        // given
        String script = MIGRATIONS_DIRECTORY + scriptName(migration.version());

        // when
        int checksum = DatabaseMigration.calculateChecksum(script);

        // then
        assertThat(migration.correctedChecksum()).isEqualTo(checksum);
    }

    @Test
    void migratesDatabase_whenSchemaHistoryDoesNotExistYet() throws SQLException {
        // given
        String database = emptyDatabase();
        var callback = new CorrectedMigrationChecksumCallback(List.of(new CorrectedMigration("1", 1, 2)));

        // when
        MigrateResult result = flyway(database, callback).migrate();

        // then
        assertThat(result.success).isTrue();
        assertThat(result.migrationsExecuted).isEqualTo(1);
    }

    @Test
    void acceptsCorrectedScript_whenDatabaseAppliedTheEarlierOne() throws SQLException {
        // given
        String database = emptyDatabase();
        flyway(database).migrate();
        int correctedChecksum = recordedChecksum(database);
        int earlierChecksum = correctedChecksum + 1;
        recordChecksum(database, earlierChecksum);
        var callback = new CorrectedMigrationChecksumCallback(
                List.of(new CorrectedMigration("1", earlierChecksum, correctedChecksum)));

        // when
        MigrateResult result = flyway(database, callback).migrate();

        // then
        assertThat(result.success).isTrue();
        assertThat(recordedChecksum(database)).isEqualTo(correctedChecksum);
    }

    @Test
    void failsValidation_whenRecordedChecksumIsNeitherScript() throws SQLException {
        // given
        String database = emptyDatabase();
        flyway(database).migrate();
        int correctedChecksum = recordedChecksum(database);
        int unknownChecksum = correctedChecksum + 2;
        recordChecksum(database, unknownChecksum);
        var callback = new CorrectedMigrationChecksumCallback(
                List.of(new CorrectedMigration("1", correctedChecksum + 1, correctedChecksum)));

        // when
        ThrowingCallable migrate = () -> flyway(database, callback).migrate();

        // then
        assertThatThrownBy(migrate).hasMessageContaining("checksum mismatch");
        assertThat(recordedChecksum(database)).isEqualTo(unknownChecksum);
    }

    // ── Helpers ───────────────────────────────────────────────────────────────

    static List<CorrectedMigration> correctedMigrations() {
        return CorrectedMigrationChecksumCallback.CORRECTED_MIGRATIONS;
    }

    private static String scriptName(String version) {
        String prefix = "V" + version + "__";
        String[] scripts = new File(MIGRATIONS_DIRECTORY)
                .list((directory, name) -> name.startsWith(prefix) && name.endsWith(".sql"));
        assertThat(scripts).as("script of version " + version).hasSize(1);
        return scripts[0];
    }

    private static Flyway flyway(String database, CorrectedMigrationChecksumCallback... callbacks) {
        return Flyway
                .configure()
                .dataSource(url(database), POSTGRES.getUsername(), POSTGRES.getPassword())
                .schemas(SCHEMA)
                .table(HISTORY_TABLE)
                .locations(MIGRATIONS)
                .callbacks(callbacks)
                .load();
    }

    private static String emptyDatabase() throws SQLException {
        String database = "db_" + UUID.randomUUID().toString().replace("-", "");
        try (Connection connection = connection(POSTGRES.getDatabaseName());
                Statement statement = connection.createStatement()) {
            statement.execute("CREATE DATABASE " + database);
        }
        return database;
    }

    private static int recordedChecksum(String database) throws SQLException {
        try (Connection connection = connection(database);
                Statement statement = connection.createStatement();
                ResultSet resultSet = statement
                        .executeQuery(
                                "SELECT checksum FROM " + SCHEMA + "." + HISTORY_TABLE + " WHERE version = '1'")) {
            resultSet.next();
            return resultSet.getInt(1);
        }
    }

    private static void recordChecksum(String database, int checksum) throws SQLException {
        try (Connection connection = connection(database);
                PreparedStatement statement = connection
                        .prepareStatement(
                                "UPDATE " + SCHEMA + "." + HISTORY_TABLE + " SET checksum = ? WHERE version = '1'")) {
            statement.setInt(1, checksum);
            statement.executeUpdate();
        }
    }

    private static Connection connection(String database) throws SQLException {
        return DriverManager.getConnection(url(database), POSTGRES.getUsername(), POSTGRES.getPassword());
    }

    private static String url(String database) {
        return "jdbc:postgresql://" + POSTGRES.getHost() + ":" + POSTGRES.getMappedPort(5432) + "/" + database;
    }
}
