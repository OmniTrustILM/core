package com.otilm.core.integration.migration;

import com.otilm.core.util.BaseSpringBootTest;
import java.nio.charset.StandardCharsets;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import javax.sql.DataSource;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.core.io.ClassPathResource;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/**
 * Runs {@code V202609141400__cbom_ingest_finding.sql} as Flyway will, and asserts what the catalogue then says.
 *
 * <p>
 * The regular test bootstrap generates its schema from the entities, so nothing else in the suite ever executes this
 * file: a check constraint that never compiled, a foreign key with the wrong delete action, or a unique constraint
 * under a different name would all pass unnoticed. That matters more than usual here, because the invariants are
 * deliberately written twice -- {@code CbomIngestFinding} states the same checks and the same names so that the
 * entity-generated schema the rest of the suite runs against carries them too -- and nothing else proves the two copies
 * agree.
 *
 * <p>
 * The migration runs in a scratch schema of its own, as {@code CryptoAssetInventoryMigrationITest} does: created,
 * populated with the one table it references, asserted against, and dropped, so the entity-generated {@code core}
 * schema is untouched and no separate container is needed.
 */
class CbomIngestFindingMigrationITest extends BaseSpringBootTest {

    private static final String MIGRATION_RESOURCE = "db/migration/V202609141400__cbom_ingest_finding.sql";

    private static final String SCRATCH_SCHEMA = "cbom_ingest_finding_migration_check";

    /** Only what the foreign key needs: the migration references {@code cbom(uuid)} and reads nothing else. */
    private static final String CBOM_STUB = """
            CREATE TABLE "cbom" (
                "uuid" UUID PRIMARY KEY,
                "serial_number" TEXT NOT NULL,
                "version" INT NOT NULL
            )
            """;

    private static final List<String> EXPECTED_CHECK_CONSTRAINTS = List
            .of("ck_cbom_ingest_finding_kind", "ck_cbom_ingest_finding_occurrences",
                    "ck_cbom_ingest_finding_detail_length", "ck_cbom_ingest_finding_component_name_length");

    private static final String CBOM_UUID = "11111111-0000-4000-8000-000000000001";
    private static final String FINDING_UUID = "22222222-0000-4000-8000-000000000001";

    @Autowired
    private DataSource dataSource;

    @Test
    void theMigrationBuildsTheSchemaItPromises() throws Exception {
        try (Connection connection = dataSource.getConnection()) {
            try {
                applyMigrationToScratchSchema(connection);

                assertForeignKeyDeleteActions(connection);
                assertCheckConstraints(connection);
                assertUniqueConstraints(connection);
                assertColumns(connection);
                assertTheChecksRefuseWhatTheyName(connection);
                assertADeletedCbomTakesItsFindings(connection);
            } finally {
                dropScratchSchema(connection);
            }
        }
    }

    // ---- setup / teardown ----

    private void applyMigrationToScratchSchema(Connection connection) throws Exception {
        String migration = new ClassPathResource(MIGRATION_RESOURCE).getContentAsString(StandardCharsets.UTF_8);
        try (Statement statement = connection.createStatement()) {
            statement.execute("DROP SCHEMA IF EXISTS " + SCRATCH_SCHEMA + " CASCADE");
            statement.execute("CREATE SCHEMA " + SCRATCH_SCHEMA);
            // Only the scratch schema is on the path, so an unqualified name in the migration cannot silently resolve
            // to the entity-generated core schema instead.
            statement.execute("SET search_path TO " + SCRATCH_SCHEMA);
            statement.execute(CBOM_STUB);
            statement.execute(migration);
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

    // ---- assertions ----

    private void assertForeignKeyDeleteActions(Connection connection) throws SQLException {
        Map<String, String> actions = new LinkedHashMap<>();
        try (PreparedStatement statement = connection.prepareStatement("""
                SELECT c.conname, c.confdeltype
                FROM pg_constraint c
                JOIN pg_class t ON t.oid = c.conrelid
                JOIN pg_namespace n ON n.oid = t.relnamespace
                WHERE n.nspname = ? AND c.contype = 'f'
                """)) {
            statement.setString(1, SCRATCH_SCHEMA);
            try (ResultSet rows = statement.executeQuery()) {
                while (rows.next()) {
                    actions.put(rows.getString(1), rows.getString(2));
                }
            }
        }

        assertThat(actions)
                .describedAs("c = CASCADE, unlike crypto_asset_source's RESTRICT: a finding is a statement about one "
                        + "document and means nothing once that document is gone")
                .containsEntry("cbom_ingest_finding_to_cbom_key", "c");
    }

    private void assertCheckConstraints(Connection connection) throws SQLException {
        List<String> checks = queryColumn(connection, """
                SELECT c.conname
                FROM pg_constraint c
                JOIN pg_class t ON t.oid = c.conrelid
                JOIN pg_namespace n ON n.oid = t.relnamespace
                WHERE n.nspname = ? AND c.contype = 'c'
                ORDER BY c.conname
                """, SCRATCH_SCHEMA);

        assertThat(checks)
                .describedAs("the same names the entity declares, so the generated schema and this one agree")
                .containsAll(EXPECTED_CHECK_CONSTRAINTS);
    }

    private void assertUniqueConstraints(Connection connection) throws SQLException {
        List<String> uniques = queryColumn(connection, """
                SELECT c.conname
                FROM pg_constraint c
                JOIN pg_class t ON t.oid = c.conrelid
                JOIN pg_namespace n ON n.oid = t.relnamespace
                WHERE n.nspname = ? AND c.contype = 'u'
                ORDER BY c.conname
                """, SCRATCH_SCHEMA);

        assertThat(uniques)
                .describedAs("the arbiter of the report's upsert, and what makes a redone ingest converge")
                .contains("uq_cbom_ingest_finding");
    }

    private void assertColumns(Connection connection) throws SQLException {
        Map<String, String> columns = new LinkedHashMap<>();
        try (PreparedStatement statement = connection.prepareStatement("""
                SELECT column_name, is_nullable || '|' || data_type
                FROM information_schema.columns
                WHERE table_schema = ? AND table_name = 'cbom_ingest_finding'
                """)) {
            statement.setString(1, SCRATCH_SCHEMA);
            try (ResultSet rows = statement.executeQuery()) {
                while (rows.next()) {
                    columns.put(rows.getString(1), rows.getString(2));
                }
            }
        }

        assertThat(columns)
                .containsOnly(Map.entry("uuid", "NO|uuid"), Map.entry("cbom_uuid", "NO|uuid"),
                        Map.entry("kind", "NO|text"), Map.entry("component_name", "YES|text"),
                        Map.entry("detail", "NO|text"), Map.entry("occurrences", "NO|integer"),
                        Map.entry("recorded_at", "NO|timestamp with time zone"));
    }

    private void assertTheChecksRefuseWhatTheyName(Connection connection) throws SQLException {
        try (Statement statement = connection.createStatement()) {
            statement
                    .execute("INSERT INTO cbom (uuid, serial_number, version) VALUES ('%s', 'urn:uuid:x', 1)"
                            .formatted(CBOM_UUID));

            assertThatThrownBy(() -> statement.execute(finding(FINDING_UUID, "WHATEVER", "d", 1)))
                    .describedAs("the kind is what the enum says, and nothing else")
                    .isInstanceOf(SQLException.class)
                    .hasMessageContaining("ck_cbom_ingest_finding_kind");

            assertThatThrownBy(() -> statement.execute(finding(FINDING_UUID, "FINDING", "d", -1)))
                    .isInstanceOf(SQLException.class)
                    .hasMessageContaining("ck_cbom_ingest_finding_occurrences");

            // 512 code points is the writer's bound; this is the backstop that makes it true of the column.
            assertThatThrownBy(() -> statement.execute(finding(FINDING_UUID, "FINDING", "d".repeat(513), 1)))
                    .isInstanceOf(SQLException.class)
                    .hasMessageContaining("ck_cbom_ingest_finding_detail_length");

            // The constraints count code points, not bytes: 512 astral characters fit where 512 * 4 bytes would not.
            statement.execute(finding(FINDING_UUID, "FINDING", "🔐".repeat(512), 1));
            statement.execute("DELETE FROM cbom_ingest_finding WHERE uuid = '%s'".formatted(FINDING_UUID));

            statement.execute(finding(FINDING_UUID, "FINDING", "d", 1));
            assertThatThrownBy(
                    () -> statement.execute(finding("33333333-0000-4000-8000-000000000001", "FINDING", "d", 2)))
                    .describedAs("one row per (document, kind, message), which is what the upsert arbitrates on")
                    .isInstanceOf(SQLException.class)
                    .hasMessageContaining("uq_cbom_ingest_finding");
        }
    }

    private void assertADeletedCbomTakesItsFindings(Connection connection) throws SQLException {
        try (Statement statement = connection.createStatement()) {
            statement.execute("DELETE FROM cbom WHERE uuid = '%s'".formatted(CBOM_UUID));
        }

        assertThat(queryColumn(connection, "SELECT count(*)::text FROM cbom_ingest_finding")).containsExactly("0");
    }

    // ---- helpers ----

    private static String finding(String uuid, String kind, String detail, int occurrences) {
        return """
                INSERT INTO cbom_ingest_finding (uuid, cbom_uuid, kind, component_name, detail, occurrences, recorded_at)
                VALUES ('%s', '%s', '%s', NULL, '%s', %d, now())
                """
                .formatted(uuid, CBOM_UUID, kind, detail, occurrences);
    }

    private List<String> queryColumn(Connection connection, String sql, String... parameters) throws SQLException {
        List<String> values = new ArrayList<>();
        try (PreparedStatement statement = connection.prepareStatement(sql)) {
            for (int i = 0; i < parameters.length; i++) {
                statement.setString(i + 1, parameters[i]);
            }
            try (ResultSet rows = statement.executeQuery()) {
                while (rows.next()) {
                    values.add(rows.getString(1));
                }
            }
        }
        return values;
    }
}
