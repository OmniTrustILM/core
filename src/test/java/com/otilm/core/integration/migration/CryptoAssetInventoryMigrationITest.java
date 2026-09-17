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
import java.util.Locale;
import java.util.Map;
import javax.sql.DataSource;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.core.io.ClassPathResource;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/**
 * Runs {@code V202608271000__crypto_asset_inventory.sql} and the {@code asset_sync_attempted_at} migration that follows
 * it, as Flyway will, and asserts what the catalogue then says.
 *
 * <p>
 * The regular test bootstrap generates its schema from the entities, so nothing else in the suite ever executes this
 * file: an index that was never created, a foreign key with the wrong delete action, or a check constraint that never
 * compiled would all pass unnoticed. The migration runs in a scratch schema of its own -- created, populated with the
 * one table it alters, asserted against, and dropped -- so the entity-generated {@code core} schema is untouched and no
 * separate container is needed.
 */
class CryptoAssetInventoryMigrationITest extends BaseSpringBootTest {

    private static final String MIGRATION_RESOURCE = "db/migration/V202608271000__crypto_asset_inventory.sql";

    /**
     * Applied after it, in Flyway's order. It drops one of the inventory migration's own indexes for a composite that
     * has it as a strict prefix, which the catalogue assertions below are the only thing that would notice.
     */
    private static final String ATTEMPT_MIGRATION_RESOURCE = "db/migration/V202609141200__cbom_asset_sync_attempted_at.sql";

    private static final String SCRATCH_SCHEMA = "crypto_asset_migration_check";

    /** Only the columns the migration's ALTER touches: it adds columns and reads nothing else about the table. */
    private static final String CBOM_STUB = """
            CREATE TABLE "cbom" (
                "uuid" UUID PRIMARY KEY,
                "serial_number" TEXT NOT NULL,
                "version" INT NOT NULL
            )
            """;

    private static final List<String> EXPECTED_INDEXES = List
            .of("idx_crypto_asset_asset_type", "idx_crypto_asset_name", "idx_crypto_asset_oid",
                    "idx_crypto_asset_algorithm_family", "idx_crypto_asset_primitive", "idx_crypto_asset_parameter_set",
                    "idx_crypto_asset_curve", "idx_crypto_asset_mode", "idx_crypto_asset_padding",
                    "idx_crypto_asset_variant", "idx_crypto_asset_pqc_verdict", "idx_crypto_asset_pqc_ruleset_version",
                    "idx_crypto_asset_ruleset_version", "idx_crypto_asset_source_count",
                    "idx_crypto_asset_properties_source", "idx_crypto_asset_source_cbom",
                    "idx_crypto_asset_alias_canonical", "idx_cbom_asset_sync_attempt", "idx_cbom_assets_synced_at");

    private static final Map<String, String> EXPECTED_FOREIGN_KEY_ACTIONS = Map
            .of("crypto_asset_source_to_crypto_asset_key", "c", "crypto_asset_source_to_cbom_key", "r",
                    "crypto_asset_to_properties_source_key", "n", "crypto_asset_alias_to_canonical_key", "c");

    private static final List<String> EXPECTED_CHECK_CONSTRAINTS = List
            .of("ck_crypto_asset_properties_pair", "ck_crypto_asset_source_count",
                    "ck_crypto_asset_properties_leaf_count", "ck_crypto_asset_source_occurrence_count",
                    "ck_crypto_asset_source_properties_leaf_count", "ck_crypto_asset_alias_not_self",
                    "ck_crypto_asset_asset_type", "ck_crypto_asset_identity_guard", "ck_crypto_asset_pqc_verdict",
                    "ck_crypto_asset_oid_length", "ck_crypto_asset_name_length", "ck_cbom_asset_sync_state");

    private static final String CBOM_UUID = "11111111-0000-4000-8000-000000000001";
    private static final String ASSET_UUID = "22222222-0000-4000-8000-000000000001";
    private static final String SOURCE_UUID = "33333333-0000-4000-8000-000000000001";

    @Autowired
    private DataSource dataSource;

    @Test
    void theMigrationBuildsTheSchemaItPromises() throws Exception {
        try (Connection connection = dataSource.getConnection()) {
            try {
                applyMigrationToScratchSchema(connection);

                assertIndexes(connection);
                assertForeignKeyDeleteActions(connection);
                assertCheckConstraints(connection);
                assertUniqueConstraints(connection);
                assertCbomColumns(connection);
                assertNoGinIndexes(connection);
                assertDeleteBehaviour(connection);
            } finally {
                dropScratchSchema(connection);
            }
        }
    }

    @Test
    void theMigrationUsesNoneOfTheThingsV1Excludes() throws Exception {
        String sql = new ClassPathResource(MIGRATION_RESOURCE).getContentAsString(StandardCharsets.UTF_8);
        // Line comments are stripped first: the migration's own rationale says these words, and a rule that matched
        // its own explanation would be unfailable for the wrong reason.
        String statements = sql.replaceAll("(?m)--.*$", "").toUpperCase(Locale.ROOT);

        assertThat(statements)
                .describedAs("no GIN, no CREATE EXTENSION and no partitioning in v1")
                .doesNotContain("USING GIN")
                .doesNotContain("CREATE EXTENSION")
                .doesNotContain("PARTITION BY");
        assertThat(statements).describedAs("the statements survived comment stripping").contains("CREATE TABLE");
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
            statement
                    .execute(new ClassPathResource(ATTEMPT_MIGRATION_RESOURCE)
                            .getContentAsString(StandardCharsets.UTF_8));
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

    private void assertIndexes(Connection connection) throws SQLException {
        List<String> indexes = queryColumn(connection,
                "SELECT indexname FROM pg_indexes WHERE schemaname = ? ORDER BY indexname", SCRATCH_SCHEMA);

        assertThat(indexes)
                .describedAs("a btree per filter column, plus the indexes the referential actions need to stay off a "
                        + "sequential scan. No lower() expression index: nothing emits lower()")
                .containsAll(EXPECTED_INDEXES);
    }

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
                .describedAs("c = CASCADE, r = RESTRICT, n = SET NULL: the delete actions are the schema's promise "
                        + "about what survives a deletion")
                .containsAllEntriesOf(EXPECTED_FOREIGN_KEY_ACTIONS);
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

        assertThat(checks).containsAll(EXPECTED_CHECK_CONSTRAINTS);
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
                .describedAs("identity_key is a plain UNIQUE so it can arbitrate ON CONFLICT")
                .contains("uq_crypto_asset_identity_key", "uq_crypto_asset_source", "uq_crypto_asset_alias_absorbed",
                        "uq_cbom_tombstone_serial_version");
    }

    private void assertCbomColumns(Connection connection) throws SQLException {
        Map<String, String> columns = new LinkedHashMap<>();
        try (PreparedStatement statement = connection.prepareStatement("""
                SELECT column_name, is_nullable || '|' || data_type || '|' || COALESCE(column_default, '')
                FROM information_schema.columns
                WHERE table_schema = ? AND table_name = 'cbom'
                  AND column_name IN ('asset_sync_state', 'asset_sync_error', 'assets_synced_at')
                """)) {
            statement.setString(1, SCRATCH_SCHEMA);
            try (ResultSet rows = statement.executeQuery()) {
                while (rows.next()) {
                    columns.put(rows.getString(1), rows.getString(2));
                }
            }
        }

        assertThat(columns).containsOnlyKeys("asset_sync_state", "asset_sync_error", "assets_synced_at");
        assertThat(columns.get("asset_sync_state"))
                .describedAs("existing header-only rows must read as PENDING: their assets were never ingested")
                .isEqualTo("NO|text|'PENDING'::text");
        assertThat(columns.get("asset_sync_error")).startsWith("YES|text|");
        assertThat(columns.get("assets_synced_at")).startsWith("YES|timestamp with time zone|");
    }

    private void assertNoGinIndexes(Connection connection) throws SQLException {
        List<String> definitions = queryColumn(connection, "SELECT indexdef FROM pg_indexes WHERE schemaname = ?",
                SCRATCH_SCHEMA);

        assertThat(definitions)
                .describedAs("v1 ships no GIN index; merged_crypto_properties is deliberately unindexed")
                .noneMatch(definition -> definition.toLowerCase(Locale.ROOT).contains("using gin"));
    }

    private void assertDeleteBehaviour(Connection connection) throws SQLException {
        try (Statement statement = connection.createStatement()) {
            statement
                    .execute("INSERT INTO cbom (uuid, serial_number, version) VALUES ('%s', 'urn:uuid:x', 1)"
                            .formatted(CBOM_UUID));
            statement.execute("""
                    INSERT INTO crypto_asset (uuid, identity_key, ruleset_version, asset_type, i_cre, i_upd)
                    VALUES ('%s', 'deadbeef', 1, 'ALGORITHM', now(), now())
                    """.formatted(ASSET_UUID));
            statement.execute("""
                    INSERT INTO crypto_asset_source (uuid, asset_uuid, cbom_uuid, first_seen_at, last_seen_at)
                    VALUES ('%s', '%s', '%s', now(), now())
                    """.formatted(SOURCE_UUID, ASSET_UUID, CBOM_UUID));
            statement
                    .execute("UPDATE crypto_asset SET properties_source_uuid = '%s' WHERE uuid = '%s'"
                            .formatted(SOURCE_UUID, ASSET_UUID));

            // RESTRICT: the CBOM cannot go while the inventory still points at it.
            assertThatThrownBy(() -> statement.execute("DELETE FROM cbom WHERE uuid = '%s'".formatted(CBOM_UUID)))
                    .isInstanceOf(SQLException.class)
                    .hasMessageContaining("crypto_asset_source_to_cbom_key");

            // SET NULL: the provenance pointer never outlives the row it names.
            statement.execute("DELETE FROM crypto_asset_source WHERE uuid = '%s'".formatted(SOURCE_UUID));
            assertThat(queryColumn(connection,
                    "SELECT COALESCE(properties_source_uuid::text, 'NULL') FROM crypto_asset WHERE uuid = ?::uuid",
                    ASSET_UUID)).containsExactly("NULL");

            // CASCADE the other way: a source reference is meaningless without its asset.
            statement.execute("""
                    INSERT INTO crypto_asset_source (uuid, asset_uuid, cbom_uuid, first_seen_at, last_seen_at)
                    VALUES ('%s', '%s', '%s', now(), now())
                    """.formatted(SOURCE_UUID, ASSET_UUID, CBOM_UUID));
            statement.execute("""
                    INSERT INTO crypto_asset_alias (uuid, absorbed_key, canonical_key, decided_at)
                    VALUES ('44444444-0000-4000-8000-000000000001', 'cafebabe', 'deadbeef', now())
                    """);
            statement.execute("DELETE FROM crypto_asset WHERE uuid = '%s'".formatted(ASSET_UUID));
            assertThat(queryColumn(connection, "SELECT count(*)::text FROM crypto_asset_source")).containsExactly("0");
            assertThat(queryColumn(connection, "SELECT count(*)::text FROM crypto_asset_alias")).containsExactly("0");

            // And with nothing referencing it any more, the CBOM goes.
            statement.execute("DELETE FROM cbom WHERE uuid = '%s'".formatted(CBOM_UUID));
        }
    }

    // ---- helpers ----

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
