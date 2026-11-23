package com.otilm.core.integration.migration;

import com.otilm.core.util.BaseSpringBootTest;
import java.nio.charset.StandardCharsets;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.ResultSetMetaData;
import java.sql.SQLException;
import java.sql.Statement;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.TreeMap;
import javax.sql.DataSource;
import org.assertj.core.api.ThrowableAssert.ThrowingCallable;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.core.io.ClassPathResource;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/**
 * Runs {@code V202611131000__est.sql} as Flyway will, against a schema that holds only the tables it extends or
 * references, with one RA Profile and its protocol attributes already in place.
 *
 * <p>
 * Nothing else in the suite executes the file: the test bootstrap generates its schema from the entities, which cannot
 * express the partial unique index and would hide a column the entity and the file name differently.
 */
class EstProfileMigrationITest extends BaseSpringBootTest {

    private static final String MIGRATION_RESOURCE = "db/migration/V202611131000__est.sql";

    private static final String SCRATCH_SCHEMA = "est_profile_migration_check";

    /** The tables the migration extends or references, as the migrations before it leave them. */
    private static final String PRECEDING_SCHEMA = """
            CREATE TABLE "ra_profile" ("uuid" UUID PRIMARY KEY);
            CREATE TABLE "token_profile" ("uuid" UUID PRIMARY KEY);
            CREATE TABLE "protocol_certificate_associations" ("uuid" UUID PRIMARY KEY);
            CREATE TABLE "ra_profile_protocol_attribute" ("uuid" UUID PRIMARY KEY, "ra_profile_uuid" UUID);
            CREATE TABLE "certificate" ("uuid" UUID PRIMARY KEY);
            CREATE TABLE "certificate_request" ("uuid" UUID PRIMARY KEY, "fingerprint" VARCHAR, "key_uuid" UUID,
                "alt_key_uuid" UUID);
            INSERT INTO "ra_profile" ("uuid") VALUES ('00000000-0000-4000-8000-0000000000a1');
            INSERT INTO "ra_profile_protocol_attribute" ("uuid", "ra_profile_uuid")
            VALUES ('00000000-0000-4000-8000-0000000000b1', '00000000-0000-4000-8000-0000000000a1');
            """;

    private static final String FIRST = "11111111-0000-4000-8000-000000000001";
    private static final String SECOND = "22222222-0000-4000-8000-000000000002";
    private static final String THIRD = "33333333-0000-4000-8000-000000000003";
    private static final String FOURTH = "44444444-0000-4000-8000-000000000004";
    private static final String REFERENCED = "55555555-0000-4000-8000-000000000005";

    @Autowired
    private DataSource dataSource;

    private Connection connection;

    @BeforeEach
    void migrateAScratchSchema() throws Exception {
        connection = dataSource.getConnection();
        execute("DROP SCHEMA IF EXISTS " + SCRATCH_SCHEMA + " CASCADE");
        execute("CREATE SCHEMA " + SCRATCH_SCHEMA);
        execute("SET search_path TO " + SCRATCH_SCHEMA);
        execute(PRECEDING_SCHEMA);
        execute(new ClassPathResource(MIGRATION_RESOURCE).getContentAsString(StandardCharsets.UTF_8));
    }

    @AfterEach
    void dropScratchSchema() throws Exception {
        if (connection == null) {
            return;
        }
        try {
            execute("DROP SCHEMA IF EXISTS " + SCRATCH_SCHEMA + " CASCADE");
        } finally {
            // The connection goes back to a pool shared with the rest of the suite.
            try (Connection scratch = connection; Statement reset = scratch.createStatement()) {
                reset.execute("RESET search_path");
            }
        }
    }

    // ── EstProfileTable ───────────────────────────────────────────────────────

    @Nested
    class EstProfileTable {

        @Test
        void appliesColumnDefaults_whenRowIsInsertedWithRequiredColumnsOnly() throws Exception {
            // given
            var requiredColumnsOnly = """
                    INSERT INTO est_profile (uuid, name, authentication_policy)
                    VALUES ('%s', 'est-devices', 'RA_BASIC')
                    """.formatted(FIRST);

            // when
            execute(requiredColumnsOnly);
            Map<String, Object> row = readSingleRow("""
                    SELECT enabled, system_default, allow_renewal, allow_rekey, server_key_generation, key_recovery,
                           cardinality(basic_credential_secret_uuids) AS secrets,
                           cardinality(trusted_ca_certificate_uuids) AS trusted_cas
                      FROM est_profile
                    """);

            // then
            assertThat(row)
                    .describedAs("a new profile is off and opts in to nothing; renewal and rekey are allowed; "
                            + "the reference lists are empty rather than NULL")
                    .containsEntry("enabled", false)
                    .containsEntry("system_default", false)
                    .containsEntry("server_key_generation", false)
                    .containsEntry("key_recovery", false)
                    .containsEntry("allow_renewal", true)
                    .containsEntry("allow_rekey", true)
                    .containsEntry("secrets", 0)
                    .containsEntry("trusted_cas", 0);
        }

        @Test
        void throwsUniqueViolation_whenSecondProfileIsTheSystemDefault() throws Exception {
            // given
            execute(buildEstProfileInsert(FIRST, "first", true));
            execute(buildEstProfileInsert(SECOND, "second", false));
            execute(buildEstProfileInsert(THIRD, "third", false));
            String secondSystemDefault = buildEstProfileInsert(FOURTH, "fourth", true);

            // when
            ThrowingCallable insertSecondSystemDefault = () -> execute(secondSystemDefault);

            // then
            assertThatThrownBy(insertSecondSystemDefault)
                    .describedAs("one profile serves requests sent without a label; any number of others may exist")
                    .isInstanceOf(SQLException.class)
                    .hasMessageContaining("uk_est_profile_single_system_default");
        }

        @Test
        void throwsUniqueViolation_whenNameIsTaken() throws Exception {
            // given
            var takenName = "est-devices";
            execute(buildEstProfileInsert(FIRST, takenName, false));
            String sameName = buildEstProfileInsert(SECOND, takenName, false);

            // when
            ThrowingCallable insertSameName = () -> execute(sameName);

            // then
            assertThatThrownBy(insertSameName)
                    .describedAs("the name is the label clients put in the URL")
                    .isInstanceOf(SQLException.class)
                    .hasMessageContaining("est_profile_name_key");
        }
    }

    // ── ExistingTables ────────────────────────────────────────────────────────

    @Nested
    class ExistingTables {

        @Test
        void leavesEstProfileUnset_whenRaProfileExistedBeforeTheMigration() throws Exception {
            // given — an RA Profile that existed before the migration

            // when
            Map<String, Object> raProfile = readSingleRow("SELECT est_profile_uuid FROM ra_profile");

            // then
            assertThat(raProfile)
                    .describedAs("an RA Profile that existed before the upgrade has no EST Profile activated")
                    .containsEntry("est_profile_uuid", null);
        }

        @Test
        void leavesEstIssueAttributesUnset_whenProtocolAttributesExistedBeforeTheMigration() throws Exception {
            // given — protocol attributes of an RA Profile that existed before the migration

            // when
            Map<String, Object> protocolAttribute = readSingleRow(
                    "SELECT est_issue_certificate_attributes FROM ra_profile_protocol_attribute");

            // then
            assertThat(protocolAttribute)
                    .describedAs("protocol attributes that existed before the upgrade store no EST issue attributes")
                    .containsEntry("est_issue_certificate_attributes", null);
        }

        @Test
        void createsIndexOnTheEstProfileOfRaProfile() throws Exception {
            // given — the migrated scratch schema

            // when
            Map<String, Object> index = readSingleRow("""
                    SELECT count(*) AS present FROM pg_indexes
                     WHERE schemaname = '%s' AND indexname = 'idx_ra_profile_est_profile_uuid'
                    """.formatted(SCRATCH_SCHEMA));

            // then
            assertThat(index)
                    .describedAs("finding the RA Profiles of an EST Profile must not scan every RA Profile")
                    .containsEntry("present", 1L);
        }
    }

    // ── ReferenceGuards ───────────────────────────────────────────────────────

    @Nested
    class ReferenceGuards {

        @Test
        void throwsForeignKeyViolation_whenDeletingAnEstProfileActivatedOnAnRaProfile() throws Exception {
            // given
            execute(buildEstProfileInsert(FIRST, "est-devices", false));
            execute("UPDATE ra_profile SET est_profile_uuid = '%s'".formatted(FIRST));

            // when
            ThrowingCallable deleteEstProfile = () -> execute("DELETE FROM est_profile");

            // then
            assertThatThrownBy(deleteEstProfile)
                    .isInstanceOf(SQLException.class)
                    .hasMessageContaining("ra_profile_to_est_profile_key");
        }

        @ParameterizedTest(name = "{0} cannot be deleted while an EST Profile references it")
        @CsvSource({
                "ra_profile, ra_profile_uuid, fk_est_profile_ra_profile",
                "token_profile, key_recovery_token_profile_uuid, fk_est_profile_key_recovery_token_profile",
                "protocol_certificate_associations, certificate_associations_uuid, fk_est_profile_certificate_associations"})
        void throwsForeignKeyViolation_whenDeletingARowAnEstProfileReferences(String table, String referencingColumn,
                String constraint) throws Exception {
            // given
            execute("INSERT INTO %s (uuid) VALUES ('%s')".formatted(table, REFERENCED));
            execute("""
                    INSERT INTO est_profile (uuid, name, authentication_policy, %s)
                    VALUES ('%s', 'est-devices', 'RA_BASIC', '%s')
                    """.formatted(referencingColumn, FIRST, REFERENCED));
            String deletion = "DELETE FROM %s WHERE uuid = '%s'".formatted(table, REFERENCED);

            // when
            ThrowingCallable deleteReferencedRow = () -> execute(deletion);

            // then
            assertThatThrownBy(deleteReferencedRow).isInstanceOf(SQLException.class).hasMessageContaining(constraint);
        }
    }

    // ── EntityMapping ─────────────────────────────────────────────────────────

    @Nested
    class EntityMapping {

        @Test
        void matchesColumnsOfTheMigratedEstProfileTable() throws Exception {
            // given — the est_profile table as the file creates it and as the entity maps it

            // when
            Map<String, String> migratedColumns = readColumns(SCRATCH_SCHEMA, "est_profile");
            Map<String, String> mappedColumns = readColumns(dbSchema, "est_profile");

            // then
            assertThat(migratedColumns)
                    .describedAs("est_profile as the file creates it, against est_profile as the entity maps it")
                    .isEqualTo(mappedColumns);
        }

        @Test
        void includesEstProfileColumnTheMigrationAddsToRaProfile() throws Exception {
            // given — the ra_profile table as the entity maps it

            // when
            Map<String, String> mappedColumns = readColumns(dbSchema, "ra_profile");

            // then
            assertThat(mappedColumns).containsKey("est_profile_uuid");
        }

        @Test
        void includesEstIssueAttributesColumnTheMigrationAddsToProtocolAttributes() throws Exception {
            // given — the ra_profile_protocol_attribute table as the entity maps it

            // when
            Map<String, String> mappedColumns = readColumns(dbSchema, "ra_profile_protocol_attribute");

            // then
            assertThat(mappedColumns).containsKey("est_issue_certificate_attributes");
        }

        // ── Helpers ───────────────────────────────────────────────────────────

        /** Column name to nullability, which the column types of the generated schema cannot be compared on. */
        private Map<String, String> readColumns(String schema, String table) throws SQLException {
            Map<String, String> columns = new TreeMap<>();
            try (PreparedStatement statement = connection.prepareStatement("""
                    SELECT column_name, is_nullable FROM information_schema.columns
                     WHERE table_schema = ? AND table_name = ?
                    """)) {
                statement.setString(1, schema);
                statement.setString(2, table);
                try (ResultSet rows = statement.executeQuery()) {
                    while (rows.next()) {
                        columns.put(rows.getString("column_name"), rows.getString("is_nullable"));
                    }
                }
            }
            return columns;
        }
    }

    // ── Helpers ───────────────────────────────────────────────────────────────

    private void execute(String sql) throws SQLException {
        try (Statement statement = connection.createStatement()) {
            statement.execute(sql);
        }
    }

    private Map<String, Object> readSingleRow(String sql) throws SQLException {
        try (Statement statement = connection.createStatement(); ResultSet rows = statement.executeQuery(sql)) {
            assertThat(rows.next()).describedAs("a row for: %s", sql).isTrue();
            ResultSetMetaData columns = rows.getMetaData();
            Map<String, Object> row = new LinkedHashMap<>();
            for (int column = 1; column <= columns.getColumnCount(); column++) {
                row.put(columns.getColumnLabel(column), rows.getObject(column));
            }
            assertThat(rows.next()).describedAs("exactly one row for: %s", sql).isFalse();
            return row;
        }
    }

    private static String buildEstProfileInsert(String uuid, String name, boolean systemDefault) {
        return """
                INSERT INTO est_profile (uuid, name, authentication_policy, system_default)
                VALUES ('%s', '%s', 'RA_BASIC', %s)
                """.formatted(uuid, name, systemDefault);
    }
}
