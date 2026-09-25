package com.otilm.core.integration.migration;

import com.otilm.core.util.BaseSpringBootTest;
import java.nio.charset.StandardCharsets;
import java.sql.Connection;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;
import java.util.ArrayList;
import java.util.List;
import java.util.stream.Stream;
import javax.sql.DataSource;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.core.io.ClassPathResource;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/**
 * Applies {@code V202609251800__listing_query_indexes.sql} to tables shaped as in production and asserts that each
 * index answers its lookup and that uuid and fingerprint stay unique without the dropped constraints.
 *
 * <p>
 * The suite's schema is generated from the entities, which declare none of these indexes, so nothing else would notice
 * an index renamed, reordered or dropped.
 */
class ListingQueryIndexesMigrationITest extends BaseSpringBootTest {

    private static final String MIGRATION_RESOURCE = "db/migration/V202609251800__listing_query_indexes.sql";

    private static final String SCRATCH_SCHEMA = "listing_query_indexes_check";

    private static final String SOME_UUID = "5f0a3c5e-9c0b-4f7e-8d8b-2b6f1c9e4a11";

    /**
     * The columns the migration touches, and a foreign key into certificate.
     *
     * <p>
     * The duplicates are added by {@code ALTER TABLE}, as in production: {@code CREATE TABLE} would fold them into one
     * index and leave nothing to drop. The primary key comes first, so the foreign key binds to it the same way.
     */
    private static final String TABLES = """
            CREATE TABLE "certificate" (
                "uuid" UUID PRIMARY KEY,
                "fingerprint" VARCHAR,
                "not_after" TIMESTAMP(6)
            );
            ALTER TABLE "certificate" ADD CONSTRAINT "certificate_uuid_unique" UNIQUE ("uuid");
            ALTER TABLE "certificate" ADD CONSTRAINT "certificate_fingerprint_key" UNIQUE ("fingerprint");
            ALTER TABLE "certificate" ADD CONSTRAINT "certificate_fingerprint_key1" UNIQUE ("fingerprint");
            CREATE TABLE "certificate_event_history" (
                "uuid" UUID PRIMARY KEY,
                "certificate_uuid" UUID NOT NULL REFERENCES "certificate" ("uuid")
            );
            CREATE TABLE "cryptographic_key_item" (
                "uuid" UUID PRIMARY KEY,
                "created_at" TIMESTAMP(6) NOT NULL
            );
            CREATE TABLE "attribute_content_item" (
                "uuid" UUID PRIMARY KEY,
                "json" JSONB NOT NULL,
                "attribute_definition_uuid" UUID NOT NULL
            );
            CREATE TABLE "attribute_content_2_object" (
                "uuid" UUID PRIMARY KEY,
                "object_type" VARCHAR NOT NULL,
                "object_uuid" UUID NOT NULL,
                "attribute_content_item_uuid" UUID NOT NULL
            );
            CREATE TABLE "group_association" (
                "uuid" UUID PRIMARY KEY,
                "resource" TEXT NOT NULL,
                "object_uuid" UUID NOT NULL,
                "group_uuid" UUID NOT NULL
            );
            CREATE TABLE "owner_association" (
                "uuid" UUID PRIMARY KEY,
                "resource" TEXT NOT NULL,
                "object_uuid" UUID NOT NULL,
                "owner_uuid" UUID NOT NULL,
                "owner_username" TEXT NOT NULL
            );
            """;

    private static final String ROWS = """
            INSERT INTO certificate (uuid, fingerprint, not_after)
            SELECT gen_random_uuid(), 'fingerprint-' || g, now() + g * INTERVAL '1 day' FROM generate_series(1, 500) g;
            INSERT INTO cryptographic_key_item (uuid, created_at)
            SELECT gen_random_uuid(), now() - g * INTERVAL '1 hour' FROM generate_series(1, 500) g;
            INSERT INTO attribute_content_item (uuid, json, attribute_definition_uuid)
            SELECT gen_random_uuid(), '{}'::JSONB, gen_random_uuid() FROM generate_series(1, 500) g;
            INSERT INTO attribute_content_2_object (uuid, object_type, object_uuid, attribute_content_item_uuid)
            SELECT gen_random_uuid(), 'CERTIFICATE', gen_random_uuid(), uuid FROM attribute_content_item;
            INSERT INTO group_association (uuid, resource, object_uuid, group_uuid)
            SELECT gen_random_uuid(), 'CERTIFICATE', gen_random_uuid(), gen_random_uuid() FROM generate_series(1, 500) g;
            INSERT INTO owner_association (uuid, resource, object_uuid, owner_uuid, owner_username)
            SELECT gen_random_uuid(), 'CERTIFICATE', gen_random_uuid(), gen_random_uuid(), 'user-' || g
            FROM generate_series(1, 500) g;
            ANALYZE certificate, cryptographic_key_item, attribute_content_item, attribute_content_2_object,
                group_association, owner_association;
            """;

    @Autowired
    private DataSource dataSource;

    static Stream<Arguments> lookups() {
        return Stream
                .of(lookup("idx_attribute_content_item_definition",
                        "SELECT uuid FROM attribute_content_item WHERE attribute_definition_uuid = '%s'"),
                        lookup("idx_attribute_content_2_object_item",
                                "SELECT object_uuid FROM attribute_content_2_object"
                                        + " WHERE attribute_content_item_uuid = '%s' AND object_type = 'CERTIFICATE'"),
                        lookup("idx_group_association_object",
                                "SELECT group_uuid FROM group_association WHERE object_uuid = '%s' AND resource = 'CERTIFICATE'"),
                        lookup("idx_group_association_group",
                                "SELECT object_uuid FROM group_association WHERE group_uuid IN ('%s') AND resource = 'CERTIFICATE'"),
                        lookup("idx_owner_association_object",
                                "SELECT owner_username FROM owner_association WHERE object_uuid = '%s'"),
                        lookup("idx_owner_association_owner",
                                "SELECT object_uuid FROM owner_association WHERE owner_username = 'user-7' AND resource = 'CERTIFICATE'"),
                        lookup("idx_cryptographic_key_item_created_at",
                                "SELECT uuid FROM cryptographic_key_item ORDER BY created_at DESC LIMIT 25"),
                        lookup("idx_certificate_not_after",
                                "SELECT uuid FROM certificate ORDER BY not_after LIMIT 25"));
    }

    /** One lookup a listing makes, and the index expected to answer it; {@code %s} stands for a uuid. */
    private static Arguments lookup(String index, String query) {
        return Arguments.of(index, query);
    }

    /**
     * Sequential scans are disabled for the check: on tables this size the planner would pick one on cost alone, and
     * the question is whether the index answers the lookup at all.
     */
    @ParameterizedTest(name = "{0}")
    @MethodSource("lookups")
    void eachIndexAnswersTheLookupItIsThereFor(String index, String lookup) throws Exception {
        try (Connection connection = dataSource.getConnection()) {
            try {
                createTables(connection);
                applyMigration(connection);
                execute(connection, ROWS);

                assertThat(planFor(connection, lookup.formatted(SOME_UUID))).contains(index);
            } finally {
                dropScratchSchema(connection);
            }
        }
    }

    @Test
    void theDuplicateConstraintsGoWhileUuidAndFingerprintStayUnique() throws Exception {
        try (Connection connection = dataSource.getConnection()) {
            try {
                createTables(connection);
                assertThat(uniqueConstraints(connection))
                        .describedAs("the duplicates exist before the migration, as in production")
                        .containsExactlyInAnyOrder("certificate_pkey", "certificate_uuid_unique",
                                "certificate_fingerprint_key", "certificate_fingerprint_key1");
                assertThat(foreignKeyIndex(connection))
                        .describedAs("the foreign key binds to the primary key before the migration, as in production")
                        .isEqualTo("certificate_pkey");

                applyMigration(connection);

                assertThat(uniqueConstraints(connection))
                        .containsExactlyInAnyOrder("certificate_pkey", "certificate_fingerprint_key");
                assertThat(foreignKeyIndex(connection)).isEqualTo("certificate_pkey");

                execute(connection, "INSERT INTO certificate (uuid, fingerprint) VALUES ('%s', 'fingerprint-a')"
                        .formatted(SOME_UUID));
                assertThatThrownBy(() -> execute(connection,
                        "INSERT INTO certificate (uuid, fingerprint) VALUES ('%s', 'fingerprint-b')"
                                .formatted(SOME_UUID)))
                        .describedAs("uuid stays unique through the primary key")
                        .isInstanceOfSatisfying(SQLException.class,
                                rejection -> assertThat(rejection.getSQLState()).isEqualTo("23505"));
                assertThatThrownBy(() -> execute(connection,
                        "INSERT INTO certificate (uuid, fingerprint) VALUES (gen_random_uuid(), 'fingerprint-a')"))
                        .describedAs("fingerprint stays unique through certificate_fingerprint_key")
                        .isInstanceOfSatisfying(SQLException.class,
                                rejection -> assertThat(rejection.getSQLState()).isEqualTo("23505"));
            } finally {
                dropScratchSchema(connection);
            }
        }
    }

    private void createTables(Connection connection) throws SQLException {
        try (Statement statement = connection.createStatement()) {
            statement.execute("DROP SCHEMA IF EXISTS " + SCRATCH_SCHEMA + " CASCADE");
            statement.execute("CREATE SCHEMA " + SCRATCH_SCHEMA);
            // Only the scratch schema is on the path, so an unqualified name cannot resolve to the entity-generated
            // core schema instead.
            statement.execute("SET search_path TO " + SCRATCH_SCHEMA);
            statement.execute(TABLES);
        }
    }

    private void applyMigration(Connection connection) throws Exception {
        execute(connection, new ClassPathResource(MIGRATION_RESOURCE).getContentAsString(StandardCharsets.UTF_8));
    }

    private String planFor(Connection connection, String query) throws SQLException {
        StringBuilder plan = new StringBuilder();
        // SET LOCAL is a no-op in autocommit; dropScratchSchema resets the setting before the connection returns to the
        // pool.
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

    private List<String> uniqueConstraints(Connection connection) throws SQLException {
        return queryAll(connection, """
                SELECT conname FROM pg_constraint
                WHERE conrelid = '%s.certificate'::regclass AND contype IN ('p', 'u')
                """.formatted(SCRATCH_SCHEMA));
    }

    private String foreignKeyIndex(Connection connection) throws SQLException {
        List<String> indexes = queryAll(connection, """
                SELECT conindid::regclass::TEXT FROM pg_constraint
                WHERE conrelid = '%s.certificate_event_history'::regclass AND contype = 'f'
                """.formatted(SCRATCH_SCHEMA));
        assertThat(indexes).hasSize(1);
        return indexes.get(0);
    }

    private List<String> queryAll(Connection connection, String sql) throws SQLException {
        List<String> values = new ArrayList<>();
        try (Statement statement = connection.createStatement(); ResultSet rows = statement.executeQuery(sql)) {
            while (rows.next()) {
                values.add(rows.getString(1));
            }
        }
        return values;
    }

    private void execute(Connection connection, String sql) throws SQLException {
        try (Statement statement = connection.createStatement()) {
            statement.execute(sql);
        }
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
