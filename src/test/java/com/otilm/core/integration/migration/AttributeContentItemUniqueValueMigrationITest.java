package com.otilm.core.integration.migration;

import com.otilm.core.util.BaseSpringBootTest;
import java.nio.charset.StandardCharsets;
import java.sql.Connection;
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
 * Runs {@code V202610061000__attribute_content_item_unique_value.sql} in a scratch schema holding stubs of the two
 * tables it rewrites, and asserts duplicates fold onto one row while encrypted rows and distinct values stay apart. The
 * regular test bootstrap generates its schema from the entities, so nothing else executes this file.
 */
class AttributeContentItemUniqueValueMigrationITest extends BaseSpringBootTest {

    private static final String MIGRATION_RESOURCE = "db/migration/V202610061000__attribute_content_item_unique_value.sql";
    private static final String SCRATCH_SCHEMA = "attribute_content_item_unique_value_migration_check";
    private static final String DEFINITION = "10000000-0000-0000-0000-000000000001";
    private static final String KEEP = "20000000-0000-0000-0000-000000000001";
    private static final String DUPLICATE = "20000000-0000-0000-0000-000000000002";
    private static final String OTHER_VALUE = "20000000-0000-0000-0000-000000000003";
    private static final String ENCRYPTED_ONE = "20000000-0000-0000-0000-000000000004";
    private static final String ENCRYPTED_TWO = "20000000-0000-0000-0000-000000000005";
    private static final String EMPTY_OBJECTS = "20000000-0000-0000-0000-000000000010";
    private static final String EMPTY_ARRAYS = "20000000-0000-0000-0000-000000000011";
    private static final String CERTIFICATE_ONE = "30000000-0000-0000-0000-000000000001";
    private static final String CERTIFICATE_TWO = "30000000-0000-0000-0000-000000000002";
    private static final String TABLE_STUBS = """
            CREATE TABLE "attribute_content_item" (
                "uuid" UUID PRIMARY KEY,
                "attribute_definition_uuid" UUID NOT NULL,
                "json" JSONB NOT NULL,
                "encrypted_data" VARCHAR
            );
            CREATE TABLE "attribute_content_2_object" (
                "uuid" UUID PRIMARY KEY,
                "attribute_content_item_uuid" UUID NOT NULL REFERENCES "attribute_content_item" ("uuid")
                    ON UPDATE CASCADE ON DELETE RESTRICT,
                "object_type" VARCHAR NOT NULL,
                "object_uuid" UUID NOT NULL,
                "connector_uuid" UUID,
                "source_object_type" VARCHAR,
                "source_object_uuid" UUID,
                "source_object_name" VARCHAR,
                "item_order" INTEGER,
                "purpose" VARCHAR,
                "object_version" INTEGER
            );
            CREATE INDEX "idx_attribute_content_item_definition" ON "attribute_content_item" ("attribute_definition_uuid")
            """;

    @Autowired
    private DataSource dataSource;

    @Test
    void duplicatesFoldOntoOneRowAndEncryptedRowsStayApart() throws Exception {
        try (Connection connection = dataSource.getConnection()) {
            try (Statement statement = connection.createStatement()) {
                statement.execute("DROP SCHEMA IF EXISTS " + SCRATCH_SCHEMA + " CASCADE");
                statement.execute("CREATE SCHEMA " + SCRATCH_SCHEMA);
                statement.execute("SET search_path TO " + SCRATCH_SCHEMA);
                statement.execute(TABLE_STUBS);
                insertItem(statement, KEEP, "{\"data\": \"shared\"}", null);
                insertItem(statement, DUPLICATE, "{\"data\": \"shared\"}", null);
                insertItem(statement, OTHER_VALUE, "{\"data\": \"other\"}", null);
                insertItem(statement, ENCRYPTED_ONE, "{\"contentType\": \"string\"}", "cipher-one");
                insertItem(statement, ENCRYPTED_TWO, "{\"contentType\": \"string\"}", "cipher-two");
                // Distinct values that jsonb_hash_extended hashes alike: the constraint must still go on.
                insertItem(statement, EMPTY_OBJECTS, "{\"data\": {\"v\": [{}, {}]}}", null);
                insertItem(statement, EMPTY_ARRAYS, "{\"data\": {\"v\": [[], []]}}", null);
                insertMapping(statement, KEEP, CERTIFICATE_ONE);
                insertMapping(statement, DUPLICATE, CERTIFICATE_TWO);
                // Certificate one held both copies: after the fold it must hold the value once, not twice.
                insertMapping(statement, DUPLICATE, CERTIFICATE_ONE);
                insertMapping(statement, ENCRYPTED_ONE, CERTIFICATE_ONE);
                insertMapping(statement, ENCRYPTED_TWO, CERTIFICATE_TWO);

                statement.execute(new ClassPathResource(MIGRATION_RESOURCE).getContentAsString(StandardCharsets.UTF_8));

                assertThat(count(statement,
                        "SELECT count(*) FROM attribute_content_item WHERE uuid = '" + DUPLICATE + "'")).isZero();
                assertThat(count(statement, "SELECT count(*) FROM attribute_content_item")).isEqualTo(6);
                assertThat(count(statement, "SELECT count(*) FROM attribute_content_2_object WHERE"
                        + " attribute_content_item_uuid = '" + KEEP + "' AND object_uuid = '" + CERTIFICATE_ONE + "'"))
                        .isEqualTo(1);
                assertThat(count(statement, "SELECT count(*) FROM attribute_content_2_object WHERE"
                        + " attribute_content_item_uuid = '" + KEEP + "' AND object_uuid = '" + CERTIFICATE_TWO + "'"))
                        .isEqualTo(1);
                assertThat(count(statement,
                        "SELECT count(*) FROM attribute_content_item WHERE encrypted_data IS NOT NULL AND json_digest IS NULL"))
                        .isEqualTo(2);
                assertThat(count(statement,
                        "SELECT count(*) FROM attribute_content_item WHERE encrypted_data IS NULL AND json_digest IS NOT NULL"))
                        .isEqualTo(4);

                assertThatThrownBy(() -> insertItem(statement, "20000000-0000-0000-0000-000000000006",
                        "{\"data\": \"shared\"}", null))
                        .isInstanceOf(SQLException.class)
                        .satisfies(e -> assertThat(((SQLException) e).getSQLState()).isEqualTo("23505"));
                insertItem(statement, "20000000-0000-0000-0000-000000000007", "{\"contentType\": \"string\"}",
                        "cipher-three");

                // The constraint's index leads with the definition, so the definition-only index goes and lookups by
                // definition use the constraint's index.
                assertThat(count(statement, "SELECT count(*) FROM pg_indexes WHERE schemaname = '" + SCRATCH_SCHEMA
                        + "' AND indexname = 'idx_attribute_content_item_definition'")).isZero();
                statement.execute("SET enable_seqscan = off");
                StringBuilder plan = new StringBuilder();
                try (ResultSet rows = statement
                        .executeQuery(
                                "EXPLAIN SELECT uuid FROM attribute_content_item WHERE attribute_definition_uuid = '"
                                        + DEFINITION + "'")) {
                    while (rows.next()) {
                        plan.append(rows.getString(1)).append('\n');
                    }
                }
                statement.execute("RESET enable_seqscan");
                assertThat(plan.toString()).contains("uq_attribute_content_item_value");

                // The constraint keys on the jsonb text, as the lookup by value does: key order and spacing are
                // normalized away, a number's written precision is not.
                insertItem(statement, "20000000-0000-0000-0000-000000000008", "{\"data\": {\"a\": 1, \"b\": 2}}", null);
                assertThatThrownBy(() -> insertItem(statement, "20000000-0000-0000-0000-000000000009",
                        "{\"data\": {\"b\": 2,  \"a\": 1}}", null))
                        .isInstanceOf(SQLException.class)
                        .satisfies(e -> assertThat(((SQLException) e).getSQLState()).isEqualTo("23505"));
                insertItem(statement, "20000000-0000-0000-0000-000000000012", "{\"data\": 1.0}", null);
                insertItem(statement, "20000000-0000-0000-0000-000000000013", "{\"data\": 1.00}", null);
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

    private static void insertItem(Statement statement, String uuid, String json, String encryptedData)
            throws SQLException {
        statement
                .execute("INSERT INTO attribute_content_item (uuid, attribute_definition_uuid, json, encrypted_data)"
                        + " VALUES ('" + uuid + "', '" + DEFINITION + "', '" + json + "', "
                        + (encryptedData == null ? "NULL" : "'" + encryptedData + "'") + ")");
    }

    private static void insertMapping(Statement statement, String itemUuid, String objectUuid) throws SQLException {
        statement
                .execute("INSERT INTO attribute_content_2_object (uuid, attribute_content_item_uuid, object_type,"
                        + " object_uuid, item_order) VALUES (gen_random_uuid(), '" + itemUuid + "', 'CERTIFICATE', '"
                        + objectUuid + "', 0)");
    }

    private static long count(Statement statement, String sql) throws SQLException {
        try (ResultSet rows = statement.executeQuery(sql)) {
            rows.next();
            return rows.getLong(1);
        }
    }
}
