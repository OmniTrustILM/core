package com.otilm.core.integration.migration;

import com.otilm.core.util.BaseSpringBootTest;
import java.nio.charset.StandardCharsets;
import java.sql.Connection;
import java.sql.ResultSet;
import java.sql.Statement;
import java.util.ArrayList;
import java.util.List;
import javax.sql.DataSource;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.core.io.ClassPathResource;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Runs {@code V202610061100__attribute_content_item_drop_unmapped.sql} in a scratch schema and asserts it removes the
 * plaintext rows an encrypted definition holds without any object mapping them, and keeps everything else.
 */
class AttributeContentItemDropUnmappedMigrationITest extends BaseSpringBootTest {

    private static final String MIGRATION_RESOURCE = "db/migration/V202610061100__attribute_content_item_drop_unmapped.sql";
    private static final String SCRATCH_SCHEMA = "attribute_content_item_drop_unmapped_migration_check";
    private static final String ENCRYPTED_DEFINITION = "10000000-0000-0000-0000-000000000001";
    private static final String PLAIN_DEFINITION = "10000000-0000-0000-0000-000000000002";
    private static final String PLAINTEXT_OF_ENCRYPTED = "20000000-0000-0000-0000-000000000001";
    private static final String CIPHERTEXT_OF_ENCRYPTED = "20000000-0000-0000-0000-000000000002";
    private static final String UNMAPPED_PLAIN = "20000000-0000-0000-0000-000000000003";
    private static final String MAPPED_PLAIN = "20000000-0000-0000-0000-000000000004";
    private static final String TABLE_STUBS = """
            CREATE TABLE "attribute_definition" (
                "uuid" UUID PRIMARY KEY,
                "protection_level" VARCHAR
            );
            CREATE TABLE "attribute_content_item" (
                "uuid" UUID PRIMARY KEY,
                "attribute_definition_uuid" UUID NOT NULL REFERENCES "attribute_definition" ("uuid"),
                "json" JSONB NOT NULL,
                "encrypted_data" VARCHAR
            );
            CREATE TABLE "attribute_content_2_object" (
                "uuid" UUID PRIMARY KEY,
                "attribute_content_item_uuid" UUID NOT NULL REFERENCES "attribute_content_item" ("uuid"),
                "object_type" VARCHAR NOT NULL,
                "object_uuid" UUID NOT NULL
            )
            """;

    @Autowired
    private DataSource dataSource;

    @Test
    void unmappedPlaintextOfAnEncryptedDefinitionIsRemoved() throws Exception {
        try (Connection connection = dataSource.getConnection()) {
            try (Statement statement = connection.createStatement()) {
                statement.execute("DROP SCHEMA IF EXISTS " + SCRATCH_SCHEMA + " CASCADE");
                statement.execute("CREATE SCHEMA " + SCRATCH_SCHEMA);
                statement.execute("SET search_path TO " + SCRATCH_SCHEMA);
                statement.execute(TABLE_STUBS);
                statement
                        .execute("INSERT INTO attribute_definition VALUES ('" + ENCRYPTED_DEFINITION
                                + "', 'ENCRYPTED'), ('" + PLAIN_DEFINITION + "', 'NONE')");
                statement
                        .execute("INSERT INTO attribute_content_item VALUES ('" + PLAINTEXT_OF_ENCRYPTED + "', '"
                                + ENCRYPTED_DEFINITION + "', '{\"data\": \"secret\"}', NULL), ('"
                                + CIPHERTEXT_OF_ENCRYPTED + "', '" + ENCRYPTED_DEFINITION
                                + "', '{\"contentType\": \"string\"}', 'cipher'), ('" + UNMAPPED_PLAIN + "', '"
                                + PLAIN_DEFINITION + "', '{\"data\": \"registered\"}', NULL), ('" + MAPPED_PLAIN
                                + "', '" + PLAIN_DEFINITION + "', '{\"data\": \"mapped\"}', NULL)");
                statement
                        .execute("INSERT INTO attribute_content_2_object VALUES (gen_random_uuid(), '"
                                + CIPHERTEXT_OF_ENCRYPTED
                                + "', 'CERTIFICATE', gen_random_uuid()), (gen_random_uuid(), '" + MAPPED_PLAIN
                                + "', 'CERTIFICATE', gen_random_uuid())");

                statement
                        .execute(new String(new ClassPathResource(MIGRATION_RESOURCE).getInputStream().readAllBytes(),
                                StandardCharsets.UTF_8));

                List<String> remaining = new ArrayList<>();
                try (ResultSet rows = statement
                        .executeQuery("SELECT uuid::text FROM attribute_content_item ORDER BY uuid")) {
                    while (rows.next()) {
                        remaining.add(rows.getString(1));
                    }
                }
                assertThat(remaining).containsExactly(CIPHERTEXT_OF_ENCRYPTED, UNMAPPED_PLAIN, MAPPED_PLAIN);
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
}
