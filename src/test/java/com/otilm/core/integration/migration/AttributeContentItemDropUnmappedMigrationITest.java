package com.otilm.core.integration.migration;

import com.otilm.core.util.BaseSpringBootTest;
import java.nio.charset.StandardCharsets;
import java.sql.Connection;
import java.sql.ResultSet;
import java.sql.Statement;
import javax.sql.DataSource;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.core.io.ClassPathResource;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Runs {@code V202610061100__attribute_content_item_drop_unmapped.sql} in a scratch schema and asserts it removes the
 * content items no object maps to and keeps the rest.
 */
class AttributeContentItemDropUnmappedMigrationITest extends BaseSpringBootTest {

    private static final String MIGRATION_RESOURCE = "db/migration/V202610061100__attribute_content_item_drop_unmapped.sql";
    private static final String SCRATCH_SCHEMA = "attribute_content_item_drop_unmapped_migration_check";
    private static final String MAPPED = "20000000-0000-0000-0000-000000000001";
    private static final String UNMAPPED = "20000000-0000-0000-0000-000000000002";
    private static final String TABLE_STUBS = """
            CREATE TABLE "attribute_content_item" (
                "uuid" UUID PRIMARY KEY,
                "attribute_definition_uuid" UUID NOT NULL,
                "json" JSONB NOT NULL
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
    void itemsNoObjectMapsToAreRemoved() throws Exception {
        try (Connection connection = dataSource.getConnection()) {
            try (Statement statement = connection.createStatement()) {
                statement.execute("DROP SCHEMA IF EXISTS " + SCRATCH_SCHEMA + " CASCADE");
                statement.execute("CREATE SCHEMA " + SCRATCH_SCHEMA);
                statement.execute("SET search_path TO " + SCRATCH_SCHEMA);
                statement.execute(TABLE_STUBS);
                statement
                        .execute("INSERT INTO attribute_content_item VALUES ('" + MAPPED
                                + "', gen_random_uuid(), '{\"data\": \"mapped\"}'), ('" + UNMAPPED
                                + "', gen_random_uuid(), '{\"data\": \"unmapped\"}')");
                statement
                        .execute("INSERT INTO attribute_content_2_object VALUES (gen_random_uuid(), '" + MAPPED
                                + "', 'CERTIFICATE', gen_random_uuid())");

                statement
                        .execute(new String(new ClassPathResource(MIGRATION_RESOURCE).getInputStream().readAllBytes(),
                                StandardCharsets.UTF_8));

                try (ResultSet rows = statement.executeQuery("SELECT uuid::text FROM attribute_content_item")) {
                    assertThat(rows.next()).isTrue();
                    assertThat(rows.getString(1)).isEqualTo(MAPPED);
                    assertThat(rows.next()).isFalse();
                }
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
