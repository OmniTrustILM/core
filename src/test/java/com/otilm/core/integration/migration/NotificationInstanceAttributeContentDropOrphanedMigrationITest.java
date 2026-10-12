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
 * Runs {@code V202610121000__notification_instance_attribute_content_drop_orphaned.sql} in a scratch schema and asserts
 * it removes the attribute values of notification instances that no longer exist, and keeps everything else.
 */
class NotificationInstanceAttributeContentDropOrphanedMigrationITest extends BaseSpringBootTest {

    private static final String MIGRATION_RESOURCE = "db/migration/V202610121000__notification_instance_attribute_content_drop_orphaned.sql";
    private static final String SCRATCH_SCHEMA = "notification_attribute_orphans_migration_check";
    private static final String LIVE_INSTANCE = "10000000-0000-0000-0000-000000000001";
    private static final String DELETED_INSTANCE = "10000000-0000-0000-0000-000000000002";
    private static final String CONTENT_ITEM = "20000000-0000-0000-0000-000000000001";
    private static final String OF_LIVE_INSTANCE = "30000000-0000-0000-0000-000000000001";
    private static final String OF_DELETED_INSTANCE = "30000000-0000-0000-0000-000000000002";
    private static final String OF_OTHER_RESOURCE = "30000000-0000-0000-0000-000000000003";
    private static final String TABLE_STUBS = """
            CREATE TABLE "notification_instance_reference" (
                "uuid" UUID PRIMARY KEY
            );
            CREATE TABLE "attribute_content_2_object" (
                "uuid" UUID PRIMARY KEY,
                "attribute_content_item_uuid" UUID NOT NULL,
                "object_type" VARCHAR NOT NULL,
                "object_uuid" UUID NOT NULL
            )
            """;

    @Autowired
    private DataSource dataSource;

    @Test
    void valuesOfADeletedNotificationInstanceAreRemoved() throws Exception {
        try (Connection connection = dataSource.getConnection()) {
            try (Statement statement = connection.createStatement()) {
                statement.execute("DROP SCHEMA IF EXISTS " + SCRATCH_SCHEMA + " CASCADE");
                statement.execute("CREATE SCHEMA " + SCRATCH_SCHEMA);
                statement.execute("SET search_path TO " + SCRATCH_SCHEMA);
                statement.execute(TABLE_STUBS);
                statement.execute("INSERT INTO notification_instance_reference VALUES ('" + LIVE_INSTANCE + "')");
                statement
                        .execute("INSERT INTO attribute_content_2_object VALUES ('" + OF_LIVE_INSTANCE + "', '"
                                + CONTENT_ITEM + "', 'NOTIFICATION_INSTANCE', '" + LIVE_INSTANCE + "'), ('"
                                + OF_DELETED_INSTANCE + "', '" + CONTENT_ITEM + "', 'NOTIFICATION_INSTANCE', '"
                                + DELETED_INSTANCE + "'), ('" + OF_OTHER_RESOURCE + "', '" + CONTENT_ITEM
                                + "', 'TOKEN', '" + DELETED_INSTANCE + "')");

                statement.execute(new ClassPathResource(MIGRATION_RESOURCE).getContentAsString(StandardCharsets.UTF_8));

                List<String> remaining = new ArrayList<>();
                try (ResultSet rows = statement
                        .executeQuery("SELECT uuid::text FROM attribute_content_2_object ORDER BY uuid")) {
                    while (rows.next()) {
                        remaining.add(rows.getString(1));
                    }
                }
                assertThat(remaining).containsExactly(OF_LIVE_INSTANCE, OF_OTHER_RESOURCE);
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
