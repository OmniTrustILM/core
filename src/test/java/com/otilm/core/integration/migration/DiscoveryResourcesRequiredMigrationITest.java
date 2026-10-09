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

/**
 * Runs {@code V202610101000__discovery_resources_required.sql} in a scratch schema and asserts it gives every v1 run
 * the certificates it targets and makes the column required. The regular test bootstrap generates its schema from the
 * entities, so nothing else executes this file.
 */
class DiscoveryResourcesRequiredMigrationITest extends BaseSpringBootTest {

    private static final String MIGRATION_RESOURCE = "db/migration/V202610101000__discovery_resources_required.sql";
    private static final String SCRATCH_SCHEMA = "discovery_resources_required_migration_check";
    private static final String V1_NULL = "50000000-0000-0000-0000-000000000001";
    private static final String V1_EMPTY = "50000000-0000-0000-0000-000000000002";
    private static final String V2 = "50000000-0000-0000-0000-000000000003";
    private static final String TABLE_STUB = """
            CREATE TABLE "discovery" ("uuid" UUID PRIMARY KEY, "resources" TEXT[])
            """;

    @Autowired
    private DataSource dataSource;

    @Test
    void everyV1RunTargetsCertificates_andTheColumnBecomesRequired() throws Exception {
        try (Connection connection = dataSource.getConnection()) {
            try (Statement statement = connection.createStatement()) {
                statement.execute("DROP SCHEMA IF EXISTS " + SCRATCH_SCHEMA + " CASCADE");
                statement.execute("CREATE SCHEMA " + SCRATCH_SCHEMA);
                statement.execute("SET search_path TO " + SCRATCH_SCHEMA);
                statement.execute(TABLE_STUB);
                statement
                        .execute("INSERT INTO discovery VALUES ('" + V1_NULL + "', NULL), ('" + V1_EMPTY
                                + "', '{}'), ('" + V2 + "', '{CERTIFICATE,CRYPTOGRAPHIC_KEY}')");
                statement
                        .execute(new String(new ClassPathResource(MIGRATION_RESOURCE).getInputStream().readAllBytes(),
                                StandardCharsets.UTF_8));

                assertThat(resources(statement, V1_NULL)).isEqualTo("{CERTIFICATE}");
                assertThat(resources(statement, V1_EMPTY)).isEqualTo("{CERTIFICATE}");
                assertThat(resources(statement, V2)).isEqualTo("{CERTIFICATE,CRYPTOGRAPHIC_KEY}");
                try (ResultSet rows = statement
                        .executeQuery("SELECT is_nullable FROM information_schema.columns WHERE table_schema = '"
                                + SCRATCH_SCHEMA + "' AND table_name = 'discovery' AND column_name = 'resources'")) {
                    rows.next();
                    assertThat(rows.getString(1)).isEqualTo("NO");
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

    private static String resources(Statement statement, String uuid) throws SQLException {
        try (ResultSet rows = statement.executeQuery("SELECT resources FROM discovery WHERE uuid = '" + uuid + "'")) {
            rows.next();
            return rows.getString(1);
        }
    }
}
