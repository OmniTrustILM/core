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
 * Runs {@code V202610061200__discovery_protected_metadata.sql} in a scratch schema and asserts it adds the columns and
 * drops encrypted attributes from rows of finished discoveries only.
 */
class DiscoveryProtectedMetadataMigrationITest extends BaseSpringBootTest {

    private static final String MIGRATION_RESOURCE = "db/migration/V202610061200__discovery_protected_metadata.sql";
    private static final String SCRATCH_SCHEMA = "discovery_protected_metadata_migration_check";
    private static final String FINISHED = "40000000-0000-0000-0000-000000000001";
    private static final String RUNNING = "40000000-0000-0000-0000-000000000002";
    // A stopped v2 run can be resumed, and its staged rows are imported then.
    private static final String STOPPED = "40000000-0000-0000-0000-000000000003";
    private static final String META = """
            [{"name": "host", "properties": {"protectionLevel": "none"}, "content": [{"data": "web-1"}]},
             {"name": "token", "properties": {"protectionLevel": "encrypted"}, "content": [{"data": "s3cr3t"}]}]
            """;
    private static final String TABLE_STUBS = """
            CREATE TABLE "discovery" ("uuid" UUID PRIMARY KEY, "status" VARCHAR);
            CREATE TABLE "discovery_certificate" ("uuid" UUID PRIMARY KEY, "discovery_uuid" UUID NOT NULL,
                                                  "meta" JSONB);
            CREATE TABLE "discovery_item" ("uuid" UUID PRIMARY KEY, "discovery_uuid" UUID NOT NULL, "meta" JSONB)
            """;

    @Autowired
    private DataSource dataSource;

    @Test
    void finishedDiscoveriesLoseTheirEncryptedAttributesAndResumableOnesKeepThem() throws Exception {
        try (Connection connection = dataSource.getConnection()) {
            try (Statement statement = connection.createStatement()) {
                statement.execute("DROP SCHEMA IF EXISTS " + SCRATCH_SCHEMA + " CASCADE");
                statement.execute("CREATE SCHEMA " + SCRATCH_SCHEMA);
                statement.execute("SET search_path TO " + SCRATCH_SCHEMA);
                statement.execute(TABLE_STUBS);
                statement
                        .execute("INSERT INTO discovery VALUES ('" + FINISHED + "', 'COMPLETED'), ('" + RUNNING
                                + "', 'PROCESSING'), ('" + STOPPED + "', 'STOPPED')");
                for (String table : new String[]{"discovery_certificate", "discovery_item"}) {
                    for (String discovery : new String[]{FINISHED, RUNNING, STOPPED}) {
                        statement
                                .execute("INSERT INTO " + table + " VALUES (gen_random_uuid(), '" + discovery + "', '"
                                        + META + "')");
                    }
                }

                statement
                        .execute(new String(new ClassPathResource(MIGRATION_RESOURCE).getInputStream().readAllBytes(),
                                StandardCharsets.UTF_8));

                for (String table : new String[]{"discovery_certificate", "discovery_item"}) {
                    assertThat(names(statement, table, FINISHED)).isEqualTo("host");
                    assertThat(names(statement, table, RUNNING)).isEqualTo("host,token");
                    assertThat(names(statement, table, STOPPED)).isEqualTo("host,token");
                    statement.execute("UPDATE " + table + " SET protected_meta = 'sealed'");
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

    private static String names(Statement statement, String table, String discovery) throws SQLException {
        try (ResultSet rows = statement
                .executeQuery("SELECT string_agg(e ->> 'name', ',' ORDER BY n) FROM " + table
                        + ", jsonb_array_elements(meta) WITH ORDINALITY AS a(e, n) WHERE discovery_uuid = '" + discovery
                        + "'")) {
            rows.next();
            return rows.getString(1);
        }
    }
}
