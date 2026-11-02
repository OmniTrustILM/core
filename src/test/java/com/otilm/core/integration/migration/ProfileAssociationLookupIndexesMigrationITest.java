package com.otilm.core.integration.migration;

import com.otilm.core.util.BaseSpringBootTest;
import java.nio.charset.StandardCharsets;
import java.sql.Connection;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;
import java.util.stream.Stream;
import javax.sql.DataSource;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.core.io.ClassPathResource;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Applies {@code V202611021200__profile_association_lookup_indexes.sql} to tables shaped as in production and asserts
 * that each index answers the user profile's lookup. The suite's schema is generated from the entities, which declare
 * neither index.
 */
class ProfileAssociationLookupIndexesMigrationITest extends BaseSpringBootTest {

    private static final String MIGRATION_RESOURCE = "db/migration/V202611021200__profile_association_lookup_indexes.sql";

    private static final String SCRATCH_SCHEMA = "profile_association_lookup_indexes_check";

    private static final String SOME_UUID = "5f0a3c5e-9c0b-4f7e-8d8b-2b6f1c9e4a11";

    private static final String TABLES = """
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
            INSERT INTO group_association (uuid, resource, object_uuid, group_uuid)
            SELECT gen_random_uuid(), 'CERTIFICATE', gen_random_uuid(), gen_random_uuid() FROM generate_series(1, 500) g;
            INSERT INTO owner_association (uuid, resource, object_uuid, owner_uuid, owner_username)
            SELECT gen_random_uuid(), 'CERTIFICATE', gen_random_uuid(), gen_random_uuid(), 'user-' || g
            FROM generate_series(1, 500) g;
            ANALYZE group_association, owner_association;
            """;

    @Autowired
    private DataSource dataSource;

    static Stream<Arguments> lookups() {
        return Stream
                .of(Arguments
                        .of("idx_owner_association_owner_uuid",
                                "SELECT 1 FROM owner_association WHERE owner_uuid = '%s' AND resource = 'CERTIFICATE'"),
                        Arguments
                                .of("idx_group_association_resource",
                                        "SELECT 1 FROM group_association WHERE resource = 'CERTIFICATE'"
                                                + " AND group_uuid <> ALL (CAST('{%s}' AS uuid[]))"));
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
                execute(connection, "DROP SCHEMA IF EXISTS " + SCRATCH_SCHEMA + " CASCADE");
                execute(connection, "CREATE SCHEMA " + SCRATCH_SCHEMA);
                execute(connection, "SET search_path TO " + SCRATCH_SCHEMA);
                execute(connection, TABLES);
                execute(connection,
                        new ClassPathResource(MIGRATION_RESOURCE).getContentAsString(StandardCharsets.UTF_8));
                execute(connection, ROWS);

                assertThat(planFor(connection, lookup.formatted(SOME_UUID))).contains(index);
            } finally {
                dropScratchSchema(connection);
            }
        }
    }

    private String planFor(Connection connection, String query) throws SQLException {
        StringBuilder plan = new StringBuilder();
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
