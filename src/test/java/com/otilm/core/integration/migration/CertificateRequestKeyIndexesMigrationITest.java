package com.otilm.core.integration.migration;

import com.otilm.core.util.BaseSpringBootTest;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.sql.Connection;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;
import java.util.List;
import java.util.stream.Stream;
import javax.sql.DataSource;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.core.io.ClassPathResource;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Applies {@code V202611131000__est.sql} to tables shaped as in production, with the certificate's key indexes the
 * earlier migrations create, and asserts that the indexes answer whether a certificate uses a key. The suite's schema
 * is generated from the entities, which declare none of the indexes.
 */
class CertificateRequestKeyIndexesMigrationITest extends BaseSpringBootTest {

    private static final String MIGRATION_RESOURCE = "db/migration/V202611131000__est.sql";

    private static final String SCRATCH_SCHEMA = "certificate_request_key_indexes_check";

    private static final String SOME_UUID = "5f0a3c5e-9c0b-4f7e-8d8b-2b6f1c9e4a11";

    private static final String TABLES = """
            CREATE TABLE "ra_profile" ("uuid" UUID PRIMARY KEY);
            CREATE TABLE "token_profile" ("uuid" UUID PRIMARY KEY);
            CREATE TABLE "protocol_certificate_associations" ("uuid" UUID PRIMARY KEY);
            CREATE TABLE "ra_profile_protocol_attribute" ("uuid" UUID PRIMARY KEY, "ra_profile_uuid" UUID);
            CREATE TABLE "certificate_request" (
                "uuid" UUID PRIMARY KEY,
                "fingerprint" VARCHAR,
                "key_uuid" UUID,
                "alt_key_uuid" UUID
            );
            CREATE TABLE "certificate" (
                "uuid" UUID PRIMARY KEY,
                "state" TEXT,
                "key_uuid" UUID,
                "alt_key_uuid" UUID,
                "certificate_request_uuid" UUID
            );
            CREATE INDEX certificate_key_uuid ON certificate (key_uuid);
            CREATE INDEX certificate_alt_key_uuid ON certificate (alt_key_uuid);
            CREATE INDEX idx_certificate_certificate_request_uuid ON certificate (certificate_request_uuid);
            """;

    private static final String ROWS = """
            INSERT INTO certificate_request (uuid, key_uuid, alt_key_uuid)
            SELECT gen_random_uuid(), gen_random_uuid(), gen_random_uuid() FROM generate_series(1, 500) g;
            INSERT INTO certificate (uuid, state, key_uuid, alt_key_uuid, certificate_request_uuid)
            SELECT gen_random_uuid(), 'ISSUED', key_uuid, alt_key_uuid, uuid FROM certificate_request;
            ANALYZE certificate_request, certificate;
            """;

    private static final String NOT_NEVER_ISSUED = "(c.state IS NULL OR c.state NOT IN ('FAILED', 'REJECTED'))";

    @Autowired
    private DataSource dataSource;

    /**
     * Sequential scans are disabled for the checks: on tables this size the planner would pick one on cost alone, and
     * the question is whether the index answers the lookup at all.
     */
    @ParameterizedTest(name = "{0}")
    @MethodSource("lookups")
    void usesIndex_whenPlanningTheLookupItIsThereFor(String index, String lookup) throws Exception {
        try (Connection connection = dataSource.getConnection()) {
            try {
                // given
                createMigratedScratchTables(connection);

                // when
                String plan = planFor(connection, lookup.formatted(SOME_UUID));

                // then
                assertThat(plan).contains(index);
            } finally {
                dropScratchSchema(connection);
            }
        }
    }

    @ParameterizedTest(name = "{0}")
    @MethodSource("keyUseQueries")
    void answersWithIndexScansOnly_whenAskingWhetherACertificateUsesAKey(String half, String query,
            List<String> indexes) throws Exception {
        try (Connection connection = dataSource.getConnection()) {
            try {
                // given
                createMigratedScratchTables(connection);

                // when
                String plan = planFor(connection, query.formatted(SOME_UUID));

                // then
                assertThat(plan).contains(indexes).doesNotContain("Seq Scan");
            } finally {
                dropScratchSchema(connection);
            }
        }
    }

    // ── Helpers ──────────────────────────────────────────────────────────────

    private static Stream<Arguments> lookups() {
        return Stream
                .of(Arguments
                        .of("idx_certificate_request_key_uuid",
                                "SELECT uuid FROM certificate_request WHERE key_uuid = '%s'"),
                        Arguments
                                .of("idx_certificate_request_alt_key_uuid",
                                        "SELECT uuid FROM certificate_request WHERE alt_key_uuid = '%s'"));
    }

    /** The two halves of {@code CertificateRepository.existsUsingKey}, as the platform runs them on a key destroy. */
    private static Stream<Arguments> keyUseQueries() {
        return Stream
                .of(Arguments
                        .of("the certificate's own keys", "SELECT COUNT(c.uuid) > 0 FROM certificate c"
                                + " WHERE (c.key_uuid = '%1$s' OR c.alt_key_uuid = '%1$s') AND " + NOT_NEVER_ISSUED,
                                List.of("certificate_key_uuid", "certificate_alt_key_uuid")),
                        Arguments
                                .of("the keys of the certificate's request",
                                        "SELECT COUNT(c.uuid) > 0 FROM certificate_request r"
                                                + " JOIN certificate c ON c.certificate_request_uuid = r.uuid"
                                                + " WHERE (r.key_uuid = '%1$s' OR r.alt_key_uuid = '%1$s') AND "
                                                + NOT_NEVER_ISSUED,
                                        List
                                                .of("idx_certificate_request_key_uuid",
                                                        "idx_certificate_request_alt_key_uuid",
                                                        "idx_certificate_certificate_request_uuid")));
    }

    private static void createMigratedScratchTables(Connection connection) throws IOException, SQLException {
        execute(connection, "DROP SCHEMA IF EXISTS " + SCRATCH_SCHEMA + " CASCADE");
        execute(connection, "CREATE SCHEMA " + SCRATCH_SCHEMA);
        execute(connection, "SET search_path TO " + SCRATCH_SCHEMA);
        execute(connection, TABLES);
        execute(connection, new ClassPathResource(MIGRATION_RESOURCE).getContentAsString(StandardCharsets.UTF_8));
        execute(connection, ROWS);
    }

    private static String planFor(Connection connection, String query) throws SQLException {
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

    private static void execute(Connection connection, String sql) throws SQLException {
        try (Statement statement = connection.createStatement()) {
            statement.execute(sql);
        }
    }

    private static void dropScratchSchema(Connection connection) throws SQLException {
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
