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
 * Runs {@code V202611031730__crl_drop_unverified.sql} in a scratch schema holding the CRL tables as
 * {@code V202401171122__ca_crl_management.sql} created them, and asserts it leaves no cached CRL or CRL entry.
 */
class CrlDropUnverifiedMigrationITest extends BaseSpringBootTest {

    private static final String MIGRATION_RESOURCE = "db/migration/V202611031730__crl_drop_unverified.sql";

    private static final String SCRATCH_SCHEMA = "crl_drop_unverified_migration_check";

    private static final String CRL_TABLES = """
            CREATE TABLE "crl" (
                "uuid" UUID PRIMARY KEY,
                "issuer_dn" VARCHAR NOT NULL,
                "serial_number" VARCHAR NOT NULL,
                "crl_issuer_dn" VARCHAR NOT NULL,
                "crl_number" VARCHAR NOT NULL,
                "next_update" TIMESTAMP NOT NULL
            );
            CREATE TABLE "crl_entry" (
                "crl_uuid" UUID REFERENCES "crl" ("uuid") ON UPDATE CASCADE ON DELETE CASCADE,
                "serial_number" VARCHAR,
                "revocation_date" TIMESTAMP NOT NULL,
                "revocation_reason" VARCHAR NOT NULL,
                PRIMARY KEY ("crl_uuid", "serial_number")
            );
            """;

    private static final String CACHED_CRL = """
            INSERT INTO "crl" VALUES ('10000000-0000-0000-0000-000000000001', 'CN=Test-Ca', '1a', 'CN=Test-Ca', '2',
                                      now() + INTERVAL '100 years');
            INSERT INTO "crl_entry" VALUES ('10000000-0000-0000-0000-000000000001', '2b', now(), 'KEY_COMPROMISE');
            """;

    @Autowired
    private DataSource dataSource;

    @Test
    void emptiesCrlCache_whenApplied() throws Exception {
        try (Connection connection = dataSource.getConnection(); Statement statement = connection.createStatement()) {
            try {
                // given
                statement.execute("DROP SCHEMA IF EXISTS " + SCRATCH_SCHEMA + " CASCADE");
                statement.execute("CREATE SCHEMA " + SCRATCH_SCHEMA);
                statement.execute("SET search_path TO " + SCRATCH_SCHEMA);
                statement.execute(CRL_TABLES);
                statement.execute(CACHED_CRL);
                String migration = new ClassPathResource(MIGRATION_RESOURCE).getContentAsString(StandardCharsets.UTF_8);

                // when
                statement.execute(migration);

                // then
                assertThat(countRows(statement, "crl")).isZero();
                assertThat(countRows(statement, "crl_entry")).isZero();
            } finally {
                // The connection goes back to a pool shared with the rest of the suite: the session's search_path
                // must not point at the schema this drops.
                statement.execute("RESET search_path");
                statement.execute("DROP SCHEMA IF EXISTS " + SCRATCH_SCHEMA + " CASCADE");
            }
        }
    }

    // ── Helpers ───────────────────────────────────────────────────────────────

    private static long countRows(Statement statement, String table) throws Exception {
        try (ResultSet rows = statement.executeQuery("SELECT count(*) FROM \"" + table + "\"")) {
            rows.next();
            return rows.getLong(1);
        }
    }
}
