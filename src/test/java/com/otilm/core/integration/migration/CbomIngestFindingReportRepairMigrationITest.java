package com.otilm.core.integration.migration;

import com.otilm.core.util.BaseSpringBootTest;
import java.nio.charset.StandardCharsets;
import java.sql.Connection;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;
import java.util.ArrayList;
import java.util.List;
import javax.sql.DataSource;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.core.io.ClassPathResource;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Runs {@code V202610211000__cbom_ingest_finding_report_repair.sql} over reports as 2.20.0 wrote them: a skip per
 * exception class, and a timestamp per line.
 */
class CbomIngestFindingReportRepairMigrationITest extends BaseSpringBootTest {

    private static final String TABLE_RESOURCE = "db/migration/V202609141400__cbom_ingest_finding.sql";

    private static final String REPAIR_RESOURCE = "db/migration/V202610211000__cbom_ingest_finding_report_repair.sql";

    private static final String SCRATCH_SCHEMA = "cbom_ingest_finding_report_repair_check";

    private static final String CBOM_STUB = """
            CREATE TABLE "cbom" (
                "uuid" UUID PRIMARY KEY,
                "serial_number" TEXT NOT NULL,
                "version" INT NOT NULL
            )
            """;

    private static final String SKIP_PREFIX = "the component could not be turned into an asset: ";

    private static final String UNREADABLE = SKIP_PREFIX + "reading it failed";

    private static final String UNROUTABLE = SKIP_PREFIX
            + "cryptoProperties is absent, so the component declares no asset type";

    private static final String LEGACY = "11111111-0000-4000-8000-000000000001";

    private static final String MIXED = "11111111-0000-4000-8000-000000000002";

    private static final String CURRENT = "11111111-0000-4000-8000-000000000003";

    @Autowired
    private DataSource dataSource;

    @Test
    void legacyReportsReadAsTheCurrentWriterWouldHaveWrittenThem() throws Exception {
        try (Connection connection = dataSource.getConnection()) {
            try {
                applyTableMigration(connection);
                seedReports(connection);

                applyRepairMigration(connection);

                assertThat(lines(connection, LEGACY))
                        .describedAs("exception classes fold into the fixed reason; other lines keep their text")
                        .containsExactly("FINDING|a finding|1", "SKIP|" + UNROUTABLE + "|4",
                                "SKIP|" + UNREADABLE + "|5");
                assertThat(queryOne(connection, "SELECT component_name FROM cbom_ingest_finding WHERE cbom_uuid = '"
                        + LEGACY + "' AND detail = '" + UNREADABLE + "'")).isEqualTo("alpha");
                assertThat(lines(connection, MIXED))
                        .describedAs("a fixed-reason line already present takes the legacy occurrences")
                        .containsExactly("SKIP|" + UNREADABLE + "|9");
                assertThat(lines(connection, CURRENT)).containsExactly("SKIP|" + UNREADABLE + "|1");

                assertThat(distinctRecordedAt(connection, LEGACY))
                        .describedAs("one report, one recordedAt: its latest line's")
                        .containsExactly("2026-09-20 10:00:03+00");
                assertThat(distinctRecordedAt(connection, MIXED)).containsExactly("2026-09-21 10:00:01+00");
                assertThat(distinctRecordedAt(connection, CURRENT)).containsExactly("2026-09-22 10:00:00+00");
            } finally {
                dropScratchSchema(connection);
            }
        }
    }

    private void applyTableMigration(Connection connection) throws Exception {
        try (Statement statement = connection.createStatement()) {
            statement.execute("DROP SCHEMA IF EXISTS " + SCRATCH_SCHEMA + " CASCADE");
            statement.execute("CREATE SCHEMA " + SCRATCH_SCHEMA);
            // Only the scratch schema is on the path, so an unqualified name cannot resolve to the entity-generated
            // core schema instead.
            statement.execute("SET search_path TO " + SCRATCH_SCHEMA);
            statement.execute(CBOM_STUB);
            statement.execute(new ClassPathResource(TABLE_RESOURCE).getContentAsString(StandardCharsets.UTF_8));
        }
    }

    private void applyRepairMigration(Connection connection) throws Exception {
        try (Statement statement = connection.createStatement()) {
            statement.execute(new ClassPathResource(REPAIR_RESOURCE).getContentAsString(StandardCharsets.UTF_8));
        }
    }

    private void seedReports(Connection connection) throws SQLException {
        try (Statement statement = connection.createStatement()) {
            for (String cbom : List.of(LEGACY, MIXED, CURRENT)) {
                statement
                        .execute("INSERT INTO cbom (uuid, serial_number, version) VALUES ('" + cbom + "', 'urn:uuid:"
                                + cbom + "', 1)");
            }
            insertLine(statement, LEGACY, "SKIP", "beta", SKIP_PREFIX + "IllegalArgumentException", 3,
                    "2026-09-20 10:00:00+00");
            insertLine(statement, LEGACY, "SKIP", "alpha", SKIP_PREFIX + "NullPointerException", 2,
                    "2026-09-20 10:00:01+00");
            insertLine(statement, LEGACY, "SKIP", "gamma", UNROUTABLE, 4, "2026-09-20 10:00:02+00");
            insertLine(statement, LEGACY, "FINDING", "delta", "a finding", 1, "2026-09-20 10:00:03+00");

            insertLine(statement, MIXED, "SKIP", "epsilon", UNREADABLE, 2, "2026-09-21 10:00:00+00");
            insertLine(statement, MIXED, "SKIP", "zeta", SKIP_PREFIX + "ClassCastException", 7,
                    "2026-09-21 10:00:01+00");

            insertLine(statement, CURRENT, "SKIP", "eta", UNREADABLE, 1, "2026-09-22 10:00:00+00");
        }
    }

    private static void insertLine(Statement statement, String cbom, String kind, String componentName, String detail,
            int occurrences, String recordedAt) throws SQLException {
        statement
                .execute("INSERT INTO cbom_ingest_finding"
                        + " (uuid, cbom_uuid, kind, component_name, detail, occurrences, recorded_at)"
                        + " VALUES (gen_random_uuid(), '" + cbom + "', '" + kind + "', '" + componentName + "', '"
                        + detail + "', " + occurrences + ", '" + recordedAt + "')");
    }

    private List<String> lines(Connection connection, String cbom) throws SQLException {
        return column(connection,
                "SELECT kind || '|' || detail || '|' || occurrences FROM cbom_ingest_finding WHERE cbom_uuid = '" + cbom
                        + "' ORDER BY kind, detail");
    }

    private List<String> distinctRecordedAt(Connection connection, String cbom) throws SQLException {
        return column(connection,
                "SELECT DISTINCT to_char(recorded_at AT TIME ZONE 'UTC', 'YYYY-MM-DD HH24:MI:SS') || '+00'"
                        + " FROM cbom_ingest_finding WHERE cbom_uuid = '" + cbom + "'");
    }

    private List<String> column(Connection connection, String sql) throws SQLException {
        List<String> values = new ArrayList<>();
        try (Statement statement = connection.createStatement(); ResultSet rows = statement.executeQuery(sql)) {
            while (rows.next()) {
                values.add(rows.getString(1));
            }
        }
        return values;
    }

    private String queryOne(Connection connection, String sql) throws SQLException {
        try (Statement statement = connection.createStatement(); ResultSet rows = statement.executeQuery(sql)) {
            assertThat(rows.next()).describedAs(sql).isTrue();
            return rows.getString(1);
        }
    }

    private void dropScratchSchema(Connection connection) throws SQLException {
        try (Statement statement = connection.createStatement()) {
            statement.execute("DROP SCHEMA IF EXISTS " + SCRATCH_SCHEMA + " CASCADE");
        } finally {
            // The connection goes back to a pool shared with the rest of the suite.
            try (Statement reset = connection.createStatement()) {
                reset.execute("RESET search_path");
            }
        }
    }
}
