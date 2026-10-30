package com.otilm.core.integration.migration;

import com.otilm.core.util.BaseSpringBootTest;
import java.nio.charset.StandardCharsets;
import java.sql.Connection;
import java.sql.PreparedStatement;
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
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/**
 * Runs {@code V202609161300__scheduled_job_unique_name.sql} as Flyway will, against a schema that already carries the
 * duplicate rows the missing constraint allowed.
 *
 * <p>
 * The constraint alone would be a one-line change; what needs proving is the half in front of it. An estate that
 * already double-registered a job cannot have the constraint added until those rows are reconciled, and
 * {@code scheduled_job_history}'s foreign key is {@code ON DELETE CASCADE} -- so deleting a duplicate outright takes
 * the runs recorded against it. The migration repoints that history first, and nothing else in the suite executes the
 * file: the test bootstrap generates its schema from the entities.
 */
class ScheduledJobUniqueNameMigrationITest extends BaseSpringBootTest {

    private static final String MIGRATION_RESOURCE = "db/migration/V202609161300__scheduled_job_unique_name.sql";

    private static final String SCRATCH_SCHEMA = "scheduled_job_unique_migration_check";

    /** The two tables as the migrations before this one leave them: no unique constraint, history cascading. */
    private static final String SCHEDULER_STUB = """
            CREATE TABLE "scheduled_job" (
                "uuid"            UUID PRIMARY KEY,
                "job_name"        VARCHAR NOT NULL,
                "cron_expression" VARCHAR NOT NULL,
                "enabled"         BOOLEAN NOT NULL,
                "one_time"        BOOLEAN NOT NULL,
                "system"          BOOLEAN NOT NULL,
                "job_class_name"  VARCHAR NOT NULL
            );
            CREATE TABLE "scheduled_job_history" (
                "uuid"               UUID PRIMARY KEY,
                "scheduled_job_uuid" UUID,
                CONSTRAINT "fk_scheduled_job_history_scheduled_job"
                    FOREIGN KEY ("scheduled_job_uuid") REFERENCES "scheduled_job" ("uuid") ON DELETE CASCADE
            );
            """;

    /** Ordered, because the survivor is the lowest uuid of a job name and the assertions say which that is. */
    private static final String KEEP = "11111111-0000-4000-8000-000000000001";
    private static final String DUPLICATE = "22222222-0000-4000-8000-000000000002";
    private static final String THIRD = "33333333-0000-4000-8000-000000000003";
    private static final String OTHER_JOB = "44444444-0000-4000-8000-000000000004";

    @Autowired
    private DataSource dataSource;

    @Test
    void theMigrationReconcilesDuplicatesAndThenForbidsThem() throws Exception {
        try (Connection connection = dataSource.getConnection()) {
            try {
                givenAJobRegisteredThreeTimes(connection);

                applyMigration(connection);

                assertOnlyTheLowestUuidSurvives(connection);
                assertEveryRunIsStillRecordedAgainstIt(connection);
                assertASecondRowForOneNameIsNowRefused(connection);
            } finally {
                dropScratchSchema(connection);
            }
        }
    }

    // ---- setup / teardown ----

    private void givenAJobRegisteredThreeTimes(Connection connection) throws SQLException {
        try (Statement statement = connection.createStatement()) {
            statement.execute("DROP SCHEMA IF EXISTS " + SCRATCH_SCHEMA + " CASCADE");
            statement.execute("CREATE SCHEMA " + SCRATCH_SCHEMA);
            statement.execute("SET search_path TO " + SCRATCH_SCHEMA);
            statement.execute(SCHEDULER_STUB);
            statement.execute(job(KEEP, "CbomReconcileTask"));
            statement.execute(job(DUPLICATE, "CbomReconcileTask"));
            statement.execute(job(THIRD, "CbomReconcileTask"));
            statement.execute(job(OTHER_JOB, "CbomSyncTask"));
            statement.execute(history("aaaaaaaa-0000-4000-8000-000000000001", KEEP));
            statement.execute(history("aaaaaaaa-0000-4000-8000-000000000002", DUPLICATE));
            statement.execute(history("aaaaaaaa-0000-4000-8000-000000000003", THIRD));
            statement.execute(history("aaaaaaaa-0000-4000-8000-000000000004", OTHER_JOB));
        }
    }

    private void applyMigration(Connection connection) throws Exception {
        String migration = new ClassPathResource(MIGRATION_RESOURCE).getContentAsString(StandardCharsets.UTF_8);
        try (Statement statement = connection.createStatement()) {
            statement.execute(migration);
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

    // ---- assertions ----

    private void assertOnlyTheLowestUuidSurvives(Connection connection) throws SQLException {
        assertThat(queryColumn(connection, "SELECT uuid::text FROM scheduled_job ORDER BY uuid"))
                .describedAs("one row per job name, and the job that was never duplicated is untouched")
                .containsExactly(KEEP, OTHER_JOB);
    }

    private void assertEveryRunIsStillRecordedAgainstIt(Connection connection) throws SQLException {
        assertThat(queryColumn(connection, "SELECT scheduled_job_uuid::text FROM scheduled_job_history ORDER BY uuid"))
                .describedAs("the cascade would have taken the losers' history; it is repointed at the survivor")
                .containsExactly(KEEP, KEEP, KEEP, OTHER_JOB);
    }

    private void assertASecondRowForOneNameIsNowRefused(Connection connection) throws SQLException {
        try (Statement statement = connection.createStatement()) {
            assertThatThrownBy(() -> statement.execute(job(DUPLICATE, "CbomReconcileTask")))
                    .describedAs("the race two nodes booting together used to win twice")
                    .isInstanceOf(SQLException.class)
                    .hasMessageContaining("uq_scheduled_job_job_name");
        }
    }

    // ---- helpers ----

    private static String job(String uuid, String jobName) {
        return """
                INSERT INTO scheduled_job (uuid, job_name, cron_expression, enabled, one_time, system, job_class_name)
                VALUES ('%s', '%s', '0 0 * * * ?', true, false, true, 'com.otilm.core.tasks.%s')
                """.formatted(uuid, jobName, jobName);
    }

    private static String history(String uuid, String jobUuid) {
        return "INSERT INTO scheduled_job_history (uuid, scheduled_job_uuid) VALUES ('%s', '%s')"
                .formatted(uuid, jobUuid);
    }

    private List<String> queryColumn(Connection connection, String sql, String... parameters) throws SQLException {
        List<String> values = new ArrayList<>();
        try (PreparedStatement statement = connection.prepareStatement(sql)) {
            for (int i = 0; i < parameters.length; i++) {
                statement.setString(i + 1, parameters[i]);
            }
            try (ResultSet rows = statement.executeQuery()) {
                while (rows.next()) {
                    values.add(rows.getString(1));
                }
            }
        }
        return values;
    }
}
