package com.otilm.core.integration.migration;

import com.otilm.core.util.BaseSpringBootTest;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;
import java.util.UUID;
import javax.sql.DataSource;
import org.flywaydb.core.Flyway;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.core.io.ClassPathResource;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class AiRuntimeMigrationITest extends BaseSpringBootTest {
    private static final String RESOURCE = "db/migration/V202611231200__ai_runtime.sql";
    private static final String SCHEMA = "ai_runtime_migration_check";
    private static final String INSERT_RUN = """
            INSERT INTO ai_runtime_run (uuid, conversation_ref, actor_uuid, scope_marker, state,
                revision, fence, attempts_used, attempt_limit, current_attempt_uuid, run_deadline,
                lease_seconds, pod_limit, created_at, updated_at, control_generation)
            VALUES (?, ?, ?, 'synthetic', 'QUEUED', 1, 1, 1, 2, ?,
                clock_timestamp() + interval '120 seconds', 5, 2, clock_timestamp(), clock_timestamp(), 0)
            """;
    private static final String INSERT_ATTEMPT = """
            INSERT INTO ai_runtime_attempt (uuid, run_uuid, attempt_no, state, fence, image_digest,
                profile_revision, security_revision, trust_revision, protocol, launch_deadline,
                max_deadline, created_at, updated_at, control_generation)
            VALUES (?, ?, 1, 'LAUNCHING', 1, 'sha256:' || repeat('a', 64), 1, 1, 1, 'v1',
                clock_timestamp() + interval '30 seconds', clock_timestamp() + interval '60 seconds',
                clock_timestamp(), clock_timestamp(), 0)
            """;

    @Autowired
    private DataSource dataSource;

    @Test
    void flywayAppliesTheActualMigrationWithoutProductRows() throws Exception {
        ClassPathResource resource = migration();
        Path directory = Files.createTempDirectory("ai-runtime-migration-");
        Path script = directory.resolve("V202611231200__ai_runtime.sql");
        try (Connection connection = dataSource.getConnection()) {
            try {
                createSchema(connection);
                Files.write(script, resource.getContentAsByteArray());
                Flyway flyway = Flyway
                        .configure()
                        .dataSource(dataSource)
                        .defaultSchema(SCHEMA)
                        .schemas(SCHEMA)
                        .locations("filesystem:" + directory)
                        .load();
                assertThat(flyway.migrate().migrationsExecuted).isEqualTo(1);
                assertThat(flyway.info().applied()).hasSize(1);
                setSchema(connection);
                for (String table : new String[]{
                        "ai_runtime_run",
                        "ai_runtime_attempt",
                        "ai_runtime_launch",
                        "ai_runtime_workload"}) {
                    try (Statement statement = connection.createStatement();
                            ResultSet count = statement.executeQuery("SELECT count(*) FROM " + table)) {
                        assertThat(count.next()).isTrue();
                        assertThat(count.getLong(1)).isZero();
                    }
                }
            } finally {
                dropSchema(connection);
            }
        } finally {
            Files.deleteIfExists(script);
            Files.deleteIfExists(directory);
        }
    }

    @Test
    void onlyOneLiveRunMayReferenceTheSameConversation() throws Exception {
        withSchema(connection -> {
            UUID conversation = UUID.randomUUID();
            createRun(connection, conversation);
            assertThatThrownBy(() -> createRun(connection, conversation))
                    .isInstanceOf(SQLException.class)
                    .hasMessageContaining("uq_ai_runtime_live_conversation");
            connection.rollback();
            connection.setAutoCommit(true);
            try (Statement statement = connection.createStatement()) {
                statement.executeUpdate("UPDATE ai_runtime_run SET state = 'CANCELLED'");
            }
            createRun(connection, conversation);
            createRun(connection, null);
            createRun(connection, null);
        });
    }

    @Test
    void deferredCurrentAttemptBindingRollsBackAllPartialRows() throws Exception {
        withSchema(connection -> {
            connection.setAutoCommit(false);
            insertRun(connection, UUID.randomUUID(), UUID.randomUUID(), null);
            assertThatThrownBy(connection::commit).isInstanceOf(SQLException.class).hasMessageContaining("foreign key");
            connection.rollback();
            connection.setAutoCommit(true);
            try (Statement statement = connection.createStatement();
                    ResultSet count = statement.executeQuery("SELECT count(*) FROM ai_runtime_run")) {
                assertThat(count.next()).isTrue();
                assertThat(count.getLong(1)).isZero();
            }
        });
    }

    @Test
    void countersAndRuntimePinsCannotEscapeTheSupportedBounds() throws Exception {
        withSchema(connection -> {
            createRun(connection, null);
            for (String assignment : new String[]{
                    "fence = 0",
                    "revision = 0",
                    "attempts_used = 0",
                    "attempt_limit = 11",
                    "lease_seconds = 61",
                    "pod_limit = 1",
                    "scope_marker = ''",
                    "state = 'SUCCEEDED'"}) {
                assertCheckRejected(connection, "ai_runtime_run", assignment);
            }
            for (String assignment : new String[]{
                    "fence = 0",
                    "attempt_no = 11",
                    "profile_revision = 0",
                    "security_revision = 0",
                    "trust_revision = 0",
                    "protocol = 'v2'",
                    "image_digest = 'image:latest'",
                    "launch_deadline = max_deadline + interval '1 second'",
                    "state = 'CLAIMED'"}) {
                assertCheckRejected(connection, "ai_runtime_attempt", assignment);
            }
        });
    }

    @Test
    void onlyOneUnfencedAttemptMayBelongToARun() throws Exception {
        withSchema(connection -> {
            UUID run = createRun(connection, null);
            connection.setAutoCommit(false);
            try (PreparedStatement statement = connection
                    .prepareStatement(INSERT_ATTEMPT.replace("1, 'LAUNCHING'", "2, 'LAUNCHING'"))) {
                statement.setObject(1, UUID.randomUUID());
                statement.setObject(2, run);
                assertThatThrownBy(statement::executeUpdate)
                        .isInstanceOf(SQLException.class)
                        .hasMessageContaining("uq_ai_runtime_live_attempt");
            } finally {
                connection.rollback();
                connection.setAutoCommit(true);
            }
        });
    }

    @Test
    void cyclicForeignKeysAreInitiallyDeferredAndLaunchBindingsAreImmediate() throws Exception {
        withSchema(connection -> {
            int deferred = 0;
            int immediate = 0;
            try (PreparedStatement statement = connection.prepareStatement("""
                    SELECT constraint_row.conname, constraint_row.condeferrable, constraint_row.condeferred
                    FROM pg_catalog.pg_constraint constraint_row
                    JOIN pg_catalog.pg_namespace namespace ON namespace.oid = constraint_row.connamespace
                    WHERE namespace.nspname = ? AND constraint_row.contype = 'f'
                        AND constraint_row.conrelid::regclass::text IN (
                            'ai_runtime_run', 'ai_runtime_attempt', 'ai_runtime_launch', 'ai_runtime_workload')
                    """)) {
                statement.setString(1, SCHEMA);
                try (ResultSet constraints = statement.executeQuery()) {
                    while (constraints.next()) {
                        String name = constraints.getString(1);
                        boolean cyclic = name.equals("fk_ai_runtime_current_attempt")
                                || name.equals("fk_ai_runtime_winner")
                                || name.equals("fk_ai_runtime_attempt_control_generation");
                        assertThat(constraints.getBoolean(2)).as(name + " is deferrable").isEqualTo(cyclic);
                        assertThat(constraints.getBoolean(3)).as(name + " starts deferred").isEqualTo(cyclic);
                        if (cyclic) {
                            deferred++;
                        } else {
                            immediate++;
                        }
                    }
                }
            }
            assertThat(deferred).isEqualTo(3);
            assertThat(immediate).isEqualTo(3);
        });
    }

    @Test
    void liveUniquenessIndexesRetainTheirColumnsAndStatePredicates() throws Exception {
        withSchema(connection -> {
            for (String[] expected : new String[][]{
                    {"uq_ai_runtime_live_conversation", "conversation_ref", "'QUEUED'", "'RUNNING'"},
                    {"uq_ai_runtime_live_attempt", "run_uuid", "'LAUNCHING'", "'CLAIMED'"}}) {
                try (PreparedStatement statement = connection.prepareStatement("""
                        SELECT index_row.indisunique,
                               pg_catalog.pg_get_indexdef(index_row.indexrelid, 1, true),
                               pg_catalog.pg_get_expr(index_row.indpred, index_row.indrelid)
                        FROM pg_catalog.pg_index index_row
                        JOIN pg_catalog.pg_class index_name ON index_name.oid = index_row.indexrelid
                        JOIN pg_catalog.pg_namespace namespace ON namespace.oid = index_name.relnamespace
                        WHERE namespace.nspname = ? AND index_name.relname = ?
                        """)) {
                    statement.setString(1, SCHEMA);
                    statement.setString(2, expected[0]);
                    try (ResultSet index = statement.executeQuery()) {
                        assertThat(index.next()).as(expected[0]).isTrue();
                        assertThat(index.getBoolean(1)).isTrue();
                        assertThat(index.getString(2)).isEqualTo(expected[1]);
                        assertThat(index.getString(3)).contains(expected[2], expected[3]);
                        if (expected[1].equals("conversation_ref")) {
                            assertThat(index.getString(3)).contains("conversation_ref IS NOT NULL");
                        }
                        assertThat(index.next()).isFalse();
                    }
                }
            }
        });
    }

    @Test
    void currentAttemptMustBelongToTheSameRunEvenWhenTheOtherAttemptExists() throws Exception {
        withSchema(connection -> {
            UUID firstRun = createRun(connection, null);
            UUID firstAttempt = currentAttempt(connection, firstRun);
            UUID otherAttempt = currentAttempt(connection, createRun(connection, null));
            connection.setAutoCommit(false);
            assertThat(updateByUuid(connection, "ai_runtime_run", firstRun,
                    "current_attempt_uuid = '" + otherAttempt + "'")).isEqualTo(1);
            assertSqlState(connection, "23503", Connection::commit);
            connection.rollback();
            connection.setAutoCommit(true);
            assertThat(currentAttempt(connection, firstRun)).isEqualTo(firstAttempt);
        });
    }

    @Test
    void launchAndWorkloadForeignKeysRequireTheExactAttemptAndCluster() throws Exception {
        withSchema(connection -> {
            UUID attempt = currentAttempt(connection, createRun(connection, null));
            UUID otherAttempt = currentAttempt(connection, createRun(connection, null));
            assertSqlState(connection, "23503", c -> insertLaunch(c, UUID.randomUUID(), "cluster-one"));
            insertLaunch(connection, attempt, "cluster-one");
            assertSqlState(connection, "23503", c -> insertWorkload(c, otherAttempt, "cluster-one", "foreign-attempt"));
            assertSqlState(connection, "23503", c -> insertWorkload(c, attempt, "cluster-two", "foreign-cluster"));
            insertWorkload(connection, attempt, "cluster-one", "registered-pod");
            assertSqlState(connection, "23505", c -> insertWorkload(c, attempt, "cluster-one", "registered-pod"));
        });
    }

    @Test
    void completeClaimTupleRequiresAWorkloadOnTheSameAttemptAndMayResolveBeforeCommit() throws Exception {
        withSchema(connection -> {
            UUID attempt = currentAttempt(connection, createRun(connection, null));
            UUID otherAttempt = currentAttempt(connection, createRun(connection, null));
            insertLaunch(connection, attempt, "cluster-one");
            insertLaunch(connection, otherAttempt, "cluster-one");
            insertWorkload(connection, otherAttempt, "cluster-one", "other-pod");
            connection.setAutoCommit(false);
            claim(connection, attempt, "cluster-one", "other-pod");
            assertSqlState(connection, "23503", Connection::commit);
            connection.rollback();
            claim(connection, attempt, "cluster-one", "winning-pod");
            insertWorkload(connection, attempt, "cluster-one", "winning-pod");
            connection.commit();
            connection.setAutoCommit(true);
            for (String assignment : new String[]{
                    "winner_cluster = NULL",
                    "winner_pod_uid = ''",
                    "claim_uuid = NULL",
                    "lease_until = NULL",
                    "last_heartbeat_sequence = -1",
                    "last_heartbeat_lease = lease_until + interval '1 second'",
                    "lease_until = max_deadline + interval '1 second'",
                    "state = 'LAUNCHING'"}) {
                assertSqlState(connection, "23514", c -> updateByUuid(c, "ai_runtime_attempt", attempt, assignment));
            }
            try (PreparedStatement statement = connection.prepareStatement("""
                    SELECT winner_cluster, winner_pod_uid, claim_uuid,
                           lease_until = last_heartbeat_lease, last_heartbeat_sequence
                    FROM ai_runtime_attempt WHERE uuid = ?
                    """)) {
                statement.setObject(1, attempt);
                try (ResultSet winner = statement.executeQuery()) {
                    assertThat(winner.next()).isTrue();
                    assertThat(winner.getString(1)).isEqualTo("cluster-one");
                    assertThat(winner.getString(2)).isEqualTo("winning-pod");
                    assertThat(winner.getObject(3)).isNotNull();
                    assertThat(winner.getBoolean(4)).isTrue();
                    assertThat(winner.getLong(5)).isZero();
                }
            }
        });
    }

    @Test
    void pendingCountersRequireCompleteOrderedDeadlinesAndAllowTheStoredLimit() throws Exception {
        withSchema(connection -> {
            UUID attempt = currentAttempt(connection, createRun(connection, null));
            insertLaunch(connection, attempt, "cluster-one");
            insertWorkload(connection, attempt, "cluster-one", "pending-pod");
            for (String assignment : new String[]{
                    "pending_returns = -1",
                    "pending_returns = 12",
                    "pending_returns = 1",
                    "first_pending_at = created_at"}) {
                assertCheckRejected(connection, "ai_runtime_workload", assignment);
            }
            try (Statement statement = connection.createStatement()) {
                assertThat(statement.executeUpdate("""
                        UPDATE ai_runtime_workload SET pending_returns = 11,
                            first_pending_at = created_at, pending_deadline = created_at + interval '10 seconds'
                        """)).isEqualTo(1);
            }
            for (String assignment : new String[]{
                    "pending_returns = 0",
                    "first_pending_at = NULL",
                    "pending_deadline = NULL",
                    "pending_deadline = first_pending_at - interval '1 second'"}) {
                assertCheckRejected(connection, "ai_runtime_workload", assignment);
            }
            try (Statement statement = connection.createStatement();
                    ResultSet pending = statement.executeQuery("SELECT pending_returns FROM ai_runtime_workload")) {
                assertThat(pending.next()).isTrue();
                assertThat(pending.getInt(1)).isEqualTo(11);
            }
        });
    }

    @Test
    void deterministicLaunchNamesAndPinnedDigestFormatsAreEnforced() throws Exception {
        withSchema(connection -> {
            UUID attempt = currentAttempt(connection, createRun(connection, null));
            insertLaunch(connection, attempt, "cluster-one");
            for (String assignment : new String[]{
                    "job_name = 'ilm-ai-unrelated'",
                    "template_digest = 'image:latest'",
                    "template_digest = 'sha256:' || repeat('A', 64)",
                    "namespace_uid = ' '",
                    "service_account_uid = ''",
                    "runtime_class = ''",
                    "job_uid = ''",
                    "observation_sequence = -1",
                    "cleanup_state = 'UNKNOWN'"}) {
                assertCheckRejected(connection, "ai_runtime_launch", assignment);
            }
            assertCheckRejected(connection, "ai_runtime_attempt", "image_digest = 'sha256:' || repeat('a', 63)");
            try (Statement statement = connection.createStatement();
                    ResultSet launch = statement.executeQuery("SELECT job_name FROM ai_runtime_launch")) {
                assertThat(launch.next()).isTrue();
                assertThat(launch.getString(1)).isEqualTo("ilm-ai-" + attempt.toString().replace("-", ""));
            }
        });
    }

    private ClassPathResource migration() {
        ClassPathResource resource = new ClassPathResource(RESOURCE);
        assertThat(resource.exists()).as("versioned AI runtime migration exists").isTrue();
        return resource;
    }

    private void withSchema(SqlWork work) throws Exception {
        String sql = new String(migration().getContentAsByteArray(), StandardCharsets.UTF_8);
        try (Connection connection = dataSource.getConnection()) {
            try {
                createSchema(connection);
                setSchema(connection);
                try (Statement statement = connection.createStatement()) {
                    statement.execute(sql);
                }
                work.run(connection);
            } finally {
                if (!connection.getAutoCommit()) {
                    connection.rollback();
                }
                connection.setAutoCommit(true);
                dropSchema(connection);
            }
        }
    }

    private static UUID createRun(Connection connection, UUID conversation) throws SQLException {
        UUID run = UUID.randomUUID();
        UUID attempt = UUID.randomUUID();
        connection.setAutoCommit(false);
        insertRun(connection, run, attempt, conversation);
        try (PreparedStatement statement = connection.prepareStatement(INSERT_ATTEMPT)) {
            statement.setObject(1, attempt);
            statement.setObject(2, run);
            statement.executeUpdate();
        }
        connection.commit();
        connection.setAutoCommit(true);
        return run;
    }

    private static void insertRun(Connection connection, UUID run, UUID attempt, UUID conversation)
            throws SQLException {
        try (PreparedStatement statement = connection.prepareStatement(INSERT_RUN)) {
            statement.setObject(1, run);
            statement.setObject(2, conversation);
            statement.setObject(3, UUID.randomUUID());
            statement.setObject(4, attempt);
            statement.executeUpdate();
        }
    }

    private static UUID currentAttempt(Connection connection, UUID run) throws SQLException {
        try (PreparedStatement statement = connection
                .prepareStatement("SELECT current_attempt_uuid FROM ai_runtime_run WHERE uuid = ?")) {
            statement.setObject(1, run);
            try (ResultSet result = statement.executeQuery()) {
                assertThat(result.next()).isTrue();
                return result.getObject(1, UUID.class);
            }
        }
    }

    private static void insertLaunch(Connection connection, UUID attempt, String cluster) throws SQLException {
        try (PreparedStatement statement = connection.prepareStatement("""
                INSERT INTO ai_runtime_launch (attempt_uuid, cluster, namespace_name, namespace_uid,
                    service_account_name, service_account_uid, job_name, template_digest, runtime_class,
                    job_uid, observation_sequence, cleanup_state, created_at, updated_at)
                VALUES (?, ?, 'synthetic-ns', 'namespace-uid', 'runner', 'account-uid', ?,
                    'sha256:' || repeat('b', 64), 'sandbox', 'job-uid', 0, 'NONE',
                    clock_timestamp(), clock_timestamp())
                """)) {
            statement.setObject(1, attempt);
            statement.setString(2, cluster);
            statement.setString(3, "ilm-ai-" + attempt.toString().replace("-", ""));
            assertThat(statement.executeUpdate()).isEqualTo(1);
        }
    }

    private static void insertWorkload(Connection connection, UUID attempt, String cluster, String pod)
            throws SQLException {
        try (PreparedStatement statement = connection.prepareStatement("""
                INSERT INTO ai_runtime_workload (cluster, pod_uid, attempt_uuid, pod_name, job_uid,
                    state, observation_sequence, observation_valid_until, created_at, updated_at)
                VALUES (?, ?, ?, 'synthetic-pod', 'job-uid', 'REGISTERED', 1,
                    clock_timestamp() + interval '30 seconds', clock_timestamp(), clock_timestamp())
                """)) {
            statement.setString(1, cluster);
            statement.setString(2, pod);
            statement.setObject(3, attempt);
            assertThat(statement.executeUpdate()).isEqualTo(1);
        }
    }

    private static void claim(Connection connection, UUID attempt, String cluster, String pod) throws SQLException {
        try (PreparedStatement statement = connection.prepareStatement("""
                UPDATE ai_runtime_attempt SET state = 'CLAIMED', winner_cluster = ?, winner_pod_uid = ?,
                    claim_uuid = ?, lease_until = max_deadline - interval '1 second',
                    last_heartbeat_sequence = 0, last_heartbeat_lease = max_deadline - interval '1 second'
                WHERE uuid = ?
                """)) {
            statement.setString(1, cluster);
            statement.setString(2, pod);
            statement.setObject(3, UUID.randomUUID());
            statement.setObject(4, attempt);
            assertThat(statement.executeUpdate()).isEqualTo(1);
        }
    }

    private static int updateByUuid(Connection connection, String table, UUID uuid, String assignment)
            throws SQLException {
        try (PreparedStatement statement = connection
                .prepareStatement("UPDATE " + table + " SET " + assignment + " WHERE uuid = ?")) {
            statement.setObject(1, uuid);
            return statement.executeUpdate();
        }
    }

    private static void assertSqlState(Connection connection, String expected, SqlWork work) {
        assertThatThrownBy(() -> work.run(connection))
                .isInstanceOf(SQLException.class)
                .extracting(failure -> ((SQLException) failure).getSQLState())
                .isEqualTo(expected);
    }

    private static void assertCheckRejected(Connection connection, String table, String assignment)
            throws SQLException {
        try (Statement statement = connection.createStatement()) {
            assertThatThrownBy(() -> statement.executeUpdate("UPDATE " + table + " SET " + assignment))
                    .isInstanceOf(SQLException.class)
                    .extracting(failure -> ((SQLException) failure).getSQLState())
                    .isEqualTo("23514");
        }
    }

    private static void createSchema(Connection connection) throws SQLException {
        try (Statement statement = connection.createStatement()) {
            statement.execute("CREATE SCHEMA " + SCHEMA);
        }
    }

    private static void setSchema(Connection connection) throws SQLException {
        try (Statement statement = connection.createStatement()) {
            statement.execute("SET search_path TO " + SCHEMA);
        }
    }

    private static void dropSchema(Connection connection) throws SQLException {
        try (Statement statement = connection.createStatement()) {
            statement.execute("SET search_path TO core");
            statement.execute("DROP SCHEMA IF EXISTS " + SCHEMA + " CASCADE");
        }
    }

    @FunctionalInterface
    private interface SqlWork {
        void run(Connection connection) throws Exception;
    }
}
