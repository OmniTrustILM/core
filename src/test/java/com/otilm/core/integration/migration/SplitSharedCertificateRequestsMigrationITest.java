package com.otilm.core.integration.migration;

import com.otilm.core.util.BaseSpringBootTest;
import java.nio.charset.StandardCharsets;
import java.sql.Connection;
import java.sql.ResultSet;
import java.sql.Statement;
import java.time.Duration;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import javax.sql.DataSource;
import org.awaitility.Awaitility;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.core.io.ClassPathResource;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Runs {@code V202610301000__split_shared_certificate_requests.sql} in a scratch schema, in one transaction as Flyway
 * does.
 */
class SplitSharedCertificateRequestsMigrationITest extends BaseSpringBootTest {

    private static final String MIGRATION_RESOURCE = "db/migration/V202610301000__split_shared_certificate_requests.sql";
    private static final String SCRATCH_SCHEMA = "split_shared_certificate_requests_migration_check";
    private static final String SHARED_REQUEST = "10000000-0000-0000-0000-000000000001";
    private static final String OWN_REQUEST = "10000000-0000-0000-0000-000000000002";
    private static final String OLDEST = "20000000-0000-0000-0000-000000000001";
    private static final String SECOND = "20000000-0000-0000-0000-000000000002";
    private static final String THIRD = "20000000-0000-0000-0000-000000000003";
    private static final String ALONE = "20000000-0000-0000-0000-000000000004";
    private static final String WITHOUT_REQUEST = "20000000-0000-0000-0000-000000000005";
    private static final String ATTRIBUTE_ITEM = "30000000-0000-0000-0000-000000000001";

    @Autowired
    private DataSource dataSource;

    @Test
    void certificatesSharingARequestGetACopyEach() throws Exception {
        try (Connection connection = dataSource.getConnection()) {
            try (Statement statement = connection.createStatement()) {
                createScratchSchema(statement);
                insertRequest(statement, SHARED_REQUEST, "CN=shared", "NOK");
                insertRequest(statement, OWN_REQUEST, "CN=own", "OK");
                // Inserted out of creation order, so the oldest is found by its creation time, not by insertion
                insertCertificate(statement, SECOND, SHARED_REQUEST, "2026-02-01");
                insertCertificate(statement, OLDEST, SHARED_REQUEST, "2026-01-01");
                insertCertificate(statement, THIRD, SHARED_REQUEST, "2026-03-01");
                insertCertificate(statement, ALONE, OWN_REQUEST, "2026-01-01");
                insertCertificate(statement, WITHOUT_REQUEST, null, "2026-01-01");
                statement
                        .execute("INSERT INTO attribute_content_2_object VALUES (gen_random_uuid(), '" + ATTRIBUTE_ITEM
                                + "', 'CERTIFICATE_REQUEST', '" + SHARED_REQUEST + "', 3)");
                statement
                        .execute("INSERT INTO compliance_profile_association VALUES (gen_random_uuid(),"
                                + " gen_random_uuid(), 'CERTIFICATE_REQUEST', '" + SHARED_REQUEST + "')");

                runMigration(connection);

                assertThat(requestOf(statement, OLDEST)).isEqualTo(SHARED_REQUEST);
                assertThat(requestOf(statement, ALONE)).isEqualTo(OWN_REQUEST);
                assertThat(requestOf(statement, WITHOUT_REQUEST)).isNull();
                String secondCopy = requestOf(statement, SECOND);
                String thirdCopy = requestOf(statement, THIRD);
                assertThat(List.of(secondCopy, thirdCopy)).doesNotContain(SHARED_REQUEST).doesNotHaveDuplicates();
                for (String copy : List.of(secondCopy, thirdCopy)) {
                    assertThat(single(statement, describeRequest(copy)))
                            .isEqualTo(single(statement, describeRequest(SHARED_REQUEST)));
                    assertThat(single(statement, "SELECT attribute_content_item_uuid || '|' || item_order FROM"
                            + " attribute_content_2_object WHERE object_type = 'CERTIFICATE_REQUEST' AND object_uuid"
                            + " = '" + copy + "'")).isEqualTo(ATTRIBUTE_ITEM + "|3");
                }
                assertThat(column(statement, "SELECT object_uuid::text FROM compliance_profile_association"))
                        .containsExactly(SHARED_REQUEST);
                List<String> requestsAfterFirstRun = column(statement, "SELECT uuid::text FROM certificate_request");
                assertThat(requestsAfterFirstRun).hasSize(4);

                runMigration(connection);

                assertThat(column(statement, "SELECT uuid::text FROM certificate_request"))
                        .containsExactlyInAnyOrderElementsOf(requestsAfterFirstRun);
                assertThat(requestOf(statement, SECOND)).isEqualTo(secondCopy);
                assertThat(column(statement, "SELECT uuid::text FROM attribute_content_2_object")).hasSize(3);
            } finally {
                dropScratchSchema(connection);
            }
        }
    }

    /**
     * A rejected approval on the previous release, still running during a rolling update, detaches a placeholder's
     * request while the split runs.
     */
    @Test
    void aCertificateDetachedWhileTheSplitRunsStaysDetached() throws Exception {
        ExecutorService executor = Executors.newSingleThreadExecutor();
        try (Connection connection = dataSource.getConnection();
                Connection previousRelease = dataSource.getConnection()) {
            try (Statement statement = connection.createStatement();
                    Statement previousReleaseStatement = previousRelease.createStatement()) {
                createScratchSchema(statement);
                insertRequest(statement, SHARED_REQUEST, "CN=shared", "NOK");
                insertCertificate(statement, OLDEST, SHARED_REQUEST, "2026-01-01");
                insertCertificate(statement, SECOND, SHARED_REQUEST, "2026-02-01");
                previousReleaseStatement.execute("SET search_path TO " + SCRATCH_SCHEMA);
                previousRelease.setAutoCommit(false);
                previousReleaseStatement
                        .execute(
                                "UPDATE certificate SET certificate_request_uuid = NULL WHERE uuid = '" + SECOND + "'");

                Future<?> split = executor.submit(() -> {
                    runMigration(connection);
                    return null;
                });
                awaitRowLockWaiter();
                previousRelease.commit();
                split.get(10, TimeUnit.SECONDS);

                assertThat(requestOf(statement, SECOND)).isNull();
                assertThat(requestOf(statement, OLDEST)).isEqualTo(SHARED_REQUEST);
            } finally {
                previousRelease.rollback();
                previousRelease.setAutoCommit(true);
                try (Statement statement = previousRelease.createStatement()) {
                    statement.execute("RESET search_path");
                }
                dropScratchSchema(connection);
            }
        } finally {
            executor.shutdownNow();
        }
    }

    private static void createScratchSchema(Statement statement) throws Exception {
        statement.execute("DROP SCHEMA IF EXISTS " + SCRATCH_SCHEMA + " CASCADE");
        statement.execute("CREATE SCHEMA " + SCRATCH_SCHEMA);
        statement.execute("SET search_path TO " + SCRATCH_SCHEMA);
        statement.execute("""
                CREATE TABLE "certificate_request" (
                    "uuid" UUID PRIMARY KEY,
                    "content" TEXT NOT NULL,
                    "fingerprint" TEXT NOT NULL,
                    "compliance_status" TEXT NOT NULL,
                    "compliance_result" JSONB
                )
                """);
        statement.execute("""
                CREATE TABLE "certificate" (
                    "uuid" UUID PRIMARY KEY,
                    "i_cre" TIMESTAMP NOT NULL,
                    "certificate_request_uuid" UUID REFERENCES "certificate_request" ("uuid")
                )
                """);
        statement.execute("""
                CREATE TABLE "attribute_content_2_object" (
                    "uuid" UUID PRIMARY KEY,
                    "attribute_content_item_uuid" UUID NOT NULL,
                    "object_type" TEXT NOT NULL,
                    "object_uuid" UUID NOT NULL,
                    "item_order" INTEGER NOT NULL
                )
                """);
        statement.execute("""
                CREATE TABLE "compliance_profile_association" (
                    "uuid" UUID PRIMARY KEY,
                    "compliance_profile_uuid" UUID NOT NULL,
                    "resource" TEXT NOT NULL,
                    "object_uuid" UUID NOT NULL
                )
                """);
    }

    /**
     * The connection goes back to a pool shared with the rest of the suite: the session's search_path must not point at
     * the schema this drops.
     */
    private static void dropScratchSchema(Connection connection) throws Exception {
        try (Statement statement = connection.createStatement()) {
            statement.execute("RESET search_path");
            statement.execute("DROP SCHEMA IF EXISTS " + SCRATCH_SCHEMA + " CASCADE");
        }
    }

    private static void runMigration(Connection connection) throws Exception {
        String migration = new ClassPathResource(MIGRATION_RESOURCE).getContentAsString(StandardCharsets.UTF_8);
        connection.setAutoCommit(false);
        try (Statement statement = connection.createStatement()) {
            statement.execute(migration);
            connection.commit();
        } catch (Exception e) {
            connection.rollback();
            throw e;
        } finally {
            connection.setAutoCommit(true);
        }
    }

    /** The split's UPDATE must be waiting on the row the other transaction holds before that one commits. */
    private void awaitRowLockWaiter() {
        Awaitility.await().atMost(Duration.ofSeconds(10)).until(() -> {
            try (Connection observer = dataSource.getConnection();
                    Statement statement = observer.createStatement();
                    ResultSet rows = statement.executeQuery("SELECT count(*) FROM pg_locks WHERE NOT granted")) {
                return rows.next() && rows.getLong(1) >= 1;
            }
        });
    }

    private static void insertRequest(Statement statement, String uuid, String subject, String complianceStatus)
            throws Exception {
        statement
                .execute("INSERT INTO certificate_request VALUES ('" + uuid + "', 'content of " + subject
                        + "', 'fingerprint of " + subject + "', '" + complianceStatus + "', '{\"status\": \""
                        + complianceStatus + "\"}')");
    }

    private static void insertCertificate(Statement statement, String uuid, String requestUuid, String created)
            throws Exception {
        statement
                .execute("INSERT INTO certificate VALUES ('" + uuid + "', '" + created + "', "
                        + (requestUuid == null ? "NULL" : "'" + requestUuid + "'") + ")");
    }

    private static String describeRequest(String requestUuid) {
        return "SELECT content || '|' || fingerprint || '|' || compliance_status || '|' || compliance_result::text"
                + " FROM certificate_request WHERE uuid = '" + requestUuid + "'";
    }

    private static String requestOf(Statement statement, String certificateUuid) throws Exception {
        return single(statement,
                "SELECT certificate_request_uuid::text FROM certificate WHERE uuid = '" + certificateUuid + "'");
    }

    private static String single(Statement statement, String sql) throws Exception {
        List<String> values = column(statement, sql);
        assertThat(values).hasSize(1);
        return values.getFirst();
    }

    private static List<String> column(Statement statement, String sql) throws Exception {
        List<String> values = new ArrayList<>();
        try (ResultSet rows = statement.executeQuery(sql)) {
            while (rows.next()) {
                values.add(rows.getString(1));
            }
        }
        return values;
    }
}
