package com.otilm.core.integration.migration;

import com.otilm.core.util.BaseSpringBootTest;
import db.migration.V202610301000__SplitSharedCertificateRequests;
import java.sql.Connection;
import java.sql.ResultSet;
import java.sql.Statement;
import java.util.ArrayList;
import java.util.List;
import javax.sql.DataSource;
import org.flywaydb.core.api.migration.Context;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

/**
 * Runs {@code V202610301000__SplitSharedCertificateRequests} in a scratch schema and asserts that every certificate but
 * the oldest of those sharing a request gets a copy of it, with the request's columns and attribute values, that the
 * oldest keeps the row and its compliance profile associations, and that a second run changes nothing.
 */
class SplitSharedCertificateRequestsMigrationITest extends BaseSpringBootTest {

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
                statement.execute("DROP SCHEMA IF EXISTS " + SCRATCH_SCHEMA + " CASCADE");
                statement.execute("CREATE SCHEMA " + SCRATCH_SCHEMA);
                statement.execute("SET search_path TO " + SCRATCH_SCHEMA);
                createTables(statement);
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
                    assertThat(single(statement,
                            "SELECT content || '|' || fingerprint || '|' || compliance_status"
                                    + " || '|' || compliance_result::text FROM certificate_request WHERE uuid = '"
                                    + copy + "'"))
                            .isEqualTo(single(statement, "SELECT content || '|' || fingerprint || '|' ||"
                                    + " compliance_status || '|' || compliance_result::text FROM certificate_request"
                                    + " WHERE uuid = '" + SHARED_REQUEST + "'"));
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
                try (Statement statement = connection.createStatement()) {
                    // The connection goes back to a pool shared with the rest of the suite: the session's search_path
                    // must not point at the schema this drops.
                    statement.execute("RESET search_path");
                    statement.execute("DROP SCHEMA IF EXISTS " + SCRATCH_SCHEMA + " CASCADE");
                }
            }
        }
    }

    private static void createTables(Statement statement) throws Exception {
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

    private static void runMigration(Connection connection) throws Exception {
        Context context = mock(Context.class);
        when(context.getConnection()).thenReturn(connection);
        new V202610301000__SplitSharedCertificateRequests().migrate(context);
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
