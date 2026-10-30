package com.otilm.core.integration.migration;

import com.otilm.core.util.BaseSpringBootTest;
import java.nio.charset.StandardCharsets;
import java.sql.Connection;
import java.sql.ResultSet;
import java.sql.Statement;
import java.util.ArrayList;
import java.util.List;
import javax.sql.DataSource;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.core.io.ClassPathResource;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Runs {@code V202610301100__certificate_request_drop_unreferenced.sql} in a scratch schema.
 */
class CertificateRequestDropUnreferencedMigrationITest extends BaseSpringBootTest {

    private static final String MIGRATION_RESOURCE = "db/migration/V202610301100__certificate_request_drop_unreferenced.sql";
    private static final String SCRATCH_SCHEMA = "certificate_request_drop_unreferenced_migration_check";
    private static final String REFERENCED_REQUEST = "10000000-0000-0000-0000-000000000001";
    private static final String UNREFERENCED_REQUEST = "10000000-0000-0000-0000-000000000002";
    private static final String OTHER_OBJECT = "20000000-0000-0000-0000-000000000001";

    @Autowired
    private DataSource dataSource;

    @Test
    void requestsNoCertificateRefersToAreDropped() throws Exception {
        try (Connection connection = dataSource.getConnection()) {
            try (Statement statement = connection.createStatement()) {
                statement.execute("DROP SCHEMA IF EXISTS " + SCRATCH_SCHEMA + " CASCADE");
                statement.execute("CREATE SCHEMA " + SCRATCH_SCHEMA);
                statement.execute("SET search_path TO " + SCRATCH_SCHEMA);
                statement.execute("CREATE TABLE \"certificate_request\" (\"uuid\" UUID PRIMARY KEY)");
                statement.execute("""
                        CREATE TABLE "certificate" (
                            "uuid" UUID PRIMARY KEY,
                            "certificate_request_uuid" UUID REFERENCES "certificate_request" ("uuid")
                        )
                        """);
                statement.execute("""
                        CREATE TABLE "attribute_content_2_object" (
                            "uuid" UUID PRIMARY KEY,
                            "object_type" TEXT NOT NULL,
                            "object_uuid" UUID NOT NULL
                        )
                        """);
                statement.execute("""
                        CREATE TABLE "compliance_profile_association" (
                            "uuid" UUID PRIMARY KEY,
                            "resource" TEXT NOT NULL,
                            "object_uuid" UUID NOT NULL
                        )
                        """);
                statement
                        .execute("INSERT INTO certificate_request VALUES ('" + REFERENCED_REQUEST + "'), ('"
                                + UNREFERENCED_REQUEST + "')");
                statement
                        .execute("INSERT INTO certificate VALUES (gen_random_uuid(), '" + REFERENCED_REQUEST
                                + "'), (gen_random_uuid(), NULL)");
                for (String objectUuid : List.of(REFERENCED_REQUEST, UNREFERENCED_REQUEST)) {
                    statement
                            .execute("INSERT INTO attribute_content_2_object VALUES (gen_random_uuid(),"
                                    + " 'CERTIFICATE_REQUEST', '" + objectUuid + "')");
                    statement
                            .execute("INSERT INTO compliance_profile_association VALUES (gen_random_uuid(),"
                                    + " 'CERTIFICATE_REQUEST', '" + objectUuid + "')");
                }
                statement
                        .execute("INSERT INTO attribute_content_2_object VALUES (gen_random_uuid(), 'CERTIFICATE', '"
                                + OTHER_OBJECT + "')");
                statement
                        .execute("INSERT INTO compliance_profile_association VALUES (gen_random_uuid(), 'RA_PROFILE',"
                                + " '" + OTHER_OBJECT + "')");

                String migration = new ClassPathResource(MIGRATION_RESOURCE).getContentAsString(StandardCharsets.UTF_8);
                for (int run = 0; run < 2; run++) {
                    statement.execute(migration);

                    assertThat(column(statement, "SELECT uuid::text FROM certificate_request"))
                            .containsExactly(REFERENCED_REQUEST);
                    assertThat(column(statement, "SELECT object_uuid::text FROM attribute_content_2_object"))
                            .containsExactlyInAnyOrder(REFERENCED_REQUEST, OTHER_OBJECT);
                    assertThat(column(statement, "SELECT object_uuid::text FROM compliance_profile_association"))
                            .containsExactlyInAnyOrder(REFERENCED_REQUEST, OTHER_OBJECT);
                    assertThat(column(statement,
                            "SELECT indexname FROM pg_indexes WHERE schemaname = '" + SCRATCH_SCHEMA
                                    + "' AND tablename = 'certificate' AND indexname <> 'certificate_pkey'"))
                            .containsExactly("idx_certificate_certificate_request_uuid");
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
