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
import org.assertj.core.api.ThrowableAssert.ThrowingCallable;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.core.io.ClassPathResource;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/**
 * Runs {@code V202611101200__certificate_protocol_association_unique.sql} as Flyway will, against a table that already
 * holds several associations for one certificate. The test bootstrap generates its schema from the entities, so nothing
 * else in the suite executes the file.
 */
class CertificateProtocolAssociationUniqueMigrationITest extends BaseSpringBootTest {

    private static final String MIGRATION_RESOURCE = "db/migration/V202611101200__certificate_protocol_association_unique.sql";

    private static final String SCRATCH_SCHEMA = "protocol_association_unique_migration_check";

    /** The table as the migrations before this one leave it: nothing limits a certificate to one association. */
    private static final String ASSOCIATION_TABLE = """
            CREATE TABLE certificate_protocol_association (
                uuid                     UUID PRIMARY KEY,
                certificate_uuid         UUID NOT NULL,
                protocol                 TEXT NOT NULL,
                protocol_profile_uuid    UUID,
                additional_protocol_uuid UUID
            );
            """;

    private static final String CERTIFICATE = "aaaaaaaa-0000-4000-8000-000000000001";
    private static final String OTHER_CERTIFICATE = "bbbbbbbb-0000-4000-8000-000000000002";

    /** Inserted in this order, so the latest association has neither the highest nor the lowest uuid. */
    private static final String FIRST = "22222222-0000-4000-8000-000000000002";
    private static final String SECOND = "33333333-0000-4000-8000-000000000003";
    private static final String LATEST = "11111111-0000-4000-8000-000000000001";
    private static final String ONLY = "44444444-0000-4000-8000-000000000004";

    @Autowired
    private DataSource dataSource;

    private Connection connection;

    @BeforeEach
    void createTheTableAsEarlierMigrationsLeaveIt() throws SQLException {
        connection = dataSource.getConnection();
        try (Statement statement = connection.createStatement()) {
            statement.execute("DROP SCHEMA IF EXISTS " + SCRATCH_SCHEMA + " CASCADE");
            statement.execute("CREATE SCHEMA " + SCRATCH_SCHEMA);
            statement.execute("SET search_path TO " + SCRATCH_SCHEMA);
            statement.execute(ASSOCIATION_TABLE);
        }
    }

    @AfterEach
    void dropTheScratchSchema() throws SQLException {
        try (Statement statement = connection.createStatement()) {
            statement.execute("DROP SCHEMA IF EXISTS " + SCRATCH_SCHEMA + " CASCADE");
            // The connection goes back to a pool shared with the rest of the suite.
            statement.execute("RESET search_path");
        } finally {
            connection.close();
        }
    }

    @Test
    void keepsTheLatestAssociationOfEachCertificate() throws Exception {
        // given
        insertAssociation(FIRST, CERTIFICATE, "SCEP");
        insertAssociation(SECOND, CERTIFICATE, "CMP");
        insertAssociation(LATEST, CERTIFICATE, "ACME");
        insertAssociation(ONLY, OTHER_CERTIFICATE, "SCEP");

        // when
        applyMigration();

        // then
        assertThat(queryUuids("SELECT uuid::text FROM certificate_protocol_association ORDER BY certificate_uuid"))
                .containsExactly(LATEST, ONLY);
    }

    @Test
    void refusesASecondAssociationOfACertificate() throws Exception {
        // given
        insertAssociation(FIRST, CERTIFICATE, "SCEP");
        applyMigration();

        // when
        ThrowingCallable secondAssociation = () -> insertAssociation(SECOND, CERTIFICATE, "CMP");

        // then
        assertThatThrownBy(secondAssociation)
                .isInstanceOf(SQLException.class)
                .hasMessageContaining("uq_certificate_protocol_association_certificate");
    }

    // ── Helpers ───────────────────────────────────────────────────────────────

    private void applyMigration() throws Exception {
        String migration = new ClassPathResource(MIGRATION_RESOURCE).getContentAsString(StandardCharsets.UTF_8);
        try (Statement statement = connection.createStatement()) {
            statement.execute(migration);
        }
    }

    private void insertAssociation(String uuid, String certificateUuid, String protocol) throws SQLException {
        try (Statement statement = connection.createStatement()) {
            statement
                    .execute("INSERT INTO certificate_protocol_association (uuid, certificate_uuid, protocol)"
                            + " VALUES ('%s', '%s', '%s')".formatted(uuid, certificateUuid, protocol));
        }
    }

    private List<String> queryUuids(String sql) throws SQLException {
        List<String> uuids = new ArrayList<>();
        try (Statement statement = connection.createStatement(); ResultSet rows = statement.executeQuery(sql)) {
            while (rows.next()) {
                uuids.add(rows.getString(1));
            }
        }
        return uuids;
    }
}
