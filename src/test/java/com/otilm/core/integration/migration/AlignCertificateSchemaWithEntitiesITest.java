package com.otilm.core.integration.migration;

import com.otilm.api.model.core.certificate.CertificateKeyUsage;
import com.otilm.core.dao.entity.Certificate;
import com.otilm.core.dao.entity.CertificateRequestEntity;
import com.otilm.core.dao.repository.CertificateRepository;
import com.otilm.core.dao.repository.CertificateRequestRepository;
import com.otilm.core.util.builders.CertificateRequestEntityBuilder;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.core.io.ClassPathResource;

import javax.sql.DataSource;
import java.nio.charset.StandardCharsets;
import java.sql.Connection;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;
import java.util.List;
import java.util.Set;
import java.util.UUID;

/**
 * Verifies the data transforms of {@code V202607141200__align_certificate_schema_with_entities.sql}
 * against seeded pre-migration rows. The regular test bootstrap applies the migration to an empty
 * schema, so without this test the backfill UPDATEs conversion would never execute against data.
 */
class AlignCertificateSchemaWithEntitiesITest extends BaseMigrationTest {

    private static final String MIGRATION_RESOURCE = "db/migration/V202607141200__align_certificate_schema_with_entities.sql";

    /** Naive wall-clock value seeded while the column is still {@code timestamp without time zone}. */
    @Autowired
    DataSource dataSource;

    @Autowired
    CertificateRepository certificateRepository;
    @Autowired
    CertificateRequestRepository certificateRequestRepository;

    @Test
    void testMigration() throws Exception {
        Certificate certificateWithNulls = new Certificate();
        Certificate certificateWithValues = new Certificate();
        certificateWithValues.setUsage(List.of(CertificateKeyUsage.DIGITAL_SIGNATURE));
        certificateWithValues.setHybridCertificate(true);
        certificateWithValues.setArchived(true);
        certificateRepository.saveAll(List.of(certificateWithNulls, certificateWithValues));

        CertificateRequestEntity certificateRequest = CertificateRequestEntityBuilder.aCertificateRequest()
                .withContent("content")
                .build();
        certificateRequestRepository.save(certificateRequest);

        try (Connection connection = dataSource.getConnection()) {
            simulateOldEnvironment(connection, certificateWithNulls.getUuid(), certificateRequest.getUuid());

            try (Statement statement = connection.createStatement()) {
                statement.execute(new ClassPathResource(MIGRATION_RESOURCE).getContentAsString(StandardCharsets.UTF_8));
            }

            assertColumnAbsent(connection, "certificate", "discovery_uuid");
            assertColumnAbsent(connection, "certificate_request", "subject_dn_normalized");
            assertNotNullable(connection, "certificate", "key_usage");
            assertNotNullable(connection, "certificate_request", "key_usage");
        }

        certificateWithNulls = certificateRepository.findByUuid(certificateWithNulls.getUuid()).orElseThrow();
        Assertions.assertEquals(0, certificateWithNulls.getKeyUsageBitMask());
        Assertions.assertFalse(certificateWithNulls.isHybridCertificate());
        Assertions.assertFalse(certificateWithNulls.isArchived());

        // Backfill must only touch NULL rows; populated values survive unchanged.
        certificateWithValues = certificateRepository.findByUuid(certificateWithValues.getUuid()).orElseThrow();
        Assertions.assertEquals(Set.of(CertificateKeyUsage.DIGITAL_SIGNATURE), certificateWithValues.getKeyUsage());
        Assertions.assertTrue(certificateWithValues.isHybridCertificate());
        Assertions.assertTrue(certificateWithValues.isArchived());

        certificateRequest = certificateRequestRepository.findByFingerprint(certificateRequest.getFingerprint()).orElseThrow();
        Assertions.assertEquals(0, certificateRequest.getKeyUsage());
    }

    /**
     * Reverts the schema to its pre-migration shape for everything V202607141200 touches, so the
     * full script can re-run, then seeds the legacy data states: NULL primitive-mapped columns and
     * a naive status_validation_timestamp.
     */
    private static void simulateOldEnvironment(Connection connection, UUID certificateUuid, UUID certificateRequestUuid) throws SQLException {
        try (Statement statement = connection.createStatement()) {
            statement.execute("ALTER TABLE certificate ADD COLUMN discovery_uuid BIGINT");
            statement.execute("ALTER TABLE certificate_request ADD COLUMN subject_dn_normalized VARCHAR");
            statement.execute("""
                    ALTER TABLE certificate
                        ALTER COLUMN key_usage DROP NOT NULL,
                        ALTER COLUMN key_usage DROP DEFAULT,
                        ALTER COLUMN hybrid_certificate DROP NOT NULL,
                        ALTER COLUMN archived DROP NOT NULL
                    """);
            statement.execute("""
                    ALTER TABLE certificate_request
                        ALTER COLUMN key_usage DROP NOT NULL,
                        ALTER COLUMN key_usage DROP DEFAULT
                    """);
            statement.execute(("""
                    UPDATE certificate
                        SET key_usage = NULL, hybrid_certificate = NULL, archived = NULL
                        WHERE uuid = '%s'
                    """).formatted(certificateUuid));
            statement.execute("UPDATE certificate_request SET key_usage = NULL WHERE uuid = '%s'".formatted(certificateRequestUuid));
        }
    }

    private static void assertColumnAbsent(Connection connection, String table, String column) throws SQLException {
        Assertions.assertNull(queryColumn(connection, table, column, "column_name"),
                "Column %s.%s should have been dropped".formatted(table, column));
    }

    private static void assertColumnType(Connection connection, String table, String column, String expectedType) throws SQLException {
        Assertions.assertEquals(expectedType, queryColumn(connection, table, column, "data_type"));
    }

    private static void assertNotNullable(Connection connection, String table, String column) throws SQLException {
        Assertions.assertEquals("NO", queryColumn(connection, table, column, "is_nullable"));
    }

    /** Returns the requested information_schema attribute of the column, or null if the column does not exist. */
    private static String queryColumn(Connection connection, String table, String column, String selected) throws SQLException {
        try (Statement statement = connection.createStatement();
             ResultSet resultSet = statement.executeQuery(("""
                     SELECT %s FROM information_schema.columns
                         WHERE table_schema = current_schema() AND table_name = '%s' AND column_name = '%s'
                     """).formatted(selected, table, column))) {
            return resultSet.next() ? resultSet.getString(1) : null;
        }
    }
}
