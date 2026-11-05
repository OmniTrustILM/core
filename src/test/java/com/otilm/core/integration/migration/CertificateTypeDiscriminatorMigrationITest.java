package com.otilm.core.integration.migration;

import com.otilm.core.dao.entity.X509CertificateEntity;
import com.otilm.core.dao.entity.X509CertificateRequestEntity;
import com.otilm.core.dao.repository.CertificateRepository;
import com.otilm.core.dao.repository.CertificateRequestRepository;
import com.otilm.core.util.builders.CertificateRequestEntityBuilder;
import java.nio.charset.StandardCharsets;
import java.sql.Connection;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;
import java.util.UUID;
import javax.sql.DataSource;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.core.io.ClassPathResource;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Verifies {@code V202611051000__certificate_type_discriminator.sql} against rows seeded in the state it repairs. The
 * regular test bootstrap applies the migration to an empty schema, so without this test its backfill would never run
 * against data.
 */
class CertificateTypeDiscriminatorMigrationITest extends BaseMigrationTest {

    private static final String MIGRATION_RESOURCE = "db/migration/V202611051000__certificate_type_discriminator.sql";

    @Autowired
    DataSource dataSource;
    @Autowired
    CertificateRepository certificateRepository;
    @Autowired
    CertificateRequestRepository certificateRequestRepository;

    // Read inside @BeforeAll: the base test class empties the tables before every test.
    private String typeOfNullTypeCertificate;
    private String typeOfEmptyTypeCertificate;
    private String typeOfOtherTypeCertificate;
    private String typeOfNullTypeRequest;

    @BeforeAll
    void seedOldStateAndMigrate() throws Exception {
        UUID nullTypeCertificateUuid = certificateRepository.save(new X509CertificateEntity()).getUuid();
        UUID emptyTypeCertificateUuid = certificateRepository.save(new X509CertificateEntity()).getUuid();
        UUID otherTypeCertificateUuid = certificateRepository.save(new X509CertificateEntity()).getUuid();
        X509CertificateRequestEntity request = CertificateRequestEntityBuilder
                .aCertificateRequest()
                .withContent("content")
                .build();
        UUID nullTypeRequestUuid = certificateRequestRepository.save(request).getUuid();

        try (Connection connection = dataSource.getConnection(); Statement statement = connection.createStatement()) {
            // the test schema is generated from the entities and checks the column against the enum; a deployed one has
            // no such check, which is how the empty values this migration repairs came to be stored
            statement.execute("ALTER TABLE certificate DROP CONSTRAINT IF EXISTS certificate_certificate_type_check");
            statement
                    .execute("ALTER TABLE certificate_request DROP CONSTRAINT IF EXISTS "
                            + "certificate_request_certificate_type_check");
            statement.execute("ALTER TABLE certificate ALTER COLUMN certificate_type DROP NOT NULL");
            statement.execute("ALTER TABLE certificate ALTER COLUMN certificate_type DROP DEFAULT");
            statement.execute("ALTER TABLE certificate_request ALTER COLUMN certificate_type DROP NOT NULL");
            statement.execute("ALTER TABLE certificate_request ALTER COLUMN certificate_type DROP DEFAULT");
            statement.execute("ALTER TABLE certificate ALTER COLUMN key_usage SET NOT NULL");
            statement.execute("ALTER TABLE certificate_request ALTER COLUMN key_usage SET NOT NULL");
            statement
                    .execute("UPDATE certificate SET certificate_type = NULL WHERE uuid = '%s'"
                            .formatted(nullTypeCertificateUuid));
            statement
                    .execute("UPDATE certificate SET certificate_type = '' WHERE uuid = '%s'"
                            .formatted(emptyTypeCertificateUuid));
            statement
                    .execute("UPDATE certificate SET certificate_type = 'SSH' WHERE uuid = '%s'"
                            .formatted(otherTypeCertificateUuid));
            statement
                    .execute("UPDATE certificate_request SET certificate_type = NULL WHERE uuid = '%s'"
                            .formatted(nullTypeRequestUuid));

            statement.execute(new ClassPathResource(MIGRATION_RESOURCE).getContentAsString(StandardCharsets.UTF_8));
        }

        typeOfNullTypeCertificate = columnOf("certificate", "certificate_type", nullTypeCertificateUuid);
        typeOfEmptyTypeCertificate = columnOf("certificate", "certificate_type", emptyTypeCertificateUuid);
        typeOfOtherTypeCertificate = columnOf("certificate", "certificate_type", otherTypeCertificateUuid);
        typeOfNullTypeRequest = columnOf("certificate_request", "certificate_type", nullTypeRequestUuid);
    }

    @Test
    void setsX509_whenCertificateTypeIsNull() {
        // given — a certificate whose type was null before the migration

        // when
        String type = typeOfNullTypeCertificate;

        // then
        assertThat(type).isEqualTo("X509");
    }

    @Test
    void setsX509_whenCertificateTypeIsEmpty() {
        // given — a certificate whose type was empty before the migration

        // when
        String type = typeOfEmptyTypeCertificate;

        // then
        assertThat(type).isEqualTo("X509");
    }

    @Test
    void setsX509_whenRequestTypeIsNull() {
        // given — a certificate request whose type was null before the migration

        // when
        String type = typeOfNullTypeRequest;

        // then
        assertThat(type).isEqualTo("X509");
    }

    @Test
    void keepsType_whenCertificateAlreadyHasOne() {
        // given — a certificate that already had another type before the migration

        // when
        String type = typeOfOtherTypeCertificate;

        // then
        assertThat(type).isEqualTo("SSH");
    }

    @Test
    void makesCertificateTypeNotNullWithDefault() throws Exception {
        // given — the migration has run

        // when
        String nullable = informationSchema("certificate", "certificate_type", "is_nullable");
        String columnDefault = informationSchema("certificate", "certificate_type", "column_default");

        // then
        assertThat(nullable).isEqualTo("NO");
        assertThat(columnDefault).contains("X509");
    }

    @Test
    void makesRequestTypeDefaultToX509() throws Exception {
        // given — the migration has run

        // when
        String columnDefault = informationSchema("certificate_request", "certificate_type", "column_default");

        // then
        assertThat(columnDefault).contains("X509");
    }

    @Test
    void allowsNullKeyUsage_onCertificateAndRequest() throws Exception {
        // given — key usage was NOT NULL before the migration

        // when
        String certificateNullable = informationSchema("certificate", "key_usage", "is_nullable");
        String requestNullable = informationSchema("certificate_request", "key_usage", "is_nullable");

        // then
        assertThat(certificateNullable).isEqualTo("YES");
        assertThat(requestNullable).isEqualTo("YES");
    }

    // ── Helpers ───────────────────────────────────────────────────────────────

    private String columnOf(String table, String column, UUID uuid) throws SQLException {
        try (Connection connection = dataSource.getConnection();
                Statement statement = connection.createStatement();
                ResultSet resultSet = statement
                        .executeQuery("SELECT %s FROM %s WHERE uuid = '%s'".formatted(column, table, uuid))) {
            resultSet.next();
            return resultSet.getString(1);
        }
    }

    private String informationSchema(String table, String column, String attribute) throws SQLException {
        try (Connection connection = dataSource.getConnection();
                Statement statement = connection.createStatement();
                ResultSet resultSet = statement.executeQuery(("""
                        SELECT %s FROM information_schema.columns
                            WHERE table_schema = current_schema() AND table_name = '%s' AND column_name = '%s'
                        """).formatted(attribute, table, column))) {
            resultSet.next();
            return resultSet.getString(1);
        }
    }
}
