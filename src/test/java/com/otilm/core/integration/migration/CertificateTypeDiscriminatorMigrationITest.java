package com.otilm.core.integration.migration;

import com.otilm.core.dao.entity.X509CertificateRequestEntity;
import com.otilm.core.dao.repository.CertificateRepository;
import com.otilm.core.dao.repository.CertificateRequestRepository;
import com.otilm.core.util.builders.CertificateRequestEntityBuilder;
import java.nio.charset.StandardCharsets;
import java.sql.Connection;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import javax.sql.DataSource;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.core.io.ClassPathResource;

import static com.otilm.core.util.builders.CertificateBuilder.aCertificate;
import static org.assertj.core.api.Assertions.assertThat;

/**
 * Verifies the {@code V20261105100x__certificate_type_discriminator*.sql} migrations against rows seeded in the state
 * they repair, including an inventory several times larger than one backfill batch.
 */
class CertificateTypeDiscriminatorMigrationITest extends BaseMigrationTest {

    private static final List<String> MIGRATION_RESOURCES = List
            .of("db/migration/V202611051000__certificate_type_discriminator_backfill.sql",
                    "db/migration/V202611051001__certificate_type_discriminator_constraint.sql",
                    "db/migration/V202611051002__certificate_type_discriminator_validate.sql",
                    "db/migration/V202611051003__certificate_type_discriminator_not_null.sql");

    // a backfill batch holds 10,000 rows, so this takes two batches per table
    private static final int GENERATED_ROWS = 12_000;
    // columns a generated row cannot copy from its template, because they are the primary key or unique
    private static final Map<String, List<String>> UNIQUE_COLUMNS = Map
            .of("certificate", List.of("uuid", "certificate_content_id", "fingerprint"), "certificate_request",
                    List.of("uuid"));

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
    private long generatedCertificatesWithoutType;
    private long generatedRequestsWithoutType;
    private long certificatesTypedX509;
    private long requestsTypedX509;

    @BeforeAll
    void seedOldStateAndMigrate() throws Exception {
        UUID nullTypeCertificateUuid = certificateRepository.save(aCertificate().build()).getUuid();
        UUID emptyTypeCertificateUuid = certificateRepository.save(aCertificate().build()).getUuid();
        UUID otherTypeCertificateUuid = certificateRepository.save(aCertificate().build()).getUuid();
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

            generateRowsWithoutType(statement, "certificate", nullTypeCertificateUuid);
            generateRowsWithoutType(statement, "certificate_request", nullTypeRequestUuid);
            generatedCertificatesWithoutType = count(statement, "certificate", "certificate_type IS NULL");
            generatedRequestsWithoutType = count(statement, "certificate_request", "certificate_type IS NULL");

            for (String migration : MIGRATION_RESOURCES) {
                statement.execute(new ClassPathResource(migration).getContentAsString(StandardCharsets.UTF_8));
            }
        }

        try (Connection connection = dataSource.getConnection(); Statement statement = connection.createStatement()) {
            certificatesTypedX509 = count(statement, "certificate", "certificate_type = 'X509'");
            requestsTypedX509 = count(statement, "certificate_request", "certificate_type = 'X509'");
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
    void setsX509OnEveryRow_whenTheInventoryIsLargerThanOneBatch() {
        // given — more certificates and requests without a type than one backfill batch holds

        // when
        long certificates = certificatesTypedX509;
        long requests = requestsTypedX509;

        // then — every generated row, the seeded null and empty ones included, now has the type
        assertThat(generatedCertificatesWithoutType).isGreaterThan(GENERATED_ROWS);
        assertThat(certificates).isEqualTo(generatedCertificatesWithoutType + 1);
        assertThat(generatedRequestsWithoutType).isGreaterThan(GENERATED_ROWS);
        assertThat(requests).isEqualTo(generatedRequestsWithoutType);
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

    private void generateRowsWithoutType(Statement statement, String table, UUID templateUuid) throws SQLException {
        String columns = copiedColumns(statement, table);
        statement.execute(("""
                INSERT INTO %1$s (uuid, %2$s)
                    SELECT gen_random_uuid(), %2$s FROM %1$s, generate_series(1, %3$d) WHERE uuid = '%4$s'
                """).formatted(table, columns, GENERATED_ROWS, templateUuid));
    }

    private String copiedColumns(Statement statement, String table) throws SQLException {
        List<String> columns = new ArrayList<>();
        try (ResultSet resultSet = statement.executeQuery(("""
                SELECT column_name FROM information_schema.columns
                    WHERE table_schema = current_schema() AND table_name = '%s' ORDER BY ordinal_position
                """).formatted(table))) {
            while (resultSet.next()) {
                String column = resultSet.getString(1);
                if (!UNIQUE_COLUMNS.get(table).contains(column)) {
                    columns.add(column);
                }
            }
        }
        return String.join(", ", columns);
    }

    private long count(Statement statement, String table, String condition) throws SQLException {
        try (ResultSet resultSet = statement
                .executeQuery("SELECT count(*) FROM %s WHERE %s".formatted(table, condition))) {
            resultSet.next();
            return resultSet.getLong(1);
        }
    }

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
