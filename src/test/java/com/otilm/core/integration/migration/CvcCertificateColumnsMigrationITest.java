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
import java.util.UUID;
import javax.sql.DataSource;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.core.io.ClassPathResource;

import static com.otilm.core.util.builders.CertificateBuilder.aCertificate;
import static org.assertj.core.api.Assertions.assertThat;

/**
 * Verifies {@code V202611261000__cvc_certificate_columns.sql} against rows seeded before the columns existed.
 */
class CvcCertificateColumnsMigrationITest extends BaseMigrationTest {

    private static final String MIGRATION_RESOURCE = "db/migration/V202611261000__cvc_certificate_columns.sql";
    private static final String SUBJECT_DN = "CN=before-the-columns";

    @Autowired
    DataSource dataSource;
    @Autowired
    CertificateRepository certificateRepository;
    @Autowired
    CertificateRequestRepository certificateRequestRepository;

    // Read inside @BeforeAll: the base test class empties the tables before every test.
    private String subjectDnAfter;
    private String holderReferenceAfter;
    private String requestSubjectDnAfter;
    private String requestHolderReferenceAfter;
    private long cvcRowsAfterInsert;

    @BeforeAll
    void seedOldStateAndMigrate() throws Exception {
        UUID certificateUuid = certificateRepository.save(aCertificate().withSubjectDn(SUBJECT_DN).build()).getUuid();
        X509CertificateRequestEntity request = CertificateRequestEntityBuilder
                .aCertificateRequest()
                .withContent("content")
                .withSubjectDn(SUBJECT_DN)
                .build();
        UUID requestUuid = certificateRequestRepository.save(request).getUuid();

        try (Connection connection = dataSource.getConnection(); Statement statement = connection.createStatement()) {
            // the test schema is generated from the entities, so it already has the columns this migration adds
            statement
                    .execute("ALTER TABLE certificate DROP COLUMN holder_reference, DROP COLUMN authority_reference, "
                            + "DROP COLUMN role, DROP COLUMN access_rights");
            statement
                    .execute("ALTER TABLE certificate_request DROP COLUMN holder_reference, "
                            + "DROP COLUMN authority_reference");
            statement.execute(loadMigrationScript());

            statement
                    .execute(("INSERT INTO certificate (uuid, certificate_type, holder_reference, authority_reference, "
                            + "role, access_rights, fingerprint, subject_type, hybrid_certificate, archived, compliance_status, "
                            + "i_cre, i_upd) VALUES ('%s', 'CVC', 'SEILMTERM00001', 'SEILMDV00001', 'terminal', '03', "
                            + "'cvc-fingerprint', 'END_ENTITY', false, false, 'NOT_CHECKED', now(), now())")
                            .formatted(UUID.randomUUID()));
            cvcRowsAfterInsert = count(statement, "certificate", "certificate_type = 'CVC'");
        }

        subjectDnAfter = columnOf("certificate", "subject_dn", certificateUuid);
        holderReferenceAfter = columnOf("certificate", "holder_reference", certificateUuid);
        requestSubjectDnAfter = columnOf("certificate_request", "subject_dn", requestUuid);
        requestHolderReferenceAfter = columnOf("certificate_request", "holder_reference", requestUuid);
    }

    @Test
    void keepsAnX509Certificate_whenTheColumnsAreAdded() {
        // given — an X.509 certificate stored before the migration

        // when
        String subjectDn = subjectDnAfter;

        // then
        assertThat(subjectDn).isEqualTo(SUBJECT_DN);
        assertThat(holderReferenceAfter).isNull();
    }

    @Test
    void keepsAnX509Request_whenTheColumnsAreAdded() {
        // given — an X.509 request stored before the migration

        // when
        String subjectDn = requestSubjectDnAfter;

        // then
        assertThat(subjectDn).isEqualTo(SUBJECT_DN);
        assertThat(requestHolderReferenceAfter).isNull();
    }

    @Test
    void storesACvcCertificateWithItsFields_whenTheColumnsAreAdded() {
        // given — a CVC row inserted after the migration

        // when
        long cvcRows = cvcRowsAfterInsert;

        // then
        assertThat(cvcRows).isEqualTo(1);
    }

    private String loadMigrationScript() throws Exception {
        return new ClassPathResource(MIGRATION_RESOURCE)
                .getContentAsString(StandardCharsets.UTF_8)
                .replace("${flyway:defaultSchema}", dbSchema);
    }

    private static long count(Statement statement, String table, String condition) throws SQLException {
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
}
