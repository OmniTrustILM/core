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
    private long sharedKeyRows;
    private UUID cvcUuid;
    private UUID cvcRequestUuid;
    private String cvcHolderReference;
    private String cvcAuthorityReference;
    private String cvcRole;
    private String cvcTerminalType;
    private String cvcAccessRights;
    private String cvcRequestHolderReference;
    private String cvcRequestAuthorityReference;
    private String cvcRequestAuthenticatedBy;

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
                            + "DROP COLUMN role, DROP COLUMN terminal_type, DROP COLUMN access_rights");
            statement
                    .execute("ALTER TABLE certificate_request DROP COLUMN holder_reference, "
                            + "DROP COLUMN authority_reference, DROP COLUMN authenticated_by");
            statement.execute(loadMigrationScript());

            cvcUuid = UUID.randomUUID();
            insertCvcCertificate(statement, cvcUuid, "cvc-fingerprint", "key-1");
            insertCvcCertificate(statement, UUID.randomUUID(), "link-fingerprint", "key-2");
            insertCvcCertificate(statement, UUID.randomUUID(), "same-key-fingerprint", "key-2");
            cvcRowsAfterInsert = count(statement, "certificate", "certificate_type = 'CVC'");
            sharedKeyRows = count(statement, "certificate",
                    "holder_reference = 'SEILMTERM00001' AND public_key_fingerprint = 'key-2'");

            cvcRequestUuid = UUID.randomUUID();
            statement
                    .execute(("INSERT INTO certificate_request (uuid, certificate_type, holder_reference, "
                            + "authority_reference, authenticated_by, content, certificate_request_format, "
                            + "compliance_status, fingerprint, i_cre, i_upd) VALUES ('%s', 'CVC', 'SEILMTERM00004', "
                            + "'SEILMDV00001', 'SEILMTERM00002', 'AAAA', 'CVC', 'NOT_CHECKED', 'request-fingerprint', "
                            + "now(), now())").formatted(cvcRequestUuid));
        }

        subjectDnAfter = readColumn("certificate", "subject_dn", certificateUuid);
        holderReferenceAfter = readColumn("certificate", "holder_reference", certificateUuid);
        requestSubjectDnAfter = readColumn("certificate_request", "subject_dn", requestUuid);
        requestHolderReferenceAfter = readColumn("certificate_request", "holder_reference", requestUuid);
        cvcHolderReference = readColumn("certificate", "holder_reference", cvcUuid);
        cvcAuthorityReference = readColumn("certificate", "authority_reference", cvcUuid);
        cvcRole = readColumn("certificate", "role", cvcUuid);
        cvcTerminalType = readColumn("certificate", "terminal_type", cvcUuid);
        cvcAccessRights = readColumn("certificate", "access_rights", cvcUuid);
        cvcRequestHolderReference = readColumn("certificate_request", "holder_reference", cvcRequestUuid);
        cvcRequestAuthorityReference = readColumn("certificate_request", "authority_reference", cvcRequestUuid);
        cvcRequestAuthenticatedBy = readColumn("certificate_request", "authenticated_by", cvcRequestUuid);
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
        assertThat(cvcRows).isEqualTo(3);
        assertThat(cvcHolderReference).isEqualTo("SEILMTERM00001");
        assertThat(cvcAuthorityReference).isEqualTo("SEILMDV00001");
        assertThat(cvcRole).isEqualTo("terminal");
        assertThat(cvcTerminalType).isEqualTo("0.4.0.127.0.7.3.1.2.2");
        assertThat(cvcAccessRights).isEqualTo("03");
    }

    @Test
    void storesACvcRequestWithBothReferences_whenTheColumnsAreAdded() {
        // given — a CVC request inserted after the migration

        // when
        String holderReference = cvcRequestHolderReference;

        // then
        assertThat(holderReference).isEqualTo("SEILMTERM00004");
        assertThat(cvcRequestAuthorityReference).isEqualTo("SEILMDV00001");
        assertThat(cvcRequestAuthenticatedBy).isEqualTo("SEILMTERM00002");
    }

    @Test
    void storesCertificatesThatShareAHolderReferenceAndAKey_whenTheirFingerprintsDiffer() {
        // given — two CVC certificates with the holder reference and public key of a link certificate

        // when
        long rows = sharedKeyRows;

        // then
        assertThat(rows).isEqualTo(2);
    }

    // ── Helpers ───────────────────────────────────────────────────────────────

    private String loadMigrationScript() throws Exception {
        return new ClassPathResource(MIGRATION_RESOURCE).getContentAsString(StandardCharsets.UTF_8);
    }

    private static void insertCvcCertificate(Statement statement, UUID uuid, String fingerprint,
            String publicKeyFingerprint) throws SQLException {
        statement
                .execute(("INSERT INTO certificate (uuid, certificate_type, holder_reference, authority_reference, "
                        + "role, terminal_type, access_rights, fingerprint, public_key_fingerprint, subject_type, "
                        + "hybrid_certificate, archived, compliance_status, i_cre, i_upd) VALUES ('%s', 'CVC', "
                        + "'SEILMTERM00001', 'SEILMDV00001', 'terminal', '0.4.0.127.0.7.3.1.2.2', '03', '%s', '%s', "
                        + "'END_ENTITY', false, false, 'NOT_CHECKED', now(), now())")
                        .formatted(uuid, fingerprint, publicKeyFingerprint));
    }

    private static long count(Statement statement, String table, String condition) throws SQLException {
        try (ResultSet resultSet = statement
                .executeQuery("SELECT count(*) FROM %s WHERE %s".formatted(table, condition))) {
            resultSet.next();
            return resultSet.getLong(1);
        }
    }

    private String readColumn(String table, String column, UUID uuid) throws SQLException {
        try (Connection connection = dataSource.getConnection();
                Statement statement = connection.createStatement();
                ResultSet resultSet = statement
                        .executeQuery("SELECT %s FROM %s WHERE uuid = '%s'".formatted(column, table, uuid))) {
            resultSet.next();
            return resultSet.getString(1);
        }
    }
}
