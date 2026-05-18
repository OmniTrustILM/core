package com.czertainly.core.migration;

import com.czertainly.core.dao.entity.Certificate;
import com.czertainly.core.dao.entity.CertificateContent;
import com.czertainly.core.dao.repository.CertificateContentRepository;
import com.czertainly.core.dao.repository.CertificateRepository;
import com.czertainly.core.util.CertificateTestUtil;
import com.czertainly.core.util.CertificateUtil;
import db.migration.V202604011901__BackfillExtendedKeyUsageCritical;
import org.flywaydb.core.api.migration.Context;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mockito;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.beans.factory.annotation.Autowired;

import javax.sql.DataSource;
import java.security.cert.X509Certificate;
import java.sql.Connection;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class BackfillExtendedKeyUsageCriticalTest extends BaseMigrationTest {

    @Autowired DataSource dataSource;
    @Autowired CertificateRepository certificateRepository;
    @Autowired CertificateContentRepository certificateContentRepository;

    @Test
    void migrate_setsCorrectCriticalityForCertsWithEku() throws Exception {
        // Certificates inserted with extended_key_usage_critical = NULL, simulating rows that
        // existed before V202604011901 ran (V202604011900 added the column with no default).
        Certificate tsaCritical    = persist(CertificateTestUtil.createTimestampingCertificate());
        Certificate tsaNonCritical = persist(CertificateTestUtil.createTimestampingCertificate(false));
        Certificate noEku          = persist(CertificateTestUtil.createCertificateWithoutEku());

        try (Connection conn = dataSource.getConnection()) {
            Context context = Mockito.mock(Context.class);
            when(context.getConnection()).thenReturn(conn);
            new V202604011901__BackfillExtendedKeyUsageCritical().migrate(context);
        }

        tsaCritical    = certificateRepository.findByUuid(tsaCritical.getUuid()).orElseThrow();
        tsaNonCritical = certificateRepository.findByUuid(tsaNonCritical.getUuid()).orElseThrow();
        noEku          = certificateRepository.findByUuid(noEku.getUuid()).orElseThrow();

        assertThat(tsaCritical.getExtendedKeyUsageCritical())
                .as("TSA cert with critical EKU must be backfilled to true")
                .isTrue();
        assertThat(tsaNonCritical.getExtendedKeyUsageCritical())
                .as("TSA cert with non-critical EKU must be backfilled to false")
                .isFalse();
        assertThat(noEku.getExtendedKeyUsageCritical())
                .as("Cert without EKU must remain null — criticality is not applicable")
                .isNull();
    }

    @Test
    void migrate_isIdempotent() throws Exception {
        Certificate tsaCritical    = persist(CertificateTestUtil.createTimestampingCertificate());
        Certificate tsaNonCritical = persist(CertificateTestUtil.createTimestampingCertificate(false));
        Certificate noEku          = persist(CertificateTestUtil.createCertificateWithoutEku());

        V202604011901__BackfillExtendedKeyUsageCritical migration = new V202604011901__BackfillExtendedKeyUsageCritical();
        try (Connection conn = dataSource.getConnection()) {
            Context context = Mockito.mock(Context.class);
            when(context.getConnection()).thenReturn(conn);
            migration.migrate(context);
            migration.migrate(context); // second run must leave already-set values untouched
        }

        assertThat(certificateRepository.findByUuid(tsaCritical.getUuid()).orElseThrow().getExtendedKeyUsageCritical())
                .as("second run must not overwrite true")
                .isTrue();
        assertThat(certificateRepository.findByUuid(tsaNonCritical.getUuid()).orElseThrow().getExtendedKeyUsageCritical())
                .as("second run must not overwrite false")
                .isFalse();
        assertThat(certificateRepository.findByUuid(noEku.getUuid()).orElseThrow().getExtendedKeyUsageCritical())
                .as("second run must not set criticality on certs without EKU")
                .isNull();
    }

    // --- helper ---

    private Certificate persist(X509Certificate x509) throws Exception {
        String pem = CertificateUtil.normalizeCertificateContent(
                java.util.Base64.getEncoder().encodeToString(x509.getEncoded()));
        CertificateContent content = new CertificateContent();
        content.setFingerprint(CertificateUtil.getThumbprint(x509));
        content.setContent(pem);
        certificateContentRepository.save(content);

        Certificate cert = new Certificate();
        CertificateUtil.prepareIssuedCertificate(cert, x509);
        cert.setExtendedKeyUsageCritical(null); // simulate pre-migration state
        cert.setCertificateContent(content);
        return certificateRepository.save(cert);
    }
}
