package com.otilm.core.integration.migration;

import com.otilm.core.dao.entity.Certificate;
import com.otilm.core.dao.entity.CertificateContent;
import com.otilm.core.dao.entity.X509CertificateEntity;
import com.otilm.core.dao.repository.CertificateContentRepository;
import com.otilm.core.dao.repository.CertificateRepository;
import com.otilm.core.util.CertificateTestUtil;
import com.otilm.core.util.CertificateUtil;
import db.migration.V202604011901__BackfillExtendedKeyUsageCritical;
import java.security.cert.X509Certificate;
import java.sql.Connection;
import javax.sql.DataSource;
import org.flywaydb.core.api.migration.Context;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mockito;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.beans.factory.annotation.Autowired;

import static com.otilm.core.util.builders.CertificateBuilder.aCertificate;
import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class BackfillExtendedKeyUsageCriticalITest extends BaseMigrationTest {

    @Autowired
    DataSource dataSource;
    @Autowired
    CertificateRepository certificateRepository;
    @Autowired
    CertificateContentRepository certificateContentRepository;

    @Test
    void migrate_setsCorrectCriticalityForCertsWithEku() throws Exception {
        // Certificates inserted with extended_key_usage_critical = NULL, simulating rows that
        // existed before V202604011901 ran (V202604011900 added the column with no default).
        X509CertificateEntity tsaCritical = X509CertificateEntity
                .from(persist(CertificateTestUtil.createTimestampingCertificate()));
        X509CertificateEntity tsaNonCritical = X509CertificateEntity
                .from(persist(CertificateTestUtil.createTimestampingCertificate(false)));
        X509CertificateEntity noEku = X509CertificateEntity
                .from(persist(CertificateTestUtil.createCertificateWithoutEku()));

        try (Connection conn = dataSource.getConnection()) {
            Context context = Mockito.mock(Context.class);
            when(context.getConnection()).thenReturn(conn);
            new V202604011901__BackfillExtendedKeyUsageCritical().migrate(context);
        }

        tsaCritical = X509CertificateEntity.from(certificateRepository.findByUuid(tsaCritical.getUuid()).orElseThrow());
        tsaNonCritical = X509CertificateEntity
                .from(certificateRepository.findByUuid(tsaNonCritical.getUuid()).orElseThrow());
        noEku = X509CertificateEntity.from(certificateRepository.findByUuid(noEku.getUuid()).orElseThrow());

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
        X509CertificateEntity tsaCritical = X509CertificateEntity
                .from(persist(CertificateTestUtil.createTimestampingCertificate()));
        X509CertificateEntity tsaNonCritical = X509CertificateEntity
                .from(persist(CertificateTestUtil.createTimestampingCertificate(false)));
        X509CertificateEntity noEku = X509CertificateEntity
                .from(persist(CertificateTestUtil.createCertificateWithoutEku()));

        V202604011901__BackfillExtendedKeyUsageCritical migration = new V202604011901__BackfillExtendedKeyUsageCritical();
        try (Connection conn = dataSource.getConnection()) {
            Context context = Mockito.mock(Context.class);
            when(context.getConnection()).thenReturn(conn);
            migration.migrate(context);
            migration.migrate(context); // second run must leave already-set values untouched
        }

        assertThat(reloadExtendedKeyUsageCritical(tsaCritical)).as("second run must not overwrite true").isTrue();
        assertThat(reloadExtendedKeyUsageCritical(tsaNonCritical)).as("second run must not overwrite false").isFalse();
        assertThat(reloadExtendedKeyUsageCritical(noEku))
                .as("second run must not set criticality on certs without EKU")
                .isNull();
    }

    // --- helper ---

    private Certificate persist(X509Certificate x509) throws Exception {
        String pem = CertificateUtil
                .normalizeCertificateContent(java.util.Base64.getEncoder().encodeToString(x509.getEncoded()));
        CertificateContent content = new CertificateContent();
        content.setFingerprint(CertificateUtil.getThumbprint(x509));
        content.setContent(pem);
        certificateContentRepository.save(content);

        X509CertificateEntity cert = aCertificate().build();
        CertificateUtil.prepareIssuedCertificate(cert, x509);
        cert.setExtendedKeyUsageCritical(null); // simulate pre-migration state
        cert.setCertificateContent(content);
        return certificateRepository.save(cert);
    }

    private Boolean reloadExtendedKeyUsageCritical(Certificate certificate) {
        return X509CertificateEntity
                .from(certificateRepository.findByUuid(certificate.getUuid()).orElseThrow())
                .getExtendedKeyUsageCritical();
    }
}
