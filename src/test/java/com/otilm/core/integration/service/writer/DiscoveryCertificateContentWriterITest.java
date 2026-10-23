package com.otilm.core.integration.service.writer;

import com.otilm.api.model.core.certificate.CertificateState;
import com.otilm.api.model.core.certificate.CertificateType;
import com.otilm.api.model.core.certificate.CertificateValidationStatus;
import com.otilm.core.dao.entity.Certificate;
import com.otilm.core.dao.repository.CertificateContentRepository;
import com.otilm.core.dao.repository.CertificateRepository;
import com.otilm.core.service.writer.DiscoveryCertificateContentWriter;
import com.otilm.core.util.BaseSpringBootTest;
import java.time.OffsetDateTime;
import java.util.Arrays;
import java.util.List;
import java.util.UUID;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;

import static org.assertj.core.api.Assertions.assertThat;

class DiscoveryCertificateContentWriterITest extends BaseSpringBootTest {

    @Autowired
    private DiscoveryCertificateContentWriter writer;

    @Autowired
    private CertificateRepository certificateRepository;

    @Autowired
    private CertificateContentRepository certificateContentRepository;

    /** The insert is native SQL, so the list columns are bound by the query rather than by the entity mapping. */
    @Test
    void insertBindsListColumnsAsArrays() {
        List<List<String>> extendedKeyUsages = Arrays
                .asList(null, List.of(), List.of("1.3.6.1.5.5.7.3.1"),
                        List.of("1.3.6.1.5.5.7.3.1", "1.3.6.1.5.5.7.3.2", "1.2.3.4.5"));
        for (List<String> extendedKeyUsage : extendedKeyUsages) {
            Certificate certificate = discovered(extendedKeyUsage);
            assertThat(writer.insertCertificate(certificate)).isEqualTo(1);

            Certificate stored = certificateRepository.findByFingerprint(certificate.getFingerprint()).orElseThrow();
            assertThat(stored.getExtendedKeyUsage()).as("EKU %s", extendedKeyUsage).isEqualTo(extendedKeyUsage);
            assertThat(stored.getQcType()).isEqualTo(List.of("ESIGN", "ESEAL"));
            assertThat(stored.getQcCcLegislation()).isEqualTo(List.of("CZ"));
        }
    }

    private Certificate discovered(List<String> extendedKeyUsage) {
        String fingerprint = UUID.randomUUID().toString();
        writer.insertContent(fingerprint, "content-" + fingerprint);
        OffsetDateTime now = OffsetDateTime.now();
        Certificate certificate = new Certificate();
        certificate.setUuid(UUID.randomUUID());
        certificate.setCreated(now);
        certificate.setUpdated(now);
        certificate.setFingerprint(fingerprint);
        certificate.setCertificateContentId(certificateContentRepository.findByFingerprint(fingerprint).getId());
        certificate.setCertificateType(CertificateType.X509);
        certificate.setState(CertificateState.ISSUED);
        certificate.setValidationStatus(CertificateValidationStatus.NOT_CHECKED);
        certificate.setExtendedKeyUsage(extendedKeyUsage);
        certificate.setQcType(List.of("ESIGN", "ESEAL"));
        certificate.setQcCcLegislation(List.of("CZ"));
        return certificate;
    }
}
