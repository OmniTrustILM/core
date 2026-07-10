package com.otilm.core.integration.service.writer;

import com.otilm.core.dao.entity.Certificate;
import com.otilm.core.dao.repository.CertificateRepository;
import com.otilm.core.service.writer.CertificateChainWriter;
import com.otilm.core.util.BaseSpringBootTest;
import org.junit.jupiter.api.Test;
import org.springframework.aop.support.AopUtils;
import org.springframework.beans.factory.annotation.Autowired;

import java.time.OffsetDateTime;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;

class CertificateChainWriterTxITest extends BaseSpringBootTest {

    @Autowired
    private CertificateChainWriter chainWriter;

    @Autowired
    private CertificateRepository certificateRepository;

    @Test
    void writerBeanIsASpringProxy() {
        assertThat(AopUtils.isAopProxy(chainWriter))
                .as("CertificateChainWriter must be a Spring AOP proxy so that @Transactional advice is applied")
                .isTrue();
    }

    @Test
    void applyIssuerReferencePersistsFieldsAndRefreshesUpdated() {
        Certificate cert = persistMinimalCertificate();
        // Reload from DB so initialUpdated reflects the DB-stored value.
        cert = certificateRepository.findByUuid(cert.getUuid()).orElseThrow();
        OffsetDateTime initialUpdated = cert.getUpdated();
        assertThat(initialUpdated).as("fixture row must have a non-null updated timestamp after insert").isNotNull();

        UUID issuerUuid = UUID.randomUUID();
        chainWriter.applyIssuerReference(cert.getUuid(), "ABCDEF", issuerUuid);

        Certificate reloaded = certificateRepository.findByUuid(cert.getUuid()).orElseThrow();
        assertThat(reloaded.getIssuerSerialNumber()).isEqualTo("ABCDEF");
        assertThat(reloaded.getIssuerCertificateUuid()).isEqualTo(issuerUuid);
        assertThat(reloaded.getUpdated()).as("updated must remain non-null after targeted UPDATE").isNotNull();
        assertThat(reloaded.getUpdated().isBefore(initialUpdated)).isFalse();
    }

    @Test
    void clearIssuerReferenceNullsBothIssuerFields() {
        Certificate cert = persistMinimalCertificate();
        cert.setIssuerSerialNumber("ABCDEF");
        cert.setIssuerCertificateUuid(UUID.randomUUID());
        certificateRepository.save(cert);

        chainWriter.clearIssuerReference(cert.getUuid());

        Certificate reloaded = certificateRepository.findByUuid(cert.getUuid()).orElseThrow();
        assertThat(reloaded.getIssuerSerialNumber()).isNull();
        assertThat(reloaded.getIssuerCertificateUuid()).isNull();
    }

    private Certificate persistMinimalCertificate() {
        Certificate cert = new Certificate();
        cert.setCommonName("writerTxTest");
        cert.setSerialNumber(UUID.randomUUID().toString());
        cert.setFingerprint(UUID.randomUUID().toString());
        return certificateRepository.save(cert);
    }
}
