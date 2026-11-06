package com.otilm.core.integration.service.writer;

import com.otilm.core.dao.entity.Certificate;
import com.otilm.core.dao.entity.X509CertificateEntity;
import com.otilm.core.dao.repository.CertificateRepository;
import com.otilm.core.service.writer.CertificateChainWriter;
import com.otilm.core.util.BaseSpringBootTest;
import java.time.OffsetDateTime;
import java.util.UUID;
import org.junit.jupiter.api.Test;
import org.springframework.aop.support.AopUtils;
import org.springframework.beans.factory.annotation.Autowired;

import static com.otilm.core.util.builders.CertificateBuilder.aCertificate;
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
    void persistsTheIssuerReferenceAndRefreshesUpdated_whenApplyingIt() {
        // given
        UUID certificateUuid = persistMinimalCertificate().getUuid();
        // Reload from DB so initialUpdated reflects the DB-stored value.
        OffsetDateTime initialUpdated = certificateRepository.findByUuid(certificateUuid).orElseThrow().getUpdated();
        assertThat(initialUpdated).as("fixture row must have a non-null updated timestamp after insert").isNotNull();
        String issuerSerialNumber = "ABCDEF";
        UUID issuerUuid = UUID.randomUUID();

        // when
        chainWriter.applyIssuerReference(certificateUuid, issuerSerialNumber, issuerUuid);

        // then
        X509CertificateEntity reloaded = X509CertificateEntity
                .from(certificateRepository.findByUuid(certificateUuid).orElseThrow());
        assertThat(reloaded.getIssuerSerialNumber()).isEqualTo(issuerSerialNumber);
        assertThat(reloaded.getIssuerCertificateUuid()).isEqualTo(issuerUuid);
        assertThat(reloaded.getUpdated()).as("updated must remain non-null after targeted UPDATE").isNotNull();
        assertThat(reloaded.getUpdated().isBefore(initialUpdated)).isFalse();
    }

    @Test
    void clearsBothIssuerFields_whenClearingTheIssuerReference() {
        // given
        X509CertificateEntity linked = X509CertificateEntity.from(persistMinimalCertificate());
        linked.setIssuerSerialNumber("ABCDEF");
        linked.setIssuerCertificateUuid(UUID.randomUUID());
        certificateRepository.save(linked);

        // when
        chainWriter.clearIssuerReference(linked.getUuid());

        // then
        X509CertificateEntity reloaded = X509CertificateEntity
                .from(certificateRepository.findByUuid(linked.getUuid()).orElseThrow());
        assertThat(reloaded.getIssuerSerialNumber()).isNull();
        assertThat(reloaded.getIssuerCertificateUuid()).isNull();
    }

    private Certificate persistMinimalCertificate() {
        X509CertificateEntity cert = aCertificate()
                .withCommonName("writerTxTest")
                .withSerialNumber(UUID.randomUUID().toString())
                .withFingerprint(UUID.randomUUID().toString())
                .build();
        return certificateRepository.save(cert);
    }
}
