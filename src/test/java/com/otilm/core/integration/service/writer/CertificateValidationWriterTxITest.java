package com.otilm.core.integration.service.writer;

import com.otilm.api.model.core.certificate.CertificateState;
import com.otilm.api.model.core.certificate.CertificateValidationStatus;
import com.otilm.core.dao.entity.Certificate;
import com.otilm.core.dao.repository.CertificateRepository;
import com.otilm.core.service.writer.CertificateValidationWriter;
import com.otilm.core.util.BaseSpringBootTest;
import org.junit.jupiter.api.Test;
import org.springframework.aop.support.AopUtils;
import org.springframework.beans.factory.annotation.Autowired;

import java.time.OffsetDateTime;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;

class CertificateValidationWriterTxITest extends BaseSpringBootTest {

    @Autowired
    private CertificateValidationWriter validationWriter;

    @Autowired
    private CertificateRepository certificateRepository;

    @Test
    void writerBeanIsASpringProxy() {
        assertThat(AopUtils.isAopProxy(validationWriter))
                .as("CertificateValidationWriter must be a Spring AOP proxy so @Transactional advice is applied")
                .isTrue();
    }

    @Test
    void applyValidationResultPersistsFieldsAndRefreshesUpdated() {
        Certificate cert = persistMinimalCertificate();
        cert = certificateRepository.findByUuid(cert.getUuid()).orElseThrow();
        OffsetDateTime initialUpdated = cert.getUpdated();
        assertThat(initialUpdated).as("fixture row must have a non-null updated timestamp after insert").isNotNull();

        OffsetDateTime ts = OffsetDateTime.now();
        validationWriter.applyValidationResult(cert.getUuid(), CertificateValidationStatus.FAILED, ts, "{\"k\":\"v\"}");

        Certificate reloaded = certificateRepository.findByUuid(cert.getUuid()).orElseThrow();
        assertThat(reloaded.getValidationStatus()).isEqualTo(CertificateValidationStatus.FAILED);
        assertThat(reloaded.getCertificateValidationResult()).isEqualTo("{\"k\":\"v\"}");
        assertThat(reloaded.getStatusValidationTimestamp()).isNotNull();
        assertThat(reloaded.getUpdated().isBefore(initialUpdated)).isFalse();
    }

    @Test
    void markRevokedIfStillIssuedTransitionsWhenStateIsIssued() {
        Certificate cert = persistMinimalCertificate();
        cert.setState(CertificateState.ISSUED);
        certificateRepository.save(cert);

        int rows = validationWriter.markRevokedIfStillIssued(cert.getUuid());

        assertThat(rows).as("exactly one row must transition ISSUED -> REVOKED").isEqualTo(1);
        Certificate reloaded = certificateRepository.findByUuid(cert.getUuid()).orElseThrow();
        assertThat(reloaded.getState()).isEqualTo(CertificateState.REVOKED);
    }

    @Test
    void markRevokedIfStillIssuedNoOpWhenStateAlreadyPendingRevoke() {
        Certificate cert = persistMinimalCertificate();
        cert.setState(CertificateState.PENDING_REVOKE);
        certificateRepository.save(cert);

        int rows = validationWriter.markRevokedIfStillIssued(cert.getUuid());

        assertThat(rows).as("rows updated must be 0 when state is not ISSUED").isZero();
        Certificate reloaded = certificateRepository.findByUuid(cert.getUuid()).orElseThrow();
        assertThat(reloaded.getState())
                .as("state must remain PENDING_REVOKE — the conditional UPDATE must not overwrite it")
                .isEqualTo(CertificateState.PENDING_REVOKE);
    }

    private Certificate persistMinimalCertificate() {
        Certificate cert = new Certificate();
        cert.setCommonName("validationWriterTxTest");
        cert.setSerialNumber(UUID.randomUUID().toString());
        cert.setFingerprint(UUID.randomUUID().toString());
        cert.setState(CertificateState.ISSUED);
        cert.setValidationStatus(CertificateValidationStatus.NOT_CHECKED);
        return certificateRepository.save(cert);
    }
}
