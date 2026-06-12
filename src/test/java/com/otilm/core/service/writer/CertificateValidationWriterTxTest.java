package com.otilm.core.service.writer;

import com.otilm.api.model.core.certificate.CertificateState;
import com.otilm.api.model.core.certificate.CertificateValidationStatus;
import com.otilm.core.dao.entity.Certificate;
import com.otilm.core.dao.repository.CertificateRepository;
import com.otilm.core.util.BaseSpringBootTest;
import org.junit.jupiter.api.Test;
import org.springframework.aop.support.AopUtils;
import org.springframework.beans.factory.annotation.Autowired;

import java.time.OffsetDateTime;
import java.util.UUID;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

class CertificateValidationWriterTxTest extends BaseSpringBootTest {

    @Autowired
    private CertificateValidationWriter validationWriter;

    @Autowired
    private CertificateRepository certificateRepository;

    @Test
    void writerBeanIsASpringProxy() {
        assertTrue(AopUtils.isAopProxy(validationWriter),
                "CertificateValidationWriter must be a Spring AOP proxy so @Transactional advice is applied");
    }

    @Test
    void applyValidationResultPersistsFieldsAndRefreshesUpdated() {
        Certificate cert = persistMinimalCertificate();
        cert = certificateRepository.findByUuid(cert.getUuid()).orElseThrow();
        OffsetDateTime initialUpdated = cert.getUpdated();
        assertNotNull(initialUpdated, "fixture row must have a non-null updated timestamp after insert");

        OffsetDateTime ts = OffsetDateTime.now();
        validationWriter.applyValidationResult(cert.getUuid(), CertificateValidationStatus.FAILED, ts, "{\"k\":\"v\"}");

        Certificate reloaded = certificateRepository.findByUuid(cert.getUuid()).orElseThrow();
        assertEquals(CertificateValidationStatus.FAILED, reloaded.getValidationStatus());
        assertEquals("{\"k\":\"v\"}", reloaded.getCertificateValidationResult());
        assertNotNull(reloaded.getStatusValidationTimestamp());
        assertFalse(reloaded.getUpdated().isBefore(initialUpdated));
    }

    @Test
    void markRevokedIfStillIssuedTransitionsWhenStateIsIssued() {
        Certificate cert = persistMinimalCertificate();
        cert.setState(CertificateState.ISSUED);
        certificateRepository.save(cert);

        int rows = validationWriter.markRevokedIfStillIssued(cert.getUuid());

        assertEquals(1, rows, "exactly one row must transition ISSUED -> REVOKED");
        Certificate reloaded = certificateRepository.findByUuid(cert.getUuid()).orElseThrow();
        assertEquals(CertificateState.REVOKED, reloaded.getState());
    }

    @Test
    void markRevokedIfStillIssuedNoOpWhenStateAlreadyPendingRevoke() {
        Certificate cert = persistMinimalCertificate();
        cert.setState(CertificateState.PENDING_REVOKE);
        certificateRepository.save(cert);

        int rows = validationWriter.markRevokedIfStillIssued(cert.getUuid());

        assertEquals(0, rows, "rows updated must be 0 when state is not ISSUED");
        Certificate reloaded = certificateRepository.findByUuid(cert.getUuid()).orElseThrow();
        assertEquals(CertificateState.PENDING_REVOKE, reloaded.getState(),
                "state must remain PENDING_REVOKE — the conditional UPDATE must not overwrite it");
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
