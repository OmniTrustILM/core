package com.czertainly.core.service.writer;

import com.czertainly.core.dao.entity.Certificate;
import com.czertainly.core.dao.repository.CertificateRepository;
import com.czertainly.core.util.BaseSpringBootTest;
import org.junit.jupiter.api.Test;
import org.springframework.aop.support.AopUtils;
import org.springframework.beans.factory.annotation.Autowired;

import java.time.OffsetDateTime;
import java.util.UUID;

import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

class CertificateChainWriterTxTest extends BaseSpringBootTest {

    @Autowired
    private CertificateChainWriter chainWriter;

    @Autowired
    private CertificateRepository certificateRepository;

    @Test
    void writerBeanIsASpringProxy() {
        assertTrue(AopUtils.isAopProxy(chainWriter),
                "CertificateChainWriter must be a Spring AOP proxy so that @Transactional advice is applied");
    }

    @Test
    void applyIssuerReferencePersistsFieldsAndRefreshesUpdated() {
        Certificate cert = persistMinimalCertificate();
        // Reload from DB so initialUpdated reflects the DB-stored value.
        cert = certificateRepository.findByUuid(cert.getUuid()).orElseThrow();
        OffsetDateTime initialUpdated = cert.getUpdated();
        assertNotNull(initialUpdated, "fixture row must have a non-null updated timestamp after insert");

        UUID issuerUuid = UUID.randomUUID();
        chainWriter.applyIssuerReference(cert.getUuid(), "ABCDEF", issuerUuid);

        Certificate reloaded = certificateRepository.findByUuid(cert.getUuid()).orElseThrow();
        assertEquals("ABCDEF", reloaded.getIssuerSerialNumber());
        assertEquals(issuerUuid, reloaded.getIssuerCertificateUuid());
        assertNotNull(reloaded.getUpdated(), "updated must remain non-null after targeted UPDATE");
        assertFalse(reloaded.getUpdated().isBefore(initialUpdated));
    }

    @Test
    void clearIssuerReferenceNullsBothIssuerFields() {
        Certificate cert = persistMinimalCertificate();
        cert.setIssuerSerialNumber("ABCDEF");
        cert.setIssuerCertificateUuid(UUID.randomUUID());
        certificateRepository.save(cert);

        chainWriter.clearIssuerReference(cert.getUuid());

        Certificate reloaded = certificateRepository.findByUuid(cert.getUuid()).orElseThrow();
        assertNull(reloaded.getIssuerSerialNumber());
        assertNull(reloaded.getIssuerCertificateUuid());
    }

    private Certificate persistMinimalCertificate() {
        Certificate cert = new Certificate();
        cert.setCommonName("writerTxTest");
        cert.setSerialNumber(UUID.randomUUID().toString());
        cert.setFingerprint(UUID.randomUUID().toString());
        return certificateRepository.save(cert);
    }
}
