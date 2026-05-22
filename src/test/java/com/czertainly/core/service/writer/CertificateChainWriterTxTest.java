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

/**
 * Verifies the {@link CertificateChainWriter} bean-pair contract.
 *
 * <p>Each writer method delegates to a {@code @Modifying} UPDATE on
 * {@link CertificateRepository}. Spring Data JPA throws
 * {@code TransactionRequiredException} if no transaction is active when an
 * {@code @Modifying} query runs. The successful side effect therefore proves
 * the writer's {@code @Transactional} advice was applied through the Spring
 * proxy — which is exactly the regression we want to guard against (a future
 * contributor moving a writer method into a sibling bean and self-invoking it
 * would bypass the proxy and surface here as a test failure).</p>
 *
 * <p>This test is also the reusable shape for the writer-tx assertions in
 * PR2 ({@code CertificateValidationWriter}) and PR3 ({@code CrlWriter}). See
 * {@code docs/superpowers/specs/2026-05-22-tx-boundary-refactor-design.md}
 * §"Writer-tx unit-test scaffolding".</p>
 */
class CertificateChainWriterTxTest extends BaseSpringBootTest {

    @Autowired
    private CertificateChainWriter chainWriter;

    @Autowired
    private CertificateRepository certificateRepository;

    @Test
    void writer_bean_is_a_spring_proxy() {
        // Sanity check: if this fails, no @Transactional advice can be applied —
        // the bean was injected as a raw class, not through the Spring proxy.
        assertTrue(AopUtils.isAopProxy(chainWriter),
                "CertificateChainWriter must be a Spring AOP proxy so that @Transactional advice is applied");
    }

    @Test
    void applyIssuerReference_persists_fields_and_refreshes_updated() {
        Certificate cert = persistMinimalCertificate();
        OffsetDateTime initialUpdated = cert.getUpdated();
        assertNotNull(initialUpdated, "fixture row must have a non-null updated timestamp after insert");

        UUID issuerUuid = UUID.randomUUID();
        chainWriter.applyIssuerReference(cert.getUuid(), "ABCDEF", issuerUuid);

        Certificate reloaded = certificateRepository.findByUuid(cert.getUuid()).orElseThrow();
        assertEquals("ABCDEF", reloaded.getIssuerSerialNumber());
        assertEquals(issuerUuid, reloaded.getIssuerCertificateUuid());
        // AUDIT-BYPASS contract: targeted UPDATE refreshes i_upd in SQL because it bypasses
        // the @UpdateTimestamp listener. Assert at least non-null and not regressed.
        assertNotNull(reloaded.getUpdated(), "updated must remain non-null after targeted UPDATE");
        assertFalse(reloaded.getUpdated().isBefore(initialUpdated),
                "AUDIT-BYPASS: updated must be refreshed (or equal) by the targeted UPDATE");
    }

    @Test
    void clearIssuerReference_nulls_both_issuer_fields() {
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
