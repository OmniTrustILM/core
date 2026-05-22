package com.czertainly.core.service.writer;

import com.czertainly.core.dao.repository.CertificateRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.UUID;

/**
 * Writer bean for issuer-reference mutations on {@link com.czertainly.core.dao.entity.Certificate}.
 *
 * <p>Each public method is a short, side-effect-only transactional operation that delegates to a
 * targeted {@code @Modifying} query on {@link CertificateRepository}. The transactional boundary
 * lives here on the service side, not on the repository.</p>
 *
 * <p>Methods use the default propagation ({@code REQUIRED}) — they join an ambient transaction
 * if one is active, or open a new one if no ambient transaction exists (e.g. when reached from
 * a caller annotated {@code @Transactional(NOT_SUPPORTED)}, or from a context that has no
 * Spring-managed transaction at all). {@link com.czertainly.core.service.CertificateChainService}
 * carries no class-level annotation and inherits whatever its own caller provides; the writer's
 * commit therefore depends on that outer caller's propagation, not on the chain service itself.</p>
 *
 * <p>Must always be invoked across a bean boundary so the Spring proxy applies the
 * transactional advice. Self-invocation from within this bean (or its callers via {@code this.})
 * would silently skip the advice.</p>
 *
 * @see com.czertainly.core.service.CertificateChainService
 */
@Service
public class CertificateChainWriter {

    private final CertificateRepository certificateRepository;

    @Autowired
    public CertificateChainWriter(CertificateRepository certificateRepository) {
        this.certificateRepository = certificateRepository;
    }

    /**
     * Sets the issuer reference (serial number + UUID) on a certificate row by UUID.
     *
     * <p>AUDIT-BYPASS: i_upd refreshed in SQL; i_author intentionally not changed (system transition).</p>
     */
    @Transactional
    public void applyIssuerReference(UUID uuid, String issuerSerialNumber, UUID issuerCertificateUuid) {
        certificateRepository.updateIssuerReference(uuid, issuerSerialNumber, issuerCertificateUuid);
    }

    /**
     * Clears both issuer-serial-number and issuer-certificate-uuid on a certificate row by UUID.
     * Used by the chain orchestrator when a dangling FK is detected during chain reconstruction.
     *
     * <p>AUDIT-BYPASS: i_upd refreshed in SQL; i_author intentionally not changed (system transition).</p>
     */
    @Transactional
    public void clearIssuerReference(UUID uuid) {
        certificateRepository.clearIssuerReference(uuid);
    }
}
