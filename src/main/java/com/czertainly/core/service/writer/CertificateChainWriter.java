package com.czertainly.core.service.writer;

import com.czertainly.core.dao.repository.CertificateRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.UUID;

/**
 * Writer bean for issuer-reference mutations on {@link com.czertainly.core.dao.entity.Certificate}.
 *
 * <p>Methods use the default propagation ({@code REQUIRED}) — they join an ambient transaction if one is active, or open
 * a new one if no ambient transaction exists.
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

    @Transactional
    public void applyIssuerReference(UUID uuid, String issuerSerialNumber, UUID issuerCertificateUuid) {
        certificateRepository.updateIssuerReference(uuid, issuerSerialNumber, issuerCertificateUuid);
    }

    @Transactional
    public void clearIssuerReference(UUID uuid) {
        certificateRepository.clearIssuerReference(uuid);
    }
}
