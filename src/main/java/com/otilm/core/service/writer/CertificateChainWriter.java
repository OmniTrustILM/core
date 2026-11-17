package com.otilm.core.service.writer;

import com.otilm.core.dao.entity.Certificate;
import com.otilm.core.dao.repository.X509CertificateRepository;
import com.otilm.core.service.CertificateChainService;
import java.util.UUID;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

/**
 * Writer bean for issuer-reference mutations on {@link Certificate}.
 *
 * <p>
 * Methods use the default propagation ({@code REQUIRED}) — they join an ambient transaction if one is active, or open a
 * new one if no ambient transaction exists.
 *
 * @see CertificateChainService
 */
@Service
public class CertificateChainWriter {

    private final X509CertificateRepository x509CertificateRepository;

    @Autowired
    public CertificateChainWriter(X509CertificateRepository x509CertificateRepository) {
        this.x509CertificateRepository = x509CertificateRepository;
    }

    @Transactional
    public void applyIssuerReference(UUID uuid, String issuerSerialNumber, UUID issuerCertificateUuid) {
        x509CertificateRepository.updateIssuerReference(uuid, issuerSerialNumber, issuerCertificateUuid);
    }

    @Transactional
    public void clearIssuerReference(UUID uuid) {
        x509CertificateRepository.clearIssuerReference(uuid);
    }
}
