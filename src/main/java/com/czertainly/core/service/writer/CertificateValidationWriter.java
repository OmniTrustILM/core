package com.czertainly.core.service.writer;

import com.czertainly.api.model.core.certificate.CertificateValidationStatus;
import com.czertainly.core.dao.repository.CertificateRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.OffsetDateTime;
import java.util.UUID;

/**
 * Writer bean for validation-result and OCSP-/CRL-driven state transitions on {@link com.czertainly.core.dao.entity.Certificate}.
 *
 * <p>Methods use the default propagation ({@code REQUIRED}) — they join an ambient transaction if one is active,
 * or open a new one if no ambient transaction exists.
 *
 * @see com.czertainly.core.service.CertificateService#validate(com.czertainly.core.dao.entity.Certificate)
 * @see com.czertainly.core.validation.certificate.X509CertificateValidator
 */
@Service
public class CertificateValidationWriter {

    private final CertificateRepository certificateRepository;

    @Autowired
    public CertificateValidationWriter(CertificateRepository certificateRepository) {
        this.certificateRepository = certificateRepository;
    }

    @Transactional
    public void applyValidationResult(UUID uuid,
                                      CertificateValidationStatus status,
                                      OffsetDateTime timestamp,
                                      String validationResultJson) {
        certificateRepository.updateValidationResult(uuid, status, timestamp, validationResultJson);
    }

    @Transactional
    public int markRevokedIfStillIssued(UUID uuid) {
        return certificateRepository.transitionIssuedToRevoked(uuid);
    }
}
