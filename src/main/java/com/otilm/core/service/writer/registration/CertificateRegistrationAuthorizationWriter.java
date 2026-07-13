package com.otilm.core.service.writer.registration;

import com.otilm.core.dao.repository.CertificateRegistrationAuthorizationRepository;
import org.springframework.stereotype.Component;
import org.springframework.transaction.annotation.Transactional;

import java.util.UUID;

/**
 * Short transactional writes against {@code certificate_registration_authorization} (repositories carry no
 * {@code @Transactional}). Methods are {@code REQUIRED} so they join an ambient transaction or open their own.
 */
@Component
public class CertificateRegistrationAuthorizationWriter {

    private final CertificateRegistrationAuthorizationRepository authorizationRepository;

    public CertificateRegistrationAuthorizationWriter(CertificateRegistrationAuthorizationRepository authorizationRepository) {
        this.authorizationRepository = authorizationRepository;
    }

    /** Removes the authorization for a certificate (idempotent) — used when a registration never became effective. */
    @Transactional
    public void deleteByCertificateUuid(UUID certificateUuid) {
        authorizationRepository.deleteByCertificateUuid(certificateUuid);
    }
}
