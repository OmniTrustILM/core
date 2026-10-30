package com.otilm.core.service.writer.registration;

import com.otilm.core.dao.entity.CertificateRegistrationAuthorization;
import com.otilm.core.dao.entity.RegistrationState;
import com.otilm.core.dao.repository.CertificateRegistrationAuthorizationRepository;
import java.util.UUID;
import org.springframework.stereotype.Component;
import org.springframework.transaction.annotation.Transactional;

/**
 * Short transactional writes against {@code certificate_registration_authorization} (repositories carry no
 * {@code @Transactional}). Methods are {@code REQUIRED} so they join an ambient transaction or open their own.
 */
@Component
public class CertificateRegistrationAuthorizationWriter {

    private final CertificateRegistrationAuthorizationRepository authorizationRepository;

    public CertificateRegistrationAuthorizationWriter(
            CertificateRegistrationAuthorizationRepository authorizationRepository) {
        this.authorizationRepository = authorizationRepository;
    }

    /** Removes the authorization for a certificate (idempotent) — used when a registration never became effective. */
    @Transactional
    public void deleteByCertificateUuid(UUID certificateUuid) {
        authorizationRepository.deleteByCertificateUuid(certificateUuid);
    }

    /**
     * Retires the authorization (state → CLOSED) when its certificate reaches a terminal FAILED/REJECTED verdict, so a
     * dead placeholder no longer carries an ACTIVE registration. Idempotent (no-op when no row exists).
     */
    @Transactional
    public void close(UUID certificateUuid) {
        authorizationRepository.updateStateByCertificateUuid(certificateUuid, RegistrationState.CLOSED);
    }

    /**
     * Clears the issuance window (expiresAt to null) once the pre-registration's initial issuance completes: the
     * deadline governed only that first issuance, so an authorization retained for a later renew/rekey carries no stale
     * deadline — a passed window must never flip a still-live authorization to EXPIRED. State is left unchanged.
     * Idempotent (no-op when no row exists).
     */
    @Transactional
    public void clearIssuanceWindow(UUID certificateUuid) {
        authorizationRepository.clearIssuanceWindowByCertificateUuid(certificateUuid);
    }

    /**
     * Copies the predecessor certificate's registration authorization onto its renew/rekey successor, so the challenge
     * credential follows the certificate lineage without ever being decrypted: the ciphertext is reused verbatim, the
     * failed-attempt counter restarts at zero, and the issuance window carries over (null once the predecessor's first
     * issuance cleared it). Only an ACTIVE authorization is copied — a LOCKED/EXPIRED/CLOSED credential must not be
     * resurrected on the successor — and the predecessor's own row is left untouched. No-op when the predecessor
     * carries no authorization.
     *
     * <p>
     * Insert-only, deliberately not an upsert: the successor is freshly created in the same renew/rekey invocation, so
     * it can never legitimately carry a prior authorization row. If a caller ever points this at a certificate that
     * already has one — such as an operator-staged successor registration, whose challenge is independent of the
     * predecessor's by design — the unique constraint on {@code certificate_uuid} must fail the call loudly rather than
     * let a copy silently replace an operator-supplied credential.
     * </p>
     */
    @Transactional
    public void copyToSuccessor(UUID predecessorCertificateUuid, UUID successorCertificateUuid) {
        authorizationRepository
                .findByCertificateUuid(predecessorCertificateUuid)
                .filter(predecessor -> predecessor.getState() == RegistrationState.ACTIVE)
                .ifPresent(predecessor -> {
                    CertificateRegistrationAuthorization successor = new CertificateRegistrationAuthorization();
                    successor.setCertificateUuid(successorCertificateUuid);
                    successor.setChallenge(predecessor.getChallenge());
                    successor.setState(RegistrationState.ACTIVE);
                    successor.setFailedAttempts(0);
                    authorizationRepository.save(successor);
                });
    }
}
