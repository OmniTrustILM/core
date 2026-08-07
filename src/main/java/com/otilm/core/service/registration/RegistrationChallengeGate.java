package com.otilm.core.service.registration;

import com.otilm.api.exception.ValidationError;
import com.otilm.api.exception.ValidationException;
import com.otilm.api.model.core.certificate.CertificateEvent;
import com.otilm.api.model.core.certificate.CertificateEventStatus;
import com.otilm.api.model.core.settings.CertificateRegistrationSettingsDto;
import com.otilm.api.model.core.settings.PlatformSettingsDto;
import com.otilm.api.model.core.settings.SettingsSection;
import com.otilm.core.dao.entity.CertificateRegistrationAuthorization;
import com.otilm.core.dao.entity.RegistrationState;
import com.otilm.core.dao.repository.CertificateRegistrationAuthorizationRepository;
import com.otilm.core.service.CertificateEventHistoryInternalService;
import com.otilm.core.settings.SettingsCache;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import org.springframework.transaction.PlatformTransactionManager;
import org.springframework.transaction.TransactionDefinition;
import org.springframework.transaction.TransactionStatus;
import org.springframework.transaction.support.DefaultTransactionDefinition;

import java.time.OffsetDateTime;
import java.time.ZoneOffset;
import java.util.function.Predicate;
import java.util.UUID;

/**
 * Challenge gate for completing a pre-registered certificate, shared by the client-operations completion
 * path and protocol enrolments. A certificate with no authorization row is not self-service and passes
 * untouched. On an ACTIVE authorization it enforces, under a per-row pessimistic lock, the issuance window
 * then the presented challenge; LOCKED/EXPIRED deny; CLOSED passes as unregistered. The failed-attempt
 * increment and lockout are committed before the caller rejects the request, so the counter survives the
 * rejection — a rollback would erase it and lockout could never trigger.
 *
 * <p>Two verification forms share one locked evaluator: an equality form for a presented secret string
 * (the plaintext never leaves {@link RegistrationChallengeStore}), and a predicate form whose caller
 * decides whether the resolved plaintext satisfies the request (CMP: whether the message MAC verifies
 * under it).
 */
@Service
public class RegistrationChallengeGate {

    private PlatformTransactionManager transactionManager;
    private CertificateRegistrationAuthorizationRepository registrationAuthorizationRepository;
    private RegistrationChallengeStore registrationChallengeStore;
    private CertificateEventHistoryInternalService certificateEventHistoryService;

    @Autowired
    public void setTransactionManager(PlatformTransactionManager transactionManager) {
        this.transactionManager = transactionManager;
    }

    @Autowired
    public void setRegistrationAuthorizationRepository(CertificateRegistrationAuthorizationRepository registrationAuthorizationRepository) {
        this.registrationAuthorizationRepository = registrationAuthorizationRepository;
    }

    @Autowired
    public void setRegistrationChallengeStore(RegistrationChallengeStore registrationChallengeStore) {
        this.registrationChallengeStore = registrationChallengeStore;
    }

    @Autowired
    public void setCertificateEventHistoryService(CertificateEventHistoryInternalService certificateEventHistoryService) {
        this.certificateEventHistoryService = certificateEventHistoryService;
    }

    /**
     * Verifies a presented registration challenge string by equality. Denials (locked, expired window,
     * wrong challenge) throw a {@link ValidationException}; the audit trail records the failure under
     * {@code operationEvent}.
     *
     * @return {@code true} when an ACTIVE authorization's challenge verified — the self-service credential
     * that stands in for the caller's operator permission on the completion write
     */
    public boolean verify(UUID certificateUuid, String presentedSecret, CertificateEvent operationEvent) {
        return verifyInternal(certificateUuid, operationEvent,
                authorization -> registrationChallengeStore.verify(authorization, presentedSecret));
    }

    /**
     * Verifies the registration challenge via a caller-supplied predicate applied to the resolved plaintext
     * (e.g. CMP: does the message MAC verify under this key). Semantics otherwise identical to the equality
     * form — same state cascade, lockout, and event history.
     */
    public boolean verify(UUID certificateUuid, CertificateEvent operationEvent, Predicate<String> secretMatches) {
        return verifyInternal(certificateUuid, operationEvent,
                authorization -> secretMatches.test(registrationChallengeStore.resolvePlaintext(authorization)));
    }

    private boolean verifyInternal(UUID certificateUuid, CertificateEvent operationEvent,
                                   Predicate<CertificateRegistrationAuthorization> matches) {
        if (registrationAuthorizationRepository.findByCertificateUuid(certificateUuid).isEmpty()) {
            return false;
        }
        RegistrationChallengeOutcome outcome = evaluateUnderLock(certificateUuid, operationEvent, matches);
        if (outcome.denial() != null) {
            throw new ValidationException(ValidationError.create(outcome.denial()));
        }
        return outcome.challengeVerified();
    }

    /**
     * Result of the registration-challenge gate: a denial reason, or — when the request passes — whether it passed
     * because an ACTIVE challenge verified, as opposed to the certificate simply not being challenge-protected.
     */
    private record RegistrationChallengeOutcome(String denial, boolean challengeVerified) {

        private static RegistrationChallengeOutcome notChallengeProtected() {
            return new RegistrationChallengeOutcome(null, false);
        }

        private static RegistrationChallengeOutcome verified() {
            return new RegistrationChallengeOutcome(null, true);
        }

        private static RegistrationChallengeOutcome denied(String reason) {
            return new RegistrationChallengeOutcome(reason, false);
        }
    }

    private RegistrationChallengeOutcome evaluateUnderLock(UUID certificateUuid, CertificateEvent operationEvent,
                                                           Predicate<CertificateRegistrationAuthorization> matches) {
        // REQUIRES_NEW so the row lock, the failed-attempt increment and the lockout commit in their own
        // short transaction and the lock is released on return — never held across an ambient transaction.
        // A caller can hold a row lock the completion (issueExistingCertificate, NOT_SUPPORTED) would then
        // re-acquire on a suspended transaction and self-deadlock; a fresh transaction here prevents that and
        // also guarantees the counter survives a caller rollback.
        DefaultTransactionDefinition definition = new DefaultTransactionDefinition();
        definition.setPropagationBehavior(TransactionDefinition.PROPAGATION_REQUIRES_NEW);
        TransactionStatus tx = transactionManager.getTransaction(definition);
        try {
            RegistrationChallengeOutcome outcome = registrationAuthorizationRepository.findAndLockByCertificateUuid(certificateUuid)
                    .map(authorization -> evaluateLockedAuthorization(authorization, operationEvent, matches))
                    // Raced with a delete/close between the peek and the lock — treat as non-self-service.
                    .orElseGet(RegistrationChallengeOutcome::notChallengeProtected);
            transactionManager.commit(tx);
            return outcome;
        } catch (RuntimeException e) {
            transactionManager.rollback(tx);
            throw e;
        }
    }

    private RegistrationChallengeOutcome evaluateLockedAuthorization(CertificateRegistrationAuthorization authorization,
                                                                     CertificateEvent operationEvent,
                                                                     Predicate<CertificateRegistrationAuthorization> matches) {
        UUID certificateUuid = authorization.getCertificateUuid();
        RegistrationState state = authorization.getState();
        if (state == RegistrationState.CLOSED) {
            return RegistrationChallengeOutcome.notChallengeProtected();
        }
        if (state == RegistrationState.LOCKED) {
            // Record every attempt against an already-locked authorization — persistent hammering is exactly when
            // the audit trail matters most.
            certificateEventHistoryService.addEventHistory(certificateUuid, operationEvent, CertificateEventStatus.FAILED,
                    "Certificate registration challenge attempted against a locked authorization", "");
            return RegistrationChallengeOutcome.denied("The certificate registration authorization is locked after too many failed attempts.");
        }
        if (state == RegistrationState.EXPIRED) {
            return RegistrationChallengeOutcome.denied("The certificate registration issuance window has expired.");
        }
        OffsetDateTime expiresAt = authorization.getExpiresAt();
        if (expiresAt != null && !OffsetDateTime.now(ZoneOffset.UTC).isBefore(expiresAt)) {
            authorization.setState(RegistrationState.EXPIRED);
            registrationAuthorizationRepository.save(authorization);
            certificateEventHistoryService.addEventHistory(certificateUuid, operationEvent, CertificateEventStatus.FAILED,
                    "Certificate registration issuance window expired", "");
            return RegistrationChallengeOutcome.denied("The certificate registration issuance window has expired.");
        }
        if (matches.test(authorization)) {
            if (authorization.getFailedAttempts() != 0) {
                authorization.setFailedAttempts(0);
                registrationAuthorizationRepository.save(authorization);
            }
            return RegistrationChallengeOutcome.verified();
        }
        int attempts = authorization.getFailedAttempts() + 1;
        authorization.setFailedAttempts(attempts);
        if (attempts >= maxFailedAttempts()) {
            authorization.setState(RegistrationState.LOCKED);
        }
        registrationAuthorizationRepository.save(authorization);
        certificateEventHistoryService.addEventHistory(certificateUuid, operationEvent, CertificateEventStatus.FAILED,
                "Certificate registration challenge verification failed (attempt %d)".formatted(attempts), "");
        return RegistrationChallengeOutcome.denied("The certificate registration challenge is invalid.");
    }

    // The fallback uses the single canonical default (the value the settings API reports and persists) so
    // the value applied on a cache miss cannot drift from the operator-visible default.
    private static int maxFailedAttempts() {
        PlatformSettingsDto platformSettings = SettingsCache.getSettings(SettingsSection.PLATFORM);
        CertificateRegistrationSettingsDto settings = platformSettings != null && platformSettings.getCertificates() != null
                ? platformSettings.getCertificates().getRegistration() : null;
        return settings != null && settings.getMaxFailedAttempts() != null
                ? settings.getMaxFailedAttempts() : CertificateRegistrationDefaults.MAX_FAILED_ATTEMPTS;
    }
}
