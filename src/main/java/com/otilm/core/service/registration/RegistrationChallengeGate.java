package com.otilm.core.service.registration;

import com.otilm.api.exception.ValidationError;
import com.otilm.api.exception.ValidationException;
import com.otilm.api.model.core.certificate.CertificateEvent;
import com.otilm.api.model.core.certificate.CertificateEventStatus;
import com.otilm.api.model.core.logging.Sensitive;
import com.otilm.api.model.core.settings.CertificateRegistrationSettingsDto;
import com.otilm.api.model.core.settings.PlatformSettingsDto;
import com.otilm.api.model.core.settings.SettingsSection;
import com.otilm.core.dao.entity.CertificateRegistrationAuthorization;
import com.otilm.core.dao.entity.RegistrationState;
import com.otilm.core.dao.repository.CertificateRegistrationAuthorizationRepository;
import com.otilm.core.service.CertificateEventHistoryInternalService;
import com.otilm.core.settings.SettingsCache;
import java.time.OffsetDateTime;
import java.time.ZoneOffset;
import java.util.UUID;
import java.util.function.Predicate;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import org.springframework.transaction.PlatformTransactionManager;
import org.springframework.transaction.TransactionDefinition;
import org.springframework.transaction.TransactionStatus;
import org.springframework.transaction.support.DefaultTransactionDefinition;

/**
 * Challenge gate for completing a pre-registered certificate, shared by the client-operations completion path and
 * protocol enrolments. A certificate with no authorization row is not self-service and passes untouched. On an ACTIVE
 * authorization it enforces, under a per-row pessimistic lock, the issuance window then the presented challenge;
 * LOCKED/EXPIRED deny; CLOSED passes as unregistered. A wrong challenge is counted toward lockout; a missing one is
 * denied as missing and not counted. The failed-attempt increment and lockout are committed before the caller rejects
 * the request, so the counter survives the rejection — a rollback would erase it and lockout could never trigger.
 *
 * <p>
 * Two verification forms share one locked evaluator: an equality form for a presented secret string (the plaintext
 * never leaves {@link RegistrationChallengeStore}), and a predicate form whose caller decides whether the resolved
 * plaintext satisfies the request (CMP: whether the message MAC verifies under it).
 */
@Service
public class RegistrationChallengeGate {

    private static final String INVALID_CHALLENGE = "The certificate registration challenge is invalid.";
    // Both answers come back only for an ACTIVE authorization within its window, and a caller knows whether it sent
    // a secret, so telling a missing challenge apart from a wrong one reveals nothing.
    private static final String REQUIRED_CHALLENGE = "The certificate registration challenge is required.";

    private PlatformTransactionManager transactionManager;
    private CertificateRegistrationAuthorizationRepository registrationAuthorizationRepository;
    private RegistrationChallengeStore registrationChallengeStore;
    private CertificateEventHistoryInternalService certificateEventHistoryService;

    @Autowired
    public void setTransactionManager(PlatformTransactionManager transactionManager) {
        this.transactionManager = transactionManager;
    }

    @Autowired
    public void setRegistrationAuthorizationRepository(
            CertificateRegistrationAuthorizationRepository registrationAuthorizationRepository) {
        this.registrationAuthorizationRepository = registrationAuthorizationRepository;
    }

    @Autowired
    public void setRegistrationChallengeStore(RegistrationChallengeStore registrationChallengeStore) {
        this.registrationChallengeStore = registrationChallengeStore;
    }

    @Autowired
    public void setCertificateEventHistoryService(
            CertificateEventHistoryInternalService certificateEventHistoryService) {
        this.certificateEventHistoryService = certificateEventHistoryService;
    }

    /**
     * Verifies a presented registration challenge string by equality. Denials (locked, expired window, wrong or missing
     * challenge) throw a {@link ValidationException}; the audit trail records the failure under {@code operationEvent}.
     * A null or blank {@code presentedSecret} is missing and spends no failed attempt.
     *
     * @return {@code true} when an ACTIVE authorization's challenge verified — the self-service credential that stands
     * in for the caller's operator permission on the completion write
     */
    public boolean verify(UUID certificateUuid, @Sensitive String presentedSecret, CertificateEvent operationEvent) {
        return verifyInternal(certificateUuid, operationEvent, isPresented(presentedSecret),
                authorization -> registrationChallengeStore.verify(authorization, presentedSecret));
    }

    /**
     * Whether a caller supplied a registration secret at all; a null or blank value is missing, not a guess.
     */
    public static boolean isPresented(@Sensitive String secret) {
        return secret != null && !secret.isBlank();
    }

    /**
     * Verifies the registration challenge via a caller-supplied predicate applied to the resolved plaintext (e.g. CMP:
     * does the message MAC verify under this key). Same state cascade, lockout, and event history as the equality form,
     * except that every call counts as presented, so a predicate that fails is always a counted attempt.
     */
    public boolean verify(UUID certificateUuid, CertificateEvent operationEvent, Predicate<String> secretMatches) {
        return verifyInternal(certificateUuid, operationEvent, true,
                authorization -> secretMatches.test(registrationChallengeStore.resolvePlaintext(authorization)));
    }

    private boolean verifyInternal(UUID certificateUuid, CertificateEvent operationEvent, boolean presented,
            Predicate<CertificateRegistrationAuthorization> matches) {
        if (registrationAuthorizationRepository.findByCertificateUuid(certificateUuid).isEmpty()) {
            return false;
        }
        RegistrationChallengeOutcome outcome = evaluateUnderLock(certificateUuid, operationEvent, presented, matches);
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
            boolean presented, Predicate<CertificateRegistrationAuthorization> matches) {
        // REQUIRES_NEW so the row lock, the failed-attempt increment and the lockout commit in their own
        // short transaction and the lock is released on return — never held across an ambient transaction.
        // A caller can hold a row lock the completion (issueExistingCertificate, NOT_SUPPORTED) would then
        // re-acquire on a suspended transaction and self-deadlock; a fresh transaction here prevents that and
        // also guarantees the counter survives a caller rollback.
        DefaultTransactionDefinition definition = new DefaultTransactionDefinition();
        definition.setPropagationBehavior(TransactionDefinition.PROPAGATION_REQUIRES_NEW);
        TransactionStatus tx = transactionManager.getTransaction(definition);
        try {
            RegistrationChallengeOutcome outcome = registrationAuthorizationRepository
                    .findAndLockByCertificateUuid(certificateUuid)
                    .map(authorization -> evaluateLockedAuthorization(authorization, operationEvent, presented,
                            matches))
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
            CertificateEvent operationEvent, boolean presented,
            Predicate<CertificateRegistrationAuthorization> matches) {
        UUID certificateUuid = authorization.getCertificateUuid();
        RegistrationState state = authorization.getState();
        if (state == RegistrationState.CLOSED) {
            return RegistrationChallengeOutcome.notChallengeProtected();
        }
        if (state == RegistrationState.LOCKED) {
            // Record every attempt against an already-locked authorization — persistent hammering is exactly when
            // the audit trail matters most. A call without a secret is recorded too, but not as an attempt.
            certificateEventHistoryService
                    .addEventHistory(certificateUuid, operationEvent, CertificateEventStatus.FAILED,
                            presented
                                    ? "Certificate registration challenge attempted against a locked authorization"
                                    : "Certificate registration challenge not presented against a locked authorization",
                            "");
            return RegistrationChallengeOutcome
                    .denied("The certificate registration authorization is locked after too many failed attempts.");
        }
        if (state == RegistrationState.EXPIRED) {
            return RegistrationChallengeOutcome.denied("The certificate registration issuance window has expired.");
        }
        OffsetDateTime expiresAt = authorization.getExpiresAt();
        if (expiresAt != null && !OffsetDateTime.now(ZoneOffset.UTC).isBefore(expiresAt)) {
            authorization.setState(RegistrationState.EXPIRED);
            registrationAuthorizationRepository.save(authorization);
            certificateEventHistoryService
                    .addEventHistory(certificateUuid, operationEvent, CertificateEventStatus.FAILED,
                            "Certificate registration issuance window expired", "");
            return RegistrationChallengeOutcome.denied("The certificate registration issuance window has expired.");
        }
        if (!presented) {
            // A missing secret is not a guess, so it spends no attempt: counting it would let callers that never
            // send one (the UI renew, a location renew) lock the holder out.
            certificateEventHistoryService
                    .addEventHistory(certificateUuid, operationEvent, CertificateEventStatus.FAILED,
                            "Certificate registration challenge not presented", "");
            return RegistrationChallengeOutcome.denied(REQUIRED_CHALLENGE);
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
        certificateEventHistoryService
                .addEventHistory(certificateUuid, operationEvent, CertificateEventStatus.FAILED,
                        "Certificate registration challenge verification failed (attempt %d)".formatted(attempts), "");
        return RegistrationChallengeOutcome.denied(INVALID_CHALLENGE);
    }

    // The fallback uses the single canonical default (the value the settings API reports and persists) so
    // the value applied on a cache miss cannot drift from the operator-visible default.
    private static int maxFailedAttempts() {
        PlatformSettingsDto platformSettings = SettingsCache.getSettings(SettingsSection.PLATFORM);
        CertificateRegistrationSettingsDto settings = platformSettings != null
                && platformSettings.getCertificates() != null
                        ? platformSettings.getCertificates().getRegistration()
                        : null;
        return settings != null && settings.getMaxFailedAttempts() != null
                ? settings.getMaxFailedAttempts()
                : CertificateRegistrationDefaults.MAX_FAILED_ATTEMPTS;
    }
}
