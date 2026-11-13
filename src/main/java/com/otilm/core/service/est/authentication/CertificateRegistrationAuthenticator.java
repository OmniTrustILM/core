package com.otilm.core.service.est.authentication;

import com.otilm.api.exception.ValidationException;
import com.otilm.api.model.core.certificate.CertificateEvent;
import com.otilm.api.model.core.certificate.CertificateEventStatus;
import com.otilm.api.model.core.certificate.CertificateState;
import com.otilm.api.model.core.est.EstAuthenticationPolicy;
import com.otilm.api.model.core.logging.Sensitive;
import com.otilm.core.dao.entity.Certificate;
import com.otilm.core.dao.entity.RaProfile;
import com.otilm.core.dao.entity.RegistrationState;
import com.otilm.core.dao.entity.X509CertificateEntity;
import com.otilm.core.dao.repository.CertificateRegistrationAuthorizationRepository;
import com.otilm.core.dao.repository.CertificateRepository;
import com.otilm.core.dao.repository.X509CertificateRepository;
import com.otilm.core.model.request.CertificateRequest;
import com.otilm.core.model.request.Pkcs10CertificateRequest;
import com.otilm.core.service.CertificateEventHistoryInternalService;
import com.otilm.core.service.est.EstRoute;
import com.otilm.core.service.est.authentication.EstClientCredentials.BasicCredentials;
import com.otilm.core.service.est.message.EstError;
import com.otilm.core.service.est.message.EstException;
import com.otilm.core.service.est.message.EstRequestDecoder;
import com.otilm.core.service.registration.RegistrationChallengeGate;
import com.otilm.core.service.registration.RegistrationIdentityMatcher;
import com.otilm.core.service.registration.RegistrationIdentityMatcher.Candidate;
import com.otilm.core.service.registration.RegistrationIdentityMatcher.MatchResult;
import com.otilm.core.service.registration.RegistrationIdentityMatcher.Outcome;
import com.otilm.core.util.CertificateUtil;
import com.otilm.core.util.NullUtil;
import java.security.NoSuchAlgorithmException;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Optional;
import java.util.UUID;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Component;

/**
 * Identifies a client by the pre-registered certificate that it completes: the registration whose UUID is the user
 * name, or, for any other user name including the empty one, the registration found by the subject of the request, as
 * for SCEP. The subject and subject alternative names of the request must match the registration either way.
 * <p>
 * A request that already completed a registration identifies it again without checking the password, so a client that
 * missed the answer can repeat it; the answer is only a public certificate or a status.
 * <p>
 * The password is the registration's challenge, verified once on completion; a failure counts against that registration
 * and locks it. A {@code challengePassword} attribute is never a credential, a client certificate is not read, and no
 * other policy is tried. The challenge is checked here only when the subject matches a registration and the subject
 * alternative names do not; that mismatch is recorded on the registration only once the signature and the challenge
 * verify.
 * <p>
 * Once credentials were presented, every refusal is {@link EstError#REGISTRATION_REJECTED}, so a client learns nothing
 * about which registrations exist.
 */
@Slf4j
@Component
public class CertificateRegistrationAuthenticator implements EstAuthenticator {

    private static final String SAN_MISMATCH_RECORD = "EST enrolment subject alternative names do not match the "
            + "registered ones";

    private final CertificateRepository certificateRepository;
    private final X509CertificateRepository x509CertificateRepository;
    private final CertificateRegistrationAuthorizationRepository authorizationRepository;
    private final RegistrationChallengeGate challengeGate;
    private final CertificateEventHistoryInternalService eventHistoryService;

    public CertificateRegistrationAuthenticator(CertificateRepository certificateRepository,
            X509CertificateRepository x509CertificateRepository,
            CertificateRegistrationAuthorizationRepository authorizationRepository,
            RegistrationChallengeGate challengeGate, CertificateEventHistoryInternalService eventHistoryService) {
        this.certificateRepository = certificateRepository;
        this.x509CertificateRepository = x509CertificateRepository;
        this.authorizationRepository = authorizationRepository;
        this.challengeGate = challengeGate;
        this.eventHistoryService = eventHistoryService;
    }

    @Override
    public EstAuthenticationPolicy policy() {
        return EstAuthenticationPolicy.CERTIFICATE_REGISTRATION;
    }

    /**
     * @return the client, identified as {@code registration:<uuid>} by the registration that it completes
     * @throws EstException carrying the realm of the route. {@link EstError#UNAUTHORIZED} when the client presented no
     * Basic credentials, ones that cannot be read, or a blank password; {@link EstError#REGISTRATION_REJECTED} for
     * every other refusal, subject alternative names that differ from the registration's included
     */
    @Override
    public EstClient authenticate(EstRoute route, @Sensitive EstClientCredentials credentials, CertificateRequest csr) {
        BasicCredentials basic = credentials
                .basic()
                .orElseThrow(() -> refused(route, EstError.UNAUTHORIZED,
                        credentials.basicMalformed()
                                ? "the Basic credentials are malformed"
                                : "no Basic credentials were presented"));
        if (!RegistrationChallengeGate.isPresented(basic.password())) {
            throw refused(route, EstError.UNAUTHORIZED, "the Basic password is blank");
        }
        Optional<UUID> completedWithTheRequest = registrationRequestedWith(route, basic.username(), csr);
        if (completedWithTheRequest.isPresent()) {
            log
                    .debug("The request completed registration {} for realm {}, which identifies it",
                            completedWithTheRequest.get(), route.realm());
            return clientOf(completedWithTheRequest.get());
        }
        Map<String, List<String>> csrSans = CertificateUtil.getSAN(csr);
        List<Candidate> candidates = candidatesOf(route, basic.username(), csr);
        MatchResult match = RegistrationIdentityMatcher.match(csr.getSubject(), csrSans, candidates);
        if (match.outcome() == Outcome.MATCHED) {
            return clientOf(match.certificateUuid());
        }
        if (match.outcome() == Outcome.SAN_MISMATCH) {
            recordSanMismatchOnceProven(match.certificateUuid(), basic.password(), csr);
        }
        throw refused(route, EstError.REGISTRATION_REJECTED,
                match.outcome() + " among " + candidates.size() + " candidate(s)");
    }

    /**
     * A reference limits the match to the registration it names; otherwise the newest registration of the RA Profile
     * that the request completed is the one.
     */
    private Optional<UUID> registrationRequestedWith(EstRoute route, String username, CertificateRequest csr) {
        List<UUID> requestedWith = certificateRepository
                .findRegistrationsRequestedWith(route.raProfile().getUuid(), fingerprintOf(csr));
        Optional<UUID> reference = registrationReferenceIn(username);
        if (reference.isPresent()) {
            return reference.filter(requestedWith::contains);
        }
        return requestedWith.stream().findFirst();
    }

    private static String fingerprintOf(CertificateRequest csr) {
        try {
            return CertificateUtil.getThumbprint(csr.getEncoded());
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException("SHA-256 is not available", e);
        }
    }

    /**
     * A reference decides the candidates alone: an empty list from it is still a value, so the CSR lookup does not run.
     */
    private List<Candidate> candidatesOf(EstRoute route, String username, CertificateRequest csr) {
        RaProfile raProfile = route.raProfile();
        Optional<UUID> reference = registrationReferenceIn(username);
        List<X509CertificateEntity> registrations = reference
                .map(uuid -> referencedRegistration(raProfile, uuid))
                .orElseGet(() -> registrationsOfSubject(raProfile, csr));
        log
                .debug("Found {} candidate registration(s) for realm {} {}", registrations.size(), route.realm(),
                        reference.isPresent() ? "by reference" : "by the subject of the request");
        return registrations
                .stream()
                .map(registration -> new Candidate(registration.getUuid(), registration.getSubjectDn(),
                        registration.getSubjectAlternativeNames()))
                .toList();
    }

    /**
     * @return the registration that the user name refers to, empty when the user name is not a canonical UUID. The JDK
     * parser also reads forms such as {@code 1-1-1-1-1}, which are no reference.
     */
    private static Optional<UUID> registrationReferenceIn(String username) {
        try {
            return Optional
                    .ofNullable(NullUtil.parseUuidOrNull(username))
                    .filter(uuid -> uuid.toString().equals(username.toLowerCase(Locale.ROOT)));
        } catch (IllegalArgumentException e) {
            return Optional.empty();
        }
    }

    /**
     * @return the certificate when it is a registration that the RA Profile can complete: of that RA Profile, still
     * {@code REGISTERED}, not archived and with an {@code ACTIVE} authorization; otherwise nothing
     */
    private List<X509CertificateEntity> referencedRegistration(RaProfile raProfile, UUID reference) {
        return x509CertificateRepository
                .findByUuid(reference)
                .filter(certificate -> isCompletableOn(raProfile, certificate))
                .stream()
                .toList();
    }

    private boolean isCompletableOn(RaProfile raProfile, Certificate certificate) {
        return raProfile.getUuid().equals(certificate.getRaProfileUuid())
                && certificate.getState() == CertificateState.REGISTERED && !certificate.isArchived()
                && hasActiveAuthorization(certificate);
    }

    /**
     * Reads the state through the detail projection: the entity holds the encrypted challenge, which a request that is
     * not yet authenticated has no use for.
     */
    private boolean hasActiveAuthorization(Certificate certificate) {
        return authorizationRepository
                .findDetailByCertificateUuid(certificate.getUuid())
                .filter(authorization -> authorization.getState() == RegistrationState.ACTIVE)
                .isPresent();
    }

    private List<X509CertificateEntity> registrationsOfSubject(RaProfile raProfile, CertificateRequest csr) {
        return x509CertificateRepository
                .findRegisteredWithActiveRegistrationAuthorizationByRaProfileUuidAndSubjectDnNormalized(
                        raProfile.getUuid(), CertificateUtil.normalizeSubjectDn(csr.getSubject()));
    }

    /**
     * The signature is verified before the challenge, so that a forged request spends no attempt of the registration.
     * The challenge is verified as completing the registration verifies it: a wrong one counts against the
     * registration, and the gate records that refusal itself.
     */
    private void recordSanMismatchOnceProven(UUID registrationUuid, @Sensitive String password,
            CertificateRequest csr) {
        if (provesPossession(csr) && challengeVerified(registrationUuid, password)) {
            eventHistoryService
                    .addEventHistory(registrationUuid, CertificateEvent.ISSUE, CertificateEventStatus.FAILED,
                            SAN_MISMATCH_RECORD, "");
        }
    }

    /** EST decodes every request as PKCS#10, and the decoder bounds its key before any is built. */
    private static boolean provesPossession(CertificateRequest csr) {
        if (!(csr instanceof Pkcs10CertificateRequest pkcs10)) {
            return false;
        }
        try {
            EstRequestDecoder.verifyProofOfPossession(pkcs10);
            return true;
        } catch (EstException e) {
            log.debug("The request does not prove possession of its key: {}", e.error());
            return false;
        }
    }

    private boolean challengeVerified(UUID registrationUuid, @Sensitive String password) {
        try {
            return challengeGate.verify(registrationUuid, password, CertificateEvent.ISSUE);
        } catch (ValidationException e) {
            log.debug("The challenge of registration {} was refused: {}", registrationUuid, e.getMessage());
            return false;
        }
    }

    private static EstClient clientOf(UUID registrationUuid) {
        return new EstClient(EstAuthenticationPolicy.CERTIFICATE_REGISTRATION, "registration:" + registrationUuid,
                registrationUuid);
    }

    private static EstException refused(EstRoute route, EstError error, String reason) {
        log
                .debug("EST client refused under the certificateRegistration policy for realm {}: {}", route.realm(),
                        reason);
        return new EstException(error, route.realm());
    }
}
