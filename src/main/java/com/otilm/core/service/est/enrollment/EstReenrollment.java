package com.otilm.core.service.est.enrollment;

import com.otilm.api.model.core.certificate.CertificateState;
import com.otilm.api.model.core.enums.CertificateRequestFormat;
import com.otilm.api.model.core.est.EstAuthenticationPolicy;
import com.otilm.api.model.core.logging.Sensitive;
import com.otilm.api.model.core.logging.enums.Operation;
import com.otilm.api.model.core.v2.ClientCertificateDataResponseDto;
import com.otilm.api.model.core.v2.ClientCertificateRekeyRequestDto;
import com.otilm.api.model.core.v2.ClientCertificateRenewRequestDto;
import com.otilm.core.aop.AuditOperationDataOverride;
import com.otilm.core.aop.AuditOperationOverride;
import com.otilm.core.dao.entity.RaProfile;
import com.otilm.core.dao.entity.RegistrationState;
import com.otilm.core.dao.entity.est.EstRequestClaim;
import com.otilm.core.dao.repository.CertificateRegistrationAuthorizationRepository;
import com.otilm.core.dao.repository.CertificateRepository;
import com.otilm.core.dao.repository.EstRequestedCertificate;
import com.otilm.core.model.auth.CertificateProtocolInfo;
import com.otilm.core.model.request.Pkcs10CertificateRequest;
import com.otilm.core.security.authz.SecuredParentUUID;
import com.otilm.core.security.authz.SecuredUUID;
import com.otilm.core.service.est.EstRoute;
import com.otilm.core.service.est.authentication.EstClient;
import com.otilm.core.service.est.authentication.EstClientCredentials;
import com.otilm.core.service.est.authentication.EstClientCredentials.BasicCredentials;
import com.otilm.core.service.est.authentication.EstSourceCertificate;
import com.otilm.core.service.est.authentication.EstSourceCertificates;
import com.otilm.core.service.est.enrollment.EstRequestClaims.ClaimedRequest;
import com.otilm.core.service.est.message.EstError;
import com.otilm.core.service.est.message.EstException;
import com.otilm.core.service.est.message.EstRequestDecoder;
import com.otilm.core.service.registration.RegistrationChallengeException;
import com.otilm.core.service.v2.ClientOperationInternalService;
import com.otilm.core.service.writer.est.EstRequestClaimLostException;
import java.time.Instant;
import java.util.Base64;
import java.util.Optional;
import java.util.UUID;
import java.util.concurrent.atomic.AtomicReference;
import java.util.function.Consumer;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Component;
import org.springframework.web.context.request.RequestContextHolder;

/**
 * Answers a {@code /simplereenroll} (RFC 7030 section 4.2.2): it renews or rekeys the certificate that the client
 * presents, whatever the authentication policy of the route, and answers by the state that the new certificate reaches.
 * A request with the key of the certificate renews it and one with another key rekeys it, as far as the EST Profile
 * allows and once the certificate is in its renewal window.
 * <p>
 * A certificate that a registration guards is renewed or rekeyed only with the password of the registration, sent as
 * the Basic password on a route whose EST Profile authenticates by registrations.
 * <p>
 * A retry is answered from what the inventory keeps for the route's RA Profile: the certificate that the request
 * created, or its rejection; while a renewal or rekey is on its way, another request is refused.
 * <p>
 * Identical concurrent requests are answered once, as {@link EstRequestClaims} does. It writes only those claims, each
 * in a short transaction of its own, and holds no transaction, so no connection is held while the certificate is
 * awaited; its only caller, the EST service, runs outside any transaction.
 */
@Slf4j
@Component
public class EstReenrollment {

    private final EstSourceCertificates sourceCertificates;
    private final ClientOperationInternalService clientOperationService;
    private final CertificateRepository certificateRepository;
    private final CertificateRegistrationAuthorizationRepository registrationAuthorizationRepository;
    private final EstIssuanceWait issuanceWait;
    private final EstAnswers answers;
    private final EstRequestClaims requestClaims;

    private AuditOperationOverride auditOperationOverride;
    private AuditOperationDataOverride auditOperationDataOverride;

    EstReenrollment(EstSourceCertificates sourceCertificates, ClientOperationInternalService clientOperationService,
            CertificateRepository certificateRepository,
            CertificateRegistrationAuthorizationRepository registrationAuthorizationRepository,
            EstIssuanceWait issuanceWait, EstAnswers answers, EstRequestClaims requestClaims) {
        this.sourceCertificates = sourceCertificates;
        this.clientOperationService = clientOperationService;
        this.certificateRepository = certificateRepository;
        this.registrationAuthorizationRepository = registrationAuthorizationRepository;
        this.issuanceWait = issuanceWait;
        this.answers = answers;
        this.requestClaims = requestClaims;
    }

    @Autowired
    public void setAuditOperationOverride(AuditOperationOverride auditOperationOverride) {
        this.auditOperationOverride = auditOperationOverride;
    }

    @Autowired
    public void setAuditOperationDataOverride(AuditOperationDataOverride auditOperationDataOverride) {
        this.auditOperationDataOverride = auditOperationDataOverride;
    }

    /**
     * @param route the route of the request
     * @param csr the request of the client, decoded but with its signature not yet verified
     * @param credentials what the client presented, of which only the certificate that it renews counts, and the Basic
     * password on a route that authenticates by registrations, when a registration guards that certificate
     * @return the new certificate, or the answer that it is not ready yet
     * @throws EstException {@link EstError#CERTIFICATE_REJECTED} when the client presented no certificate that may be
     * renewed through the route; {@link EstError#INVALID_SIGNATURE} when the signature of the request does not verify;
     * {@link EstError#SUBJECT_CHANGE_UNSUPPORTED} or {@link EstError#IDENTITY_MISMATCH} when the request asks for
     * another subject or other names than the certificate has; {@link EstError#RENEWAL_NOT_ALLOWED} or
     * {@link EstError#REKEY_NOT_ALLOWED} when the EST Profile forbids what the request asks for;
     * {@link EstError#RENEWAL_NOT_DUE} when the certificate is not in its renewal window; {@link EstError#UNAUTHORIZED}
     * when a registration guards the certificate and its password is missing or wrong, or the registration is locked or
     * expired; {@link EstError#POLICY_VIOLATION} when the request does not meet the policy of the RA Profile;
     * {@link EstError#REQUEST_REJECTED} when the new certificate was rejected, or the same request was rejected before;
     * {@link EstError#RENEWAL_PENDING} when the certificate has a renewal or rekey on its way that another request
     * asked for; {@link EstError#ISSUANCE_FAILED} when the new certificate could not be issued; and
     * {@link EstError#SERVICE_UNAVAILABLE} when the request could not be submitted
     * @throws IllegalStateException when the new certificate ends in a state that no re-enrolment reaches
     */
    public ResponseEntity<byte[]> reenroll(EstRoute route, Pkcs10CertificateRequest csr,
            @Sensitive EstClientCredentials credentials) {
        EstSourceCertificate source = sourceCertificates.authenticate(route, credentials);
        verifyProofOfPossession(route, source, csr);
        requireSameSubject(route, source, csr);
        String requestFingerprint = answers.fingerprintOf(csr);
        EstReenrollmentKind kind = classify(route, source, csr);
        auditAs(kind);
        String requestKey = source.uuid() + ":" + requestFingerprint;
        return requestClaims
                .answerOnce(route, EstRequestClaim.Operation.REENROLL, requestKey, requestFingerprint,
                        new ClaimedRequest() {
                            @Override
                            public Optional<EstRequestedCertificate> find() {
                                return findAnsweringSuccessor(route, source, requestFingerprint);
                            }

                            @Override
                            public UUID submit(Consumer<UUID> onStored) {
                                requireNewRequest(route, source, requestFingerprint);
                                requireAllowed(route, source, kind);
                                requireDue(route, source);
                                return EstReenrollment.this.submit(route, source, csr, kind, credentials, onStored);
                            }

                            @Override
                            public ResponseEntity<byte[]> answer(UUID successorUuid, CertificateState state) {
                                log
                                        .debug("Certificate {} requested through EST for the {} of certificate {} is {}",
                                                successorUuid, describe(kind), source.uuid(), state);
                                return answers
                                        .answer(route, successorUuid, requestFingerprint, state,
                                                recordingAnswer(route, source, kind, successorUuid));
                            }

                            @Override
                            public ResponseEntity<byte[]> pending() {
                                return answers.pending(route, recordingAnswer(route, source, kind, null));
                            }
                        });
    }

    /**
     * Has the audit record of the request name a rekey, where the endpoint names a renewal. There is nothing to set
     * without a request: the service-level callers run without one, which has no scope for the override to live in.
     */
    private void auditAs(EstReenrollmentKind kind) {
        if (kind == EstReenrollmentKind.REKEY && RequestContextHolder.getRequestAttributes() != null) {
            auditOperationOverride.set(Operation.REKEY);
        }
    }

    /** Records the answer that the successor gives the client, as {@link #recordAnswer} does. */
    private Consumer<String> recordingAnswer(EstRoute route, EstSourceCertificate source, EstReenrollmentKind kind,
            UUID successorUuid) {
        return outcome -> recordAnswer(route, source, kind, successorUuid, outcome);
    }

    /**
     * Logs the answer once, and hands it to the audit record of the request when there is one. The client is the
     * certificate that it presented, whatever the policy of the route.
     */
    private void recordAnswer(EstRoute route, EstSourceCertificate source, EstReenrollmentKind kind, UUID successorUuid,
            String outcome) {
        EstAuthenticationPolicy policy = route.estProfile().getAuthenticationPolicy();
        String identity = EstClient.ofCertificate(policy, source.fingerprint()).identity();
        log
                .info("EST {} {} for certificate {}, new certificate {}, client {}, realm {}", describe(kind), outcome,
                        source.uuid(), successorUuid, identity, route.realm());
        if (RequestContextHolder.getRequestAttributes() != null) {
            auditOperationDataOverride
                    .set(new EstReenrollmentAudit(route.label(), policy, identity, source.uuid(), outcome));
        }
    }

    /**
     * Verifies the signature only once the certificate of the client is accepted, as an enrolment verifies it only once
     * the policy of its route has accepted the client: checking a signature takes computing time, which a client that
     * nobody identified must not be able to spend. The refusal is the same under every policy.
     */
    private static void verifyProofOfPossession(EstRoute route, EstSourceCertificate source,
            Pkcs10CertificateRequest csr) {
        try {
            EstRequestDecoder.verifyProofOfPossession(csr);
        } catch (EstException e) {
            throw refused(route, source, e);
        }
    }

    private static void requireSameSubject(EstRoute route, EstSourceCertificate source, Pkcs10CertificateRequest csr) {
        try {
            EstReenrollmentRules.refuseSubjectChange(csr);
            EstReenrollmentRules.requireSameIdentity(source, csr);
        } catch (EstException e) {
            throw refused(route, source, e);
        }
    }

    /**
     * Finds the certificate that the source was renewed or rekeyed into with this request, when it still answers a
     * retry of it, as {@link EstAnswers#answersRetry} tells. The relation that the platform keeps between the two finds
     * it whatever its type, so a client whose answer was lost gets that certificate rather than a second one. It is
     * answered as it stands, without a wait, so that a client that polls a request which cannot progress holds no
     * thread.
     */
    private Optional<EstRequestedCertificate> findAnsweringSuccessor(EstRoute route, EstSourceCertificate source,
            String requestFingerprint) {
        Optional<EstRequestedCertificate> found = certificateRepository
                .findSuccessorRequestedWith(source.uuid(), route.raProfile().getUuid(), requestFingerprint);
        if (found.isEmpty()) {
            return Optional.empty();
        }
        EstRequestedCertificate successor = found.get();
        if (!answers.answersRetry(successor)) {
            log
                    .debug("Certificate {} that certificate {} was renewed or rekeyed into with this request is {} and does not answer it",
                            successor.getUuid(), source.uuid(), successor.getState());
            return Optional.empty();
        }
        log
                .debug("Certificate {} that certificate {} was renewed or rekeyed into with this request is {} and answers it",
                        successor.getUuid(), source.uuid(), successor.getState());
        return found;
    }

    /**
     * Lets the request start a renewal or rekey only when nothing in the inventory answers it already: a rejected
     * request stays rejected, and a source with a renewal or rekey on its way refuses another request.
     */
    private void requireNewRequest(EstRoute route, EstSourceCertificate source, String requestFingerprint) {
        Optional<EstRequestedCertificate> rejected = certificateRepository
                .findLatestRequestedThroughEst(route.raProfile().getUuid(), route.estProfile().getUuid(),
                        requestFingerprint)
                .filter(certificate -> certificate.getState() == CertificateState.REJECTED);
        if (rejected.isPresent()) {
            log.debug("Certificate {} requested through EST with this request was rejected", rejected.get().getUuid());
            throw refused(route, source, new EstException(EstError.REQUEST_REJECTED));
        }
        if (certificateRepository.existsPendingSuccessor(source.uuid())) {
            log.debug("Certificate {} has a renewal or rekey on its way that another request asked for", source.uuid());
            throw refused(route, source, new EstException(EstError.RENEWAL_PENDING));
        }
        log
                .debug("Nothing in the inventory answers this request for the renewal of certificate {}, so it is a new request",
                        source.uuid());
    }

    private static EstReenrollmentKind classify(EstRoute route, EstSourceCertificate source,
            Pkcs10CertificateRequest csr) {
        try {
            EstReenrollmentKind kind = EstReenrollmentRules.classify(source, csr);
            log.debug("The EST request asks for the {} of certificate {}", describe(kind), source.uuid());
            return kind;
        } catch (EstException e) {
            throw refused(route, source, e);
        }
    }

    private static void requireAllowed(EstRoute route, EstSourceCertificate source, EstReenrollmentKind kind) {
        try {
            EstReenrollmentRules.requireAllowed(kind, route.estProfile());
        } catch (EstException e) {
            throw refused(route, source, e);
        }
    }

    private static void requireDue(EstRoute route, EstSourceCertificate source) {
        boolean due = EstReenrollmentRules
                .isDue(source.notBefore(), source.notAfter(), route.estProfile().getRenewalThreshold(), Instant.now());
        if (!due) {
            throw refused(route, source, new EstException(EstError.RENEWAL_NOT_DUE));
        }
    }

    /** Gives a refusal of the rules the realm of the route, and logs at DEBUG which certificate it refuses. */
    private static EstException refused(EstRoute route, EstSourceCertificate source, EstException refusal) {
        log
                .debug("EST re-enrolment of certificate {} refused for realm {} as {}", source.uuid(), route.realm(),
                        refusal.error());
        return refusal.withRealm(route.realm());
    }

    /**
     * Submits the renewal or rekey through the platform, attributing the new certificate to the EST Profile. A refusal
     * by the registration asks the client for its password; any other failure is answered as
     * {@link EstAnswers#submissionFailed} answers it.
     *
     * @param onStored run in the transaction that stores the new certificate
     * @return the new certificate, which the platform returns also when compliance rejected it and queued nothing
     * @throws EstRequestClaimLostException when {@code onStored} found the claim taken over
     */
    private UUID submit(EstRoute route, EstSourceCertificate source, Pkcs10CertificateRequest csr,
            EstReenrollmentKind kind, @Sensitive EstClientCredentials credentials, Consumer<UUID> onStored) {
        RaProfile raProfile = route.raProfile();
        SecuredParentUUID authorityUuid = raProfile.getAuthorityInstanceReference().getSecuredParentUuid();
        SecuredUUID raProfileUuid = raProfile.getSecuredUuid();
        String sourceUuid = source.uuid().toString();
        String request = Base64.getEncoder().encodeToString(csr.getEncoded());
        CertificateProtocolInfo throughEst = CertificateProtocolInfo.est(route.estProfile().getUuid(), onStored);
        String authorizationSecret = registrationSecretOf(route, source, credentials);
        AtomicReference<UUID> successor = new AtomicReference<>();
        try {
            ClientCertificateDataResponseDto response = switch (kind) {
                case RENEWAL -> clientOperationService
                        .renewCertificate(authorityUuid, raProfileUuid, sourceUuid,
                                renewalRequest(request, authorizationSecret), throughEst, successor::set);
                case REKEY -> clientOperationService
                        .rekeyCertificate(authorityUuid, raProfileUuid, sourceUuid,
                                rekeyRequest(request, authorizationSecret), throughEst, successor::set);
            };
            return UUID.fromString(response.getUuid());
        } catch (RegistrationChallengeException e) {
            throw askForPassword(route, source, kind, e);
        } catch (Exception e) {
            EstRequestClaimLostException.rethrowIfCause(e);
            String what = "The " + describe(kind) + " of certificate " + source.uuid();
            throw answers.submissionFailed(route, successor.get(), what, e);
        }
    }

    /**
     * The secret of the registration that guards the certificate: the Basic password of the client, but only on a route
     * whose EST Profile authenticates by registrations, and only for a certificate whose registration authorization is
     * not closed, against which the platform verifies the password. A password meant for anything else, as the password
     * of an RA is, then never reaches the registration as a guess, also once a profile that authenticated by
     * registrations authenticates otherwise.
     *
     * @return the password, or {@code null} for none, which the platform refuses as missing for a certificate that a
     * registration guards, without counting a failed attempt
     */
    private String registrationSecretOf(EstRoute route, EstSourceCertificate source,
            @Sensitive EstClientCredentials credentials) {
        boolean registrationRoute = route
                .estProfile()
                .getAuthenticationPolicy() == EstAuthenticationPolicy.CERTIFICATE_REGISTRATION;
        boolean guardedByRegistration = registrationRoute && registrationAuthorizationRepository
                .existsByCertificateUuidAndStateNot(source.uuid(), RegistrationState.CLOSED);
        return guardedByRegistration ? passwordOf(credentials) : null;
    }

    /**
     * @return the Basic password that the client presented, or {@code null} when it presented none, which the platform
     * refuses as missing without counting a failed attempt
     */
    private static String passwordOf(@Sensitive EstClientCredentials credentials) {
        return credentials.basic().map(BasicCredentials::password).orElse(null);
    }

    /**
     * Asks the client for the password of the registration that guards its certificate, and logs at DEBUG why the
     * registration refused the request, in the fixed text of the platform, which carries no secret.
     */
    private static EstException askForPassword(EstRoute route, EstSourceCertificate source, EstReenrollmentKind kind,
            RegistrationChallengeException refusal) {
        log
                .debug("The registration that guards certificate {} refused its {}: {}", source.uuid(), describe(kind),
                        refusal.getMessage());
        return refused(route, source, new EstException(EstError.UNAUTHORIZED));
    }

    private static ClientCertificateRenewRequestDto renewalRequest(String request,
            @Sensitive String authorizationSecret) {
        return ClientCertificateRenewRequestDto
                .builder()
                .request(request)
                .format(CertificateRequestFormat.PKCS10)
                .authorizationSecret(authorizationSecret)
                .build();
    }

    private static ClientCertificateRekeyRequestDto rekeyRequest(String request,
            @Sensitive String authorizationSecret) {
        return ClientCertificateRekeyRequestDto
                .builder()
                .request(request)
                .format(CertificateRequestFormat.PKCS10)
                .authorizationSecret(authorizationSecret)
                .build();
    }

    private static String describe(EstReenrollmentKind kind) {
        return kind == EstReenrollmentKind.RENEWAL ? "renewal" : "rekey";
    }
}
