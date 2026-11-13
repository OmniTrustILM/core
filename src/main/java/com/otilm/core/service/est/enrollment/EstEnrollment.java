package com.otilm.core.service.est.enrollment;

import com.otilm.api.exception.NotFoundException;
import com.otilm.api.exception.ValidationException;
import com.otilm.api.model.core.certificate.CertificateState;
import com.otilm.api.model.core.logging.Sensitive;
import com.otilm.api.model.core.v2.ClientCertificateDataResponseDto;
import com.otilm.api.model.core.v2.ClientCertificateIssueRequestDto;
import com.otilm.core.aop.AuditOperationDataOverride;
import com.otilm.core.certificate.request.RequestAttributePolicyViolationException;
import com.otilm.core.dao.entity.RaProfile;
import com.otilm.core.dao.entity.est.EstRequestClaim;
import com.otilm.core.dao.repository.CertificateRepository;
import com.otilm.core.dao.repository.EstRequestedCertificate;
import com.otilm.core.model.auth.CertificateProtocolInfo;
import com.otilm.core.model.request.Pkcs10CertificateRequest;
import com.otilm.core.service.CertificateInternalService;
import com.otilm.core.service.est.EstRoute;
import com.otilm.core.service.est.authentication.EstClient;
import com.otilm.core.service.est.authentication.EstClientCredentials;
import com.otilm.core.service.est.authentication.EstClientCredentials.BasicCredentials;
import com.otilm.core.service.est.enrollment.EstRequestClaims.ClaimedRequest;
import com.otilm.core.service.est.message.EstError;
import com.otilm.core.service.est.message.EstException;
import com.otilm.core.service.v2.ClientOperationExternalService;
import com.otilm.core.service.v2.ClientOperationInternalService;
import com.otilm.core.service.writer.est.EstRequestClaimLostException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
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
 * Answers an authenticated {@code /simpleenroll}: it submits the request of the client for issuing, or completes the
 * registration that identified the client with it, and answers by the state that the certificate reaches. Every answer
 * comes from a read that requires the certificate to carry the request, so that no request is answered with the
 * certificate of another. Identical concurrent requests are answered once, as {@link EstRequestClaims} does. It writes
 * only those claims, each in a short transaction of its own, and holds no transaction, because submitting and waiting
 * both take as long as the connector takes. It carries no transactional annotation on purpose, so that no scope keeps a
 * connection while the certificate is awaited; its only caller, the EST service, runs outside any transaction.
 */
@Slf4j
@Component
public class EstEnrollment {

    private final ClientOperationInternalService clientOperationService;
    private final ClientOperationExternalService clientOperationExternalService;
    private final CertificateInternalService certificateService;
    private final CertificateRepository certificateRepository;
    private final EstIssueRequests issueRequests;
    private final EstIssuanceWait issuanceWait;
    private final EstAnswers answers;
    private final EstRequestClaims requestClaims;

    private AuditOperationDataOverride auditOperationDataOverride;

    EstEnrollment(ClientOperationInternalService clientOperationService,
            ClientOperationExternalService clientOperationExternalService,
            CertificateInternalService certificateService, CertificateRepository certificateRepository,
            EstIssueRequests issueRequests, EstIssuanceWait issuanceWait, EstAnswers answers,
            EstRequestClaims requestClaims) {
        this.clientOperationService = clientOperationService;
        this.clientOperationExternalService = clientOperationExternalService;
        this.certificateService = certificateService;
        this.certificateRepository = certificateRepository;
        this.issueRequests = issueRequests;
        this.issuanceWait = issuanceWait;
        this.answers = answers;
        this.requestClaims = requestClaims;
    }

    @Autowired
    public void setAuditOperationDataOverride(AuditOperationDataOverride auditOperationDataOverride) {
        this.auditOperationDataOverride = auditOperationDataOverride;
    }

    /**
     * @param route the route of the request
     * @param client the client that the policy of the route identified
     * @param csr the request of the client, whose proof of possession is verified
     * @param credentials what the client presented: under {@code certificateRegistration} the Basic password is the
     * challenge that completing the registration verifies
     * @return the certificate, or the answer that it is not ready yet
     * @throws EstException {@link EstError#POLICY_VIOLATION} when the request does not meet the policy of the RA
     * Profile, {@link EstError#REQUEST_REJECTED} when the certificate was rejected, {@link EstError#ISSUANCE_FAILED}
     * when it could not be issued, {@link EstError#SERVICE_UNAVAILABLE} when the request could not be submitted, and
     * {@link EstError#REGISTRATION_REJECTED} when the registration of the client cannot answer the request
     * @throws IllegalStateException when the certificate ends in a state that no enrolment reaches
     */
    public ResponseEntity<byte[]> enroll(EstRoute route, EstClient client, Pkcs10CertificateRequest csr,
            @Sensitive EstClientCredentials credentials) {
        return switch (client.policy()) {
            case RA_BASIC, VENDOR_MTLS, RA_MTLS -> enrollNew(route, client, csr);
            case CERTIFICATE_REGISTRATION -> enrollRegistration(route, client, csr, credentials);
        };
    }

    /**
     * A certificate that the same request created answers it as it stands. Only a request that EST has just submitted
     * is given the time to be issued, so that a client that polls a request which cannot progress holds no thread.
     */
    private ResponseEntity<byte[]> enrollNew(EstRoute route, EstClient client, Pkcs10CertificateRequest csr) {
        String requestFingerprint = answers.fingerprintOf(csr);
        return requestClaims
                .answerOnce(route, EstRequestClaim.Operation.ENROLL, requestFingerprint, requestFingerprint,
                        new ClaimedRequest() {
                            @Override
                            public Optional<EstRequestedCertificate> find() {
                                return findAnswering(route, requestFingerprint);
                            }

                            @Override
                            public UUID submit(Consumer<UUID> onStored) {
                                return EstEnrollment.this.submit(route, csr, onStored);
                            }

                            @Override
                            public ResponseEntity<byte[]> answer(UUID certificateUuid, CertificateState state) {
                                return answers
                                        .answer(route, certificateUuid, requestFingerprint, state,
                                                recordingAnswer(route, client, certificateUuid));
                            }

                            @Override
                            public ResponseEntity<byte[]> pending() {
                                return answers.pending(route, recordingAnswer(route, client, null));
                            }
                        });
    }

    /**
     * Finds the certificate that the same request created through this route, when it still answers a retry, as
     * {@link EstAnswers#answersRetry} tells.
     */
    private Optional<EstRequestedCertificate> findAnswering(EstRoute route, String requestFingerprint) {
        Optional<EstRequestedCertificate> found = certificateRepository
                .findLatestRequestedThroughEst(route.raProfile().getUuid(), route.estProfile().getUuid(),
                        requestFingerprint);
        if (found.isEmpty()) {
            log.debug("No certificate was requested through EST by this request, so it is a new request");
            return Optional.empty();
        }
        EstRequestedCertificate certificate = found.get();
        if (!answers.answersRetry(certificate)) {
            log
                    .debug("Certificate {} requested through EST by this request is {} and does not answer it, so it is a new request",
                            certificate.getUuid(), certificate.getState());
            return Optional.empty();
        }
        log
                .debug("Certificate {} requested through EST by this request is {} and answers it",
                        certificate.getUuid(), certificate.getState());
        return found;
    }

    /**
     * Submits the request for a new certificate, attributed to the EST Profile of the route.
     *
     * @return the new certificate
     * @throws EstException as {@link EstAnswers#submissionFailed} answers a failure
     */
    UUID submit(EstRoute route, Pkcs10CertificateRequest csr) {
        return submit(route, csr, null);
    }

    private UUID submit(EstRoute route, Pkcs10CertificateRequest csr, Consumer<UUID> onStored) {
        return submit(route, issueRequests.newRequest(route, csr), onStored, certificateUuid -> {
        });
    }

    /**
     * Submits the request signed by a key on a token for a new certificate, which the platform links to the key, as
     * {@link #submit(EstRoute, Pkcs10CertificateRequest)} does.
     *
     * @param keyUuid the key that signed the request
     * @param tokenProfileUuid the token profile that the key was created on
     * @param created told the new certificate as soon as it exists, so that a caller learns it even when the submission
     * fails afterwards
     * @return the new certificate
     */
    UUID submitForKey(EstRoute route, Pkcs10CertificateRequest csr, UUID keyUuid, UUID tokenProfileUuid,
            Consumer<UUID> created) {
        ClientCertificateIssueRequestDto request = issueRequests.newRequest(route, csr);
        request.setKeyUuid(keyUuid);
        request.setTokenProfileUuid(tokenProfileUuid);
        return submit(route, request, null, created);
    }

    /**
     * @param onStored run in the transaction that stores the certificate, or null
     * @throws EstRequestClaimLostException when {@code onStored} found the claim taken over
     */
    private UUID submit(EstRoute route, ClientCertificateIssueRequestDto request, Consumer<UUID> onStored,
            Consumer<UUID> created) {
        RaProfile raProfile = route.raProfile();
        AtomicReference<UUID> submitted = new AtomicReference<>();
        Consumer<UUID> beforeDispatch = certificateUuid -> {
            submitted.set(certificateUuid);
            created.accept(certificateUuid);
        };
        try {
            ClientCertificateDataResponseDto response = clientOperationService
                    .issueCertificate(raProfile.getAuthorityInstanceReference().getSecuredParentUuid(),
                            raProfile.getSecuredUuid(), request,
                            CertificateProtocolInfo.est(route.estProfile().getUuid(), onStored), beforeDispatch);
            return UUID.fromString(response.getUuid());
        } catch (Exception e) {
            EstRequestClaimLostException.rethrowIfCause(e);
            throw answers.submissionFailed(route, submitted.get(), "The issue of an EST request", e);
        }
    }

    /** Records the answer that the certificate gives the client, as {@link #recordAnswer} does. */
    private Consumer<String> recordingAnswer(EstRoute route, EstClient client, UUID certificateUuid) {
        return outcome -> recordAnswer(route, client, certificateUuid, outcome);
    }

    /**
     * Logs the answer once, and hands it to the audit record of the request when there is one: the service-level
     * callers run without a request, which has no scope for the override to live in.
     */
    private void recordAnswer(EstRoute route, EstClient client, UUID certificateUuid, String outcome) {
        log
                .info("EST enrolment {} for certificate {}, client {}, realm {}", outcome, certificateUuid,
                        client.identity(), route.realm());
        if (RequestContextHolder.getRequestAttributes() != null) {
            auditOperationDataOverride
                    .set(new EstEnrollmentAudit(route.label(), client.policy(), client.identity(), outcome));
        }
    }

    /**
     * Answers from the certificate of the registration, the only certificate that the client may have. A registration
     * that this request completed answers it as its certificate stands. A registration without a request is completed
     * with this one, and only then is the certificate given the time to be issued. Any other is refused as a request
     * that matches no registration is, so that the client learns nothing about it.
     */
    private ResponseEntity<byte[]> enrollRegistration(EstRoute route, EstClient client, Pkcs10CertificateRequest csr,
            @Sensitive EstClientCredentials credentials) {
        UUID registrationUuid = client.registrationCertificateUuid();
        String requestFingerprint = answers.fingerprintOf(csr);
        EstRequestedCertificate registration = findRegistration(route, registrationUuid);
        if (requestFingerprint.equals(registration.getRequestFingerprint())) {
            return answerCompletedRegistration(route, client, registration, requestFingerprint);
        }
        completeOpenRegistration(route, registration, csr, credentials);
        CertificateState state = issuanceWait
                .awaitSettled(route, registrationUuid, requestFingerprint)
                .orElseThrow(() -> registrationRejected(route, registrationUuid, "no longer carries this request"));
        log.debug("Registration {} completed through EST is {}", registrationUuid, state);
        return answerRegistration(route, client, registrationUuid, state, requestFingerprint);
    }

    /**
     * Completes the registration that identified the client with the request, as {@link #complete} does, when the
     * registration still waits for a request.
     *
     * @return the certificate of the registration
     * @throws EstException {@link EstError#REGISTRATION_REJECTED} when the registration no longer exists, already
     * carries a request or cannot be completed, and as {@link #complete} throws
     */
    UUID completeRegistration(EstRoute route, EstClient client, Pkcs10CertificateRequest csr,
            @Sensitive EstClientCredentials credentials) {
        UUID registrationUuid = client.registrationCertificateUuid();
        try {
            EstRequestedCertificate registration = findRegistration(route, registrationUuid);
            completeOpenRegistration(route, registration, csr, credentials);
            return registrationUuid;
        } catch (EstException e) {
            log.warn("Registration {} could not be completed for the EST request: {}", registrationUuid, e.error());
            throw e;
        }
    }

    private EstRequestedCertificate findRegistration(EstRoute route, UUID registrationUuid) {
        return certificateRepository
                .findEstRequestedCertificateByUuid(registrationUuid)
                .orElseThrow(() -> registrationRejected(route, registrationUuid, "no longer exists"));
    }

    private void completeOpenRegistration(EstRoute route, EstRequestedCertificate registration,
            Pkcs10CertificateRequest csr, @Sensitive EstClientCredentials credentials) {
        if (registration.getState() != CertificateState.REGISTERED || registration.getRequestFingerprint() != null) {
            throw registrationRejected(route, registration.getUuid(),
                    "is " + registration.getState() + " and was not completed with this request");
        }
        complete(route, registration.getUuid(), csr, passwordOf(credentials));
    }

    /**
     * Answers at once, without verifying the password again, which is safe because the answer is only the public
     * certificate or a status: anyone who holds the request can repeat it, and an operator completion attaches a
     * request without the challenge. A {@code REGISTERED} registration carries this request, so its issue is still to
     * be claimed. One whose issue was never queued, as when the node stopped between attaching the request and queueing
     * its issue, stays so, and a client that polls it must not hold a thread each time.
     */
    private ResponseEntity<byte[]> answerCompletedRegistration(EstRoute route, EstClient client,
            EstRequestedCertificate registration, String requestFingerprint) {
        UUID registrationUuid = registration.getUuid();
        CertificateState state = registration.getState();
        log.debug("Registration {} was completed with this request and is {}", registrationUuid, state);
        if (state == CertificateState.ISSUED && !answers.isUnexpired(registration)) {
            throw registrationRejected(route, registrationUuid, "has expired");
        }
        return answerRegistration(route, client, registrationUuid, state, requestFingerprint);
    }

    /** The authenticator of {@code certificateRegistration} accepts no client without a Basic password. */
    private static String passwordOf(@Sensitive EstClientCredentials credentials) {
        return credentials
                .basic()
                .map(BasicCredentials::password)
                .orElseThrow(() -> new IllegalStateException("A registration client presented no Basic password"));
    }

    /**
     * Completes the registration through the platform, which verifies the password and counts a wrong one against it. A
     * refusal is answered as a request that matches no registration; a {@link CertificateException} as the service
     * being unavailable. Both are logged by class only.
     */
    private void complete(EstRoute route, UUID registrationUuid, Pkcs10CertificateRequest csr,
            @Sensitive String password) {
        RaProfile raProfile = route.raProfile();
        ClientCertificateIssueRequestDto request = issueRequests.completionRequest(route, csr, password);
        try {
            clientOperationExternalService
                    .issueExistingCertificate(raProfile.getAuthorityInstanceReference().getSecuredParentUuid(),
                            raProfile.getSecuredUuid(), registrationUuid.toString(), request);
        } catch (RequestAttributePolicyViolationException e) {
            throw new EstException(EstError.POLICY_VIOLATION, route.realm()).withDetail(e.getMessage());
        } catch (ValidationException | NotFoundException e) {
            throw registrationRejected(route, registrationUuid, "could not be completed: " + e.getClass().getName());
        } catch (CertificateException e) {
            answers.logClassNames("Registration " + registrationUuid + " could not be completed for EST", e);
            throw new EstException(EstError.SERVICE_UNAVAILABLE, route.realm());
        } catch (Exception e) {
            answers.logFailure("Registration " + registrationUuid + " could not be completed for EST", e);
            throw new EstException(EstError.SERVICE_UNAVAILABLE, route.realm());
        }
        applyEstAttribution(route, registrationUuid);
    }

    /**
     * The completion is stored and its issue queued, so failing to attribute the certificate to the EST Profile must
     * not fail the enrolment. A registration completed again after a refused approval keeps its one protocol
     * association, which the platform attributes to this EST Profile again. Only the class of a failure is logged, as
     * its text can quote what the platform read.
     */
    private void applyEstAttribution(EstRoute route, UUID registrationUuid) {
        try {
            certificateService
                    .applyProtocolAssociations(registrationUuid,
                            CertificateProtocolInfo.est(route.estProfile().getUuid()));
        } catch (Exception e) {
            log
                    .warn("The completed registration {} could not be attributed to EST: {}", registrationUuid,
                            e.getClass().getName());
        }
    }

    /**
     * Answers by the state that the registration has with the request. A {@code REGISTERED} one was read with the
     * fingerprint of the request, so it carries the request and its issue is still to be claimed.
     */
    private ResponseEntity<byte[]> answerRegistration(EstRoute route, EstClient client, UUID registrationUuid,
            CertificateState state, String requestFingerprint) {
        return switch (state) {
            case ISSUED -> answerIssuedRegistration(route, client, registrationUuid, requestFingerprint);
            case REQUESTED, PENDING_APPROVAL, PENDING_ISSUE, REGISTERED ->
                answers.pending(route, recordingAnswer(route, client, registrationUuid));
            default -> throw registrationRejected(route, registrationUuid, "is " + state);
        };
    }

    private ResponseEntity<byte[]> answerIssuedRegistration(EstRoute route, EstClient client, UUID registrationUuid,
            String requestFingerprint) {
        X509Certificate certificate = answers
                .issuedCertificate(registrationUuid, requestFingerprint)
                .orElseThrow(() -> registrationRejected(route, registrationUuid, "holds no content for this request"));
        return answers.issued(certificate, recordingAnswer(route, client, registrationUuid));
    }

    /** Refuses a request that the registration of the client cannot answer, as one that matches no registration. */
    static EstException registrationRejected(EstRoute route, UUID registrationUuid, String reason) {
        log.debug("Registration {} does not answer the EST request: it {}", registrationUuid, reason);
        return new EstException(EstError.REGISTRATION_REJECTED, route.realm());
    }
}
