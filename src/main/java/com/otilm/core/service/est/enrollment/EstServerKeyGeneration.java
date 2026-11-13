package com.otilm.core.service.est.enrollment;

import com.otilm.api.exception.AttributeException;
import com.otilm.api.exception.CertificateRequestException;
import com.otilm.api.exception.NotFoundException;
import com.otilm.api.model.client.certificate.CancelPendingCertificateRequestDto;
import com.otilm.api.model.core.auth.Resource;
import com.otilm.api.model.core.certificate.CertificateState;
import com.otilm.api.model.core.est.EstAuthenticationPolicy;
import com.otilm.api.model.core.logging.Sensitive;
import com.otilm.core.aop.AuditOperationDataOverride;
import com.otilm.core.dao.entity.RaProfile;
import com.otilm.core.dao.repository.ApprovalProfileRelationRepository;
import com.otilm.core.key.normalization.Pkcs8Envelopes;
import com.otilm.core.model.request.Pkcs10CertificateRequest;
import com.otilm.core.service.est.EstRoute;
import com.otilm.core.service.est.authentication.EstClient;
import com.otilm.core.service.est.authentication.EstClientCredentials;
import com.otilm.core.service.est.enrollment.EstKeyPairGenerator.GeneratedKey;
import com.otilm.core.service.est.enrollment.EstKeyRecovery.NoSignatureAlgorithmException;
import com.otilm.core.service.est.enrollment.EstKeyRecovery.TokenKey;
import com.otilm.core.service.est.message.EstError;
import com.otilm.core.service.est.message.EstException;
import com.otilm.core.service.est.message.EstResponses;
import com.otilm.core.service.est.message.EstServerKeyGenerationRequest;
import com.otilm.core.service.est.message.EstServerKeyGenerationRequest.Content;
import com.otilm.core.service.v2.CancelConfirmation;
import com.otilm.core.service.v2.ClientOperationExternalService;
import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.PublicKey;
import java.security.cert.X509Certificate;
import java.time.Duration;
import java.util.Arrays;
import java.util.Optional;
import java.util.UUID;
import java.util.concurrent.atomic.AtomicReference;
import lombok.extern.slf4j.Slf4j;
import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Component;
import org.springframework.web.context.request.RequestContextHolder;

/**
 * Answers an authenticated {@code /serverkeygen}: generates a key pair, submits a request signed by the new key, waits
 * for the certificate and answers with the key and the certificate. In memory the key is dropped once the answer is
 * built; with key recovery the token profile of the EST Profile keeps it, linked to the certificate. It holds no
 * transaction on purpose, because submitting and waiting take as long as the connector takes.
 */
@Slf4j
@Component
public class EstServerKeyGeneration {

    private static final String CANCEL_REASON = "EST server-side key generation timed out";

    private static final Runnable NO_KEY_TO_DISCARD = () -> {
    };

    private final EstEnrollment enrollment;
    private final EstKeyRecovery keyRecovery;
    private final EstIssuanceWait issuanceWait;
    private final EstAnswers answers;
    private final ClientOperationExternalService clientOperationService;
    private final ApprovalProfileRelationRepository approvalProfileRelationRepository;

    private AuditOperationDataOverride auditOperationDataOverride;

    EstServerKeyGeneration(EstEnrollment enrollment, EstKeyRecovery keyRecovery, EstIssuanceWait issuanceWait,
            EstAnswers answers, ClientOperationExternalService clientOperationService,
            ApprovalProfileRelationRepository approvalProfileRelationRepository) {
        this.enrollment = enrollment;
        this.keyRecovery = keyRecovery;
        this.issuanceWait = issuanceWait;
        this.answers = answers;
        this.clientOperationService = clientOperationService;
        this.approvalProfileRelationRepository = approvalProfileRelationRepository;
    }

    @Autowired
    public void setAuditOperationDataOverride(AuditOperationDataOverride auditOperationDataOverride) {
        this.auditOperationDataOverride = auditOperationDataOverride;
    }

    /**
     * Refuses a route that cannot answer a key generation before the request is read. An approval would keep the
     * certificate from being issued while the request waits, and the key cannot be handed out later.
     *
     * @throws EstException {@link EstError#SERVER_KEYGEN_DISABLED} when the EST Profile does not generate keys, and
     * {@link EstError#SERVER_KEYGEN_UNAVAILABLE} when the RA Profile asks for an approval
     */
    public void requireAvailable(EstRoute route) {
        if (!route.estProfile().isServerKeyGeneration()) {
            log.debug("EST Profile {} does not generate keys", route.estProfile().getUuid());
            throw new EstException(EstError.SERVER_KEYGEN_DISABLED, route.realm());
        }
        UUID raProfileUuid = route.raProfile().getUuid();
        if (approvalProfileRelationRepository.existsByResourceAndResourceUuid(Resource.RA_PROFILE, raProfileUuid)) {
            log.debug("RA Profile {} asks for an approval, so it cannot answer a key generation", raProfileUuid);
            throw new EstException(EstError.SERVER_KEYGEN_UNAVAILABLE, route.realm());
        }
    }

    /**
     * @param route the route of the request, which {@link #requireAvailable} accepted
     * @param client the client that the policy of the route identified
     * @param clientCsr the request of the client, whose subject and requested extensions the new request carries
     * @param credentials what the client presented: under {@code certificateRegistration} the Basic password is the
     * challenge that completing the registration verifies
     * @return the new private key and its certificate
     * @throws EstException {@link EstError#POLICY_VIOLATION} when the request does not meet the policy of the RA
     * Profile, {@link EstError#REQUEST_REJECTED} when the certificate was rejected, {@link EstError#ISSUANCE_FAILED}
     * when it could not be issued, {@link EstError#ISSUANCE_TIMED_OUT} when it was not issued in time,
     * {@link EstError#SERVICE_UNAVAILABLE} when the request could not be submitted, and
     * {@link EstError#REGISTRATION_REJECTED} when the registration of the client cannot take the request; each answer,
     * a refusal included, is logged once and recorded in the audit record of the request
     */
    public ResponseEntity<byte[]> generate(EstRoute route, EstClient client, Pkcs10CertificateRequest clientCsr,
            @Sensitive EstClientCredentials credentials) {
        Trail trail = new Trail(EstServerKeyGenerationMode.of(route.estProfile()));
        String outcome = EstError.INTERNAL_ERROR.name();
        try {
            Content content = contentOf(route, clientCsr);
            ResponseEntity<byte[]> answer = switch (trail.mode) {
                case IN_MEMORY -> generateInMemory(route, client, clientCsr, content, credentials, trail);
                case KEY_RECOVERY -> generateOnToken(route, client, content, credentials, trail);
            };
            outcome = EstEnrollmentAudit.ISSUED;
            return answer;
        } catch (EstException refusal) {
            outcome = refusal.error().name();
            throw refusal;
        } finally {
            recordAnswer(route, client, trail, outcome);
        }
    }

    /**
     * What a key generation has created so far, for its log line; either is {@code null} until it exists, and the key
     * stays {@code null} in memory, where nothing keeps it.
     */
    private static final class Trail {

        private final EstServerKeyGenerationMode mode;
        private UUID certificateUuid;
        private UUID keyUuid;

        private Trail(EstServerKeyGenerationMode mode) {
            this.mode = mode;
        }
    }

    private ResponseEntity<byte[]> generateInMemory(EstRoute route, EstClient client,
            Pkcs10CertificateRequest clientCsr, Content content, @Sensitive EstClientCredentials credentials,
            Trail trail) {
        GeneratedKey generated = generateLike(route, clientCsr, content);
        Pkcs10CertificateRequest request = toPkcs10(generated);
        UUID certificateUuid = switch (client.policy()) {
            case RA_BASIC, VENDOR_MTLS, RA_MTLS -> enrollment.submit(route, request);
            case CERTIFICATE_REGISTRATION -> enrollment.completeRegistration(route, client, request, credentials);
        };
        trail.certificateUuid = certificateUuid;
        X509Certificate certificate = awaitIssued(route, client, certificateUuid, answers.fingerprintOf(request), null,
                NO_KEY_TO_DISCARD);
        if (!certifies(certificate, generated.keyPair().getPublic())) {
            throw certifiesAnotherKey(route, certificateUuid);
        }
        return EstResponses.serverKeyGenerated(privateKeyInfoOf(generated), certificate);
    }

    /**
     * Generates the key on the key-recovery token profile of the EST Profile, which keeps it linked to the certificate,
     * and answers with the key that it exports once the certificate is issued. The key is destroyed only on proof that
     * the authority will not certify it: the certificate was rejected, its request never reached the authority, or the
     * authority confirmed the cancel of an issue that timed out. Any other failure keeps the key linked to its
     * certificate, which an operator can destroy once the certificate is failed or rejected.
     */
    private ResponseEntity<byte[]> generateOnToken(EstRoute route, EstClient client, Content content,
            @Sensitive EstClientCredentials credentials, Trail trail) {
        TokenKey key = createKey(route);
        trail.keyUuid = key.keyUuid();
        Submission submission = submitSignedBy(route, client, content, credentials, key);
        UUID certificateUuid = submission.certificateUuid();
        trail.certificateUuid = certificateUuid;
        X509Certificate certificate = awaitIssued(route, client, certificateUuid, submission.requestFingerprint(),
                key.keyUuid(), () -> keyRecovery.destroy(certificateUuid, key));
        return answerWithTheExportedKey(route, certificateUuid, certificate, key);
    }

    /**
     * Logs the answer once, without any key material, and hands it to the audit record of the request when there is
     * one: the service-level callers run without a request, which has no scope for the override to live in.
     *
     * @param outcome {@link EstEnrollmentAudit#ISSUED}, or the name of the {@link EstError} the request is refused
     * with, which is {@link EstError#INTERNAL_ERROR} for an unexpected failure
     */
    private void recordAnswer(EstRoute route, EstClient client, Trail trail, String outcome) {
        log
                .info("EST server-side key generation {} {} for certificate {}, key {}, client {}, realm {}", outcome,
                        trail.mode.getCode(), orDash(trail.certificateUuid), orDash(trail.keyUuid), client.identity(),
                        route.realm());
        if (RequestContextHolder.getRequestAttributes() != null) {
            auditOperationDataOverride
                    .set(new EstServerKeyGenerationAudit(route.label(), client.policy(), client.identity(), trail.mode,
                            outcome));
        }
    }

    private static Object orDash(UUID uuid) {
        return uuid == null ? "-" : uuid;
    }

    /** The request submitted for a certificate and the fingerprint by which its answer is read. */
    private record Submission(UUID certificateUuid, String requestFingerprint) {
    }

    private TokenKey createKey(EstRoute route) {
        try {
            return keyRecovery.create(route);
        } catch (Exception e) {
            answers.logFailure("The key for an EST request could not be created", e);
            throw new EstException(EstError.SERVICE_UNAVAILABLE, route.realm());
        }
    }

    /**
     * Submits a request signed by the token key, as the request of a key generated in memory is submitted. A request
     * that fails is answered as refused, and its key is destroyed when the request provably never reached the
     * authority, as {@link #keepOrDestroyUnsubmitted} tells.
     */
    private Submission submitSignedBy(EstRoute route, EstClient client, Content content,
            @Sensitive EstClientCredentials credentials, TokenKey key) {
        AtomicReference<UUID> dispatched = new AtomicReference<>();
        Pkcs10CertificateRequest request = null;
        try {
            request = signRequest(route, key, content);
            UUID certificateUuid = switch (client.policy()) {
                case RA_BASIC, VENDOR_MTLS, RA_MTLS ->
                    enrollment.submitForKey(route, request, key.keyUuid(), key.tokenProfileUuid(), dispatched::set);
                case CERTIFICATE_REGISTRATION -> enrollment.completeRegistration(route, client, request, credentials);
            };
            return new Submission(certificateUuid, answers.fingerprintOf(request));
        } catch (Exception e) {
            keepOrDestroyUnsubmitted(client, key, request, dispatched.get());
            throw e instanceof EstException refusal
                    ? refusal
                    : answers.submissionFailed(route, null, "The request signed by token key " + key.keyUuid(), e);
        }
    }

    /**
     * Keeps or destroys the key of a request whose submission failed. A request that was never signed reached nobody.
     * The platform runs the dispatch step of a new certificate once it is stored and right before its issue is queued,
     * and a queue that failed may still have delivered the issue, so a certificate that the step ran for may still be
     * certified. A registration carries the request from the moment it is attached, right before its issue is queued,
     * until a failed queue takes it off again, after which no issue queued for it is claimed, so one that does not
     * carry the request will not be certified with the key.
     *
     * @param request the signed request, or {@code null} when the key did not sign one
     * @param dispatchedUuid the certificate that the dispatch step ran for, or {@code null} when it did not run
     */
    private void keepOrDestroyUnsubmitted(EstClient client, TokenKey key, Pkcs10CertificateRequest request,
            UUID dispatchedUuid) {
        boolean registration = client.policy() == EstAuthenticationPolicy.CERTIFICATE_REGISTRATION;
        UUID certificateUuid = registration ? client.registrationCertificateUuid() : dispatchedUuid;
        boolean mayBeCertified = request != null && certificateUuid != null
                && (!registration || mayCarry(certificateUuid, request));
        if (mayBeCertified) {
            keepKey(certificateUuid, key.keyUuid(), "may have been requested from the authority");
        } else {
            keyRecovery.destroy(certificateUuid, key);
        }
    }

    /** Whether the registration carries the request, which it does as well when it cannot be read. */
    private boolean mayCarry(UUID registrationUuid, Pkcs10CertificateRequest request) {
        try {
            return issuanceWait.carriesRequest(registrationUuid, answers.fingerprintOf(request));
        } catch (RuntimeException e) {
            log
                    .warn("Registration {} could not be read after its completion through EST failed: {}",
                            registrationUuid, e.getClass().getName());
            return true;
        }
    }

    /**
     * Has the token key sign the request. A key of a type that no signature algorithm of the platform signs with is a
     * configuration of the token profile that no retry changes, so it is answered as an internal error.
     */
    private Pkcs10CertificateRequest signRequest(EstRoute route, TokenKey key, Content content)
            throws NotFoundException, GeneralSecurityException, IOException, AttributeException,
            CertificateRequestException {
        try {
            return keyRecovery.signRequest(key, content);
        } catch (NoSignatureAlgorithmException e) {
            log.error("Token key {} cannot sign the request of an EST client: {}", key.keyUuid(), e.getMessage());
            throw new EstException(EstError.INTERNAL_ERROR, route.realm());
        }
    }

    /**
     * Exports the key of the issued certificate and answers with it. The certificate and the key stay as they are when
     * the key cannot be exported or is not the key of the certificate, as the authority has issued the certificate and
     * the key can be recovered through the key export.
     */
    private ResponseEntity<byte[]> answerWithTheExportedKey(EstRoute route, UUID certificateUuid,
            X509Certificate certificate, TokenKey key) {
        PrivateKeyInfo exported = export(route, certificateUuid, key);
        try {
            boolean certified = keyRecovery
                    .publicKeyOf(exported)
                    .filter(exportedKey -> certifies(certificate, exportedKey))
                    .isPresent();
            if (!certified) {
                throw certifiesAnotherKey(route, certificateUuid);
            }
            return EstResponses.serverKeyGenerated(exported, certificate);
        } finally {
            Pkcs8Envelopes.overwrite(exported);
        }
    }

    private PrivateKeyInfo export(EstRoute route, UUID certificateUuid, TokenKey key) {
        try {
            return keyRecovery.export(key);
        } catch (Exception e) {
            log
                    .error("Key {} of certificate {} requested through EST could not be exported: {}", key.keyUuid(),
                            certificateUuid, e.getClass().getName());
            throw new EstException(EstError.INTERNAL_ERROR, route.realm());
        }
    }

    /** The content of the client's request; a refusal of it is thrown again with the realm of the route. */
    private static Content contentOf(EstRoute route, Pkcs10CertificateRequest clientCsr) {
        try {
            return EstServerKeyGenerationRequest.contentOf(clientCsr.getJcaObject());
        } catch (EstException e) {
            throw e.withRealm(route.realm());
        }
    }

    /**
     * Generates a key like the client's and a request signed by it. The generator knows no route, so a refusal of it is
     * thrown again with the realm of the route.
     */
    private static GeneratedKey generateLike(EstRoute route, Pkcs10CertificateRequest clientCsr, Content content) {
        try {
            return EstKeyPairGenerator
                    .generate(clientCsr.getJcaObject().getSubjectPublicKeyInfo(), content.subject(),
                            content.extensions());
        } catch (EstException e) {
            throw e.withRealm(route.realm());
        }
    }

    /**
     * @param keyUuid the key-recovery key of the certificate, or {@code null} for a key generated in memory
     * @param discardKey discards the key of a certificate that the authority will not certify: one that was rejected,
     * or whose issue the authority confirmed cancelled or does not know; every other certificate keeps its key, as a
     * failed one may have failed after the authority took its request, by an operator's cancel that the authority did
     * not confirm, say
     */
    private X509Certificate awaitIssued(EstRoute route, EstClient client, UUID certificateUuid,
            String requestFingerprint, UUID keyUuid, Runnable discardKey) {
        Optional<CertificateState> settled = awaitSettled(route, certificateUuid, requestFingerprint, keyUuid);
        if (settled.isEmpty()) {
            keepKey(certificateUuid, keyUuid, "no longer carries its request");
            throw requestLost(route, client, certificateUuid);
        }
        CertificateState state = settled.get();
        log.debug("Certificate {} requested through EST with a generated key is {}", certificateUuid, state);
        return switch (state) {
            case ISSUED -> answers
                    .issuedCertificate(certificateUuid, requestFingerprint)
                    .orElseThrow(() -> new IllegalStateException(
                            "Issued certificate " + certificateUuid + " holds no content for its request"));
            case REJECTED ->
                throw discarded(discardKey, refused(route, certificateUuid, "was rejected", EstError.REQUEST_REJECTED));
            case FAILED -> {
                keepKey(certificateUuid, keyUuid, "failed");
                throw refused(route, certificateUuid, "could not be issued", EstError.ISSUANCE_FAILED);
            }
            case REQUESTED, PENDING_APPROVAL, PENDING_ISSUE, REGISTERED ->
                throw timedOut(route, certificateUuid, state, keyUuid, discardKey);
            default -> throw new IllegalStateException(
                    "Certificate " + certificateUuid + " requested through EST is in the unexpected state " + state);
        };
    }

    /**
     * Waits for the certificate to settle. A wait that fails, as when the certificate is deleted meanwhile, tells
     * nothing about the authority, so the key is kept.
     */
    private Optional<CertificateState> awaitSettled(EstRoute route, UUID certificateUuid, String requestFingerprint,
            UUID keyUuid) {
        Duration timeout = Duration.ofSeconds(route.estProfile().getServerKeyGenerationTimeout());
        try {
            return issuanceWait.awaitSettledThroughStatusPolls(certificateUuid, requestFingerprint, timeout);
        } catch (RuntimeException e) {
            keepKey(certificateUuid, keyUuid, "could not be waited for");
            throw e;
        }
    }

    /**
     * Cancels an issue that the authority has accepted, so that the certificate of a key that nobody keeps fails rather
     * than being issued later, and discards its key once the authority will not issue it. A certificate in any other
     * state, or one whose authority refuses the cancel or does not confirm it, keeps its key.
     */
    private EstException timedOut(EstRoute route, UUID certificateUuid, CertificateState state, UUID keyUuid,
            Runnable discardKey) {
        if (state == CertificateState.PENDING_ISSUE && cancel(route, certificateUuid, keyUuid)) {
            discardKey.run();
        }
        return refused(route, certificateUuid, "was not issued in time, waiting in " + state,
                EstError.ISSUANCE_TIMED_OUT);
    }

    private static EstException discarded(Runnable discardKey, EstException refusal) {
        discardKey.run();
        return refusal;
    }

    /**
     * Logs that the key-recovery key stays linked to its certificate, as the authority may still certify it.
     *
     * @param keyUuid the key, or {@code null} for a key generated in memory, which nothing keeps
     */
    private static void keepKey(UUID certificateUuid, UUID keyUuid, String reason) {
        if (keyUuid != null) {
            log
                    .warn("Key {} of certificate {} requested through EST is kept linked to it, as the certificate {}",
                            keyUuid, certificateUuid, reason);
        }
    }

    /**
     * @return whether the authority will not issue the certificate: it cancelled the issue or does not know it. An
     * authority that could not be asked may still issue it, so the key stays linked to the certificate.
     */
    private boolean cancel(EstRoute route, UUID certificateUuid, UUID keyUuid) {
        RaProfile raProfile = route.raProfile();
        CancelPendingCertificateRequestDto request = new CancelPendingCertificateRequestDto();
        request.setReason(CANCEL_REASON);
        try {
            CancelConfirmation confirmation = clientOperationService
                    .cancelPendingCertificateOperationWithConfirmation(
                            raProfile.getAuthorityInstanceReference().getSecuredParentUuid(),
                            raProfile.getSecuredUuid(), certificateUuid.toString(), request);
            if (confirmation == CancelConfirmation.UNCONFIRMED) {
                log
                        .warn("The authority did not confirm the cancel of the issue of certificate {} requested through EST; key {} is kept",
                                certificateUuid, orDash(keyUuid));
                return false;
            }
            return true;
        } catch (Exception e) {
            log
                    .warn("The issue of certificate {} requested through EST could not be cancelled: {}; key {} is kept",
                            certificateUuid, e.getClass().getName(), orDash(keyUuid));
            return false;
        }
    }

    /**
     * A registration whose request was taken off during the wait is refused as {@code /simpleenroll} refuses it; any
     * other certificate that lost its request answers as one that could not be issued.
     */
    private static EstException requestLost(EstRoute route, EstClient client, UUID certificateUuid) {
        if (client.policy() == EstAuthenticationPolicy.CERTIFICATE_REGISTRATION) {
            log
                    .warn("Registration {} completed through EST with a generated key no longer carries its request",
                            certificateUuid);
            return EstEnrollment.registrationRejected(route, certificateUuid, "no longer carries this request");
        }
        return refused(route, certificateUuid, "no longer carries its request", EstError.ISSUANCE_FAILED);
    }

    /**
     * Whether the certificate certifies the key, by the key material that both encode. The key is handed out only with
     * a certificate for it.
     */
    private static boolean certifies(X509Certificate certificate, PublicKey key) {
        Optional<PublicKey> certifiedKey = EstPublicKeys.read(certificate.getPublicKey().getEncoded());
        return certifiedKey.isPresent() && certifiedKey.equals(EstPublicKeys.read(key.getEncoded()));
    }

    /** A certificate for another key is left as it is, as the authority has issued it. */
    private static EstException certifiesAnotherKey(EstRoute route, UUID certificateUuid) {
        log.error("Certificate {} requested through EST with a generated key certifies another key", certificateUuid);
        return new EstException(EstError.INTERNAL_ERROR, route.realm());
    }

    private static EstException refused(EstRoute route, UUID certificateUuid, String reason, EstError error) {
        log.warn("Certificate {} requested through EST with a generated key {}", certificateUuid, reason);
        return new EstException(error, route.realm());
    }

    private static Pkcs10CertificateRequest toPkcs10(GeneratedKey generated) {
        try {
            return new Pkcs10CertificateRequest(generated.request().getEncoded());
        } catch (IOException | CertificateRequestException e) {
            throw new IllegalStateException("The request signed by a generated key cannot be encoded", e);
        }
    }

    /** The private key for the answer, which consumes it; the encoding read from the key is zeroed. */
    private static PrivateKeyInfo privateKeyInfoOf(GeneratedKey generated) {
        byte[] encoded = generated.keyPair().getPrivate().getEncoded();
        try {
            return PrivateKeyInfo.getInstance(encoded);
        } finally {
            Arrays.fill(encoded, (byte) 0);
        }
    }
}
