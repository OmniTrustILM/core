package com.otilm.core.service.est.enrollment;

import com.otilm.api.exception.CertificateOperationException;
import com.otilm.api.model.core.certificate.CertificateState;
import com.otilm.core.certificate.request.RequestAttributePolicyViolationException;
import com.otilm.core.dao.repository.CertificateRepository;
import com.otilm.core.dao.repository.EstRequestedCertificate;
import com.otilm.core.model.request.Pkcs10CertificateRequest;
import com.otilm.core.service.est.EstConnectorFailures;
import com.otilm.core.service.est.EstRoute;
import com.otilm.core.service.est.message.EstError;
import com.otilm.core.service.est.message.EstException;
import com.otilm.core.service.est.message.EstResponses;
import com.otilm.core.util.CertificateUtil;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.time.Duration;
import java.util.Date;
import java.util.Optional;
import java.util.UUID;
import java.util.function.Consumer;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Component;

/**
 * How an EST request that asks for a certificate is answered once the certificate that the request created is known,
 * and how its failures are logged. Every answer with a certificate comes from a read that requires the certificate to
 * carry the request, so that no request is answered with the certificate of another. It writes nothing and holds no
 * transaction.
 */
@Slf4j
@Component
class EstAnswers {

    private final CertificateRepository certificateRepository;

    EstAnswers(CertificateRepository certificateRepository) {
        this.certificateRepository = certificateRepository;
    }

    /** @return SHA-256 of the request in lower-case hexadecimal, as the inventory keeps the fingerprint of a request */
    String fingerprintOf(Pkcs10CertificateRequest csr) {
        try {
            return CertificateUtil.getThumbprint(csr.getEncoded());
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException("SHA-256 is not available", e);
        }
    }

    /**
     * Whether a certificate that the same request created answers a retry of it: an issued certificate that has not
     * expired, one that is on its way, or one that was rejected. A {@code REGISTERED} one was found by the fingerprint
     * of the request, so it carries the request and is a completion on its way. A failed, revoked or expired one, and a
     * state that no request reaches, lets the retry start a new request.
     */
    boolean answersRetry(EstRequestedCertificate found) {
        return switch (found.getState()) {
            case ISSUED -> isUnexpired(found);
            case REQUESTED, PENDING_APPROVAL, PENDING_ISSUE, REGISTERED, REJECTED -> true;
            default -> false;
        };
    }

    /** Whether the certificate has no end of validity yet, or one that has not passed. */
    boolean isUnexpired(EstRequestedCertificate certificate) {
        return certificate.getNotAfter() == null || certificate.getNotAfter().after(new Date());
    }

    /**
     * Answers by the state that the certificate has with the request. A {@code REGISTERED} one was read with the
     * fingerprint of the request, so it carries the request and its completion is on its way.
     *
     * @param recordOutcome told {@link EstEnrollmentAudit#ISSUED} or {@link EstEnrollmentAudit#PENDING} once the answer
     * is known, and nothing for a refusal
     * @throws EstException {@link EstError#REQUEST_REJECTED} when the certificate was rejected, and
     * {@link EstError#ISSUANCE_FAILED} when it could not be issued
     * @throws IllegalStateException when the certificate is in a state that no request reaches, or is issued without
     * content for the request
     */
    ResponseEntity<byte[]> answer(EstRoute route, UUID certificateUuid, String requestFingerprint,
            CertificateState state, Consumer<String> recordOutcome) {
        return switch (state) {
            case ISSUED -> answerIssued(certificateUuid, requestFingerprint, recordOutcome);
            case REQUESTED, PENDING_APPROVAL, PENDING_ISSUE, REGISTERED -> pending(route, recordOutcome);
            case REJECTED -> throw new EstException(EstError.REQUEST_REJECTED, route.realm());
            case FAILED -> throw new EstException(EstError.ISSUANCE_FAILED, route.realm());
            default -> throw new IllegalStateException(
                    "Certificate " + certificateUuid + " requested through EST is in the unexpected state " + state);
        };
    }

    private ResponseEntity<byte[]> answerIssued(UUID certificateUuid, String requestFingerprint,
            Consumer<String> recordOutcome) {
        X509Certificate certificate = issuedCertificate(certificateUuid, requestFingerprint)
                .orElseThrow(() -> new IllegalStateException(
                        "Issued certificate " + certificateUuid + " holds no content for its request"));
        return issued(certificate, recordOutcome);
    }

    /**
     * Reads the content in the same query that requires the request, so that a certificate given another request since
     * its state was read never gives its content to this one.
     */
    Optional<X509Certificate> issuedCertificate(UUID certificateUuid, String requestFingerprint) {
        return certificateRepository
                .findContentByUuidAndRequestFingerprint(certificateUuid, requestFingerprint)
                .map(content -> parse(certificateUuid, content));
    }

    /** Answers with the certificate, as a certificates-only CMS. */
    ResponseEntity<byte[]> issued(X509Certificate certificate, Consumer<String> recordOutcome) {
        ResponseEntity<byte[]> response = EstResponses.enrolled(certificate);
        recordOutcome.accept(EstEnrollmentAudit.ISSUED);
        return response;
    }

    /** Answers that the certificate is not ready yet, telling the client when to ask again, as its EST Profile sets. */
    ResponseEntity<byte[]> pending(EstRoute route, Consumer<String> recordOutcome) {
        recordOutcome.accept(EstEnrollmentAudit.PENDING);
        return EstResponses.pending(Duration.ofSeconds(route.estProfile().getRetryAfter()));
    }

    /**
     * Answers a failure to take a request for a new certificate: a policy violation with the platform's text, a failed
     * issue once the platform has handed over the new certificate's UUID, otherwise service unavailable. Logged once,
     * by the rule of {@link #logFailure}.
     *
     * @param submittedUuid the certificate that the platform handed to that step, {@code null} when it handed none
     * @param what what was submitted, as the log line names it
     */
    EstException submissionFailed(EstRoute route, UUID submittedUuid, String what, Exception failure) {
        if (failure instanceof RequestAttributePolicyViolationException violation) {
            return new EstException(EstError.POLICY_VIOLATION, route.realm()).withDetail(violation.getMessage());
        }
        if (submittedUuid != null) {
            logFailure(what + " could not be queued for certificate " + submittedUuid, failure);
            return new EstException(EstError.ISSUANCE_FAILED, route.realm());
        }
        logFailure(what + " could not be submitted", failure);
        return new EstException(EstError.SERVICE_UNAVAILABLE, route.realm());
    }

    /**
     * Logs a failure that is answered as unavailable or failed, once. The platform logged a
     * {@link CertificateOperationException} before it shaped it, keeping validation text without the cause, and what a
     * connector reports can echo the credentials of the authority, so both are logged by the classes of their chain
     * only. Any other failure is logged with its stack trace.
     */
    void logFailure(String what, Exception failure) {
        if (failure instanceof CertificateOperationException || EstConnectorFailures.isConnectorFailure(failure)) {
            logClassNames(what, failure);
        } else {
            log.error(what, failure);
        }
    }

    /** Logs a failure by the classes of its chain only, without any message. */
    void logClassNames(String what, Exception failure) {
        log.error("{}: {}", what, EstConnectorFailures.classNames(failure));
    }

    private static X509Certificate parse(UUID certificateUuid, String content) {
        try {
            return CertificateUtil.getX509Certificate(content);
        } catch (CertificateException e) {
            throw new IllegalStateException("Issued certificate " + certificateUuid + " cannot be parsed", e);
        }
    }
}
