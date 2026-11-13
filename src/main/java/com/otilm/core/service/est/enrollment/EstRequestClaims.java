package com.otilm.core.service.est.enrollment;

import com.otilm.api.model.core.certificate.CertificateState;
import com.otilm.core.dao.entity.est.EstRequestClaim.Operation;
import com.otilm.core.dao.repository.EstRequestedCertificate;
import com.otilm.core.dao.repository.est.EstRequestClaimRepository.ClaimLink;
import com.otilm.core.service.est.EstRoute;
import com.otilm.core.service.writer.est.EstRequestClaimLostException;
import com.otilm.core.service.writer.est.EstRequestClaimWriter;
import java.time.Duration;
import java.util.Optional;
import java.util.UUID;
import java.util.function.Consumer;
import java.util.function.Supplier;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Component;

/**
 * Lets one of several identical concurrent requests submit, so that a retry that arrives while its twin is still being
 * submitted does not issue a second certificate; the others follow the claim to the certificate that it links once the
 * winner stored it, and answer from that certificate in whatever state it reached. A winner whose claim was taken over
 * before it stored its certificate stores nothing and follows the claim too. Only the link joins the transaction that
 * stores the certificate; every other claim write and read is a short transaction of its own, so no connection is held
 * while the connector works or a request waits.
 */
@Slf4j
@Component
class EstRequestClaims {

    private final EstRequestClaimWriter claimWriter;
    private final EstIssuanceWait issuanceWait;

    EstRequestClaims(EstRequestClaimWriter claimWriter, EstIssuanceWait issuanceWait) {
        this.claimWriter = claimWriter;
        this.issuanceWait = issuanceWait;
    }

    /** What a caller does for the request that it answers; the helper decides when each step runs. */
    interface ClaimedRequest {

        /** @return the certificate that a previous identical request created and that still answers a retry */
        Optional<EstRequestedCertificate> find();

        /**
         * Submits the request, including the checks that precede a submission.
         *
         * @param onStored to be run inside the transaction that stores the certificate, as
         * {@link com.otilm.core.model.auth.CertificateProtocolInfo#getOnStored()} is; it throws
         * {@link EstRequestClaimLostException} when the claim was taken over, which the submission lets through
         * @return the new certificate
         */
        UUID submit(Consumer<UUID> onStored);

        /** Answers by the state that the certificate reached. */
        ResponseEntity<byte[]> answer(UUID certificateUuid, CertificateState state);

        /** Answers that the certificate is not ready, for a request that waited and saw none appear. */
        ResponseEntity<byte[]> pending();
    }

    /**
     * Answers the request from the certificate that an identical one created, or submits it when none did.
     *
     * @param requestKey tells the requests that are identical apart, within the route and the operation
     * @param requestFingerprint SHA-256 of the request, which the certificate must carry to answer it
     * @throws IllegalStateException when the certificate no longer carries the request once it was awaited
     */
    ResponseEntity<byte[]> answerOnce(EstRoute route, Operation operation, String requestKey, String requestFingerprint,
            ClaimedRequest request) {
        Optional<EstRequestedCertificate> found = request.find();
        if (found.isPresent()) {
            return answerFrom(found.get(), request);
        }
        UUID estProfileUuid = route.estProfile().getUuid();
        UUID raProfileUuid = route.raProfile().getUuid();
        Supplier<Optional<ClaimLink>> readClaim = () -> claimWriter
                .findLink(estProfileUuid, raProfileUuid, operation, requestKey);
        Duration timeout = EstIssuanceWait.issueWaitTimeout(route);
        Optional<UUID> claim = claimWriter.claim(estProfileUuid, raProfileUuid, operation, requestKey);
        return claim.isPresent()
                ? submitClaimed(claim.get(), timeout, requestFingerprint, request, readClaim)
                : followClaim(timeout, requestFingerprint, request, readClaim);
    }

    /**
     * Submits under the claim, which is released as soon as the submission returned or threw and before the wait, so
     * that a request that arrives meanwhile finds the certificate instead of waiting for the claim; a claim that links
     * the certificate stays. A previous winner may have committed its certificate since the caller looked, so it looks
     * once more.
     */
    private ResponseEntity<byte[]> submitClaimed(UUID claimUuid, Duration timeout, String requestFingerprint,
            ClaimedRequest request, Supplier<Optional<ClaimLink>> readClaim) {
        Optional<EstRequestedCertificate> committed;
        UUID certificateUuid = null;
        try {
            committed = request.find();
            if (committed.isEmpty()) {
                certificateUuid = request.submit(stored -> claimWriter.link(claimUuid, stored));
            }
        } catch (EstRequestClaimLostException e) {
            log
                    .debug("EST request claim {} was taken over while its request was submitted, so it follows the claim",
                            claimUuid);
            return followClaim(timeout, requestFingerprint, request, readClaim);
        } finally {
            claimWriter.release(claimUuid);
        }
        if (committed.isPresent()) {
            log.debug("Certificate {} was created by an identical request meanwhile", committed.get().getUuid());
            return answerFrom(committed.get(), request);
        }
        UUID submitted = certificateUuid;
        CertificateState state = issuanceWait
                .awaitSettled(submitted, requestFingerprint, timeout)
                .orElseThrow(() -> noLongerCarries(submitted));
        log.debug("Certificate {} requested through EST is {}", submitted, state);
        return request.answer(submitted, state);
    }

    /**
     * Waits within the issue wait for the request that holds the claim to link its certificate, then gives that
     * certificate what is left of that time to be issued and answers from the state it reached, a failure included. A
     * claim that is gone was released by a request that stored nothing, so the request looks for a certificate once
     * more.
     */
    private ResponseEntity<byte[]> followClaim(Duration timeout, String requestFingerprint, ClaimedRequest request,
            Supplier<Optional<ClaimLink>> readClaim) {
        long start = System.nanoTime();
        Optional<ClaimLink> claim = issuanceWait
                .awaitRead(timeout, readClaim,
                        read -> read.map(link -> link.getCertificateUuid() != null).orElse(true));
        if (claim.isEmpty()) {
            log.debug("The claim of an identical request is gone, so the request looks for its certificate once more");
            return request.find().map(found -> answerFrom(found, request)).orElseGet(request::pending);
        }
        UUID certificateUuid = claim.get().getCertificateUuid();
        if (certificateUuid == null) {
            log.debug("An identical request holds the claim and stored no certificate in time");
            return request.pending();
        }
        Duration left = timeout.minus(Duration.ofNanos(System.nanoTime() - start));
        CertificateState state = issuanceWait
                .awaitSettled(certificateUuid, requestFingerprint, left.isNegative() ? Duration.ZERO : left)
                .orElseThrow(() -> noLongerCarries(certificateUuid));
        log.debug("Certificate {} requested through EST by an identical request is {}", certificateUuid, state);
        return request.answer(certificateUuid, state);
    }

    private static ResponseEntity<byte[]> answerFrom(EstRequestedCertificate certificate, ClaimedRequest request) {
        return request.answer(certificate.getUuid(), certificate.getState());
    }

    private static IllegalStateException noLongerCarries(UUID certificateUuid) {
        return new IllegalStateException(
                "Certificate " + certificateUuid + " requested through EST no longer carries its request");
    }
}
