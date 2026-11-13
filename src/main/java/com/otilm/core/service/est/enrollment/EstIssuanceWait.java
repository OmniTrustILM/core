package com.otilm.core.service.est.enrollment;

import com.otilm.api.model.core.certificate.CertificateState;
import com.otilm.core.dao.repository.CertificateRepository;
import com.otilm.core.dao.repository.CertificateStatusPollRepository;
import com.otilm.core.dao.repository.EstRequestedCertificate;
import com.otilm.core.service.est.EstProtocolProperties;
import com.otilm.core.service.est.EstRoute;
import java.time.Duration;
import java.util.Optional;
import java.util.UUID;
import java.util.function.Predicate;
import java.util.function.Supplier;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Component;

/**
 * Gives a certificate that was just submitted the issue wait of its EST Profile to be issued, reading its state every
 * {@code est.protocol.issue-wait.interval}, so that a connector that answers at once lets the client have its
 * certificate in the same exchange. A request that arrives while an identical one is being submitted is given the same
 * time to see that request store its certificate. The wait reads the state with projections and writes nothing, and
 * holds no transaction, so nothing stays managed or locked while it sleeps. It carries no transactional annotation on
 * purpose, so that each read borrows a pooled connection only for its own query and none is held between reads.
 */
@Slf4j
@Component
public class EstIssuanceWait {

    private final CertificateRepository certificateRepository;
    private final CertificateStatusPollRepository statusPollRepository;
    private final Duration interval;

    public EstIssuanceWait(CertificateRepository certificateRepository,
            CertificateStatusPollRepository statusPollRepository, EstProtocolProperties protocolProperties) {
        this.certificateRepository = certificateRepository;
        this.statusPollRepository = statusPollRepository;
        this.interval = protocolProperties.issueWait().interval();
    }

    /**
     * Waits while the certificate carries the request and is {@code REQUESTED}, {@code REGISTERED} or
     * {@code PENDING_ISSUE} without a scheduled status poll: the issue is then on its way and ends within moments.
     * Every other state, including {@code PENDING_APPROVAL} and a {@code PENDING_ISSUE} that waits for a poll, ends the
     * wait at once, as no moment will change it. So does another request or none: a refused approval takes the request
     * off a registration, which another request can complete since.
     *
     * @param route the route whose EST Profile sets the issue wait
     * @param certificateUuid the certificate that was submitted
     * @param requestFingerprint SHA-256 of the request that the certificate was submitted with
     * @return the state when the wait ended, which is still a waiting one once the timeout has passed, at the first
     * read when it is zero, or the thread was interrupted, in which case the interrupt flag is set again; empty once
     * the certificate carries another request or none, as its state then no longer answers this one
     * @throws IllegalStateException when the certificate no longer exists
     */
    public Optional<CertificateState> awaitSettled(EstRoute route, UUID certificateUuid, String requestFingerprint) {
        return await(certificateUuid, requestFingerprint, issueWaitTimeout(route), this::isIssuing);
    }

    /**
     * As {@link #awaitSettled(EstRoute, UUID, String)}, for a certificate that appeared while the request waited for
     * it, which is therefore given only what is left of the timeout.
     *
     * @param waitTimeout how long the certificate is given to be issued
     */
    Optional<CertificateState> awaitSettled(UUID certificateUuid, String requestFingerprint, Duration waitTimeout) {
        return await(certificateUuid, requestFingerprint, waitTimeout, this::isIssuing);
    }

    /**
     * Waits for what an identical request is submitting, reading it every interval until the read is done or the
     * timeout passes.
     *
     * @param waitTimeout how long the request waits
     * @param read reads the state of the identical request
     * @param done tells whether a read ends the wait
     * @return the last read, which is not done once the timeout has passed or the thread was interrupted, in which case
     * the interrupt flag is set again
     */
    <T> T awaitRead(Duration waitTimeout, Supplier<T> read, Predicate<T> done) {
        long deadline = System.nanoTime() + waitTimeout.toNanos();
        while (true) {
            T last = read.get();
            long remaining = deadline - System.nanoTime();
            if (done.test(last) || remaining <= 0) {
                return last;
            }
            try {
                Thread.sleep(Duration.ofNanos(Math.min(remaining, interval.toNanos())));
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                return last;
            }
        }
    }

    /** @return how long a request that EST has just submitted on the route is given to be issued */
    static Duration issueWaitTimeout(EstRoute route) {
        return Duration.ofSeconds(route.estProfile().getIssueWaitTimeout());
    }

    /**
     * As {@link #awaitSettled(EstRoute, UUID, String)}, for a request that cannot be answered later: it waits for as
     * long as its own timeout allows, and through a {@code PENDING_ISSUE} that waits for a status poll too, as the poll
     * can still issue the certificate within that time.
     *
     * @param waitTimeout how long the certificate is given to be issued
     */
    Optional<CertificateState> awaitSettledThroughStatusPolls(UUID certificateUuid, String requestFingerprint,
            Duration waitTimeout) {
        return await(certificateUuid, requestFingerprint, waitTimeout, EstIssuanceWait::isIssuingOrPolled);
    }

    /**
     * @param certificateUuid the certificate that a request was submitted to
     * @param requestFingerprint SHA-256 of the request
     * @return whether the certificate exists and carries the request
     */
    boolean carriesRequest(UUID certificateUuid, String requestFingerprint) {
        return certificateRepository
                .findEstRequestedCertificateByUuid(certificateUuid)
                .map(certificate -> requestFingerprint.equals(certificate.getRequestFingerprint()))
                .orElse(false);
    }

    private Optional<CertificateState> await(UUID certificateUuid, String requestFingerprint, Duration waitTimeout,
            Predicate<EstRequestedCertificate> issuing) {
        long deadline = System.nanoTime() + waitTimeout.toNanos();
        while (true) {
            EstRequestedCertificate certificate = certificateRepository
                    .findEstRequestedCertificateByUuid(certificateUuid)
                    .orElseThrow(() -> new IllegalStateException("The certificate " + certificateUuid + " is gone."));
            if (!requestFingerprint.equals(certificate.getRequestFingerprint())) {
                log.debug("Certificate {} no longer carries the request that it was submitted with", certificateUuid);
                return Optional.empty();
            }
            CertificateState state = certificate.getState();
            long remaining = deadline - System.nanoTime();
            if (remaining <= 0 || !issuing.test(certificate)) {
                log.debug("Certificate {} left the wait in the state {}", certificateUuid, state);
                return Optional.of(state);
            }
            try {
                Thread.sleep(Duration.ofNanos(Math.min(remaining, interval.toNanos())));
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                return Optional.of(state);
            }
        }
    }

    private boolean isIssuing(EstRequestedCertificate certificate) {
        return switch (certificate.getState()) {
            case REQUESTED, REGISTERED -> true;
            case PENDING_ISSUE -> !statusPollRepository.existsByCertificateUuid(certificate.getUuid());
            default -> false;
        };
    }

    private static boolean isIssuingOrPolled(EstRequestedCertificate certificate) {
        return switch (certificate.getState()) {
            case REQUESTED, REGISTERED, PENDING_ISSUE -> true;
            default -> false;
        };
    }
}
