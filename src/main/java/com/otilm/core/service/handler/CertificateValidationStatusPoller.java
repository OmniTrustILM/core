package com.otilm.core.service.handler;

import com.otilm.api.model.core.certificate.CertificateDetailDto;
import com.otilm.api.model.core.certificate.CertificateValidationStatus;
import com.otilm.core.dao.repository.CertificateRepository;
import java.util.Optional;
import java.util.UUID;
import java.util.concurrent.TimeUnit;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;
import org.springframework.transaction.PlatformTransactionManager;
import org.springframework.transaction.annotation.Propagation;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.transaction.support.TransactionTemplate;

/**
 * Resolves a freshly-issued certificate's {@link CertificateValidationStatus}, waiting briefly for the asynchronous
 * post-issuance validation to land. Shared by the CMP and SCEP handlers so the wait budget and the resolve/fallback
 * policy live in one place.
 */
@Slf4j
@Component
public class CertificateValidationStatusPoller {

    /**
     * Sampling interval. The event-driven post-issuance validation typically lands ~100 ms after the certificate
     * reaches ISSUED, so a sub-second interval avoids overshooting.
     */
    private static final long POLL_INTERVAL_MS = 250L;

    /**
     * Default wait budget for {@link #resolveOrKeep(CertificateDetailDto)}. The validation listener typically lands
     * within ~100 ms of issuance; 3 s covers slow OCSP/CRL checks without stretching the request unreasonably.
     */
    private static final long DEFAULT_WAIT_MS = 3_000L;

    private CertificateRepository certificateRepository;

    private TransactionTemplate sampleTransaction;

    @Autowired
    public void setCertificateRepository(CertificateRepository certificateRepository) {
        this.certificateRepository = certificateRepository;
    }

    @Autowired
    public void setTransactionManager(PlatformTransactionManager transactionManager) {
        TransactionTemplate readOnlyTransaction = new TransactionTemplate(transactionManager);
        readOnlyTransaction.setReadOnly(true);
        this.sampleTransaction = readOnlyTransaction;
    }

    /**
     * Resolve {@code certificate}'s validation status, waiting up to the default budget if it is still
     * {@code NOT_CHECKED}.
     *
     * <p>
     * Validation is advanced asynchronously — event-driven on the validation-listener thread right after issuance, with
     * the hourly batch as fallback. An already-resolved status is returned as-is (no DB hit). A {@code NOT_CHECKED}
     * status is polled so a definitively bad status can still be caught; if it never resolves within the budget (or the
     * certificate can no longer be found, or the thread is interrupted) the caller gets {@code NOT_CHECKED} back and
     * decides the fallback — it is a transient state, not a verdict.
     * </p>
     *
     * <p>
     * Each sample reads the status alone, through {@link CertificateRepository#findValidationStatusByUuid}: under
     * open-in-view the request's EntityManager may already hold the certificate as the caller loaded it with its CA
     * chain, and reading the entity would return that copy for the whole budget. A caller's transaction is suspended
     * ({@link Propagation#NOT_SUPPORTED}), so a sample never runs inside it, where the read could flush the caller's
     * changed certificates and hold their row locks across the sleeps. Each sample runs in a short read-only
     * transaction of its own: a read outside a transaction in this scope would bind an EntityManager, and the
     * connection it takes, until the wait ends.
     * </p>
     *
     * @param certificate the certificate whose status to resolve (its DTO status is the starting point)
     * @return the validation status observed when the wait ended
     */
    @Transactional(propagation = Propagation.NOT_SUPPORTED)
    public CertificateValidationStatus resolveOrKeep(CertificateDetailDto certificate) {
        return resolveOrKeep(certificate, DEFAULT_WAIT_MS);
    }

    /**
     * Budget-parameterised variant of {@link #resolveOrKeep(CertificateDetailDto)}. Package-private so unit tests can
     * drive a short wait; not the transactional entry point — it is invoked from the public method, which has already
     * suspended the caller's transaction.
     */
    CertificateValidationStatus resolveOrKeep(CertificateDetailDto certificate, long budgetMs) {
        if (certificate.getValidationStatus() != CertificateValidationStatus.NOT_CHECKED) {
            return certificate.getValidationStatus();
        }
        UUID certUuid = UUID.fromString(certificate.getUuid());
        long deadline = System.currentTimeMillis() + budgetMs;
        try {
            Optional<CertificateValidationStatus> status = readStatus(certUuid);
            while (status.isPresent() && status.get() == CertificateValidationStatus.NOT_CHECKED) {
                long remaining = deadline - System.currentTimeMillis();
                if (remaining <= 0) {
                    break;
                }
                // Clamp to the remaining budget so total wait never exceeds budgetMs, even
                // when budgetMs is smaller than one sampling interval.
                TimeUnit.MILLISECONDS.sleep(Math.min(POLL_INTERVAL_MS, remaining));
                status = readStatus(certUuid);
            }
            if (status.isEmpty()) {
                log.warn("UUID={} | certificate not found while waiting for validation status", certificate.getUuid());
                return certificate.getValidationStatus();
            }
            return status.get();
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            log.debug("UUID={} | validation-status wait interrupted; keeping current status", certificate.getUuid());
            return certificate.getValidationStatus();
        }
    }

    private Optional<CertificateValidationStatus> readStatus(UUID certUuid) {
        return sampleTransaction.execute(status -> certificateRepository.findValidationStatusByUuid(certUuid));
    }
}
