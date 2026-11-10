package com.otilm.core.service.cmp.message.handler;

import com.otilm.api.exception.NotFoundException;
import com.otilm.api.interfaces.core.cmp.error.CmpProcessingException;
import com.otilm.api.model.core.certificate.CertificateState;
import com.otilm.core.dao.entity.Certificate;
import com.otilm.core.dao.repository.CertificateRepository;
import com.otilm.core.security.authz.SecuredUUID;
import com.otilm.core.service.CertificateInternalService;
import jakarta.persistence.EntityManager;
import jakarta.persistence.PersistenceContext;
import java.util.UUID;
import java.util.concurrent.TimeUnit;
import lombok.extern.slf4j.Slf4j;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.cmp.PKIFailureInfo;
import org.bouncycastle.asn1.cmp.PKIHeader;
import org.hibernate.Hibernate;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;
import org.springframework.transaction.PlatformTransactionManager;
import org.springframework.transaction.TransactionStatus;
import org.springframework.transaction.support.DefaultTransactionDefinition;

@Slf4j
@Component
public class PollFeature {

    private static final int DEFAULT_POLL_TIMEOUT_SECONDS = 10;
    private static final long POLL_INTERVAL_MS = 1_000L;

    private EntityManager entityManager;

    private Integer pollFeatureTimeout;

    private CertificateInternalService certificateService;

    private CertificateRepository certificateRepository;

    private PlatformTransactionManager transactionManager;

    @PersistenceContext
    public void setEntityManager(EntityManager entityManager) {
        this.entityManager = entityManager;
    }

    @Value("${cmp.protocol.poll.feature.timeout}")
    public void setPollFeatureTimeout(Integer pollFeatureTimeout) {
        this.pollFeatureTimeout = pollFeatureTimeout;
    }

    @Autowired
    public void setCertificateService(CertificateInternalService certificateService) {
        this.certificateService = certificateService;
    }

    @Autowired
    public void setCertificateRepository(CertificateRepository certificateRepository) {
        this.certificateRepository = certificateRepository;
    }

    @Autowired
    public void setTransactionManager(PlatformTransactionManager transactionManager) {
        this.transactionManager = transactionManager;
    }

    /**
     * Convert asynchronous certificate-state transitions (issue / renew / rekey / revoke) into a synchronous
     * {@link PollResult} the CMP / SCEP layers can act on.
     *
     * <p>
     * Loops on the configured budget ({@code cmp.protocol.poll.feature.timeout}, default
     * {@value #DEFAULT_POLL_TIMEOUT_SECONDS} s) re-reading the certificate's state from the database each iteration and
     * returns:
     *
     * <ul>
     * <li>{@link PollResult.Reached} when the certificate's state equals {@code expectedState};</li>
     * <li>{@link PollResult.StillPending} when the certificate is still in {@code PENDING_ISSUE} /
     * {@code PENDING_REVOKE}, is a submitted request the actions listener has not claimed yet ({@code REQUESTED}), or
     * is a registration placeholder still {@code REGISTERED}, once the poll budget is exhausted. These are ridden out
     * within the budget — every issuance routes through {@code PENDING_ISSUE} on the actions-listener thread (a request
     * or a registration placeholder is first claimed there out of {@code REQUESTED} or {@code REGISTERED}), even when
     * the connector completes synchronously moments later, so an immediate return here would misreport nearly every
     * issuance as asynchronous;</li>
     * <li>{@link PollResult.Diverted} when the certificate reaches a terminal state (one of {@code ISSUED},
     * {@code REVOKED}, {@code FAILED}, {@code REJECTED}) that is not the expected one — typically because another
     * thread (an operator cancel, a scheduled task) transitioned the certificate while this poll was running.</li>
     * </ul>
     *
     * <p>
     * Transitional states ({@code REGISTERED}, {@code REQUESTED}, {@code PENDING_APPROVAL}, {@code PENDING_*}) are not
     * reported back to the caller mid-budget — the loop sleeps and re-reads until one of the outcomes above is observed
     * or the budget is exhausted (which yields {@link PollResult.StillPending} for the asynchronous states listed
     * above, or a timeout exception for the other transitional states).
     * </p>
     *
     * <p>
     * The loop holds no transaction, so its sleeps keep no connection {@code idle in transaction}. Each iteration reads
     * the state alone, a value that always comes from the database and attaches nothing to the request's EntityManager.
     * Only the certificate that reached the expected state is loaded, in one short transaction.
     * </p>
     *
     * @param tid processing transaction id, see {@link PKIHeader#getTransactionID()}
     * @param serialNumber serial number of the polled certificate (for log context; filled in from the certificate once
     * it reaches the expected state if {@code null})
     * @param uuid internal UUID of the certificate
     * @param expectedState the terminal state the caller is waiting for ({@code ISSUED} for issue / renew / rekey,
     * {@code REVOKED} for revoke)
     * @return the {@link PollResult} describing the observed outcome
     * @throws CmpProcessingException if the cert is not found, the polling thread is interrupted, or the budget is
     * exhausted while the certificate is still in a transitional state
     */
    public PollResult pollCertificate(ASN1OctetString tid, String serialNumber, String uuid,
            CertificateState expectedState) throws CmpProcessingException {
        log.trace(">>>>> CERT POLL (begin) >>>>> ");
        UUID certificateUuid = UUID.fromString(uuid);
        SecuredUUID certUUID = SecuredUUID.fromUUID(certificateUuid);
        long timeoutMs = 1_000L * (pollFeatureTimeout == null ? DEFAULT_POLL_TIMEOUT_SECONDS : pollFeatureTimeout);
        long startRequest = System.currentTimeMillis();
        int counter = 0;

        try {
            while (true) {
                counter++;
                CertificateState current = certificateRepository
                        .findStateByUuid(certificateUuid)
                        .orElseThrow(() -> new NotFoundException(Certificate.class, certificateUuid));
                log
                        .trace("TID={}, POLL=[{}], SN={} | observed state={}, uuid={}", tid, counter, serialNumber,
                                current, certUUID);

                if (expectedState.equals(current)) {
                    Certificate reached = loadFresh(certUUID);
                    // A second read: the certificate may have moved on since the state read.
                    current = reached.getState();
                    if (expectedState.equals(current)) {
                        if (serialNumber == null) {
                            serialNumber = reached.getSerialNumber();
                        }
                        log
                                .trace("TID={}, SN={} | certificate uuid={} reached expected state {}", tid,
                                        serialNumber, certUUID, expectedState);
                        return new PollResult.Reached(reached);
                    }
                }
                if (isDivergentTerminal(current, expectedState)) {
                    log
                            .warn("TID={}, SN={} | certificate uuid={} diverted to {} while waiting for {}", tid,
                                    serialNumber, certUUID, current, expectedState);
                    return new PollResult.Diverted(current);
                }
                if (System.currentTimeMillis() - startRequest >= timeoutMs) {
                    return resultAtBudgetEnd(tid, serialNumber, certUUID, current, expectedState, timeoutMs);
                }
                // Clamp to the remaining budget so the loop never overshoots timeoutMs by up to a
                // full interval (matches CertificateValidationStatusPoller). Positive here: the
                // elapsed >= timeoutMs check above already returned/threw when the budget was spent.
                long remaining = timeoutMs - (System.currentTimeMillis() - startRequest);
                TimeUnit.MILLISECONDS.sleep(Math.min(POLL_INTERVAL_MS, remaining));
            }
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            throw new CmpProcessingException(tid, PKIFailureInfo.systemFailure,
                    "SN=" + serialNumber + " | cannot poll certificate - processing thread has been interrupted", e);
        } catch (NotFoundException e) {
            throw new CmpProcessingException(tid, PKIFailureInfo.badDataFormat,
                    "SN=" + serialNumber + " | issued certificate from CA cannot be found, uuid=" + certUUID, e);
        } finally {
            log.trace("<<<<< CERT polling (  end) <<<<< ");
        }
    }

    /**
     * The outcome once the budget is spent: {@link PollResult.StillPending} for a certificate still in an asynchronous
     * state, otherwise a timeout.
     */
    private static PollResult resultAtBudgetEnd(ASN1OctetString tid, String serialNumber, SecuredUUID certUUID,
            CertificateState current, CertificateState expectedState, long timeoutMs) throws CmpProcessingException {
        if (isStillPending(current)) {
            log
                    .debug("TID={}, SN={} | certificate uuid={} still in asynchronous state {} after {} ms — caller will signal client to retry",
                            tid, serialNumber, certUUID, current, timeoutMs);
            return new PollResult.StillPending(current);
        }
        throw new CmpProcessingException(tid, PKIFailureInfo.systemFailure,
                String
                        .format("SN=%s | polling timed out after %d ms — cert is in transitional state %s, expected %s",
                                serialNumber, timeoutMs, current, expectedState));
    }

    private static boolean isStillPending(CertificateState state) {
        return state == CertificateState.PENDING_ISSUE || state == CertificateState.PENDING_REVOKE
                || state == CertificateState.REGISTERED || state == CertificateState.REQUESTED;
    }

    /**
     * Loads and refreshes the certificate in one short transaction: the request's EntityManager may hold the copy
     * cached at submission, and {@code refresh} needs a transaction. The content is loaded inside it because the caller
     * parses the content afterwards, when the EntityManager the transaction used may already be closed (none bound to
     * the request, or {@code NOT_SUPPORTED} after a read outside a transaction).
     */
    private Certificate loadFresh(SecuredUUID certUUID) throws NotFoundException {
        TransactionStatus transaction = transactionManager.getTransaction(new DefaultTransactionDefinition());
        try {
            Certificate certificate = certificateService.getCertificateEntity(certUUID);
            entityManager.refresh(certificate);
            Hibernate.initialize(certificate.getCertificateContent());
            transactionManager.commit(transaction);
            return certificate;
        } finally {
            // Not in a catch: a failed commit has already completed the transaction, and an Error must roll back too.
            if (!transaction.isCompleted()) {
                transactionManager.rollback(transaction);
            }
        }
    }

    private static boolean isTerminal(CertificateState state) {
        return state == CertificateState.ISSUED || state == CertificateState.REVOKED || state == CertificateState.FAILED
                || state == CertificateState.REJECTED;
    }

    /**
     * A terminal state that is not the expected one usually means the operation diverged (e.g. an operator cancel
     * flipped an in-flight issue to FAILED). The one exception is {@code ISSUED} while waiting for {@code REVOKED}:
     * {@code ISSUED} is the resting state a certificate occupies <em>before</em> a revocation transition lands, so
     * observing it means "revocation not applied yet", not a divergence — treating it as one would reject a revocation
     * poll on its first sample, before the async {@code ISSUED -> REVOKED} transition can land. Such a poll instead
     * keeps waiting and, if the transition never lands within the budget, ends as a timeout — a rejection either way,
     * but never a false "diverted to ISSUED".
     *
     * <p>
     * The {@code current == expectedState} guard is unreachable from the poll loop (which returns {@code Reached}
     * before calling this) but keeps the predicate correct on its own terms: the expected state is never divergent.
     * </p>
     */
    private static boolean isDivergentTerminal(CertificateState current, CertificateState expectedState) {
        if (!isTerminal(current) || current == expectedState) {
            return false;
        }
        return !(expectedState == CertificateState.REVOKED && current == CertificateState.ISSUED);
    }
}
