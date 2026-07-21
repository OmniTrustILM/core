package com.otilm.core.service.cmp.message.handler;

import com.otilm.api.exception.NotFoundException;
import com.otilm.api.model.core.certificate.CertificateState;
import com.otilm.api.interfaces.core.cmp.error.CmpProcessingException;
import com.otilm.core.dao.entity.Certificate;
import com.otilm.core.security.authz.SecuredUUID;
import com.otilm.core.service.CertificateInternalService;
import jakarta.persistence.EntityManager;
import jakarta.persistence.PersistenceContext;
import lombok.extern.slf4j.Slf4j;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.cmp.PKIFailureInfo;
import org.bouncycastle.asn1.cmp.PKIHeader;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import java.util.concurrent.TimeUnit;

@Slf4j
@Component
public class PollFeature {

    private static final int DEFAULT_POLL_TIMEOUT_SECONDS = 10;
    private static final long POLL_INTERVAL_MS = 1_000L;

    @PersistenceContext
    private EntityManager entityManager;

    @Value("${cmp.protocol.poll.feature.timeout}")
    private Integer pollFeatureTimeout;

    private CertificateInternalService certificateService;

    @Autowired
    public void setCertificateService(CertificateInternalService certificateService) {
        this.certificateService = certificateService;
    }

    /**
     * Convert asynchronous certificate-state transitions (issue / renew / rekey / revoke)
     * into a synchronous {@link PollResult} the CMP / SCEP layers can act on.
     *
     * <p>Loops on the configured budget ({@code cmp.protocol.poll.feature.timeout}, default
     * {@value #DEFAULT_POLL_TIMEOUT_SECONDS} s) re-reading the certificate from the database
     * each iteration and returns:
     *
     * <ul>
     *   <li>{@link PollResult.Reached} when the certificate's state equals
     *       {@code expectedState};</li>
     *   <li>{@link PollResult.StillPending} when the certificate is still in
     *       {@code PENDING_ISSUE} / {@code PENDING_REVOKE} once the poll budget is
     *       exhausted. {@code PENDING_*} is ridden out within the budget — every issuance
     *       routes through {@code PENDING_ISSUE} on the actions-listener thread, even when
     *       the connector completes synchronously moments later, so an immediate return
     *       here would misreport nearly every issuance as asynchronous;</li>
     *   <li>{@link PollResult.Diverted} when the certificate reaches a terminal state
     *       (one of {@code ISSUED}, {@code REVOKED}, {@code FAILED}, {@code REJECTED})
     *       that is not the expected one — typically because another thread (an operator
     *       cancel, a scheduled task) transitioned the certificate while this poll was
     *       running.</li>
     * </ul>
     *
     * <p>Transitional states ({@code REQUESTED}, {@code PENDING_APPROVAL}, {@code PENDING_*})
     * are not reported back to the caller mid-budget — the loop sleeps and re-reads until one
     * of the outcomes above is observed or the budget is exhausted (which yields
     * {@link PollResult.StillPending} for {@code PENDING_*}, or a timeout exception for the
     * other transitional states).</p>
     *
     * @param tid           processing transaction id, see {@link PKIHeader#getTransactionID()}
     * @param serialNumber  serial number of the polled certificate (for log context;
     *                      filled in from the entity if {@code null})
     * @param uuid          internal UUID of the certificate
     * @param expectedState the terminal state the caller is waiting for ({@code ISSUED}
     *                      for issue / renew / rekey, {@code REVOKED} for revoke)
     * @return the {@link PollResult} describing the observed outcome
     * @throws CmpProcessingException if the cert is not found, the polling thread is
     *                                interrupted, or the budget is exhausted while the
     *                                certificate is still in a transitional state
     */
    public PollResult pollCertificate(ASN1OctetString tid, String serialNumber, String uuid,
                                      CertificateState expectedState) throws CmpProcessingException {
        log.trace(">>>>> CERT POLL (begin) >>>>> ");
        SecuredUUID certUUID = SecuredUUID.fromString(uuid);
        long timeoutMs = 1_000L * (pollFeatureTimeout == null ? DEFAULT_POLL_TIMEOUT_SECONDS : pollFeatureTimeout);
        long startRequest = System.currentTimeMillis();
        int counter = 0;
        Certificate polledCert = null;

        try {
            while (true) {
                counter++;
                polledCert = certificateService.getCertificateEntity(certUUID);
                entityManager.refresh(polledCert);
                CertificateState current = polledCert.getState();
                if (serialNumber == null) {
                    serialNumber = polledCert.getSerialNumber();
                }
                log.trace("TID={}, POLL=[{}], SN={} | observed state={}, uuid={}",
                        tid, counter, serialNumber, current, certUUID);

                if (expectedState.equals(current)) {
                    log.trace("TID={}, SN={} | certificate uuid={} reached expected state {}",
                            tid, serialNumber, certUUID, expectedState);
                    return new PollResult.Reached(polledCert);
                }
                if (isDivergentTerminal(current, expectedState)) {
                    log.warn("TID={}, SN={} | certificate uuid={} diverted to {} while waiting for {}",
                            tid, serialNumber, certUUID, current, expectedState);
                    return new PollResult.Diverted(current);
                }
                if (System.currentTimeMillis() - startRequest >= timeoutMs) {
                    // PENDING_* is ridden out for the whole budget: even a synchronously-
                    // completing connector transits PENDING_ISSUE on the actions-listener
                    // thread, so only budget exhaustion makes "still pending" a verdict.
                    if (current == CertificateState.PENDING_ISSUE || current == CertificateState.PENDING_REVOKE) {
                        log.debug("TID={}, SN={} | certificate uuid={} still in asynchronous state {} after {} ms — caller will signal client to retry",
                                tid, serialNumber, certUUID, current, timeoutMs);
                        return new PollResult.StillPending(current);
                    }
                    throw new CmpProcessingException(tid, PKIFailureInfo.systemFailure,
                            String.format("SN=%s | polling timed out after %d ms — cert is in transitional state %s, expected %s",
                                    serialNumber, timeoutMs, current, expectedState));
                }
                TimeUnit.MILLISECONDS.sleep(POLL_INTERVAL_MS);
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

    private static boolean isTerminal(CertificateState state) {
        return state == CertificateState.ISSUED
                || state == CertificateState.REVOKED
                || state == CertificateState.FAILED
                || state == CertificateState.REJECTED;
    }

    /**
     * A terminal state that is not the expected one usually means the operation diverged
     * (e.g. an operator cancel flipped an in-flight issue to FAILED). The one exception is
     * {@code ISSUED} while waiting for {@code REVOKED}: {@code ISSUED} is the resting state a
     * certificate occupies <em>before</em> a revocation transition lands, so observing it
     * means "revocation not applied yet", not a divergence — treating it as one would reject
     * a revocation poll on its first sample, before the async {@code ISSUED -> REVOKED}
     * transition can land. Such a poll instead keeps waiting and, if the transition never
     * lands within the budget, ends as a timeout — a rejection either way, but never a false
     * "diverted to ISSUED".
     *
     * <p>The {@code current == expectedState} guard is unreachable from the poll loop (which
     * returns {@code Reached} before calling this) but keeps the predicate correct on its
     * own terms: the expected state is never divergent.</p>
     */
    private static boolean isDivergentTerminal(CertificateState current, CertificateState expectedState) {
        if (!isTerminal(current) || current == expectedState) {
            return false;
        }
        return !(expectedState == CertificateState.REVOKED && current == CertificateState.ISSUED);
    }
}
