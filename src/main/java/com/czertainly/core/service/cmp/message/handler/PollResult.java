package com.czertainly.core.service.cmp.message.handler;

import com.czertainly.api.model.core.certificate.CertificateState;
import com.czertainly.core.dao.entity.Certificate;

/**
 * Outcome of a {@link PollFeature#pollCertificate} call. Three possibilities:
 *
 * <ul>
 *   <li>{@link Reached} — the certificate transitioned to the expected terminal state
 *       within the poll-timeout window. Caller proceeds with the normal success path.</li>
 *   <li>{@link StillPending} — the certificate is in {@code PENDING_ISSUE} or
 *       {@code PENDING_REVOKE}. The authority provider connector accepted the operation
 *       asynchronously (HTTP 202) and completion is out-of-band. CMP callers translate
 *       this into a {@code pollRep} for issue/renew/rekey, or a per-certificate
 *       {@code rejection} for revocation (RFC 4210 §5.2.6 limits polling to ip/cp/kup).
 *       SCEP callers translate to {@code pkiPending}.</li>
 *   <li>{@link Diverted} — the certificate reached a terminal state that is <em>not</em>
 *       the expected one. Most likely cause: another thread (e.g. an operator-driven
 *       {@code cancelPendingCertificateOperation}, a scheduled task) transitioned the
 *       certificate while this poll was running. Callers reject the operation cleanly;
 *       the upstream operation is no longer in progress and the {@code currentState}
 *       carried by the result tells the caller (and the user-facing message) what the
 *       certificate ended up in.</li>
 * </ul>
 *
 * <p>Timeout is intentionally not represented here: it is a system-level condition
 * (the polling thread did not observe a state transition within the configured budget),
 * not a domain outcome, and is signalled by a checked
 * {@link com.czertainly.api.interfaces.core.cmp.error.CmpProcessingException} on the
 * polling method.</p>
 */
public sealed interface PollResult {

    /** Certificate reached the requested expected state. */
    record Reached(Certificate certificate) implements PollResult {}

    /**
     * Certificate is in a {@code PENDING_*} state — the authority provider connector
     * returned HTTP 202 and the operation will complete asynchronously.
     */
    record StillPending(CertificateState currentState) implements PollResult {}

    /**
     * Certificate reached a terminal state that is not the expected one (e.g. expected
     * {@code ISSUED} but observed {@code FAILED} after a concurrent cancel).
     */
    record Diverted(CertificateState currentState) implements PollResult {}
}
