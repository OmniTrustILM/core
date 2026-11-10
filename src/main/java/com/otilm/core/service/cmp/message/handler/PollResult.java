package com.otilm.core.service.cmp.message.handler;

import com.otilm.api.model.core.certificate.CertificateState;
import com.otilm.core.dao.entity.Certificate;

/**
 * Outcome of a {@link PollFeature#pollCertificate} call. Three possibilities:
 *
 * <ul>
 * <li>{@link Reached} — the certificate transitioned to the expected terminal state within the poll-timeout window.
 * Caller proceeds with the normal success path.</li>
 * <li>{@link StillPending} — the certificate is still queued for the actions listener ({@code REQUESTED} or
 * {@code REGISTERED}), or in {@code PENDING_ISSUE} / {@code PENDING_REVOKE} because the authority provider connector
 * accepted the operation asynchronously (HTTP 202); either way completion is out-of-band. CMP answers issue, renew and
 * rekey with an ip/cp/kup whose status is {@code waiting}, which opens the pollReq exchange, and a revocation with a
 * per-certificate {@code rejection} (RFC 4210 §5.2.6 limits polling to ip/cp/kup).</li>
 * <li>{@link Diverted} — the certificate reached a terminal state that is <em>not</em> the expected one. Most likely
 * cause: another thread (e.g. an operator-driven {@code cancelPendingCertificateOperation}, a scheduled task)
 * transitioned the certificate while this poll was running. Callers reject the operation cleanly; the upstream
 * operation is no longer in progress and the {@code currentState} carried by the result tells the caller (and the
 * user-facing message) what the certificate ended up in.</li>
 * </ul>
 *
 * <p>
 * Timeout is intentionally not represented here: it is a system-level condition (the polling thread did not observe a
 * state transition within the configured budget), not a domain outcome, and is signalled by a checked
 * {@link com.otilm.api.interfaces.core.cmp.error.CmpProcessingException} on the polling method.
 * </p>
 */
public sealed interface PollResult {

    /** Certificate reached the requested expected state. */
    record Reached(Certificate certificate) implements PollResult {
    }

    /**
     * Certificate is still in an asynchronous state when the budget ends; the operation completes later.
     */
    record StillPending(CertificateState currentState) implements PollResult {
    }

    /**
     * Certificate reached a terminal state that is not the expected one (e.g. expected {@code ISSUED} but observed
     * {@code FAILED} after a concurrent cancel).
     */
    record Diverted(CertificateState currentState) implements PollResult {
    }
}
