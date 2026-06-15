package com.otilm.core.service.handler.authority.lifecycle;

import com.otilm.api.model.core.certificate.CertificateEvent;
import com.otilm.api.model.core.certificate.CertificateEventStatus;
import com.otilm.api.model.core.certificate.CertificateState;

import java.util.Arrays;
import java.util.Optional;

import static com.otilm.api.model.core.certificate.CertificateState.*;

/**
 * Allowed certificate state transitions, keyed on (from, to) pairs.
 * Every distinct lifecycle transition has a unique (from, to) pair.
 *
 * <p>Each row also declares the audit-history {@code defaultStatus}: SUCCESS for forward progress
 * and successful completion, FAILED for failures, rejections, and failed-operation restores. The
 * destination state alone is not sufficient — e.g. {@code PENDING_REVOKE -> ISSUED} restores an
 * ISSUED certificate but records a FAILED revoke, so it must be audited FAILED, not SUCCESS.</p>
 *
 * <p>The reason for a transition (e.g., issue-failed vs cancelled vs timed out) is captured via the
 * reasonMessage parameter on {@link CertificateStateMachine#transition} — not via separate rows,
 * following the established free-text audit-history reason pattern.</p>
 */
public enum CertificateStateTransition {

    // Issue (sync + async)
    REQUESTED_TO_PENDING_ISSUE        (REQUESTED,            PENDING_ISSUE,        CertificateEvent.ISSUE,            CertificateEventStatus.SUCCESS),
    PENDING_ISSUE_TO_ISSUED           (PENDING_ISSUE,        ISSUED,               CertificateEvent.ISSUE,            CertificateEventStatus.SUCCESS),
    PENDING_ISSUE_TO_FAILED           (PENDING_ISSUE,        FAILED,               CertificateEvent.ISSUE,            CertificateEventStatus.FAILED),

    // Issue approval flow
    REQUESTED_TO_PENDING_APPROVAL     (REQUESTED,            PENDING_APPROVAL,     CertificateEvent.APPROVAL_REQUEST, CertificateEventStatus.SUCCESS),
    PENDING_APPROVAL_TO_PENDING_ISSUE (PENDING_APPROVAL,     PENDING_ISSUE,        CertificateEvent.APPROVAL_CLOSE,   CertificateEventStatus.SUCCESS),
    PENDING_APPROVAL_TO_REJECTED      (PENDING_APPROVAL,     REJECTED,             CertificateEvent.APPROVAL_CLOSE,   CertificateEventStatus.FAILED),

    // Revoke (sync + async)
    ISSUED_TO_PENDING_REVOKE          (ISSUED,               PENDING_REVOKE,       CertificateEvent.REVOKE,           CertificateEventStatus.SUCCESS),
    PENDING_REVOKE_TO_REVOKED         (PENDING_REVOKE,       REVOKED,              CertificateEvent.REVOKE,           CertificateEventStatus.SUCCESS),
    PENDING_REVOKE_TO_ISSUED          (PENDING_REVOKE,       ISSUED,               CertificateEvent.REVOKE,           CertificateEventStatus.FAILED),  // revoke failed/cancelled — restore
    ISSUED_TO_REVOKED                 (ISSUED,               REVOKED,              CertificateEvent.REVOKE,           CertificateEventStatus.SUCCESS),

    // Revoke approval flow
    ISSUED_TO_PENDING_APPROVAL        (ISSUED,               PENDING_APPROVAL,     CertificateEvent.APPROVAL_REQUEST, CertificateEventStatus.SUCCESS),
    PENDING_APPROVAL_TO_PENDING_REVOKE(PENDING_APPROVAL,     PENDING_REVOKE,       CertificateEvent.APPROVAL_CLOSE,   CertificateEventStatus.SUCCESS),
    PENDING_APPROVAL_TO_ISSUED        (PENDING_APPROVAL,     ISSUED,               CertificateEvent.APPROVAL_CLOSE,   CertificateEventStatus.FAILED),  // revoke rejected — restore

    // v3 register lifecycle
    REQUESTED_TO_PENDING_REGISTRATION (REQUESTED,            PENDING_REGISTRATION, CertificateEvent.UPDATE_STATE,     CertificateEventStatus.SUCCESS),
    PENDING_REGISTRATION_TO_REGISTERED(PENDING_REGISTRATION, REGISTERED,           CertificateEvent.UPDATE_STATE,     CertificateEventStatus.SUCCESS),
    PENDING_REGISTRATION_TO_FAILED    (PENDING_REGISTRATION, FAILED,               CertificateEvent.UPDATE_STATE,     CertificateEventStatus.FAILED),
    REGISTERED_TO_PENDING_ISSUE       (REGISTERED,           PENDING_ISSUE,        CertificateEvent.ISSUE,            CertificateEventStatus.SUCCESS),

    // Compliance rejection
    REQUESTED_TO_REJECTED             (REQUESTED,            REJECTED,             CertificateEvent.UPDATE_STATE,     CertificateEventStatus.FAILED),

    // Issue / renew / rekey failure
    REQUESTED_TO_FAILED               (REQUESTED,            FAILED,               CertificateEvent.ISSUE,            CertificateEventStatus.FAILED),
    PENDING_APPROVAL_TO_FAILED        (PENDING_APPROVAL,     FAILED,               CertificateEvent.ISSUE,            CertificateEventStatus.FAILED),

    // Approval-rejected transition for certs that were ISSUED before the approval was raised.
    ISSUED_TO_REJECTED                (ISSUED,               REJECTED,             CertificateEvent.UPDATE_STATE,     CertificateEventStatus.FAILED),
    ;

    public final CertificateState from;
    public final CertificateState to;
    public final CertificateEvent defaultAuditEvent;
    public final CertificateEventStatus defaultStatus;

    CertificateStateTransition(CertificateState from, CertificateState to,
                               CertificateEvent defaultAuditEvent, CertificateEventStatus defaultStatus) {
        this.from = from;
        this.to = to;
        this.defaultAuditEvent = defaultAuditEvent;
        this.defaultStatus = defaultStatus;
    }

    public static Optional<CertificateStateTransition> lookup(CertificateState from, CertificateState to) {
        return Arrays.stream(values())
            .filter(t -> t.from == from && t.to == to)
            .findFirst();
    }
}
