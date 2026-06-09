package com.czertainly.core.service.handler.authority.lifecycle;

import com.otilm.api.model.core.certificate.CertificateEvent;
import com.otilm.api.model.core.certificate.CertificateState;

import java.util.Arrays;
import java.util.Optional;

import static com.otilm.api.model.core.certificate.CertificateState.*;

/**
 * Allowed certificate state transitions, keyed on (from, to) pairs.
 * Every distinct lifecycle transition has a unique (from, to) pair.
 * The reason for a transition (e.g., issue-failed vs cancelled vs timed out) is captured
 * via the reasonMessage parameter on {@link CertificateStateMachine#transition} — not via
 * separate rows. This matches v2's line 386 pattern of free-text audit-history reasons.
 */
public enum CertificateStateTransition {

    // Issue (sync + async)
    REQUESTED_TO_PENDING_ISSUE       (REQUESTED,            PENDING_ISSUE,        CertificateEvent.ISSUE),
    PENDING_ISSUE_TO_ISSUED          (PENDING_ISSUE,        ISSUED,               CertificateEvent.ISSUE),
    PENDING_ISSUE_TO_FAILED          (PENDING_ISSUE,        FAILED,               CertificateEvent.ISSUE),

    // Issue approval flow
    REQUESTED_TO_PENDING_APPROVAL    (REQUESTED,            PENDING_APPROVAL,     CertificateEvent.APPROVAL_REQUEST),
    PENDING_APPROVAL_TO_PENDING_ISSUE(PENDING_APPROVAL,     PENDING_ISSUE,        CertificateEvent.APPROVAL_CLOSE),
    PENDING_APPROVAL_TO_REJECTED     (PENDING_APPROVAL,     REJECTED,             CertificateEvent.APPROVAL_CLOSE),

    // Revoke (sync + async)
    ISSUED_TO_PENDING_REVOKE         (ISSUED,               PENDING_REVOKE,       CertificateEvent.REVOKE),
    PENDING_REVOKE_TO_REVOKED        (PENDING_REVOKE,       REVOKED,              CertificateEvent.REVOKE),
    PENDING_REVOKE_TO_ISSUED         (PENDING_REVOKE,       ISSUED,               CertificateEvent.REVOKE),
    ISSUED_TO_REVOKED                (ISSUED,               REVOKED,              CertificateEvent.REVOKE),

    // Revoke approval flow
    ISSUED_TO_PENDING_APPROVAL       (ISSUED,               PENDING_APPROVAL,     CertificateEvent.APPROVAL_REQUEST),
    PENDING_APPROVAL_TO_PENDING_REVOKE(PENDING_APPROVAL,    PENDING_REVOKE,       CertificateEvent.APPROVAL_CLOSE),
    PENDING_APPROVAL_TO_ISSUED       (PENDING_APPROVAL,     ISSUED,               CertificateEvent.APPROVAL_CLOSE),

    // v3 register lifecycle
    REQUESTED_TO_PENDING_REGISTRATION(REQUESTED,            PENDING_REGISTRATION, CertificateEvent.UPDATE_STATE),
    PENDING_REGISTRATION_TO_REGISTERED(PENDING_REGISTRATION,REGISTERED,           CertificateEvent.UPDATE_STATE),
    PENDING_REGISTRATION_TO_FAILED   (PENDING_REGISTRATION, FAILED,               CertificateEvent.UPDATE_STATE),
    REGISTERED_TO_PENDING_ISSUE      (REGISTERED,           PENDING_ISSUE,        CertificateEvent.ISSUE),

    // Compliance rejection (v2 line 481)
    REQUESTED_TO_REJECTED            (REQUESTED,            REJECTED,             CertificateEvent.UPDATE_STATE),

    // Issue / renew / rekey failure (v2 handleFailedOrRejectedEvent)
    REQUESTED_TO_FAILED              (REQUESTED,            FAILED,               CertificateEvent.ISSUE),
    PENDING_APPROVAL_TO_FAILED       (PENDING_APPROVAL,     FAILED,               CertificateEvent.ISSUE),

    // Approval-rejected transition for certs that were ISSUED before the approval was raised
    // (v2 issueCertificateRejectedAction; covers the ISSUED→REJECTED path in tests)
    ISSUED_TO_REJECTED               (ISSUED,               REJECTED,             CertificateEvent.UPDATE_STATE),
    ;

    public final CertificateState from;
    public final CertificateState to;
    public final CertificateEvent defaultAuditEvent;

    CertificateStateTransition(CertificateState from, CertificateState to, CertificateEvent defaultAuditEvent) {
        this.from = from;
        this.to = to;
        this.defaultAuditEvent = defaultAuditEvent;
    }

    public static Optional<CertificateStateTransition> lookup(CertificateState from, CertificateState to) {
        return Arrays.stream(values())
            .filter(t -> t.from == from && t.to == to)
            .findFirst();
    }
}
