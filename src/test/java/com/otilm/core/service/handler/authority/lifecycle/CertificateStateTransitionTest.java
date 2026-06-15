package com.otilm.core.service.handler.authority.lifecycle;

import com.otilm.api.model.core.certificate.CertificateEvent;
import com.otilm.api.model.core.certificate.CertificateEventStatus;
import com.otilm.api.model.core.certificate.CertificateState;
import org.junit.jupiter.api.Test;

import java.util.Optional;

import static com.otilm.api.model.core.certificate.CertificateState.*;
import static org.junit.jupiter.api.Assertions.*;

class CertificateStateTransitionTest {

    @Test
    void lookupReturnsRowForKnownTransition() {
        Optional<CertificateStateTransition> row =
            CertificateStateTransition.lookup(CertificateState.REQUESTED, CertificateState.PENDING_ISSUE);
        assertTrue(row.isPresent());
        assertEquals(CertificateEvent.ISSUE, row.get().defaultAuditEvent);
    }

    @Test
    void lookupReturnsEmptyForUnknownTransition() {
        Optional<CertificateStateTransition> row =
            CertificateStateTransition.lookup(CertificateState.REVOKED, CertificateState.ISSUED);
        assertFalse(row.isPresent());
    }

    @Test
    void everyTransitionHasExpectedAuditEventAndStatus() {
        // Asserts presence AND the default audit event + status for every row, so a wrong mapping
        // (e.g. a mislabeled audit event, or a failure transition that records SUCCESS) fails here.
        CertificateEvent issue = CertificateEvent.ISSUE;
        CertificateEvent approvalRequest = CertificateEvent.APPROVAL_REQUEST;
        CertificateEvent approvalClose = CertificateEvent.APPROVAL_CLOSE;
        CertificateEvent revoke = CertificateEvent.REVOKE;
        CertificateEvent updateState = CertificateEvent.UPDATE_STATE;
        CertificateEventStatus success = CertificateEventStatus.SUCCESS;
        CertificateEventStatus failed = CertificateEventStatus.FAILED;

        // Issue (sync + async)
        assertRow(REQUESTED, PENDING_ISSUE, issue, success);
        assertRow(PENDING_ISSUE, ISSUED, issue, success);
        assertRow(PENDING_ISSUE, FAILED, issue, failed);

        // Issue approval flow
        assertRow(REQUESTED, PENDING_APPROVAL, approvalRequest, success);
        assertRow(PENDING_APPROVAL, PENDING_ISSUE, approvalClose, success);
        assertRow(PENDING_APPROVAL, REJECTED, approvalClose, failed);

        // Revoke (sync + async)
        assertRow(ISSUED, PENDING_REVOKE, revoke, success);
        assertRow(PENDING_REVOKE, REVOKED, revoke, success);
        assertRow(PENDING_REVOKE, ISSUED, revoke, failed);   // revoke failed/cancelled — restore
        assertRow(ISSUED, REVOKED, revoke, success);

        // Revoke approval flow
        assertRow(ISSUED, PENDING_APPROVAL, approvalRequest, success);
        assertRow(PENDING_APPROVAL, PENDING_REVOKE, approvalClose, success);
        assertRow(PENDING_APPROVAL, ISSUED, approvalClose, failed);   // revoke rejected — restore

        // v3 register lifecycle
        assertRow(REQUESTED, PENDING_REGISTRATION, updateState, success);
        assertRow(PENDING_REGISTRATION, REGISTERED, updateState, success);
        assertRow(PENDING_REGISTRATION, FAILED, updateState, failed);
        assertRow(REGISTERED, PENDING_ISSUE, issue, success);

        // Compliance rejection + issue/renew/rekey failure + ISSUED-rejection
        assertRow(REQUESTED, REJECTED, updateState, failed);
        assertRow(REQUESTED, FAILED, issue, failed);
        assertRow(PENDING_APPROVAL, FAILED, issue, failed);
        assertRow(ISSUED, REJECTED, updateState, failed);
    }

    private static void assertRow(CertificateState from, CertificateState to,
                                  CertificateEvent expectedEvent, CertificateEventStatus expectedStatus) {
        Optional<CertificateStateTransition> row = CertificateStateTransition.lookup(from, to);
        assertTrue(row.isPresent(), () -> "missing transition " + from + " -> " + to);
        assertEquals(expectedEvent, row.get().defaultAuditEvent,
            () -> "wrong default audit event for " + from + " -> " + to);
        assertEquals(expectedStatus, row.get().defaultStatus,
            () -> "wrong default status for " + from + " -> " + to);
    }
}
