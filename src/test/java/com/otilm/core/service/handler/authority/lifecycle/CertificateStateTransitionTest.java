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
        CertificateEvent ISSUE = CertificateEvent.ISSUE;
        CertificateEvent APPROVAL_REQUEST = CertificateEvent.APPROVAL_REQUEST;
        CertificateEvent APPROVAL_CLOSE = CertificateEvent.APPROVAL_CLOSE;
        CertificateEvent REVOKE = CertificateEvent.REVOKE;
        CertificateEvent UPDATE_STATE = CertificateEvent.UPDATE_STATE;
        CertificateEventStatus OK = CertificateEventStatus.SUCCESS;
        CertificateEventStatus FAIL = CertificateEventStatus.FAILED;

        // Issue (sync + async)
        assertRow(REQUESTED, PENDING_ISSUE, ISSUE, OK);
        assertRow(PENDING_ISSUE, ISSUED, ISSUE, OK);
        assertRow(PENDING_ISSUE, FAILED, ISSUE, FAIL);

        // Issue approval flow
        assertRow(REQUESTED, PENDING_APPROVAL, APPROVAL_REQUEST, OK);
        assertRow(PENDING_APPROVAL, PENDING_ISSUE, APPROVAL_CLOSE, OK);
        assertRow(PENDING_APPROVAL, REJECTED, APPROVAL_CLOSE, FAIL);

        // Revoke (sync + async)
        assertRow(ISSUED, PENDING_REVOKE, REVOKE, OK);
        assertRow(PENDING_REVOKE, REVOKED, REVOKE, OK);
        assertRow(PENDING_REVOKE, ISSUED, REVOKE, FAIL);   // revoke failed/cancelled — restore
        assertRow(ISSUED, REVOKED, REVOKE, OK);

        // Revoke approval flow
        assertRow(ISSUED, PENDING_APPROVAL, APPROVAL_REQUEST, OK);
        assertRow(PENDING_APPROVAL, PENDING_REVOKE, APPROVAL_CLOSE, OK);
        assertRow(PENDING_APPROVAL, ISSUED, APPROVAL_CLOSE, FAIL);   // revoke rejected — restore

        // v3 register lifecycle
        assertRow(REQUESTED, PENDING_REGISTRATION, UPDATE_STATE, OK);
        assertRow(PENDING_REGISTRATION, REGISTERED, UPDATE_STATE, OK);
        assertRow(PENDING_REGISTRATION, FAILED, UPDATE_STATE, FAIL);
        assertRow(REGISTERED, PENDING_ISSUE, ISSUE, OK);

        // Compliance rejection + issue/renew/rekey failure + ISSUED-rejection
        assertRow(REQUESTED, REJECTED, UPDATE_STATE, FAIL);
        assertRow(REQUESTED, FAILED, ISSUE, FAIL);
        assertRow(PENDING_APPROVAL, FAILED, ISSUE, FAIL);
        assertRow(ISSUED, REJECTED, UPDATE_STATE, FAIL);
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
