package com.czertainly.core.service.handler.authority.lifecycle;

import com.czertainly.api.model.core.certificate.CertificateEvent;
import com.czertainly.api.model.core.certificate.CertificateState;
import org.junit.jupiter.api.Test;

import java.util.Optional;

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
    void allCriticalTransitionsArePresent() {
        // Issue / renew / register
        assertTrue(CertificateStateTransition.lookup(CertificateState.REQUESTED, CertificateState.PENDING_ISSUE).isPresent());
        assertTrue(CertificateStateTransition.lookup(CertificateState.PENDING_ISSUE, CertificateState.ISSUED).isPresent());
        assertTrue(CertificateStateTransition.lookup(CertificateState.PENDING_ISSUE, CertificateState.FAILED).isPresent());
        assertTrue(CertificateStateTransition.lookup(CertificateState.REQUESTED, CertificateState.PENDING_REGISTRATION).isPresent());
        assertTrue(CertificateStateTransition.lookup(CertificateState.PENDING_REGISTRATION, CertificateState.REGISTERED).isPresent());
        assertTrue(CertificateStateTransition.lookup(CertificateState.PENDING_REGISTRATION, CertificateState.FAILED).isPresent());
        assertTrue(CertificateStateTransition.lookup(CertificateState.REGISTERED, CertificateState.PENDING_ISSUE).isPresent());

        // Revoke
        assertTrue(CertificateStateTransition.lookup(CertificateState.ISSUED, CertificateState.PENDING_REVOKE).isPresent());
        assertTrue(CertificateStateTransition.lookup(CertificateState.PENDING_REVOKE, CertificateState.REVOKED).isPresent());
        assertTrue(CertificateStateTransition.lookup(CertificateState.PENDING_REVOKE, CertificateState.ISSUED).isPresent());
        assertTrue(CertificateStateTransition.lookup(CertificateState.ISSUED, CertificateState.REVOKED).isPresent());

        // Approval flows
        assertTrue(CertificateStateTransition.lookup(CertificateState.REQUESTED, CertificateState.PENDING_APPROVAL).isPresent());
        assertTrue(CertificateStateTransition.lookup(CertificateState.ISSUED, CertificateState.PENDING_APPROVAL).isPresent());
        assertTrue(CertificateStateTransition.lookup(CertificateState.PENDING_APPROVAL, CertificateState.PENDING_ISSUE).isPresent());
        assertTrue(CertificateStateTransition.lookup(CertificateState.PENDING_APPROVAL, CertificateState.PENDING_REVOKE).isPresent());
        assertTrue(CertificateStateTransition.lookup(CertificateState.PENDING_APPROVAL, CertificateState.REJECTED).isPresent());
        assertTrue(CertificateStateTransition.lookup(CertificateState.PENDING_APPROVAL, CertificateState.ISSUED).isPresent());

        // Compliance rejection
        assertTrue(CertificateStateTransition.lookup(CertificateState.REQUESTED, CertificateState.REJECTED).isPresent());
    }
}
