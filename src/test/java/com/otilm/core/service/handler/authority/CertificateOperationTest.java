package com.otilm.core.service.handler.authority;

import com.otilm.api.model.core.certificate.CertificateState;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;

class CertificateOperationTest {

    @Test
    void pendingStateMapsPerOperation() {
        assertEquals(CertificateState.PENDING_ISSUE, CertificateOperation.ISSUE.pendingState());
        assertEquals(CertificateState.PENDING_ISSUE, CertificateOperation.RENEW.pendingState());
        assertEquals(CertificateState.PENDING_REVOKE, CertificateOperation.REVOKE.pendingState());
        assertEquals(CertificateState.PENDING_REGISTRATION, CertificateOperation.REGISTER.pendingState());
    }

    @Test
    void terminalSuccessStateMapsPerOperation() {
        assertEquals(CertificateState.ISSUED, CertificateOperation.ISSUE.terminalSuccessState());
        assertEquals(CertificateState.ISSUED, CertificateOperation.RENEW.terminalSuccessState());
        assertEquals(CertificateState.REGISTERED, CertificateOperation.REGISTER.terminalSuccessState());
        assertEquals(CertificateState.REVOKED, CertificateOperation.REVOKE.terminalSuccessState());
    }

    @Test
    void terminalFailureStateMapsPerOperation() {
        assertEquals(CertificateState.FAILED, CertificateOperation.ISSUE.terminalFailureState());
        assertEquals(CertificateState.FAILED, CertificateOperation.RENEW.terminalFailureState());
        assertEquals(CertificateState.FAILED, CertificateOperation.REGISTER.terminalFailureState());
        // A failed/cancelled revoke leaves the certificate ISSUED, not FAILED.
        assertEquals(CertificateState.ISSUED, CertificateOperation.REVOKE.terminalFailureState());
    }
}
