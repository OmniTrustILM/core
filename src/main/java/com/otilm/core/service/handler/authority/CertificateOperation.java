package com.otilm.core.service.handler.authority;

import com.otilm.api.model.core.certificate.CertificateState;

public enum CertificateOperation {
    ISSUE,
    RENEW,
    REVOKE,
    REGISTER;

    /** The PENDING state a certificate sits in while this operation is async-in-flight. */
    public CertificateState pendingState() {
        return switch (this) {
            case ISSUE, RENEW -> CertificateState.PENDING_ISSUE;
            case REVOKE       -> CertificateState.PENDING_REVOKE;
            case REGISTER     -> CertificateState.PENDING_REGISTRATION;
        };
    }

    /** Terminal state when this operation completes successfully. */
    public CertificateState terminalSuccessState() {
        return switch (this) {
            case ISSUE, RENEW -> CertificateState.ISSUED;
            case REGISTER     -> CertificateState.REGISTERED;
            case REVOKE       -> CertificateState.REVOKED;
        };
    }

    /**
     * Terminal state when this operation fails or is cancelled. Note REVOKE failure returns the
     * certificate to ISSUED — a failed/cancelled revocation leaves the cert valid, not FAILED.
     */
    public CertificateState terminalFailureState() {
        return switch (this) {
            case ISSUE, RENEW, REGISTER -> CertificateState.FAILED;
            case REVOKE                 -> CertificateState.ISSUED;
        };
    }
}
