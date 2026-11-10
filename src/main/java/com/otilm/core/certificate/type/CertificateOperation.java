package com.otilm.core.certificate.type;

/**
 * An operation a certificate type may or may not support. A handler declares the set it supports; callers check it
 * before offering or running the operation.
 */
public enum CertificateOperation {
    REVOKE,
    RENEW,
    REKEY,
    CHAIN_VALIDATION,
    COMPLIANCE,
    PUSH_TO_LOCATION,
    DISCOVERY,
    ACME_ENROLLMENT,
    SCEP_ENROLLMENT,
    CMP_ENROLLMENT,
    EST_ENROLLMENT
}
