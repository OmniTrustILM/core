package com.otilm.core.dao.entity;

/**
 * Lifecycle of a {@link CertificateRegistrationAuthorization}: {@code ACTIVE} while it can still authorize an
 * operation, {@code EXPIRED} once its issuance window has passed, {@code LOCKED} after too many failed challenge
 * attempts, and {@code CLOSED} once it has been retired.
 */
public enum RegistrationState {
    ACTIVE,
    EXPIRED,
    LOCKED,
    CLOSED
}
