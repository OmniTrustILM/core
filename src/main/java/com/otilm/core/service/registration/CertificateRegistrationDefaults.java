package com.otilm.core.service.registration;

/**
 * Canonical defaults for certificate pre-registration, shared by the settings service (as the operator-visible
 * default it seeds and persists) and the client-operations gate (as the cache-miss fallback) so the value the
 * platform reports can never drift from the value it applies.
 */
public final class CertificateRegistrationDefaults {

    private CertificateRegistrationDefaults() {
    }

    /** Default issuance window in days, applied when a pre-registration omits an explicit expiry. */
    public static final int ISSUANCE_WINDOW_DAYS = 7;

    /** Maximum failed challenge-verification attempts before the registration authorization locks. */
    public static final int MAX_FAILED_ATTEMPTS = 5;
}
