package com.czertainly.core.signing.tsa.certificate;

import com.czertainly.core.model.signing.resolved.ResolvedManagedScheme;

/**
 * Per-scheme strategy that validates the signing certificate against the signing workflow requirements.
 *
 * <p>The certificate chain itself is built and validated once at resolution time and carried by the
 * resolved scheme ({@link ResolvedManagedScheme#chain()}); this type does not source it.</p>
 */
public interface SigningCertificateValidator {

    boolean supports(ResolvedManagedScheme signingScheme);

    /**
     * Validates the signing certificate against the signing workflow requirements.
     *
     * @return {@link ValidationResult#ok()} if the certificate is acceptable,
     *         or {@link ValidationResult#nok} describing the reason for rejection.
     */
    ValidationResult validate(ResolvedManagedScheme signingScheme, boolean qualifiedTimestamp);
}
