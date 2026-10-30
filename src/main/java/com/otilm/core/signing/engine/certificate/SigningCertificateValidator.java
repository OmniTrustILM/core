package com.otilm.core.signing.engine.certificate;

import com.otilm.api.model.client.signing.profile.workflow.SigningWorkflowType;
import com.otilm.core.model.signing.CertificatePurposeRequirements;
import com.otilm.core.model.signing.resolved.ResolvedManagedScheme;

/**
 * Per-scheme strategy that validates the signing certificate against the signing workflow requirements.
 *
 * <p>
 * The certificate chain itself is built and validated once at resolution time and carried by the resolved scheme
 * ({@link ResolvedManagedScheme#chain()}); this type does not source it.
 * </p>
 */
public interface SigningCertificateValidator {

    boolean supports(ResolvedManagedScheme signingScheme);

    /**
     * Validates the signing certificate against the workflow's requirements.
     *
     * @param signingScheme the resolved scheme this validator declared support for via {@link #supports}
     * @param workflowType drives which eligibility rules apply
     * @param qualifiedTimestamp meaningful only for {@link SigningWorkflowType#TIMESTAMPING}
     * @param certificatePurpose the profile's certificate-purpose constraints
     * @return {@link ValidationResult#ok()} if the certificate is acceptable, or {@link ValidationResult#nok}
     * describing the reason for rejection.
     */
    ValidationResult validate(ResolvedManagedScheme signingScheme, SigningWorkflowType workflowType,
            boolean qualifiedTimestamp, CertificatePurposeRequirements certificatePurpose);
}
