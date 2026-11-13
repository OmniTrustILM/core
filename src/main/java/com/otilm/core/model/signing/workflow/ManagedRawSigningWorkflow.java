package com.otilm.core.model.signing.workflow;

import com.otilm.core.model.signing.CertificatePurposeRequirements;

/**
 * Raw-signing workflow for ILM-managed signing.
 *
 * @param certificatePurpose what the signing certificate must carry; {@code null} means no requirement
 */
public record ManagedRawSigningWorkflow(
        CertificatePurposeRequirements certificatePurpose) implements RawSigningWorkflow {

    public ManagedRawSigningWorkflow {
        if (certificatePurpose == null) {
            certificatePurpose = CertificatePurposeRequirements.NONE;
        }
    }
}
