package com.otilm.core.signing.engine.certificate;

import com.otilm.api.model.client.signing.profile.workflow.SigningWorkflowType;
import com.otilm.core.model.signing.CertificatePurposeRequirements;
import com.otilm.core.model.signing.resolved.ResolvedManagedScheme;
import com.otilm.core.model.signing.resolved.ResolvedStaticKeyManagedSigning;
import com.otilm.core.signing.engine.error.SigningEngineFailure;
import com.otilm.core.util.CertificateEligibilityUtil;
import org.springframework.stereotype.Component;

@Component
public class StaticKeyManagedSigningCertificateValidator implements SigningCertificateValidator {

    @Override
    public boolean supports(ResolvedManagedScheme signingScheme) {
        return signingScheme instanceof ResolvedStaticKeyManagedSigning;
    }

    @Override
    public ValidationResult validate(ResolvedManagedScheme signingScheme, SigningWorkflowType workflowType,
            boolean qualifiedTimestamp, CertificatePurposeRequirements certificatePurpose) {
        if (!(signingScheme instanceof ResolvedStaticKeyManagedSigning signingSchemeModel)) {
            return ValidationResult
                    .nok(SigningEngineFailure.MISCONFIGURED,
                            "The signing scheme '%s' is not supported by 'StaticKeyManagedSigningCertificateValidator'."
                                    .formatted(signingScheme.getClass().getSimpleName()),
                            "The system is misconfigured.");
        }
        if (!CertificateEligibilityUtil
                .isCertificateDigitalSigningAcceptable(signingSchemeModel.certificate(), signingSchemeModel.keyItems(),
                        workflowType, qualifiedTimestamp, certificatePurpose)) {
            return ValidationResult
                    .nok(SigningEngineFailure.MISCONFIGURED,
                            "Signing certificate is not acceptable for %s%s"
                                    .formatted(qualifier(workflowType, qualifiedTimestamp), workflowType.getCode()),
                            "Signing certificate failed validation.");
        }
        return ValidationResult.ok();
    }

    /** The qualified/non-qualified distinction is an ETSI EN 319 421 concept, so it only qualifies timestamping. */
    private static String qualifier(SigningWorkflowType workflowType, boolean qualifiedTimestamp) {
        if (workflowType != SigningWorkflowType.TIMESTAMPING) {
            return "";
        }
        return qualifiedTimestamp ? "qualified " : "non-qualified ";
    }
}
