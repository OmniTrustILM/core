package com.czertainly.core.signing.tsa.certificate;

import com.otilm.api.interfaces.core.tsp.error.TspFailureInfo;
import com.otilm.api.model.client.signing.profile.workflow.SigningWorkflowType;
import com.czertainly.core.model.signing.resolved.ResolvedManagedScheme;
import com.czertainly.core.model.signing.resolved.ResolvedStaticKeyManagedSigning;
import com.czertainly.core.util.CertificateEligibilityUtil;
import org.springframework.stereotype.Component;

@Component
public class StaticKeyManagedSigningCertificateValidator implements SigningCertificateValidator {

    @Override
    public boolean supports(ResolvedManagedScheme signingScheme) {
        return signingScheme instanceof ResolvedStaticKeyManagedSigning;
    }

    @Override
    public ValidationResult validate(ResolvedManagedScheme signingScheme, boolean qualifiedTimestamp) {
        if (!(signingScheme instanceof ResolvedStaticKeyManagedSigning signingSchemeModel)) {
            return ValidationResult.nok(TspFailureInfo.SYSTEM_FAILURE,
                    "The signing scheme '%s' is not supported by 'StaticKeyManagedSigningCertificateValidator'.".formatted(signingScheme.getClass().getSimpleName()),
                    "The system is misconfigured.");
        }
        if (!CertificateEligibilityUtil.isCertificateDigitalSigningAcceptable(signingSchemeModel.certificate(), signingSchemeModel.keyItems(), SigningWorkflowType.TIMESTAMPING, qualifiedTimestamp)) {
            return ValidationResult.nok(TspFailureInfo.SYSTEM_FAILURE,
                    "Signing certificate is not acceptable for %s timestamping".formatted(qualifiedTimestamp ? "qualified" : "non-qualified"),
                    "Signing certificate failed validation.");
        }
        return ValidationResult.ok();
    }
}
