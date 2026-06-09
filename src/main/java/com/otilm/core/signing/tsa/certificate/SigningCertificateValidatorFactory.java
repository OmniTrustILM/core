package com.otilm.core.signing.tsa.certificate;

import com.otilm.api.interfaces.core.tsp.error.TspException;
import com.otilm.api.interfaces.core.tsp.error.TspFailureInfo;
import com.otilm.core.model.signing.resolved.ResolvedManagedScheme;
import org.springframework.stereotype.Component;

import java.util.List;

/**
 * Selects the appropriate {@link SigningCertificateValidator} for a given signing scheme.
 */
@Component
public class SigningCertificateValidatorFactory {

    private final List<SigningCertificateValidator> providers;

    public SigningCertificateValidatorFactory(List<SigningCertificateValidator> providers) {
        this.providers = providers;
    }

    public SigningCertificateValidator getValidator(ResolvedManagedScheme signingScheme) throws TspException {
        return providers.stream()
                .filter(p -> p.supports(signingScheme))
                .findFirst()
                .orElseThrow(() -> new TspException(
                        TspFailureInfo.SYSTEM_FAILURE,
                        "No SigningCertificateValidator supports signing scheme '%s'".formatted(
                                signingScheme.getClass().getSimpleName()),
                        "The system is misconfigured."));
    }
}