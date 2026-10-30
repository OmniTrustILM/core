package com.otilm.core.signing.engine.certificate;

import com.otilm.core.model.signing.resolved.ResolvedManagedScheme;
import com.otilm.core.signing.engine.error.SigningEngineException;
import com.otilm.core.signing.engine.error.SigningEngineFailure;
import java.util.List;
import org.springframework.stereotype.Component;

/**
 * Selects the appropriate {@link SigningCertificateValidator} for a given signing scheme.
 */
@Component
public class SigningCertificateValidatorFactory {

    private final List<SigningCertificateValidator> providers;

    public SigningCertificateValidatorFactory(List<SigningCertificateValidator> providers) {
        this.providers = providers;
    }

    public SigningCertificateValidator getValidator(ResolvedManagedScheme signingScheme) throws SigningEngineException {
        return providers
                .stream()
                .filter(p -> p.supports(signingScheme))
                .findFirst()
                .orElseThrow(
                        () -> new SigningEngineException(SigningEngineFailure.MISCONFIGURED,
                                "No SigningCertificateValidator supports signing scheme '%s'"
                                        .formatted(signingScheme.getClass().getSimpleName()),
                                "The system is misconfigured."));
    }
}
