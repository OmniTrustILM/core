package com.otilm.core.signing.engine.signer;

import com.otilm.api.model.common.enums.cryptography.SignatureAlgorithm;
import com.otilm.core.model.signing.resolved.ResolvedManagedScheme;
import com.otilm.core.signing.engine.error.SigningEngineException;
import com.otilm.core.signing.engine.error.SigningEngineFailure;
import java.util.List;
import org.springframework.stereotype.Component;

/**
 * Selects the appropriate {@link SignerCreator} for a given signing scheme.
 */
@Component
public class SignerFactory {

    private final List<SignerCreator> creators;

    public SignerFactory(List<SignerCreator> creators) {
        this.creators = creators;
    }

    public Signer create(ResolvedManagedScheme signingScheme) throws SigningEngineException {
        return creators
                .stream()
                .filter(c -> c.supports(signingScheme))
                .findFirst()
                .orElseThrow(() -> new SigningEngineException(SigningEngineFailure.MISCONFIGURED,
                        "No SignerCreator supports signing scheme '%s'"
                                .formatted(signingScheme.getClass().getSimpleName()),
                        "The system is misconfigured."))
                .create(signingScheme);
    }

    /**
     * The signature algorithm {@link #create} would sign with, answered without exercising the key. It resolves a
     * throwaway {@link Signer} that the signing call resolves again, and the two agree by the determinism
     * {@link SignerCreator#create} requires.
     */
    public SignatureAlgorithm signatureAlgorithm(ResolvedManagedScheme signingScheme) throws SigningEngineException {
        return create(signingScheme).getSignatureAlgorithm();
    }
}
