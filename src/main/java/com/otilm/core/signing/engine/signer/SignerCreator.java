package com.otilm.core.signing.engine.signer;

import com.otilm.core.model.signing.resolved.ResolvedManagedScheme;
import com.otilm.core.signing.engine.error.SigningEngineException;

/**
 * Creates a {@link Signer} for a specific type of signing scheme. Each implementation handles one scheme type and
 * declares support via {@link #supports}.
 */
public interface SignerCreator {

    boolean supports(ResolvedManagedScheme signingScheme);

    /**
     * The signature algorithm of the returned {@link Signer} must derive purely from the {@link ResolvedManagedScheme},
     * which is immutable for the run. An algorithm depending on anything else -- a clock, a counter, a remote lookup --
     * would let the algorithm {@link SignerFactory#signatureAlgorithm} announces drift from the one that signs.
     *
     * <p>
     * The returned {@link Signer} may be created only so its algorithm can be read and then discarded, so acquire
     * nothing that needs releasing.
     */
    Signer create(ResolvedManagedScheme signingScheme) throws SigningEngineException;
}
