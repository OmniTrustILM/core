package com.otilm.core.signing.tsa.signer;

import com.otilm.api.interfaces.core.tsp.error.TspException;
import com.otilm.core.model.signing.resolved.ResolvedManagedScheme;

/**
 * Creates a {@link Signer} for a specific type of signing scheme.
 * Each implementation handles one scheme type and declares support via {@link #supports}.
 */
public interface SignerCreator {

    boolean supports(ResolvedManagedScheme signingScheme);

    Signer create(ResolvedManagedScheme signingScheme) throws TspException;
}
