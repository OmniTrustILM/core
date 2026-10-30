package com.otilm.core.signing.contentsigning.acquisition;

import com.otilm.api.model.common.enums.cryptography.SignatureAlgorithm;
import com.otilm.core.model.signing.resolved.ResolvedManagedContentSigningProfile;
import com.otilm.core.signing.engine.error.SigningEngineException;
import com.otilm.core.signing.tsa.messages.IssuedTimestamp;
import com.otilm.core.signing.tsa.messages.TimestampImprint;

/**
 * The engine's non-idempotent steps. Every acquisition enters the machine through this seam rather than inline.
 */
public interface ContentSigningAcquisitions {

    /**
     * The algorithm {@link #signatureValue} will sign with, answered without exercising the key. Content signing has to
     * announce it to the formatting connector before it has anything to sign.
     */
    SignatureAlgorithm signatureAlgorithm(ResolvedManagedContentSigningProfile profile) throws SigningEngineException;

    byte[] signatureValue(ResolvedManagedContentSigningProfile profile, byte[] dtbs) throws SigningEngineException;

    IssuedTimestamp signatureTimestamp(ResolvedManagedContentSigningProfile profile, TimestampImprint imprint,
            String step) throws SigningEngineException;
}
