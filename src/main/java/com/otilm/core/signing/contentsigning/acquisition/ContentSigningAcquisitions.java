package com.otilm.core.signing.contentsigning.acquisition;

import com.otilm.core.model.signing.resolved.ResolvedManagedContentSigningProfile;
import com.otilm.core.signing.engine.error.SigningEngineException;
import com.otilm.core.signing.tsa.messages.IssuedTimestamp;
import com.otilm.core.signing.tsa.messages.TimestampImprint;

/**
 * The engine's non-idempotent steps. Every acquisition enters the machine through this seam rather than inline, so an
 * asynchronous lifecycle can persist one and replay it without reshaping the engine.
 */
public interface ContentSigningAcquisitions {

    byte[] signatureValue(ResolvedManagedContentSigningProfile profile, byte[] dtbs) throws SigningEngineException;

    IssuedTimestamp signatureTimestamp(ResolvedManagedContentSigningProfile profile, TimestampImprint imprint,
            String step) throws SigningEngineException;
}
