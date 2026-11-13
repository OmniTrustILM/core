package com.otilm.core.signing.contentsigning.acquisition;

import com.otilm.api.model.common.enums.cryptography.SignatureAlgorithm;
import com.otilm.core.model.signing.resolved.ResolvedManagedContentSigningProfile;
import com.otilm.core.signing.engine.error.ItemSigningException;
import com.otilm.core.signing.engine.error.SigningEngineException;
import com.otilm.core.signing.tsa.messages.IssuedTimestamp;
import com.otilm.core.signing.tsa.messages.TimestampImprint;
import java.util.List;

/**
 * The engine's steps that make something new on every call: a signature with the profile's key and a timestamp from its
 * TSA. A run reaches them only here, so a persisted run can replay the rest of its steps with their results injected.
 */
public interface ContentSigningAcquisitions {

    /**
     * The algorithm {@link #signDtbs} will sign with, answered without signing anything. Content signing has to
     * announce it to the formatting connector before it has anything to sign.
     */
    SignatureAlgorithm signatureAlgorithm(ResolvedManagedContentSigningProfile profile) throws SigningEngineException;

    /**
     * Signs every data-to-be-signed in one call of the profile's key.
     *
     * @return the signature values, where element {@code i} signs {@code dtbsList.get(i)}
     * @throws ItemSigningException if the key fails one element, at that element's index in {@code dtbsList}
     */
    List<byte[]> signDtbs(ResolvedManagedContentSigningProfile profile, List<byte[]> dtbsList)
            throws SigningEngineException;

    IssuedTimestamp timestampSignature(ResolvedManagedContentSigningProfile profile, TimestampImprint imprint,
            String step) throws SigningEngineException;
}
