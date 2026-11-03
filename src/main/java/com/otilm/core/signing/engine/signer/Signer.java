package com.otilm.core.signing.engine.signer;

import com.otilm.api.model.common.enums.cryptography.SignatureAlgorithm;
import com.otilm.core.signing.engine.error.SigningEngineException;

import java.util.List;

/**
 * Signs a byte array and returns the raw signature bytes. The bytes passed are the DER-encoded SignedAttributes as
 * produced by BouncyCastle's SignerInfoGenerator — i.e. the DTBS for the timestamp token.
 */
public interface Signer {

    /**
     * The signature algorithm this signer uses, e.g. SHA256withRSA. Required so the formatting can configure the
     * content signer and derive the content digest algorithm for the timestamp token generator.
     */
    SignatureAlgorithm getSignatureAlgorithm();

    /**
     * Signs {@code dtbs} and returns the raw signature bytes. A batch of one.
     *
     * @param dtbs DER-encoded SignedAttributes to sign; must not be null or empty
     * @return raw signature bytes
     * @throws SigningEngineException if signing fails
     * @throws IllegalArgumentException if dtbs is null or empty
     */
    default byte[] sign(byte[] dtbs) throws SigningEngineException {
        if (dtbs == null || dtbs.length == 0) {
            throw new IllegalArgumentException("dtbs must not be null or empty");
        }
        return signAll(List.of(dtbs)).getFirst();
    }

    /**
     * Signs every item in one provider call.
     *
     * @param dtbsList the items to sign; must not be null or empty, and no item may be null or empty
     * @return raw signatures, where element {@code i} is the signature of {@code dtbsList.get(i)}
     * @throws SigningEngineException if signing fails
     * @throws IllegalArgumentException if the list or any item is null or empty
     */
    List<byte[]> signAll(List<byte[]> dtbsList) throws SigningEngineException;
}
