package com.czertainly.core.signing.tsa.signer;

import com.czertainly.api.interfaces.core.tsp.error.TspException;
import com.czertainly.api.model.common.enums.cryptography.SignatureAlgorithm;

/**
 * Signs a byte array and returns the raw signature bytes.
 * The bytes passed are the DER-encoded SignedAttributes as produced
 * by BouncyCastle's SignerInfoGenerator — i.e. the DTBS for the timestamp token.
 */
public interface Signer {

    /**
     * The signature algorithm this signer uses, e.g. SHA256withRSA.
     * Required so the formatter can configure the content signer and
     * derive the content digest algorithm for the timestamp token generator.
     */
    SignatureAlgorithm getSignatureAlgorithm();

    /**
     * Signs {@code dtbs} and returns the raw signature bytes.
     *
     * @param dtbs DER-encoded SignedAttributes to sign; must not be null or empty
     * @return raw signature bytes
     * @throws TspException if signing fails
     * @throws IllegalArgumentException if dtbs is null or empty
     */
    byte[] sign(byte[] dtbs) throws TspException;
}
