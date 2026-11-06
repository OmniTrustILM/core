package com.otilm.core.signing.engine.signer;

import com.otilm.api.model.common.enums.cryptography.SignatureAlgorithm;
import com.otilm.api.model.common.enums.cryptography.SignatureInputMode;
import com.otilm.core.signing.engine.error.SigningEngineException;

import java.util.List;

/**
 * Signs opaque data-to-be-signed with its configured key, one item or a batch, and returns the raw signature bytes. The
 * caller decides what the bytes are, for example a DTBS or a digest.
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
     * @param dtbs the bytes to sign; must not be null or empty
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
     * Signs every item in one provider call, treating each as data to hash and sign.
     *
     * @param dtbsList the items to sign; must not be null or empty, and no item may be null or empty
     * @return raw signatures, where element {@code i} is the signature of {@code dtbsList.get(i)}
     * @throws SigningEngineException if signing fails
     * @throws IllegalArgumentException if the list or any item is null or empty
     */
    default List<byte[]> signAll(List<byte[]> dtbsList) throws SigningEngineException {
        return signAll(dtbsList, SignatureInputMode.DATA);
    }

    /**
     * Signs every item in one provider call. The mode states what each item is: data the provider hashes and signs, or
     * a digest it signs as is.
     *
     * @param items the items to sign; must not be null or empty, and no item may be null or empty
     * @param inputMode what each item is; null means {@link SignatureInputMode#DATA}
     * @return raw signatures, where element {@code i} is the signature of {@code items.get(i)}
     * @throws SigningEngineException if the input cannot be signed in this mode or signing fails
     * @throws IllegalArgumentException if the list or any item is null or empty
     */
    List<byte[]> signAll(List<byte[]> items, SignatureInputMode inputMode) throws SigningEngineException;
}
