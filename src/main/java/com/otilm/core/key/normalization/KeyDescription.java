package com.otilm.core.key.normalization;

import com.otilm.api.model.client.cryptography.key.KeyRequestType;
import com.otilm.api.model.common.enums.cryptography.KeyAlgorithm;

/**
 * What an uploaded key turned out to be, read without protecting it for a connector.
 *
 * @param type the key type, or {@code null} when the algorithm is one the platform does not support
 * @param algorithm the key's algorithm, or {@code null} when the platform does not support it
 * @param length the key's length in bits, 0 when unknown
 * @param subjectPublicKeyInfo the DER {@code SubjectPublicKeyInfo} derived from the key, {@code null} for a secret key
 * or an unsupported algorithm
 * @param unsupportedAlgorithm the object identifier of an algorithm the platform does not support, or the name a JCEKS
 * store gives it for a secret key; {@value #UNRECOGNIZED_ALGORITHM} when it is too long or unusual to repeat;
 * {@code null} for a supported algorithm
 */
// S6218: nothing compares, hashes or prints a description as a whole; its public key is compared as bytes.
@SuppressWarnings("java:S6218")
public record KeyDescription(KeyRequestType type, KeyAlgorithm algorithm, int length, byte[] subjectPublicKeyInfo,
        String unsupportedAlgorithm) {

    /** The unsupported algorithm of a key whose object identifier is too long or unusual to repeat. */
    public static final String UNRECOGNIZED_ALGORITHM = "unrecognized";

    /**
     * Whether the platform supports the key's algorithm.
     *
     * @return {@code true} when the key has an algorithm the platform supports
     */
    public boolean supported() {
        return algorithm != null;
    }

    /**
     * A key of an algorithm the platform does not support.
     *
     * @param algorithm the algorithm's object identifier, or its name when the file names it without one; it is kept
     * only when it is plain and short enough to repeat
     * @return the description
     */
    static KeyDescription unsupported(String algorithm) {
        return new KeyDescription(null, null, 0, null,
                KeyFileRefusal.repeatable(algorithm) ? algorithm : UNRECOGNIZED_ALGORITHM);
    }
}
