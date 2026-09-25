package com.otilm.core.service.handler.key;

import com.otilm.api.exception.ValidationError;
import com.otilm.api.exception.ValidationException;
import com.otilm.api.model.common.enums.cryptography.SignatureAlgorithm;
import com.otilm.core.util.CryptographyUtil;
import java.util.Objects;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;

/**
 * The signature algorithm a signing selection produces.
 *
 * @param name the algorithm as the selection names it, kept for the operator who has to act on it
 * @param platformAlgorithm the platform's entry for it, or null when the platform has none
 */
public record ResolvedSignatureAlgorithm(String name, SignatureAlgorithm platformAlgorithm) {

    public ResolvedSignatureAlgorithm {
        Objects.requireNonNull(name, "A signature algorithm name is required.");
    }

    public static ResolvedSignatureAlgorithm of(SignatureAlgorithm algorithm) {
        return new ResolvedSignatureAlgorithm(algorithm.getCode(), algorithm);
    }

    public SignatureAlgorithm requirePlatformAlgorithm() {
        if (platformAlgorithm == null) {
            throw new ValidationException(
                    ValidationError.create("Signature algorithm " + name + " is not one the platform supports."));
        }
        return platformAlgorithm;
    }

    /**
     * The identifier a signature under this algorithm is labelled with. A legacy provider can select an algorithm the
     * platform has no entry for, such as a SHA-3 digest, which is then looked up by name.
     */
    public AlgorithmIdentifier algorithmIdentifier() {
        return platformAlgorithm != null
                ? platformAlgorithm.getAlgorithmIdentifier()
                : CryptographyUtil.getAlgorithmIdentifierInstance(name);
    }
}
