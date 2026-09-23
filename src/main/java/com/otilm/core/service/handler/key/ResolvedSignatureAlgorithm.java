package com.otilm.core.service.handler.key;

import com.otilm.api.exception.ValidationError;
import com.otilm.api.exception.ValidationException;
import com.otilm.api.model.common.enums.cryptography.SignatureAlgorithm;
import java.util.Objects;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;

/**
 * What a provider signs with, in the two forms callers need.
 *
 * <p>
 * Naming an algorithm inside a structure needs only an {@link AlgorithmIdentifier}, and one always exists. Driving CMS
 * needs the platform's own {@link SignatureAlgorithm}, which also fixes the digest the signature commits to, and that
 * vocabulary is narrower: a legacy provider can be configured with a digest the platform has no entry for, which is
 * usable in a certificate request but not in a timestamp token. Keeping both apart lets each caller ask for what it can
 * actually use instead of the widest common answer.
 * </p>
 *
 * @param name the algorithm as the provider named it, kept for the operator who has to act on it
 * @param identifier the algorithm as it is written into a signed structure
 * @param platformAlgorithm the platform's entry for it, or null when the platform has none
 */
public record ResolvedSignatureAlgorithm(String name, AlgorithmIdentifier identifier,
        SignatureAlgorithm platformAlgorithm) {

    public ResolvedSignatureAlgorithm {
        Objects.requireNonNull(name, "A signature algorithm name is required.");
        Objects.requireNonNull(identifier, "A signature algorithm identifier is required.");
    }

    public static ResolvedSignatureAlgorithm of(SignatureAlgorithm algorithm) {
        return new ResolvedSignatureAlgorithm(algorithm.getCode(), algorithm.getAlgorithmIdentifier(), algorithm);
    }

    /**
     * The platform's entry for this algorithm, for a caller that cannot work without one.
     *
     * @throws ValidationException when the platform has no entry, which is an operator-fixable configuration and not a
     * platform fault
     */
    public SignatureAlgorithm requirePlatformAlgorithm() {
        if (platformAlgorithm == null) {
            throw new ValidationException(
                    ValidationError.create("Signature algorithm " + name + " is not one the platform supports."));
        }
        return platformAlgorithm;
    }
}
