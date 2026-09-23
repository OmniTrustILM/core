package com.otilm.core.service.handler.key;

import com.otilm.api.exception.ValidationError;
import com.otilm.api.exception.ValidationException;
import com.otilm.api.model.common.enums.cryptography.SignatureAlgorithm;
import java.util.Objects;

/**
 * What a provider signs with.
 *
 * @param name the algorithm as the provider named it, kept for the operator who has to act on it
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
}
