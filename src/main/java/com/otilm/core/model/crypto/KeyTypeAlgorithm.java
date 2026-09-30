package com.otilm.core.model.crypto;

import com.otilm.api.exception.ValidationError;
import com.otilm.api.exception.ValidationException;
import com.otilm.api.model.client.cryptography.key.KeyRequestType;
import com.otilm.api.model.common.enums.cryptography.KeyAlgorithm;

/**
 * A key request type with one of its algorithms, as a token profile filter names it: {@code keyPair:RSA}.
 *
 * @param type the key request type
 * @param algorithm the algorithm
 */
public record KeyTypeAlgorithm(KeyRequestType type, KeyAlgorithm algorithm) {

    /**
     * Reads a {@code type:algorithm} pair of codes.
     *
     * @param value the pair, such as {@code keyPair:RSA}
     * @return the key request type and algorithm
     * @throws ValidationException if the value is not a known type code and algorithm code joined by a colon
     */
    public static KeyTypeAlgorithm parse(String value) {
        String[] parts = value.split(":", -1);
        if (parts.length != 2 || parts[0].isEmpty() || parts[1].isEmpty()) {
            throw new ValidationException(ValidationError
                    .create("importable must be a key request type and an algorithm, such as keyPair:RSA"));
        }
        return new KeyTypeAlgorithm(KeyRequestType.findByCode(parts[0]), KeyAlgorithm.findByCode(parts[1]));
    }
}
