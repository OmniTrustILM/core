package com.otilm.core.key.normalization;

import com.otilm.api.exception.ValidationError;
import com.otilm.api.exception.ValidationException;
import com.otilm.api.model.client.cryptography.key.KeyRequestType;
import java.util.Locale;

/**
 * Why a key file cannot be imported, each reason a fixed message. What can be seen without the passphrase is named;
 * every failure after decryption shares one message, so a refusal says nothing about the passphrase.
 */
final class KeyFileRefusal {

    static final String NOT_A_KEY_FILE = "The file must hold exactly one private key, as PKCS#8 or OpenSSL traditional"
            + " PEM.";

    static final String UNSUPPORTED_PROTECTION = "The key file is protected with %s, which is not supported.";

    static final String LIMIT_EXCEEDED = "The key file exceeds the %s limit of %s.";

    static final String UNREADABLE = "The key could not be read: the passphrase is wrong or missing, or the file is"
            + " damaged.";

    static final String UNSUPPORTED_ALGORITHM = "The file holds a key of algorithm %s that cannot be imported.";

    static final String NOT_OF_TYPE = "A key file holds a key pair, so it cannot be imported as a %s.";

    private KeyFileRefusal() {
    }

    static ValidationException notAKeyFile() {
        return refusal(NOT_A_KEY_FILE);
    }

    static ValidationException unsupportedProtection(String scheme) {
        return refusal(UNSUPPORTED_PROTECTION.formatted(scheme));
    }

    static ValidationException limitExceeded(String limit, Object maximum) {
        return refusal(LIMIT_EXCEEDED.formatted(limit, maximum));
    }

    static ValidationException unreadableKey() {
        return refusal(UNREADABLE);
    }

    static ValidationException unsupportedAlgorithm(String algorithm) {
        return refusal(UNSUPPORTED_ALGORITHM.formatted(algorithm));
    }

    static ValidationException notOfType(KeyRequestType type) {
        return refusal(NOT_OF_TYPE.formatted(type.getLabel().toLowerCase(Locale.ROOT)));
    }

    private static ValidationException refusal(String message) {
        return new ValidationException(ValidationError.create(message));
    }
}
