package com.otilm.core.key.normalization;

import com.otilm.api.exception.ValidationError;
import com.otilm.api.exception.ValidationException;
import com.otilm.api.model.client.cryptography.key.KeyRequestType;
import java.util.Locale;
import java.util.regex.Pattern;

/**
 * Why an uploaded file or a key it holds cannot be read, each reason a fixed message. What can be seen without the
 * passphrase is named; every failure after decryption shares one message, so a refusal says nothing about the
 * passphrase. A name or object identifier the file supplies is repeated only when it is plain and short enough.
 */
public final class KeyFileRefusal {

    public static final String NOT_A_KEY_FILE = "The file must hold exactly one key, as PKCS#8, OpenSSL traditional PEM"
            + " or OpenSSH.";

    public static final String UNSUPPORTED_PROTECTION = "The file is protected with %s, which is not supported.";

    public static final String LIMIT_EXCEEDED = "The file exceeds the %s limit of %s.";

    public static final String UNREADABLE = "The key could not be read: the passphrase is wrong or missing, or the file"
            + " is damaged.";

    public static final String UNSUPPORTED_ALGORITHM = "The file holds a key of %s that cannot be imported.";

    public static final String NOT_OF_TYPE = "A key file holds a %s, so it cannot be imported as a %s.";

    public static final String UNPROTECTED_SECRET = "The file holds a secret key without protection, which is not"
            + " supported.";

    /** What a name or object identifier from the file may look like to be repeated. */
    private static final Pattern REPEATABLE = Pattern.compile("[A-Za-z0-9 .-]{1,64}");

    private static final String UNRECOGNIZED_SCHEME = "an unrecognized scheme";

    private static final String UNRECOGNIZED_ALGORITHM = "an unrecognized algorithm";

    private KeyFileRefusal() {
    }

    public static ValidationException notAKeyFile() {
        return refusal(NOT_A_KEY_FILE);
    }

    public static ValidationException unsupportedProtection(String scheme) {
        return refusal(UNSUPPORTED_PROTECTION.formatted(repeatable(scheme) ? scheme : UNRECOGNIZED_SCHEME));
    }

    public static ValidationException limitExceeded(String limit, Object maximum) {
        return refusal(LIMIT_EXCEEDED.formatted(limit, maximum));
    }

    public static ValidationException unreadableKey() {
        return refusal(UNREADABLE);
    }

    public static ValidationException unsupportedAlgorithm(String algorithm) {
        return refusal(UNSUPPORTED_ALGORITHM
                .formatted(repeatable(algorithm) ? "algorithm " + algorithm : UNRECOGNIZED_ALGORITHM));
    }

    public static ValidationException notOfType(KeyRequestType held, KeyRequestType requested) {
        return refusal(NOT_OF_TYPE.formatted(named(held), named(requested)));
    }

    public static ValidationException unprotectedSecret() {
        return refusal(UNPROTECTED_SECRET);
    }

    private static String named(KeyRequestType type) {
        return type.getLabel().toLowerCase(Locale.ROOT);
    }

    /**
     * Whether a name or object identifier from the file is plain and short enough to repeat, which bounds what a file
     * can make a refusal or a description carry.
     *
     * @param name the name or the dotted object identifier
     * @return whether it may be repeated
     */
    public static boolean repeatable(String name) {
        return REPEATABLE.matcher(name).matches();
    }

    private static ValidationException refusal(String message) {
        return new ValidationException(ValidationError.create(message));
    }
}
