package com.otilm.core.container;

import com.otilm.api.exception.ValidationError;
import com.otilm.api.exception.ValidationException;
import com.otilm.core.key.normalization.KeyFileRefusal;

/**
 * Why an uploaded file cannot be read as a container, each reason a fixed message. A type or object identifier from the
 * file is repeated only when it is plain enough to repeat.
 */
public final class ContainerRefusal {

    public static final String NOT_SUPPORTED_FORMAT = "The file is not in a supported format: PKCS#12, JKS, JCEKS, PEM,"
            + " PKCS#7, a certificate, a certificate request, a PKCS#8 key, an OpenSSL traditional key or an OpenSSH"
            + " private key.";

    public static final String PEM_BLOCK_UNSUPPORTED = "The file holds a PEM block of type %s, which is not supported.";

    public static final String PEM_TOO_MANY_KEYS = "A PEM file can hold at most one private key.";

    public static final String INTEGRITY_FAILED = "The file's integrity check failed: the passphrase is wrong or missing,"
            + " or the file is damaged.";

    public static final String INTEGRITY_UNSUPPORTED = "The file's integrity is protected with %s, which is not"
            + " supported.";

    public static final String TWO_PASSPHRASES = "The file protects its keys with a different passphrase than the file"
            + " itself, which is not supported.";

    public static final String RECIPIENT_PROTECTED = "The file's content is protected for a recipient's key, which is"
            + " not supported.";

    public static final String ENTRY_UNSUPPORTED = "The file holds an entry of type %s, which is not supported.";

    private static final String UNRECOGNIZED = "an unrecognized type";

    private ContainerRefusal() {
    }

    public static ValidationException notSupportedFormat() {
        return refusal(NOT_SUPPORTED_FORMAT);
    }

    /**
     * A PEM block of a type the reader does not take.
     *
     * @param type the block's type, as the file states it
     * @return the refusal
     */
    public static ValidationException pemBlockUnsupported(String type) {
        return refusal(PEM_BLOCK_UNSUPPORTED.formatted(named(type)));
    }

    public static ValidationException pemTooManyKeys() {
        return refusal(PEM_TOO_MANY_KEYS);
    }

    public static ValidationException integrityFailed() {
        return refusal(INTEGRITY_FAILED);
    }

    /**
     * An integrity scheme the reader does not verify.
     *
     * @param scheme the scheme's object identifier, as the file states it
     * @return the refusal
     */
    public static ValidationException integrityUnsupported(String scheme) {
        return refusal(INTEGRITY_UNSUPPORTED.formatted(named(scheme)));
    }

    public static ValidationException twoPassphrases() {
        return refusal(TWO_PASSPHRASES);
    }

    public static ValidationException recipientProtected() {
        return refusal(RECIPIENT_PROTECTED);
    }

    /**
     * An entry of a type the reader does not take.
     *
     * @param type the entry's type, as the file states it
     * @return the refusal
     */
    public static ValidationException entryUnsupported(String type) {
        return refusal(ENTRY_UNSUPPORTED.formatted(named(type)));
    }

    /** The value when it is plain enough to repeat, otherwise words that say nothing about it. */
    private static String named(String value) {
        return value != null && KeyFileRefusal.repeatable(value) ? value : UNRECOGNIZED;
    }

    private static ValidationException refusal(String message) {
        return new ValidationException(ValidationError.create(message));
    }
}
