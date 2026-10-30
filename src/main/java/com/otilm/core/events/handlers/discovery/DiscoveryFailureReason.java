package com.otilm.core.events.handlers.discovery;

import com.otilm.api.exception.ValidationException;
import com.otilm.core.util.UniqueViolations;
import java.security.cert.CertificateException;
import org.hibernate.exception.ConstraintViolationException;
import org.springframework.dao.DataIntegrityViolationException;
import org.springframework.transaction.UnexpectedRollbackException;

/**
 * Turns an exception into text that is safe to expose.
 *
 * <p>
 * {@code processedError} is returned to API clients through {@code DiscoveryCertificate.mapToDto}, so a raw
 * {@code getMessage()} would put SQL fragments, table and column names, and provider internals on the wire.
 *
 * <p>
 * Exactly one type is forwarded verbatim: {@link DiscoveryImportRollbackException}, whose message this class shaped in
 * the first place. Everything else is classified, {@link ValidationException} included — and it in particular, because
 * a platform-authored message is not the same as a payload-free one. Reachable throw sites concatenate entity data into
 * theirs (a key upload failure embeds the key material), and no property of the type distinguishes those from the
 * useful ones. The full exception still reaches the log.
 */
public final class DiscoveryFailureReason {

    private static final String GENERIC = "an unexpected error occurred";
    private static final String IMPORT_ROLLED_BACK = "the import transaction was rolled back";
    private static final String TRIGGER_ROLLED_BACK = "the trigger's transaction was rolled back";
    private static final int MAX_CAUSE_DEPTH = 10;

    private DiscoveryFailureReason() {
    }

    public static String shape(Throwable throwable) {
        return shape(throwable, IMPORT_ROLLED_BACK);
    }

    /**
     * As {@link #shape(Throwable)}, but for a failure raised once the import has committed: only the trigger's own
     * transaction can have rolled back by then, so naming the import's would send the operator to the wrong place.
     */
    public static String shapeTriggerFailure(Throwable throwable) {
        return shape(throwable, TRIGGER_ROLLED_BACK);
    }

    private static String shape(Throwable throwable, String rollbackReason) {
        // Walk the causes: a data-integrity failure usually arrives wrapped, and if the wrapper's own message
        // embeds the driver text, passing that through would leak exactly what this class exists to withhold.
        Throwable cause = throwable;
        for (int depth = 0; cause != null && depth < MAX_CAUSE_DEPTH; cause = cause.getCause(), depth++) {
            String classified = classify(cause, rollbackReason);
            if (classified != null) {
                return classified;
            }
        }
        return GENERIC;
    }

    private static boolean isUsable(String message) {
        return message != null && !message.isBlank() && !"null".equals(message.trim());
    }

    private static String classify(Throwable throwable, String rollbackReason) {
        // First, so it matches before the cause walk reaches whatever it wraps: the reason it carries is already
        // shaped and more specific than anything re-derived from the cause would be.
        if (throwable instanceof DiscoveryImportRollbackException && isUsable(throwable.getMessage())) {
            return throwable.getMessage();
        }
        if (throwable instanceof DataIntegrityViolationException || throwable instanceof ConstraintViolationException) {
            // Only a UNIQUE violation is the duplicate this design guards against. A foreign-key, not-null or check
            // violation is a different defect, and reporting it as a benign race would hide it from whoever reads the
            // certificate list.
            return UniqueViolations.isUniqueViolation(throwable)
                    ? "a concurrent import committed the same certificate"
                    : "a database constraint rejected the certificate";
        }
        if (throwable instanceof UnexpectedRollbackException) {
            return rollbackReason;
        }
        if (throwable instanceof ValidationException) {
            return "the certificate did not pass validation";
        }
        // Parser messages come from the JDK and BouncyCastle, not from the platform, so they are classified
        // rather than forwarded.
        if (throwable instanceof CertificateException) {
            return "the discovered certificate could not be parsed";
        }
        return null;
    }
}
