package com.otilm.core.logging;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.otilm.api.exception.ConnectorException;
import com.otilm.api.exception.LocationException;
import com.otilm.api.exception.PlatformException;
import com.otilm.api.exception.ValidationException;
import java.util.List;
import org.apache.commons.lang3.exception.ExceptionUtils;

/**
 * Stands in for each link of a failure's chain in the log: its type and frames, never its message. A connector's error
 * text, or Jackson's quote of an answer Core could not parse, can echo the secrets the request carried, so a chain a
 * connector wrote part of is logged this way, as BaseApiClient logs only types.
 */
public final class RedactedFailure extends RuntimeException implements PlatformException {

    private RedactedFailure(Throwable original, RedactedFailure cause) {
        super(original.getClass().getName(), cause, false, true);
        setStackTrace(original.getStackTrace());
    }

    /** The failure to log: the failure itself, or its redacted chain when a connector wrote part of it. */
    public static Throwable forLog(Throwable failure) {
        return isConnectorWritten(failure) ? redact(failure) : failure;
    }

    /**
     * Whether a connector may have written part of the failure's chain: a {@link JsonProcessingException},
     * {@link ConnectorException}, {@link ValidationException} or {@link LocationException} (which carries a location
     * connector's refusal in its message) anywhere in it.
     */
    public static boolean isConnectorWritten(Throwable failure) {
        return ExceptionUtils.indexOfType(failure, JsonProcessingException.class) >= 0
                || ExceptionUtils.indexOfType(failure, ConnectorException.class) >= 0
                || ExceptionUtils.indexOfType(failure, ValidationException.class) >= 0
                || ExceptionUtils.indexOfType(failure, LocationException.class) >= 0;
    }

    private static RedactedFailure redact(Throwable failure) {
        List<Throwable> chain = ExceptionUtils.getThrowableList(failure);
        RedactedFailure redacted = null;
        for (int i = chain.size() - 1; i >= 0; i--) {
            redacted = new RedactedFailure(chain.get(i), redacted);
        }
        return redacted;
    }
}
