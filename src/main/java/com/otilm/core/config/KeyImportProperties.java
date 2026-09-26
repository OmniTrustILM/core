package com.otilm.core.config;

import java.time.Duration;
import org.springframework.boot.context.properties.ConfigurationProperties;

/**
 * How long a key import request waits on a connector that imports asynchronously, and how often it asks meanwhile.
 * Bound from {@code key-import.*}; a value left out takes its default, and one out of range fails at startup.
 *
 * @param requestTimeout how long the request waits before it cancels the import
 * @param pollInterval how long it waits between two questions
 * @param unresolvedAfter how long the outcome of an import can still be learned from its connector, which keeps a
 * record of it for at least 24 hours, so it has to be shorter; an older import the connector does not know is not sent
 * again, and the reconciliation gives up on an import this long after it was last sent
 * @param retryWindow how long an import is left to its requester's retries after each send before the reconciliation
 * looks at it, and how long the reconciliation waits between two looks; it exceeds the request timeout by at least 5
 * minutes, room for the connector calls around a request's wait or for one look, and with the sweep interval stays
 * shorter than the time after which the reconciliation gives up
 * @param sweepInterval how often the reconciliation runs
 */
@ConfigurationProperties(prefix = "key-import")
public record KeyImportProperties(Duration requestTimeout, Duration pollInterval, Duration unresolvedAfter,
        Duration retryWindow, Duration sweepInterval) {

    private static final Duration CONNECTOR_RETENTION = Duration.ofHours(24);

    /**
     * Room for up to three connector calls at the default connector timeouts: those around a request's wait, or a look.
     */
    private static final Duration CONNECTOR_CALLS = Duration.ofMinutes(5);

    public KeyImportProperties {
        requestTimeout = positive(requestTimeout == null ? Duration.ofSeconds(60) : requestTimeout, "request-timeout");
        pollInterval = positive(pollInterval == null ? Duration.ofSeconds(2) : pollInterval, "poll-interval");
        if (pollInterval.compareTo(Duration.ofMillis(1)) < 0) {
            throw new IllegalArgumentException(
                    "key-import.poll-interval must be at least a millisecond, was " + pollInterval);
        }
        unresolvedAfter = positive(unresolvedAfter == null ? Duration.ofHours(20) : unresolvedAfter,
                "unresolved-after");
        if (unresolvedAfter.compareTo(CONNECTOR_RETENTION) >= 0) {
            throw new IllegalArgumentException(
                    "key-import.unresolved-after must be shorter than 24 hours, was " + unresolvedAfter);
        }
        retryWindow = positive(retryWindow == null ? Duration.ofMinutes(15) : retryWindow, "retry-window");
        sweepInterval = positive(sweepInterval == null ? Duration.ofSeconds(60) : sweepInterval, "sweep-interval");
        if (retryWindow.compareTo(requestTimeout.plus(CONNECTOR_CALLS)) < 0) {
            throw new IllegalArgumentException(
                    "key-import.retry-window must exceed key-import.request-timeout by at least 5 minutes, was "
                            + retryWindow);
        }
        if (retryWindow.plus(sweepInterval).compareTo(unresolvedAfter) >= 0) {
            throw new IllegalArgumentException("key-import.retry-window and key-import.sweep-interval together must "
                    + "be shorter than key-import.unresolved-after, were " + retryWindow + " and " + sweepInterval);
        }
    }

    private static Duration positive(Duration value, String name) {
        if (value.isNegative() || value.isZero()) {
            throw new IllegalArgumentException("key-import." + name + " must be a positive duration, was " + value);
        }
        return value;
    }
}
