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
 * looks at it, and how long the reconciliation waits between two looks; at least 5 minutes, since it must outlast one
 * look, which makes up to three connector calls
 * @param sweepInterval how often the reconciliation runs
 */
@ConfigurationProperties(prefix = "key-import")
public record KeyImportProperties(Duration requestTimeout, Duration pollInterval, Duration unresolvedAfter,
        Duration retryWindow, Duration sweepInterval) {

    private static final Duration CONNECTOR_RETENTION = Duration.ofHours(24);

    /** Up to three connector calls fit in it at the default connector timeouts, which one look at an import makes. */
    private static final Duration SHORTEST_RETRY_WINDOW = Duration.ofMinutes(5);

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
        if (retryWindow.compareTo(SHORTEST_RETRY_WINDOW) < 0) {
            throw new IllegalArgumentException(
                    "key-import.retry-window must be at least 5 minutes, was " + retryWindow);
        }
        if (retryWindow.compareTo(unresolvedAfter) >= 0) {
            throw new IllegalArgumentException(
                    "key-import.retry-window must be shorter than key-import.unresolved-after, was " + retryWindow);
        }
        sweepInterval = positive(sweepInterval == null ? Duration.ofSeconds(60) : sweepInterval, "sweep-interval");
    }

    private static Duration positive(Duration value, String name) {
        if (value.isNegative() || value.isZero()) {
            throw new IllegalArgumentException("key-import." + name + " must be a positive duration, was " + value);
        }
        return value;
    }
}
