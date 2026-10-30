package com.otilm.core.oid;

import java.time.Duration;
import java.time.Instant;

/**
 * Decides when a warning about a persistent condition should be re-emitted.
 *
 * <p>
 * The OID registry rebuilds on a short schedule, so warning on every rebuild floods the log until it is filtered out.
 * Warning only when the condition changes has the opposite problem: the log falls silent, and silence then means both
 * "resolved" and "still broken, already reported". Re-emitting periodically while the condition lasts makes the log
 * answer the question an operator actually has — whether the condition holds now — from any recent window, without
 * needing to have seen the original warning. It also keeps the log carrying problems only, with no all-clear line to
 * interpret.
 */
public final class PersistentWarningThrottle {

    private final Duration repeatAfter;
    private Instant lastWarned;

    public PersistentWarningThrottle(Duration repeatAfter) {
        this.repeatAfter = repeatAfter;
    }

    /**
     * @param stateChanged whether the condition's detail differs from the last time it was published
     * @param unresolved whether the condition currently holds at all
     * @return {@code true} when the caller should emit its warning now
     */
    public synchronized boolean shouldWarn(boolean stateChanged, boolean unresolved) {
        if (!unresolved) {
            // Reset, so a condition that recurs later is reported immediately rather than waiting out
            // an interval started by the previous occurrence.
            lastWarned = null;
            return false;
        }
        Instant now = Instant.now();
        if (stateChanged || lastWarned == null || !now.isBefore(lastWarned.plus(repeatAfter))) {
            lastWarned = now;
            return true;
        }
        return false;
    }
}
