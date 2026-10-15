package com.otilm.core.api;

import com.otilm.api.exception.PlatformException;
import java.util.Objects;

/**
 * Thrown by a task that declines its run: nothing to do, or a condition it cannot proceed under. The run leaves no
 * history row; the reason is recorded on the job instead ({@code scheduled_job.last_skip_reason}) and served to the
 * operator, so it is fixed text in the task's own words -- never an exception's message, which can quote internals. A
 * reason that cannot be recorded leaves the run's row in place, closed as FAILED.
 */
public class ScheduledJobSkippedException extends RuntimeException implements PlatformException {

    public ScheduledJobSkippedException(final String reason) {
        super(Objects.requireNonNull(reason, "a skipped run states its reason"));
    }

    public String getReason() {
        return getMessage();
    }
}
