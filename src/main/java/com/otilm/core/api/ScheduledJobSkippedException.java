package com.otilm.core.api;

import com.otilm.api.exception.PlatformException;

/**
 * Signals that a {@link com.otilm.core.tasks.ScheduledJobTask#performJob} run was skipped
 * (not an error) and should be treated as such by the caller.
 * <p>
 * If the throwing task class is {@code @Transactional}, it must declare
 * {@code @Transactional(noRollbackFor = ScheduledJobSkippedException.class)} — otherwise the
 * exception marks the ambient transaction (shared with {@code SchedulerListener}) rollback-only
 * before it is caught, causing {@code UnexpectedRollbackException} on commit even though the
 * skip itself is handled correctly.
 */
public class ScheduledJobSkippedException extends RuntimeException implements PlatformException {
}
