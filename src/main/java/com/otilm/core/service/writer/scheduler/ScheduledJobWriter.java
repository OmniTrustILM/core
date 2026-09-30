package com.otilm.core.service.writer.scheduler;

import com.otilm.core.dao.repository.ScheduledJobsRepository;
import java.time.OffsetDateTime;
import java.util.UUID;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

/**
 * The one write to {@code scheduled_job} a run makes: the skip it declined, recorded in place. {@code REQUIRED} like
 * every writer (Rule D of {@code TransactionalBoundaryArchTest}); its caller,
 * {@code SchedulerServiceImpl.runScheduledJob}, holds no transaction, so this is a short transaction of its own,
 * committed before the run's history row is removed. The row is removed only once this has committed; when it throws,
 * the row is closed as FAILED instead.
 */
@Service
public class ScheduledJobWriter {

    private final ScheduledJobsRepository repository;

    public ScheduledJobWriter(ScheduledJobsRepository repository) {
        this.repository = repository;
    }

    /**
     * The task declined the run ({@code ScheduledJobSkippedException}): when, and the task's own reason. A job that no
     * longer exists is reported, not ignored.
     */
    @Transactional
    public void recordSkipped(UUID jobUuid, String reason) {
        if (repository.recordSkip(jobUuid, OffsetDateTime.now(), reason) == 0) {
            throw new IllegalStateException("scheduled_job row " + jobUuid + " vanished before its skip was recorded");
        }
    }
}
