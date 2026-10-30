package com.otilm.core.service.writer.discovery;

import com.otilm.core.dao.repository.DiscoveryWorkRepository;
import com.otilm.core.model.discovery.DiscoveryWorkType;
import java.time.OffsetDateTime;
import java.util.UUID;
import org.springframework.stereotype.Component;
import org.springframework.transaction.annotation.Propagation;
import org.springframework.transaction.annotation.Transactional;

/**
 * Short transactional writes against the {@code discovery_work} agenda. The repository carries no
 * {@code @Transactional} (per the repository rule); every {@code @Modifying} write goes through this bean. Methods are
 * {@code REQUIRED} so an agenda change commits or rolls back with the run state it supervises — except
 * {@link #resetAttempt}, whose callers run outside any usable transaction.
 *
 * <p>
 * A live run's agenda must never be observably empty: the reaper treats a non-terminal run with no agenda rows past its
 * creation grace as lost work. A caller replacing a run's last row therefore deletes and schedules in the same
 * transaction.
 *
 * <p>
 * <b>A backstop row is due in the future, never due-now.</b> A worker that publishes its own continuation tick also
 * writes a row here as a backstop for a publish that never lands. Due-now, that row races the sweep, which would claim
 * and publish it too, putting two workers onto the same unclaimed work — so callers using {@link #schedule} or
 * {@link #reschedule} this way pass a due time comfortably in the future.
 * </p>
 */
@Component
public class DiscoveryWorkWriter {

    private final DiscoveryWorkRepository workRepository;

    public DiscoveryWorkWriter(DiscoveryWorkRepository workRepository) {
        this.workRepository = workRepository;
    }

    /**
     * Schedules the run's pending row for {@code workType}, due at {@code nextDueAt}, or re-arms an existing one — a
     * fresh start, counter included.
     */
    @Transactional
    public void schedule(UUID discoveryUuid, DiscoveryWorkType workType, OffsetDateTime nextDueAt) {
        workRepository.schedule(UUID.randomUUID(), discoveryUuid, workType.name(), nextDueAt);
    }

    /**
     * Brings the run's {@code workType} work forward to {@code nextDueAt} without refreshing what it has already spent.
     */
    @Transactional
    public void expedite(UUID discoveryUuid, DiscoveryWorkType workType, OffsetDateTime nextDueAt) {
        workRepository.expedite(UUID.randomUUID(), discoveryUuid, workType.name(), nextDueAt);
    }

    /**
     * Advances an agenda row's {@code attempt}/{@code next_due_at}. {@code REQUIRED} (not {@code REQUIRES_NEW}) so it
     * joins the sweep claimer's lock-holding transaction — a row is claimed and rescheduled atomically, or neither.
     */
    @Transactional
    public void reschedule(UUID discoveryUuid, DiscoveryWorkType workType, int attempt, OffsetDateTime nextDueAt) {
        workRepository.reschedule(discoveryUuid, workType, attempt, nextDueAt);
    }

    /**
     * Lowers an agenda row's attempt counter to {@code attempt} if it is above {@code attempt} — how a clear connector
     * answer refreshes the attempt budget without restarting the backoff ramp.
     */
    @Transactional(propagation = Propagation.REQUIRES_NEW)
    public void resetAttempt(UUID discoveryUuid, DiscoveryWorkType workType, int attempt) {
        workRepository.resetAttemptTo(discoveryUuid, workType, attempt);
    }

    /**
     * Drops every agenda row of a run — the terminal-transition cleanup.
     */
    @Transactional
    public void deleteForRun(UUID discoveryUuid) {
        workRepository.deleteByDiscoveryUuid(discoveryUuid);
    }

    /**
     * Drops only the run's pending row for {@code workType}.
     *
     * <p>
     * Distinct from {@link #deleteForRun} because the two mean opposite things. A worker that finds its own kind of
     * work obsolete — a drain tick arriving after the run already handed over to processing — must not take the rest of
     * the agenda with it: deleting the {@code PROCESS} row there would strand the run's import and leave the reaper
     * reading a live run as work-lost.
     */
    @Transactional
    public void deleteForRun(UUID discoveryUuid, DiscoveryWorkType workType) {
        workRepository.deleteByDiscoveryUuidAndWorkType(discoveryUuid, workType);
    }
}
