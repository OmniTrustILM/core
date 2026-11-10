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
 * <b>A row whose tick is published outside the sweep is leased to that tick first.</b> A worker that publishes its own
 * continuation hands the row over ({@link #handOverLease}) or schedules it leased ({@link #scheduleLeased}) before it
 * publishes, so the sweep leaves the row alone while the tick runs and claims it if the publish never lands.
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
     * fresh start, counter and lease included.
     */
    @Transactional
    public void schedule(UUID discoveryUuid, DiscoveryWorkType workType, OffsetDateTime nextDueAt) {
        workRepository.schedule(UUID.randomUUID(), discoveryUuid, workType.name(), nextDueAt);
    }

    /**
     * Schedules the run's pending row for {@code workType}, or re-arms an existing one, already leased to
     * {@code leaseToken} until {@code leasedUntil} — for a caller that publishes the row's tick itself.
     */
    @Transactional
    public void scheduleLeased(UUID discoveryUuid, DiscoveryWorkType workType, UUID leaseToken,
            OffsetDateTime leasedUntil) {
        workRepository.scheduleLeased(UUID.randomUUID(), discoveryUuid, workType.name(), leaseToken, leasedUntil);
    }

    /**
     * Brings the run's {@code workType} work forward to {@code nextDueAt} without refreshing what it has already spent,
     * and frees the row from any tick that holds it.
     */
    @Transactional
    public void expedite(UUID discoveryUuid, DiscoveryWorkType workType, OffsetDateTime nextDueAt) {
        workRepository.expedite(UUID.randomUUID(), discoveryUuid, workType.name(), nextDueAt);
    }

    /**
     * Leases an agenda row to the tick the sweep is about to publish, if it is still due at {@code dueCutoff} and no
     * live lease holds it at {@code now}. {@code REQUIRED} (not {@code REQUIRES_NEW}) so it joins the sweep claimer's
     * lock-holding transaction.
     *
     * @return whether the row was claimed
     */
    @Transactional
    public boolean claim(UUID discoveryUuid, DiscoveryWorkType workType, UUID leaseToken, int attempt,
            OffsetDateTime dueCutoff, OffsetDateTime now, OffsetDateTime leasedUntil) {
        return workRepository.claim(discoveryUuid, workType, leaseToken, attempt, dueCutoff, now, leasedUntil) > 0;
    }

    /**
     * Moves the row's lease from {@code leaseToken} to {@code tickToken}, extended to {@code leasedUntil}.
     *
     * @return whether the row still held {@code leaseToken}
     */
    @Transactional
    public boolean swapLease(UUID discoveryUuid, DiscoveryWorkType workType, UUID leaseToken, UUID tickToken,
            OffsetDateTime leasedUntil) {
        return workRepository.swapLease(discoveryUuid, workType, leaseToken, tickToken, leasedUntil) > 0;
    }

    /**
     * Extends the lease of the tick holding {@code leaseToken} to {@code leasedUntil}.
     *
     * @return whether the row still held the token
     */
    @Transactional
    public boolean renewLease(UUID discoveryUuid, DiscoveryWorkType workType, UUID leaseToken,
            OffsetDateTime leasedUntil) {
        return workRepository.renewLease(discoveryUuid, workType, leaseToken, leasedUntil) > 0;
    }

    /**
     * Leases the row to {@code leaseToken} until {@code leasedUntil}, if no live lease holds it at {@code now}.
     *
     * @return whether the row is now leased to the token
     */
    @Transactional
    public boolean leaseIfFree(UUID discoveryUuid, DiscoveryWorkType workType, UUID leaseToken,
            OffsetDateTime leasedUntil, OffsetDateTime now) {
        return workRepository.leaseIfFree(discoveryUuid, workType, leaseToken, leasedUntil, now) > 0;
    }

    /**
     * Schedules the row's next tick and frees it, if the tick holding {@code leaseToken} still holds it.
     */
    @Transactional
    public void rescheduleLeased(UUID discoveryUuid, DiscoveryWorkType workType, UUID leaseToken, int attempt,
            OffsetDateTime nextDueAt) {
        workRepository.rescheduleLeased(discoveryUuid, workType, leaseToken, attempt, nextDueAt);
    }

    /**
     * Schedules the row's next tick at {@code attempt} without charging the budget, and frees it, if the tick holding
     * {@code leaseToken} still holds it; starts the busy clock at {@code now} unless it is already running.
     */
    @Transactional
    public void deferBusyLeased(UUID discoveryUuid, DiscoveryWorkType workType, UUID leaseToken, int attempt,
            OffsetDateTime nextDueAt, OffsetDateTime now) {
        workRepository.deferBusyLeased(discoveryUuid, workType, leaseToken, attempt, nextDueAt, now);
    }

    /** Stops the busy clock on the run's {@code workType} row. */
    @Transactional
    public void clearBusySince(UUID discoveryUuid, DiscoveryWorkType workType) {
        workRepository.clearBusySince(discoveryUuid, workType);
    }

    /**
     * Frees the row, due no later than {@code now}, if the tick holding {@code leaseToken} still holds it.
     */
    @Transactional
    public void releaseLease(UUID discoveryUuid, DiscoveryWorkType workType, UUID leaseToken, OffsetDateTime now) {
        workRepository.releaseLease(discoveryUuid, workType, leaseToken, now);
    }

    /**
     * Passes the row from the tick holding {@code leaseToken} to its continuation under {@code nextToken}.
     *
     * @return whether the tick still held the row, and so handed it over
     */
    @Transactional
    public boolean handOverLease(UUID discoveryUuid, DiscoveryWorkType workType, UUID leaseToken, UUID nextToken,
            OffsetDateTime leasedUntil) {
        return workRepository.handOverLease(discoveryUuid, workType, leaseToken, nextToken, leasedUntil) > 0;
    }

    /**
     * Advances an agenda row's {@code attempt}/{@code next_due_at}.
     */
    @Transactional
    public void reschedule(UUID discoveryUuid, DiscoveryWorkType workType, int attempt, OffsetDateTime nextDueAt) {
        workRepository.reschedule(discoveryUuid, workType, attempt, nextDueAt);
    }

    /**
     * Lowers an agenda row's attempt counter to {@code attempt} if it is above {@code attempt}, refreshing the budget
     * without restarting the backoff ramp, and frees the row from any tick that holds it.
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
