package com.otilm.core.messaging.jms.listeners.discovery;

import com.otilm.core.cluster.ClusterOperationSynchronizer;
import com.otilm.core.dao.entity.DiscoveryWork;
import com.otilm.core.dao.repository.DiscoveryWorkRepository;
import com.otilm.core.messaging.jms.configuration.DiscoveryWorkProperties;
import com.otilm.core.messaging.model.DiscoveryWorkMessage;
import com.otilm.core.model.discovery.DiscoveryWorkType;
import com.otilm.core.service.writer.discovery.DiscoveryWorkWriter;
import java.time.Duration;
import java.time.OffsetDateTime;
import java.time.ZoneOffset;
import java.util.ArrayList;
import java.util.List;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.data.domain.PageRequest;
import org.springframework.stereotype.Component;
import org.springframework.transaction.annotation.Propagation;
import org.springframework.transaction.annotation.Transactional;

/**
 * Transactional claim half of the discovery work sweep, kept in its own bean so the {@link Transactional} boundary is
 * honoured (a self-invoked {@code @Transactional} method on {@link DiscoveryWorkSweeper} would be silently skipped by
 * the Spring proxy).
 *
 * <p>
 * One claim runs entirely against the database — no external call — so the advisory lock and the transaction are held
 * only for the duration of the read and the reschedules. The reschedule commits with the same transaction that holds
 * the lock, so a row is either claimed-and-rescheduled or neither.
 * </p>
 */
@Component
public class DiscoveryWorkClaimer {

    private static final Logger logger = LoggerFactory.getLogger(DiscoveryWorkClaimer.class);

    private final ClusterOperationSynchronizer clusterSynchronizer;
    private final DiscoveryWorkRepository workRepository;
    private final DiscoveryWorkWriter workWriter;
    private final DiscoveryWorkProperties workProperties;
    private final Duration claimFloor;

    public DiscoveryWorkClaimer(ClusterOperationSynchronizer clusterSynchronizer,
            DiscoveryWorkRepository workRepository, DiscoveryWorkWriter workWriter,
            DiscoveryWorkProperties workProperties, @Value("${discovery.work.claim-floor:PT35S}") Duration claimFloor) {
        this.clusterSynchronizer = clusterSynchronizer;
        this.workRepository = workRepository;
        this.workWriter = workWriter;
        this.workProperties = workProperties;
        this.claimFloor = claimFloor;
    }

    /**
     * Claims up to {@code batchSize} rows due at {@code dueCutoff} and returns the tick message to send for each.
     *
     * <p>
     * <b>Locking:</b> returns empty when another node already holds the sweep lock. Each claimed row's
     * {@code attempt}/{@code next_due_at} advances up the backoff curve within the lock-holding transaction.
     *
     * <p>
     * <b>Publishing:</b> the caller sends the returned messages after this method returns, outside the lock and
     * transaction.
     *
     * <p>
     * <b>Duplicate prevention:</b> the caller passes one cutoff for its whole sweep, and a claimed row is parked past a
     * tick's expected worst case — see {@link #parkFor}.
     */
    @Transactional(propagation = Propagation.REQUIRES_NEW)
    public List<DiscoveryWorkMessage> claimDueBatch(int batchSize, OffsetDateTime dueCutoff) {
        if (!clusterSynchronizer.tryLock(ClusterOperationSynchronizer.Operation.DISCOVERY_WORK_SWEEP)) {
            logger.debug("Discovery work sweep skipped: another instance holds the lock");
            return List.of();
        }
        List<DiscoveryWork> due = workRepository
                .findByNextDueAtLessThanEqualOrderByNextDueAt(dueCutoff, PageRequest.of(0, batchSize));
        List<DiscoveryWorkMessage> messages = new ArrayList<>(due.size());
        for (DiscoveryWork work : due) {
            messages.add(new DiscoveryWorkMessage(work.getDiscoveryUuid(), work.getWorkType(), work.getAttempt()));

            int nextAttempt = work.getAttempt() + 1;
            workWriter
                    .reschedule(work.getDiscoveryUuid(), work.getWorkType(), nextAttempt,
                            OffsetDateTime.now(ZoneOffset.UTC).plus(parkFor(work.getWorkType(), nextAttempt)));
        }
        return messages;
    }

    /**
     * How far out a claimed row is parked. Nothing marks a row as being worked, so the sweep republishes any row that
     * comes due again — and the early rungs are seconds against a connector call that may take its full timeout, so two
     * ticks drain the same page and the one that stages nothing spends the run's budget reading that as the connector
     * withholding items.
     *
     * <p>
     * It is a floor, so it does change the cadence of any ladder whose ceiling is shorter than it: {@code STATUS} keeps
     * its five minutes, while {@code DRAIN} and {@code PROCESS} idle here rather than on the thirty seconds their own
     * rungs end at. That reaches only a tick with nothing to do — one with more to fetch direct-publishes its
     * continuation instead of waiting on a rung at all.
     *
     * <p>
     * It does not cover a tick outliving the floor itself — a lease the worker releases would, and core#1962's agenda
     * has no such column.
     */
    private Duration parkFor(DiscoveryWorkType workType, int nextAttempt) {
        Duration rung = workProperties.scheduleFor(workType).delayFor(nextAttempt);
        return rung.compareTo(claimFloor) >= 0 ? rung : claimFloor;
    }
}
