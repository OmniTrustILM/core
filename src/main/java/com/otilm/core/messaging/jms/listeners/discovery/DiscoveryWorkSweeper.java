package com.otilm.core.messaging.jms.listeners.discovery;

import com.otilm.core.cluster.ClusterOperationSynchronizer;
import com.otilm.core.messaging.jms.producers.DiscoveryWorkProducer;
import com.otilm.core.messaging.model.DiscoveryWorkMessage;
import java.time.OffsetDateTime;
import java.time.ZoneOffset;
import java.util.List;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

/**
 * Drives the discovery v2 tick cadence off the {@code discovery_work} due-time agenda. Every node triggers this on its
 * own timer (see {@link DiscoveryWorkSweepScheduler}); a cluster-wide advisory lock
 * ({@link ClusterOperationSynchronizer.Operation#DISCOVERY_WORK_SWEEP}) keeps exactly one node sweeping at a time.
 *
 * <p>
 * Each round {@link DiscoveryWorkClaimer#claimDueBatch} reads the due rows and advances their {@code next_due_at} under
 * the lock (database only), then this orchestrator sends the tick messages <em>outside</em> the lock and transaction —
 * the broker round-trips must never pin the advisory lock or a DB connection. A lost tick message is self-correcting:
 * the row stays scheduled and is re-enqueued (at the advanced attempt) when next due.
 * </p>
 *
 * <p>
 * The sweep owns only scheduling recovery; ticks a worker publishes directly on continuation make the sweep cadence a
 * recovery latency, never the throughput ceiling. As a final phase the sweep also reaps runs the tick engine can no
 * longer drive (see {@link DiscoveryRunReaper}).
 * </p>
 */
@Component
public class DiscoveryWorkSweeper {

    private static final Logger logger = LoggerFactory.getLogger(DiscoveryWorkSweeper.class);

    private final DiscoveryWorkClaimer workClaimer;
    private final DiscoveryWorkProducer workProducer;
    private final DiscoveryRunReaper runReaper;
    private final int batchSize;
    private final int maxBatchesPerRun;

    public DiscoveryWorkSweeper(DiscoveryWorkClaimer workClaimer, DiscoveryWorkProducer workProducer,
            DiscoveryRunReaper runReaper, @Value("${discovery.work.sweep-batch-size:200}") int batchSize,
            @Value("${discovery.work.sweep-max-batches-per-run:10}") int maxBatchesPerRun) {
        this.workClaimer = workClaimer;
        this.workProducer = workProducer;
        this.runReaper = runReaper;
        this.batchSize = batchSize;
        this.maxBatchesPerRun = maxBatchesPerRun;
    }

    /**
     * The batch cap bounds how long a single run takes; a large backlog is enqueued across several runs. Claiming (lock
     * + read + reschedule) happens in {@link DiscoveryWorkClaimer}.
     */
    public void sweep() {
        // One cutoff for the whole sweep: a claimed row is rescheduled past it (first rung >= PT1S),
        // so no batch of this sweep can claim the same row twice, however long publishing takes.
        OffsetDateTime dueCutoff = OffsetDateTime.now(ZoneOffset.UTC);
        int enqueued = 0;
        int batchesRun = 0;
        int batchCount;
        do {
            List<DiscoveryWorkMessage> due = workClaimer.claimDueBatch(batchSize, dueCutoff);
            batchCount = due.size();
            for (DiscoveryWorkMessage message : due) {
                try {
                    workProducer.produceMessage(message);
                    enqueued++;
                } catch (RuntimeException e) {
                    // One bad send (broker hiccup) must not abort the rest of the batch.
                    logger
                            .warn("Failed to enqueue discovery work tick for run {} (type {}); will retry when next due",
                                    message.discoveryUuid(), message.workType(), e);
                }
            }
            batchesRun++;
        } while (batchCount == batchSize && batchesRun < maxBatchesPerRun);

        if (enqueued > 0) {
            logger.info("Discovery work sweep enqueued {} tick(s)", enqueued);
        }

        runReaper.reap();
    }
}
