package com.otilm.core.messaging.jms.listeners.poll;

import com.otilm.core.cluster.ClusterOperationSynchronizer;
import com.otilm.core.messaging.jms.producers.CertificateStatusPollProducer;
import com.otilm.core.messaging.model.CertificateStatusPollMessage;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import java.util.List;

/**
 * Drives the async-operation polling cadence off the {@code certificate_status_poll} due-time table.
 * Every node triggers this on its own timer (see {@link CertificateStatusPollSweepScheduler}); a
 * cluster-wide advisory lock ({@link ClusterOperationSynchronizer.Operation#PROVIDER_STATUS_POLL_SWEEP})
 * keeps exactly one node sweeping at a time.
 *
 * <p>Each round {@link CertificateStatusPollClaimer#claimDueBatch} reads the due rows and advances their
 * {@code next_poll_at} under the lock (database only), then this orchestrator sends the poll messages
 * <em>outside</em> the lock and transaction — the broker round-trips must never pin the advisory lock or a
 * DB connection. A lost poll message is self-correcting: the row stays scheduled and is re-enqueued (at the
 * advanced attempt) when next due.</p>
 *
 * <p>The sweep owns only scheduling; the listener owns every state transition and deletes the row on a
 * terminal outcome or timeout.</p>
 */
@Component
public class CertificateStatusPollSweeper {

    private static final Logger logger = LoggerFactory.getLogger(CertificateStatusPollSweeper.class);

    private final CertificateStatusPollClaimer pollClaimer;
    private final CertificateStatusPollProducer pollProducer;
    private final int batchSize;
    private final int maxBatchesPerRun;

    public CertificateStatusPollSweeper(CertificateStatusPollClaimer pollClaimer,
                                        CertificateStatusPollProducer pollProducer,
                                        @Value("${provider.status-poll.sweep-batch-size:200}") int batchSize,
                                        @Value("${provider.status-poll.sweep-max-batches-per-run:10}") int maxBatchesPerRun) {
        this.pollClaimer = pollClaimer;
        this.pollProducer = pollProducer;
        this.batchSize = batchSize;
        this.maxBatchesPerRun = maxBatchesPerRun;
    }

    /**
     * The batch cap bounds how long a single run takes; a large backlog is enqueued across several runs.
     * Claiming (lock + read + reschedule) happens in {@link CertificateStatusPollClaimer}; the sends here run
     * after each claim's transaction has committed, so neither the lock nor a transaction is held across them.
     */
    public void sweep() {
        int enqueued = 0;
        int batchesRun = 0;
        int batchCount;
        do {
            List<CertificateStatusPollMessage> due = pollClaimer.claimDueBatch(batchSize);
            batchCount = due.size();
            for (CertificateStatusPollMessage message : due) {
                pollProducer.produceMessage(message);
                enqueued++;
            }
            batchesRun++;
        } while (batchCount == batchSize && batchesRun < maxBatchesPerRun);

        if (enqueued > 0) {
            logger.info("Status-poll sweep enqueued {} poll(s)", enqueued);
        }
    }
}
