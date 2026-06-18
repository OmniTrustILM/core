package com.otilm.core.messaging.jms.listeners.poll;

import com.otilm.api.model.core.auth.Resource;
import com.otilm.core.cluster.ClusterOperationSynchronizer;
import com.otilm.core.dao.entity.CertificateStatusPoll;
import com.otilm.core.dao.repository.CertificateStatusPollRepository;
import com.otilm.core.messaging.jms.configuration.StatusPollProperties;
import com.otilm.core.messaging.jms.producers.CertificateStatusPollProducer;
import com.otilm.core.messaging.model.CertificateStatusPollMessage;
import com.otilm.core.service.writer.statuspoll.CertificateStatusPollWriter;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.data.domain.PageRequest;
import org.springframework.stereotype.Component;
import org.springframework.transaction.annotation.Propagation;
import org.springframework.transaction.annotation.Transactional;

import java.time.Duration;
import java.time.OffsetDateTime;
import java.util.List;

/**
 * Drives the async-operation polling cadence off the {@code certificate_status_poll} due-time table.
 * Every node triggers this on its own timer (see {@link CertificateStatusPollSweepScheduler}); a
 * cluster-wide advisory lock ({@link ClusterOperationSynchronizer.Operation#PROVIDER_STATUS_POLL_SWEEP})
 * keeps exactly one node sweeping at a time, so the due read needs no row locks.
 *
 * <p>For each due row the sweep enqueues one poll message and pushes {@code next_poll_at} forward by the
 * backoff curve (incrementing {@code attempt}). The sweep owns <em>only</em> scheduling; the listener owns
 * every state transition and deletes the row on a terminal outcome or timeout. A lost poll message is
 * self-correcting — the row stays scheduled and is re-enqueued (at the advanced attempt) when next due.</p>
 */
@Component
public class CertificateStatusPollSweeper {

    private static final Logger logger = LoggerFactory.getLogger(CertificateStatusPollSweeper.class);

    private final ClusterOperationSynchronizer clusterSynchronizer;
    private final CertificateStatusPollRepository pollRepository;
    private final CertificateStatusPollWriter pollWriter;
    private final CertificateStatusPollProducer pollProducer;
    private final StatusPollProperties statusPollProperties;
    private final int batchSize;
    private final int maxBatchesPerRun;

    public CertificateStatusPollSweeper(ClusterOperationSynchronizer clusterSynchronizer,
                                        CertificateStatusPollRepository pollRepository,
                                        CertificateStatusPollWriter pollWriter,
                                        CertificateStatusPollProducer pollProducer,
                                        StatusPollProperties statusPollProperties,
                                        @Value("${provider.status-poll.sweep-batch-size:200}") int batchSize,
                                        @Value("${provider.status-poll.sweep-max-batches-per-run:10}") int maxBatchesPerRun) {
        this.clusterSynchronizer = clusterSynchronizer;
        this.pollRepository = pollRepository;
        this.pollWriter = pollWriter;
        this.pollProducer = pollProducer;
        this.statusPollProperties = statusPollProperties;
        this.batchSize = batchSize;
        this.maxBatchesPerRun = maxBatchesPerRun;
    }

    /**
     * The outer transaction holds only the advisory lock and the due reads; each reschedule commits in
     * its own {@code REQUIRES_NEW} transaction via the writer. The batch cap bounds how long the lock and
     * this transaction stay open, so a large backlog is enqueued across several runs rather than one long
     * transaction that would pin a connection idle-in-transaction.
     */
    @Transactional(propagation = Propagation.REQUIRES_NEW)
    public void sweep() {
        if (!clusterSynchronizer.tryLock(ClusterOperationSynchronizer.Operation.PROVIDER_STATUS_POLL_SWEEP)) {
            logger.debug("Status-poll sweep skipped: another instance holds the lock");
            return;
        }
        int enqueued = 0;
        try {
            int batchesRun = 0;
            int batchCount;
            do {
                List<CertificateStatusPoll> due = pollRepository
                        .findByNextPollAtLessThanEqualOrderByNextPollAt(OffsetDateTime.now(), PageRequest.of(0, batchSize));
                batchCount = due.size();
                for (CertificateStatusPoll poll : due) {
                    enqueueAndReschedule(poll);
                    enqueued++;
                }
                batchesRun++;
            } while (batchCount == batchSize && batchesRun < maxBatchesPerRun);
        } catch (RuntimeException e) {
            logger.warn("Status-poll sweep aborted after enqueuing {} poll(s); will retry next interval", enqueued, e);
        }
        if (enqueued > 0) {
            logger.info("Status-poll sweep enqueued {} poll(s)", enqueued);
        }
    }

    private void enqueueAndReschedule(CertificateStatusPoll poll) {
        pollProducer.produceMessage(new CertificateStatusPollMessage(
                Resource.CERTIFICATE, poll.getCertificateUuid(), poll.getOperation(), poll.getAttempt()));

        int nextAttempt = poll.getAttempt() + 1;
        Duration nextDelay = statusPollProperties.scheduleFor(poll.getOperation()).delayFor(nextAttempt);
        pollWriter.reschedule(poll.getCertificateUuid(), nextAttempt, OffsetDateTime.now().plus(nextDelay));
    }
}
