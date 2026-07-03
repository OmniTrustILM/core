package com.otilm.core.messaging.jms.listeners.poll;

import com.otilm.api.model.core.certificate.CertificateEvent;
import com.otilm.api.model.core.certificate.CertificateState;
import com.otilm.core.cluster.ClusterOperationSynchronizer;
import com.otilm.core.dao.entity.Certificate;
import com.otilm.core.dao.repository.CertificateRepository;
import com.otilm.core.events.transaction.TransactionHandler;
import com.otilm.core.service.handler.authority.lifecycle.CertificateStateMachine;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.data.domain.PageRequest;
import org.springframework.stereotype.Component;

import java.time.Duration;
import java.time.OffsetDateTime;
import java.time.ZoneOffset;
import java.util.List;
import java.util.UUID;

/**
 * Fails certificates left orphaned in {@link CertificateState#PENDING_ISSUE} by a crash on the
 * synchronous (HTTP 200) issue/renew/rekey path. That path commits PENDING_ISSUE before the connector
 * call but, unlike the asynchronous (202) path, creates no {@code certificate_status_poll} row — so the
 * poll sweep, which is driven by those rows, never re-drives it. Re-drive is impossible anyway (the
 * connector response is lost), so a stale orphan is moved to FAILED, which makes it actionable/retriable.
 *
 * <p>Runs as a phase of {@link CertificateStatusPollSweeper#sweep()} (no separate schedule) and reuses
 * that sweep's {@code PROVIDER_STATUS_POLL_SWEEP} advisory lock. Correctness across nodes rests on the
 * per-certificate pessimistic lock plus a state re-assertion; the advisory lock only avoids redundant
 * selection.</p>
 */
@Component
public class PendingIssueReaper {

    private static final Logger logger = LoggerFactory.getLogger(PendingIssueReaper.class);

    private final CertificateRepository certificateRepository;
    private final TransactionHandler transactionHandler;
    private final ClusterOperationSynchronizer clusterSynchronizer;
    private final CertificateStateMachine stateMachine;
    private final Duration staleAfter;
    private final int batchSize;

    public PendingIssueReaper(CertificateRepository certificateRepository,
                              TransactionHandler transactionHandler,
                              ClusterOperationSynchronizer clusterSynchronizer,
                              CertificateStateMachine stateMachine,
                              @Value("${provider.status-poll.reap-stale-after:PT30M}") Duration staleAfter,
                              @Value("${provider.status-poll.sweep-batch-size:200}") int batchSize) {
        this.certificateRepository = certificateRepository;
        this.transactionHandler = transactionHandler;
        this.clusterSynchronizer = clusterSynchronizer;
        this.stateMachine = stateMachine;
        this.staleAfter = staleAfter;
        this.batchSize = batchSize;
    }

    /**
     * Selects one bounded batch of stale, poll-less PENDING_ISSUE certificates under the shared advisory
     * lock, then fails each in its own transaction outside the lock. One batch per sweep is sufficient:
     * the sweep cadence drains any backlog, and a certificate is not a candidate until it has been stuck
     * for {@code stale-after}.
     */
    public void reapStaleOrphans() {
        List<UUID> candidates = transactionHandler.runInNewTransaction(() -> {
            if (!clusterSynchronizer.tryLock(ClusterOperationSynchronizer.Operation.PROVIDER_STATUS_POLL_SWEEP)) {
                return List.<UUID>of();
            }
            OffsetDateTime threshold = OffsetDateTime.now(ZoneOffset.UTC).minus(staleAfter);
            return certificateRepository.findStalePendingIssueWithoutPollRow(
                    threshold, PageRequest.of(0, batchSize));
        });

        int reaped = 0;
        for (UUID uuid : candidates) {
            if (reapOne(uuid)) {
                reaped++;
            }
        }
        if (reaped > 0) {
            logger.info("Reaped {} orphaned PENDING_ISSUE certificate(s)", reaped);
        }
    }

    private boolean reapOne(UUID uuid) {
        try {
            return Boolean.TRUE.equals(transactionHandler.runInNewTransaction(() -> {
                Certificate locked = certificateRepository.findAndLockWithAssociationsByUuid(uuid).orElse(null);
                // Re-assert under the row lock: the certificate may have completed or been reaped by
                // another node between selection and locking.
                if (locked == null || locked.getState() != CertificateState.PENDING_ISSUE) {
                    return false;
                }
                stateMachine.transition(locked, CertificateState.FAILED, CertificateEvent.ISSUE,
                        "Operation did not complete; reaped from PENDING_ISSUE (no in-flight poll)");
                return true;
            }));
        } catch (RuntimeException e) {
            // One certificate's failure (e.g. a lock timeout) must not abort the rest of the batch.
            logger.warn("Failed to reap stuck PENDING_ISSUE certificate {}", uuid, e);
            return false;
        }
    }
}
