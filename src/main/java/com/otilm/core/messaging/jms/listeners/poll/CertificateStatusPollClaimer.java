package com.otilm.core.messaging.jms.listeners.poll;

import com.otilm.api.model.core.auth.Resource;
import com.otilm.core.cluster.ClusterOperationSynchronizer;
import com.otilm.core.dao.entity.CertificateStatusPoll;
import com.otilm.core.dao.repository.CertificateStatusPollRepository;
import com.otilm.core.messaging.jms.configuration.StatusPollProperties;
import com.otilm.core.messaging.model.CertificateStatusPollMessage;
import com.otilm.core.service.writer.statuspoll.CertificateStatusPollWriter;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.data.domain.PageRequest;
import org.springframework.stereotype.Component;
import org.springframework.transaction.annotation.Propagation;
import org.springframework.transaction.annotation.Transactional;

import java.time.Duration;
import java.time.OffsetDateTime;
import java.util.ArrayList;
import java.util.List;

/**
 * Transactional claim half of the status-poll sweep, kept in its own bean so the {@link Transactional}
 * boundary is honoured (a self-invoked {@code @Transactional} method on {@link CertificateStatusPollSweeper}
 * would be silently skipped by the Spring proxy).
 *
 * <p>One claim runs entirely against the database — no external call — so the advisory lock and the
 * transaction are held only for the duration of the read and the reschedules. The reschedule commits with
 * the same transaction that holds the lock, so a row is either claimed-and-rescheduled or neither; the
 * caller then sends the returned poll messages <em>outside</em> this transaction and lock.</p>
 */
@Component
public class CertificateStatusPollClaimer {

    private static final Logger logger = LoggerFactory.getLogger(CertificateStatusPollClaimer.class);

    private final ClusterOperationSynchronizer clusterSynchronizer;
    private final CertificateStatusPollRepository pollRepository;
    private final CertificateStatusPollWriter pollWriter;
    private final StatusPollProperties statusPollProperties;

    public CertificateStatusPollClaimer(ClusterOperationSynchronizer clusterSynchronizer,
                                        CertificateStatusPollRepository pollRepository,
                                        CertificateStatusPollWriter pollWriter,
                                        StatusPollProperties statusPollProperties) {
        this.clusterSynchronizer = clusterSynchronizer;
        this.pollRepository = pollRepository;
        this.pollWriter = pollWriter;
        this.statusPollProperties = statusPollProperties;
    }

    /**
     * Claims up to {@code batchSize} due rows: advances each row's {@code attempt}/{@code next_poll_at} by the
     * backoff curve and returns the poll message to send for each. Returns empty when another node already holds
     * the sweep lock. The returned messages must be sent by the caller after this method returns (outside the
     * lock/transaction).
     */
    @Transactional(propagation = Propagation.REQUIRES_NEW)
    public List<CertificateStatusPollMessage> claimDueBatch(int batchSize) {
        if (!clusterSynchronizer.tryLock(ClusterOperationSynchronizer.Operation.PROVIDER_STATUS_POLL_SWEEP)) {
            logger.debug("Status-poll sweep skipped: another instance holds the lock");
            return List.of();
        }
        List<CertificateStatusPoll> due = pollRepository
                .findByNextPollAtLessThanEqualOrderByNextPollAt(OffsetDateTime.now(), PageRequest.of(0, batchSize));
        List<CertificateStatusPollMessage> messages = new ArrayList<>(due.size());
        for (CertificateStatusPoll poll : due) {
            messages.add(new CertificateStatusPollMessage(
                    Resource.CERTIFICATE, poll.getCertificateUuid(), poll.getOperation(), poll.getAttempt()));

            int nextAttempt = poll.getAttempt() + 1;
            Duration nextDelay = statusPollProperties.scheduleFor(poll.getOperation()).delayFor(nextAttempt);
            pollWriter.reschedule(poll.getCertificateUuid(), nextAttempt, OffsetDateTime.now().plus(nextDelay));
        }
        return messages;
    }
}
