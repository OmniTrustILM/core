package com.otilm.core.messaging.jms.listeners.discovery;

import com.otilm.core.cluster.ClusterOperationSynchronizer;
import com.otilm.core.dao.entity.DiscoveryWork;
import com.otilm.core.dao.repository.DiscoveryWorkRepository;
import com.otilm.core.messaging.model.DiscoveryWorkMessage;
import com.otilm.core.service.writer.discovery.DiscoveryWorkWriter;
import java.time.Duration;
import java.time.OffsetDateTime;
import java.time.ZoneOffset;
import java.util.ArrayList;
import java.util.List;
import java.util.UUID;
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
 * only for the duration of the read and the claims. The claim commits with the same transaction that holds the lock, so
 * a row is either read-and-claimed or neither.
 * </p>
 */
@Component
public class DiscoveryWorkClaimer {

    private static final Logger logger = LoggerFactory.getLogger(DiscoveryWorkClaimer.class);

    private final ClusterOperationSynchronizer clusterSynchronizer;
    private final DiscoveryWorkRepository workRepository;
    private final DiscoveryWorkWriter workWriter;
    private final Duration leaseDuration;

    public DiscoveryWorkClaimer(ClusterOperationSynchronizer clusterSynchronizer,
            DiscoveryWorkRepository workRepository, DiscoveryWorkWriter workWriter,
            @Value("${discovery.work.lease-duration:PT2M}") Duration leaseDuration) {
        this.clusterSynchronizer = clusterSynchronizer;
        this.workRepository = workRepository;
        this.workWriter = workWriter;
        this.leaseDuration = leaseDuration;
    }

    /**
     * Claims up to {@code batchSize} rows due at {@code dueCutoff} that no tick holds, and returns the tick message to
     * send for each.
     *
     * <p>
     * <b>Locking:</b> returns empty when another node already holds the sweep lock.
     *
     * <p>
     * <b>Claiming:</b> each row gets a fresh lease token, valid for {@code discovery.work.lease-duration}, and one more
     * attempt charged against its budget. The message carries the token; the tick runs only while the row still holds
     * it, and renews it while it works. A row whose tick never runs — a lost message, a node that died holding it —
     * becomes claimable again when its lease runs out.
     *
     * <p>
     * <b>Publishing:</b> the caller sends the returned messages after this method returns, outside the lock and
     * transaction.
     */
    @Transactional(propagation = Propagation.REQUIRES_NEW)
    public List<DiscoveryWorkMessage> claimDueBatch(int batchSize, OffsetDateTime dueCutoff) {
        if (!clusterSynchronizer.tryLock(ClusterOperationSynchronizer.Operation.DISCOVERY_WORK_SWEEP)) {
            logger.debug("Discovery work sweep skipped: another instance holds the lock");
            return List.of();
        }
        OffsetDateTime now = OffsetDateTime.now(ZoneOffset.UTC);
        List<DiscoveryWork> claimable = workRepository.findClaimable(dueCutoff, now, PageRequest.of(0, batchSize));
        OffsetDateTime leasedUntil = now.plus(leaseDuration);
        List<DiscoveryWorkMessage> messages = new ArrayList<>(claimable.size());
        for (DiscoveryWork work : claimable) {
            UUID leaseToken = UUID.randomUUID();
            workWriter
                    .claim(work.getDiscoveryUuid(), work.getWorkType(), leaseToken, work.getAttempt() + 1, leasedUntil);
            messages
                    .add(new DiscoveryWorkMessage(work.getDiscoveryUuid(), work.getWorkType(), work.getAttempt(),
                            leaseToken));
        }
        return messages;
    }
}
