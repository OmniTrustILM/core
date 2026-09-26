package com.otilm.core.service.handler;

import com.otilm.core.cluster.ClusterOperationSynchronizer;
import com.otilm.core.config.KeyImportProperties;
import com.otilm.core.dao.entity.KeyImport;
import com.otilm.core.dao.entity.KeyImportState;
import com.otilm.core.dao.repository.KeyImportRepository;
import com.otilm.core.model.crypto.KeyImportCheck;
import com.otilm.core.service.writer.KeyImportWriter;
import java.time.OffsetDateTime;
import java.util.Arrays;
import java.util.Optional;
import java.util.Set;
import java.util.stream.Collectors;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.data.domain.PageRequest;
import org.springframework.stereotype.Component;
import org.springframework.transaction.annotation.Propagation;
import org.springframework.transaction.annotation.Transactional;

/**
 * Claims the import attempts due for the reconciliation, one attempt and one node at a time. A claim runs against the
 * database alone, so the cluster lock and the transaction are held only while due attempts are read and one of them is
 * rescheduled; it is reconciled once the claim has committed, well within the retry window its claim holds it for.
 */
@Component
public class KeyImportClaimer {

    public static final String UNRESOLVED = "The outcome of the key import could not be learned in time.";

    private static final Logger logger = LoggerFactory.getLogger(KeyImportClaimer.class);

    public static final int LOOK_AHEAD = 50;

    private static final Set<KeyImportState> UNSETTLED = Arrays
            .stream(KeyImportState.values())
            .filter(KeyImportState::isUnsettled)
            .collect(Collectors.toUnmodifiableSet());

    private final ClusterOperationSynchronizer clusterSynchronizer;
    private final KeyImportRepository keyImportRepository;
    private final KeyImportWriter keyImportWriter;
    private final KeyImportProperties properties;

    public KeyImportClaimer(ClusterOperationSynchronizer clusterSynchronizer, KeyImportRepository keyImportRepository,
            KeyImportWriter keyImportWriter, KeyImportProperties properties) {
        this.clusterSynchronizer = clusterSynchronizer;
        this.keyImportRepository = keyImportRepository;
        this.keyImportWriter = keyImportWriter;
        this.properties = properties;
    }

    /**
     * Claims the attempt that has waited longest for a look, until a retry window from now. Attempts last sent longer
     * ago than the connector is trusted to keep its records are closed as unresolved on the way, since the connector's
     * answer about them would prove nothing; a claim looks at most {@link #LOOK_AHEAD} due attempts. Nothing is claimed
     * while another node claims.
     *
     * @return the claimed attempt, to be reconciled once this claim has committed, or nothing when none is due among
     * those it looked at
     */
    @Transactional(propagation = Propagation.REQUIRES_NEW)
    public Optional<KeyImportCheck> claimNext() {
        if (!clusterSynchronizer.tryLock(ClusterOperationSynchronizer.Operation.KEY_IMPORT_SWEEP)) {
            logger.debug("Key import reconciliation skipped: another instance holds the lock");
            return Optional.empty();
        }
        OffsetDateTime now = OffsetDateTime.now();
        for (KeyImport due : keyImportRepository
                .findForUpdateByStateInAndNextCheckAtLessThanEqualOrderByNextCheckAt(UNSETTLED, now,
                        PageRequest.of(0, LOOK_AHEAD))) {
            if (due.getLastSentAt().plus(properties.unresolvedAfter()).isAfter(now)) {
                keyImportWriter.reschedule(due.getUuid(), now.plus(properties.retryWindow()));
                return Optional.of(KeyImportCheck.of(due));
            }
            keyImportWriter.unresolved(due.getUuid(), UNRESOLVED);
            logger
                    .warn("Key import {} is unresolved; key reference {} identifies its key in token instance {}",
                            due.getUuid(), due.getKeyReference(), due.getTokenInstanceUuid());
        }
        return Optional.empty();
    }
}
