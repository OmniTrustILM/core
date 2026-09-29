package com.otilm.core.service.handler;

import com.otilm.core.config.KeyImportProperties;
import com.otilm.core.model.crypto.KeyImportCheck;
import com.otilm.core.service.writer.KeyImportRetentionWriter;
import java.time.OffsetDateTime;
import java.time.ZoneOffset;
import java.util.HashSet;
import java.util.Optional;
import java.util.Set;
import java.util.UUID;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;

/**
 * Settles the import attempts whose outcome their requesters never learned, then deletes the attempts that completed,
 * failed or were compensated longer than the retention ago. Every node runs it on its own timer. Due attempts are
 * claimed one at a time through {@link KeyImportClaimer}, just before each is reconciled, and each is reconciled after
 * its claim has committed, so no connector call holds the cluster lock or a database connection. A connector that does
 * not answer is asked about one attempt of its token a run; the token's other attempts claimed in the run wait for
 * their next look, so a connector that hangs does not hold up the others. An attempt on its last look is asked about
 * regardless, since it has no later one.
 */
@Component
public class KeyImportSweeper {

    private static final int MAX_CLAIMS_PER_RUN = 500;
    private static final int DELETE_BATCH_SIZE = 500;
    static final int MAX_DELETE_BATCHES_PER_RUN = 20;

    private static final Logger logger = LoggerFactory.getLogger(KeyImportSweeper.class);

    private final KeyImportClaimer claimer;
    private final KeyImportReconciler reconciler;
    private final KeyImportRetentionWriter retentionWriter;
    private final KeyImportProperties properties;

    public KeyImportSweeper(KeyImportClaimer claimer, KeyImportReconciler reconciler,
            KeyImportRetentionWriter retentionWriter, KeyImportProperties properties) {
        this.claimer = claimer;
        this.reconciler = reconciler;
        this.retentionWriter = retentionWriter;
        this.properties = properties;
    }

    /** Reconciles the due attempts, then deletes the completed, failed and compensated ones past their retention. */
    public void sweep() {
        reconcileDue();
        deleteFinished();
    }

    /** Reconciles the due attempts one by one, up to a bound of claims per run, each attempt on its own. */
    private void reconcileDue() {
        Set<UUID> silentTokens = new HashSet<>();
        for (int claims = 0; claims < MAX_CLAIMS_PER_RUN; claims++) {
            Optional<KeyImportCheck> claimed = claimer.claimNext();
            if (claimed.isEmpty()) {
                return;
            }
            KeyImportCheck check = claimed.get();
            boolean asked = check.lastLook() || !silentTokens.contains(check.tokenInstanceUuid());
            if (asked && !reconcile(check)) {
                silentTokens.add(check.tokenInstanceUuid());
            }
        }
    }

    /**
     * Deletes the attempts that completed, failed or were compensated longer than the retention ago, a batch at a time,
     * up to a bound of batches per run. Every node deletes, without the cluster lock: a batch skips the attempts
     * another node's batch holds, so nodes deleting at once neither wait for nor fail on each other. A short batch ends
     * the run, and what it skipped goes on a later one.
     */
    private void deleteFinished() {
        OffsetDateTime cutoff = OffsetDateTime.now(ZoneOffset.UTC).minus(properties.retention());
        int deleted = 0;
        int batches = 0;
        int batch;
        do {
            batch = retentionWriter.deleteFinishedBefore(cutoff, DELETE_BATCH_SIZE);
            deleted += batch;
            batches++;
        } while (batch == DELETE_BATCH_SIZE && batches < MAX_DELETE_BATCHES_PER_RUN);
        if (deleted > 0) {
            logger.debug("Deleted {} key import attempts that finished before {}", deleted, cutoff);
        }
    }

    /** Whether the connector answered about the attempt. */
    private boolean reconcile(KeyImportCheck check) {
        try {
            return reconciler.reconcile(check);
        } catch (RuntimeException e) {
            logger
                    .warn("Key import {} could not be reconciled ({}); it is looked at again when next due",
                            check.attempt().uuid(), e.getClass().getSimpleName());
            return false;
        }
    }
}
