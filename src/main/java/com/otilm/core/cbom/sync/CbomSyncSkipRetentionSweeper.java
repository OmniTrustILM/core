package com.otilm.core.cbom.sync;

import com.otilm.core.cluster.ClusterOperationSynchronizer;
import com.otilm.core.service.writer.cbom.CbomSyncSkipRetentionWriter;
import java.time.OffsetDateTime;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Component;
import org.springframework.transaction.annotation.Propagation;
import org.springframework.transaction.annotation.Transactional;

/**
 * Removes the records of documents the sync gave up on once they are older than the retention the operator set.
 *
 * <p>
 * Age is the last attempt: a written-off document the repository keeps offering is failed on again each run and stays
 * listed, one the repository no longer lists expires. Batches of {@value #BATCH_SIZE} in their own transactions through
 * {@link CbomSyncSkipRetentionWriter}, at most {@value #MAX_BATCHES_PER_SWEEP} per sweep, so one daily run never holds
 * row locks for long and a backlog clears over a few days. Both are constants rather than settings: the operator's knob
 * is the retention itself, a platform setting; how the sweep paces itself is not policy.
 *
 * <p>
 * {@code REQUIRES_NEW} holds the cluster-wide advisory lock for the sweep (the lock is transaction-scoped) while every
 * batch commits on its own, the shape {@code PqcVerdictSweeper} and {@code SigningRecordRetentionSweeper} share.
 */
@Slf4j
@Component
public class CbomSyncSkipRetentionSweeper {

    public static final int BATCH_SIZE = 500;
    public static final int MAX_BATCHES_PER_SWEEP = 20;

    private final CbomSyncSkipRetentionWriter writer;
    private final ClusterOperationSynchronizer clusterSynchronizer;

    public CbomSyncSkipRetentionSweeper(CbomSyncSkipRetentionWriter writer,
            ClusterOperationSynchronizer clusterSynchronizer) {
        this.writer = writer;
        this.clusterSynchronizer = clusterSynchronizer;
    }

    /**
     * @param retentionDays how long a written-off record stays after its last attempt; the cutoff is that far back from
     * now
     * @return what the sweep did, for the job's history entry
     */
    @Transactional(propagation = Propagation.REQUIRES_NEW)
    public SweepOutcome sweep(int retentionDays) {
        if (!clusterSynchronizer.tryLock(ClusterOperationSynchronizer.Operation.CBOM_SYNC_SKIP_RETENTION)) {
            log.debug("CBOM sync skip retention sweep skipped: another instance holds the lock");
            return SweepOutcome.skipped();
        }
        final OffsetDateTime cutoff = OffsetDateTime.now().minusDays(retentionDays);
        int deleted = 0;
        int batches = 0;
        int lastBatch;
        try {
            // A short batch ends the sweep without proving the table is clean: the delete skips rows a concurrent
            // writer holds, and a document stored meanwhile takes its own row out of the batch. Whatever is left is a
            // day older at the next run, which is what running daily is for.
            do {
                lastBatch = writer.deleteWrittenOffBatch(cutoff, BATCH_SIZE);
                deleted += lastBatch;
                batches++;
            } while (lastBatch == BATCH_SIZE && batches < MAX_BATCHES_PER_SWEEP);
        } catch (RuntimeException e) {
            log
                    .warn("CBOM sync skip retention sweep aborted after removing {} record(s); the next run continues",
                            deleted, e);
            return new SweepOutcome(true, true, deleted, batches, false);
        }
        boolean capped = lastBatch == BATCH_SIZE;
        if (deleted > 0) {
            log
                    .info("CBOM sync skip retention sweep removed {} record(s) of documents given up on before {}{}",
                            deleted, cutoff,
                            capped ? "; stopped at the per-sweep cap, anything left goes on the next run" : "");
        }
        return new SweepOutcome(true, false, deleted, batches, capped);
    }

    /**
     * @param ran whether this instance held the lock and swept
     * @param aborted whether a batch failed; {@code deleted} then counts what landed before it
     * @param deleted rows removed
     * @param batches delete statements that committed, the final short one included; the one that aborted is not
     * counted
     * @param capped whether the sweep stopped at {@link #MAX_BATCHES_PER_SWEEP} with a full last batch, so more rows
     * may remain
     */
    public record SweepOutcome(boolean ran, boolean aborted, int deleted, int batches, boolean capped) {

        public static SweepOutcome skipped() {
            return new SweepOutcome(false, false, 0, 0, false);
        }
    }
}
