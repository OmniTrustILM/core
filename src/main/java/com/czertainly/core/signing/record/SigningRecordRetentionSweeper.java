package com.czertainly.core.signing.record;

import com.czertainly.core.cluster.ClusterOperationSynchronizer;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Component;
import org.springframework.transaction.annotation.Propagation;
import org.springframework.transaction.annotation.Transactional;

@Slf4j
@Component
@ConditionalOnProperty(value = "scheduled-tasks.enabled", matchIfMissing = true, havingValue = "true")
public class SigningRecordRetentionSweeper {

    private final SigningRecordDeletionWriter writer;
    private final SigningRecordMetrics metrics;
    private final ClusterOperationSynchronizer clusterSynchronizer;
    private final int batchSize;
    private final int maxBatchesPerSweep;

    public SigningRecordRetentionSweeper(SigningRecordDeletionWriter writer,
                                         SigningRecordMetrics metrics,
                                         ClusterOperationSynchronizer clusterSynchronizer,
                                         @Value("${signing-record.retention.batch-size:10000}") int batchSize,
                                         @Value("${signing-record.retention.max-batches-per-sweep:10}") int maxBatchesPerSweep) {
        this.writer = writer;
        this.metrics = metrics;
        this.clusterSynchronizer = clusterSynchronizer;
        this.batchSize = batchSize;
        this.maxBatchesPerSweep = maxBatchesPerSweep;
    }

    /**
     * Holds the cluster-wide advisory lock for the sweep via this transaction (the lock is
     * transaction-scoped). Each batch deletes and commits in its own transaction through
     * {@link SigningRecordDeletionWriter}, so row locks and WAL release incrementally while this
     * outer transaction keeps the single-node guarantee.
     * <p>
     * The sweep deletes at most {@code maxBatchesPerSweep} batches per run. The cap bounds how long this
     * outer transaction stays open — a long hold would keep a connection idle-in-transaction and pin the
     * vacuum horizon — so a large expired backlog is cleared across several scheduled sweeps rather than one
     * long-running transaction.
     */
    @Scheduled(fixedDelayString = "${signing-record.retention.sweep-interval-minutes:60}",
            timeUnit = java.util.concurrent.TimeUnit.MINUTES)
    @Transactional(propagation = Propagation.REQUIRES_NEW)
    public void sweep() {
        if (maxBatchesPerSweep <= 0) {
            log.debug("Retention sweep disabled: max-batches-per-sweep is {}", maxBatchesPerSweep);
            return;
        }
        if (!clusterSynchronizer.tryLock(ClusterOperationSynchronizer.Operation.SIGNING_RECORD_RETENTION)) {
            log.debug("Retention sweep skipped: another instance holds the lock");
            return;
        }
        int total = 0;
        try {
            int batchesRun = 0;
            int deleted;
            do {
                deleted = writer.deleteExpiredBatch(batchSize);
                total += deleted;
                batchesRun++;
            } while (deleted == batchSize && batchesRun < maxBatchesPerSweep);
            if (deleted == batchSize) {
                log.debug("Retention sweep stopped at the per-sweep cap of {} batch(es); any rows still expired clear on the next sweep",
                        maxBatchesPerSweep);
            }
        } catch (RuntimeException e) {
            metrics.retentionFailed().increment();
            log.warn("Retention sweep aborted after deleting {} record(s); will retry next interval", total, e);
        }
        if (total > 0) {
            metrics.retentionDeleted().increment(total);
            log.info("Retention sweep deleted {} signing record(s)", total);
        }
    }
}
