package com.otilm.core.signing.record;

import com.otilm.core.cluster.ClusterOperationSynchronizer;
import com.otilm.core.service.writer.signingrecord.SigningRecordWriter;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Component;
import org.springframework.transaction.annotation.Propagation;
import org.springframework.transaction.annotation.Transactional;

@Slf4j
@Component
public class SigningRecordRetentionSweeper {

    private final SigningRecordWriter writer;
    private final SigningRecordMetrics metrics;
    private final ClusterOperationSynchronizer clusterSynchronizer;
    private final int batchSize;
    private final int maxBatchesPerSweep;

    public SigningRecordRetentionSweeper(SigningRecordWriter writer,
                                         SigningRecordMetrics metrics,
                                         ClusterOperationSynchronizer clusterSynchronizer,
                                         SigningRecordRetentionProperties properties) {
        this.writer = writer;
        this.metrics = metrics;
        this.clusterSynchronizer = clusterSynchronizer;
        this.batchSize = properties.batchSize();
        this.maxBatchesPerSweep = properties.maxBatchesPerSweep();
    }

    /**
     * Holds the cluster-wide advisory lock for the sweep via this transaction (the lock is
     * transaction-scoped). Each batch deletes and commits in its own transaction through
     * {@link SigningRecordWriter}, so row locks and WAL release incrementally while this
     * outer transaction keeps the single-node guarantee.
     * <p>
     * The sweep deletes at most {@code maxBatchesPerSweep} batches per run. The cap bounds how long this
     * outer transaction stays open — a long hold would keep a connection idle-in-transaction and pin the
     * vacuum horizon — so a large expired backlog is cleared across several scheduled sweeps rather than one
     * long-running transaction.
     */
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
        metrics.sweep(SigningRecordMetrics.DELETE_TYPE_EXPIRED).increment();
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
            metrics.sweepFailed(SigningRecordMetrics.DELETE_TYPE_EXPIRED).increment();
            log.warn("Retention sweep aborted after deleting {} record(s); will retry next interval", total, e);
        }
        if (total > 0) {
            metrics.deleted(SigningRecordMetrics.DELETE_TYPE_EXPIRED).increment(total);
            log.info("Retention sweep deleted {} signing record(s)", total);
        }
    }
}
