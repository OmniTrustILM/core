package com.czertainly.core.signing.record;

import com.czertainly.core.cluster.ClusterOperationSynchronizer;
import com.czertainly.core.dao.entity.signing.SigningRecordOutbox;
import com.czertainly.core.dao.repository.signing.SigningRecordOutboxRepository;
import com.czertainly.core.service.writer.signingrecord.OutboxSigningRecordWriter;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;
import org.springframework.transaction.annotation.Propagation;
import org.springframework.transaction.annotation.Transactional;

import java.util.List;
import java.util.UUID;

/**
 * Drains the {@code signing_record_outbox} into {@code signing_record}. Holds the claim/retry orchestration
 * but no scheduling — the periodic trigger lives in {@link SigningRecordOutboxDrainScheduler}.
 *
 * <p>Cross-node mutual exclusion is a single cluster-wide advisory lock held for the whole drain (the same
 * {@link ClusterOperationSynchronizer} pattern the retention sweep uses): only one node drains at a time, so
 * the claim is a plain ordered read with no row locks. The lock is transaction-scoped, hence the
 * {@link Propagation#REQUIRES_NEW} outer transaction — which does nothing but hold the lock and read batches.
 *
 * <p>Each row is copied in its own short transaction via
 * {@link OutboxSigningRecordWriter#drainRow(java.util.UUID)}, and a failed row has its attempt recorded
 * in a separate transaction via {@link OutboxSigningRecordWriter#recordFailure(java.util.UUID, String)}.
 * This per-row isolation is what makes the retry/poison machinery work: a single un-persistable row rolls
 * back only its own transaction (leaving the healthy rows in the batch drained and committed) while its
 * attempt count still advances toward the poison threshold. Because the per-row writes run in their own
 * transactions and the outer transaction holds no row locks (only the advisory lock), there is nothing for
 * them to deadlock against.
 */
@Slf4j
@Component
public class SigningRecordOutboxDrainer {

    private final SigningRecordOutboxRepository outboxRepo;
    private final OutboxSigningRecordWriter writer;
    private final ClusterOperationSynchronizer clusterSynchronizer;
    private final SigningRecordMetrics metrics;

    private final int batchSize;
    private final int poisonThreshold;
    private final int maxBatchesPerRun;

    public SigningRecordOutboxDrainer(SigningRecordOutboxRepository outboxRepo,
                                      OutboxSigningRecordWriter writer,
                                      ClusterOperationSynchronizer clusterSynchronizer,
                                      SigningRecordMetrics metrics,
                                      @Value("${signing-record.outbox.max-batch-size:200}") int batchSize,
                                      @Value("${signing-record.outbox.poison-threshold:10}") int poisonThreshold,
                                      @Value("${signing-record.outbox.max-batches-per-run:10}") int maxBatchesPerRun) {
        this.outboxRepo = outboxRepo;
        this.writer = writer;
        this.clusterSynchronizer = clusterSynchronizer;
        this.metrics = metrics;
        this.batchSize = batchSize;
        this.poisonThreshold = poisonThreshold;
        this.maxBatchesPerRun = maxBatchesPerRun;
    }

    @Transactional(propagation = Propagation.REQUIRES_NEW)
    public void drainOnce() {
        if (!clusterSynchronizer.tryLock(ClusterOperationSynchronizer.Operation.SIGNING_RECORD_OUTBOX_DRAIN)) {
            log.debug("Outbox drain skipped: another instance holds the lock");
            return;
        }
        try {
            drainBatches();
        } catch (RuntimeException e) {
            log.warn("Outbox drain iteration failed", e);
        }
    }

    /**
     * Drains successive batches, stopping at the first non-full batch or once {@code maxBatchesPerRun} batches
     * have been drained. The cap bounds how long this run holds the advisory lock and its enclosing
     * transaction open — a long hold would keep a connection idle-in-transaction and pin the vacuum horizon —
     * so a large backlog is drained across several scheduled runs rather than one long-running transaction.
     * A batch is "full" only when every claimed row was copied; a partial batch (the last short one, or one
     * where a row failed and was left for retry) ends the run, so a failing row is attempted at most once per
     * run and retried on the next.
     */
    private void drainBatches() {
        int batchesRun = 0;
        int drained;
        do {
            List<SigningRecordOutbox> batch = outboxRepo.findDrainableBatch(poisonThreshold, batchSize);
            drained = drainRows(batch);
            if (drained > 0) {
                metrics.outboxDrained().increment(drained);
            }
            batchesRun++;
        } while (drained == batchSize && batchesRun < maxBatchesPerRun);

        if (drained == batchSize) {
            log.debug("Outbox drain hit the per-run cap of {} batch(es); remaining rows drain on the next run",
                    maxBatchesPerRun);
        }
    }

    private int drainRows(List<SigningRecordOutbox> outboxRecordsToDrain) {
        int drained = 0;
        for (SigningRecordOutbox outboxRecord : outboxRecordsToDrain) {
            if (attemptDrain(outboxRecord)) {
                drained++;
            }
        }
        return drained;
    }

    /**
     * Drains one row, or — when the copy fails — records the failed attempt so the row advances toward the
     * poison threshold. Both steps run in the writer's own transactions and either may throw; this method
     * absorbs both, so one row never aborts the rest of the batch. A row already present in
     * {@code signing_record} (crash recovery) is reconciled by the writer's idempotent merge copy and counts
     * as drained.
     */
    private boolean attemptDrain(SigningRecordOutbox outboxRecord) {
        try {
            return writer.drainRow(outboxRecord.getUuid());
        } catch (RuntimeException drainError) {
            metrics.outboxFailed().increment();
            log.warn("Failed to drain outbox row {}", outboxRecord.getUuid(), drainError);
            recordFailure(outboxRecord.getUuid(), drainError.getMessage());
            return false;
        }
    }

    /**
     * Records the failed attempt in the writer's own transaction. A failure to even record it (e.g. the
     * database is unavailable) is logged and swallowed: the row keeps its current attempt count and is
     * retried on the next run, while the rest of the batch still drains.
     */
    private void recordFailure(UUID uuid, String error) {
        try {
            writer.recordFailure(uuid, error);
        } catch (RuntimeException e) {
            log.warn("Failed to record the drain failure for outbox row {}", uuid, e);
        }
    }
}
