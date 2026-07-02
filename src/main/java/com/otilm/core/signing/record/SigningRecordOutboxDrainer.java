package com.otilm.core.signing.record;

import com.otilm.api.model.client.signing.profile.record.SigningRecordPersistenceMode;
import com.otilm.core.cluster.ClusterOperationSynchronizer;
import com.otilm.core.dao.entity.signing.SigningRecord;
import com.otilm.core.dao.entity.signing.SigningRecordOutbox;
import com.otilm.core.dao.repository.signing.SigningRecordOutboxRepository;
import com.otilm.core.mapper.signing.SigningRecordMapper;
import com.otilm.core.service.writer.signingrecord.SigningRecordWriter;
import jakarta.persistence.EntityManager;
import jakarta.persistence.PersistenceException;
import lombok.extern.slf4j.Slf4j;
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
 * <p>Normal path: each batch is drained in one transaction via
 * {@link SigningRecordWriter#persistBatchAndDeleteOutbox} — Hibernate JDBC batching + one bulk DELETE, so the
 * per-batch cost is two round-trips regardless of batch size. If that transaction fails (rare crash-recovery
 * duplicate: a node crashed after inserting into {@code signing_record} but before deleting the outbox row),
 * the batch falls back to per-row draining via {@link SigningRecordWriter#saveRecordAndDeleteOutbox}, which
 * uses a merge copy (idempotent) and records failed attempts toward the poison threshold via
 * {@link SigningRecordWriter#recordFailure(java.util.UUID, String)}.
 */
@Slf4j
@Component
public class SigningRecordOutboxDrainer {

    private final EntityManager entityManager;
    private final SigningRecordOutboxRepository outboxRepo;
    private final SigningRecordWriter writer;
    private final ClusterOperationSynchronizer clusterSynchronizer;
    private final SigningRecordMetrics metrics;

    private final int batchSize;
    private final int poisonThreshold;
    private final int maxBatchesPerRun;

    public SigningRecordOutboxDrainer(EntityManager entityManager,
                                      SigningRecordOutboxRepository outboxRepo,
                                      SigningRecordWriter writer,
                                      ClusterOperationSynchronizer clusterSynchronizer,
                                      SigningRecordMetrics metrics,
                                      SigningRecordOutboxProperties properties) {
        this.entityManager = entityManager;
        this.outboxRepo = outboxRepo;
        this.writer = writer;
        this.clusterSynchronizer = clusterSynchronizer;
        this.metrics = metrics;
        this.batchSize = properties.maxBatchSize();
        this.poisonThreshold = properties.poisonThreshold();
        this.maxBatchesPerRun = properties.maxBatchesPerRun();
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
            List<UUID> batch = outboxRepo.findDrainableBatch(poisonThreshold, batchSize);
            drained = drainRows(batch);
            // Evict this batch's blob entities from the long-lived outer PC; left managed they would pin up to
            // maxBatchesPerRun × maxBatchSize in heap.
            entityManager.clear();
            batchesRun++;
        } while (drained == batchSize && batchesRun < maxBatchesPerRun);

        if (drained == batchSize) {
            log.debug("Outbox drain hit the per-run cap of {} batch(es); remaining rows drain on the next run",
                    maxBatchesPerRun);
        }
    }

    /**
     * Drains a batch using the fast bulk path: loads all rows in one query, maps them, and hands them to
     * {@link SigningRecordWriter#persistBatchAndDeleteOutbox} which persists all records via Hibernate JDBC batching
     * and removes the outbox rows with a single bulk DELETE — two round-trips per batch instead of four per row.
     *
     * <p>Falls back to per-row draining when the batch path throws. The only expected failure is a
     * {@link PersistenceException} on the flush in crash-recovery: a node crashed after writing to
     * {@code signing_record} but before deleting the outbox row, leaving a duplicate. The per-row fallback
     * handles this via the idempotent {@link SigningRecordWriter#saveRecordAndDeleteOutbox} merge copy, and
     * gives each row individual retry/poison accounting via {@link #recordFailure}.
     */
    private int drainRows(List<UUID> outboxRowUuids) {
        if (outboxRowUuids.isEmpty())
            return 0;

        List<SigningRecordOutbox> rows = outboxRepo.findAllById(outboxRowUuids);
        if (rows.isEmpty())
            return 0;

        metrics.persist(SigningRecordPersistenceMode.DEFERRED_DURABLE.name()).increment(rows.size());

        List<SigningRecord> records = rows.stream().map(this::mapAndEvict).toList();

        try {
            writer.persistBatchAndDeleteOutbox(records);
            return records.size();
        } catch (RuntimeException e) {
            log.debug("Batch drain failed (crash-recovery duplicate?), falling back to row-by-row for {} rows: {}",
                    outboxRowUuids.size(), e.getMessage());
            metrics.batchDrainFallback().increment();
            return drainRowsOneByOne(records);
        }
    }

    private int drainRowsOneByOne(List<SigningRecord> records) {
        int drained = 0;
        for (SigningRecord signingRecord : records) {
            if (attemptDrain(signingRecord)) {
                drained++;
            }
        }
        return drained;
    }

    private SigningRecord mapAndEvict(SigningRecordOutbox row) {
        SigningRecord signingRecord = SigningRecordMapper.toRecord(row);
        entityManager.detach(row);
        return signingRecord;
    }

    /**
     * Per-row fallback used when the batch path fails. Copies the record to {@code signing_record} via
     * {@link SigningRecordWriter#saveRecordAndDeleteOutbox} (idempotent merge copy that handles
     * crash-recovery duplicates), and records a failed attempt when the copy throws so the row advances
     * toward the poison threshold without aborting the rest of the batch.
     */
    private boolean attemptDrain(SigningRecord signingRecord) {
        try {
            writer.saveRecordAndDeleteOutbox(signingRecord);
            return true;
        } catch (RuntimeException drainError) {
            metrics.persistFailed(SigningRecordPersistenceMode.DEFERRED_DURABLE.name()).increment();
            log.warn("Failed to drain outbox row {}", signingRecord.getUuid(), drainError);
            recordFailure(signingRecord.getUuid(), drainError.toString());
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
