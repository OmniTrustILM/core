package com.czertainly.core.service.writer.signingrecord;

import com.czertainly.core.dao.entity.signing.SigningRecord;
import com.czertainly.core.dao.repository.signing.SigningRecordRepository;
import com.czertainly.core.signing.record.*;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;
import org.springframework.transaction.PlatformTransactionManager;
import org.springframework.transaction.support.TransactionTemplate;

import java.util.List;

@Slf4j
@Component
public class BestEffortSigningRecordWriter implements SigningRecordWriter {

    private final SigningRecordRepository repository;
    private final SigningRecordMapper mapper;
    private final SigningRecordMetrics metrics;
    private final TransactionTemplate tx;
    private final BestEffortBackpressurePolicy policy;
    private final BestEffortSigningRecordQueue queue;
    private final int maxBatchSize;

    public BestEffortSigningRecordWriter(
            SigningRecordRepository repository,
            SigningRecordMapper mapper,
            SigningRecordMetrics metrics,
            PlatformTransactionManager txm,
            BestEffortSigningRecordQueue queue,
            @Value("${signing-record.best-effort.backpressure-policy:DROP_OLDEST}") BestEffortBackpressurePolicy policy,
            @Value("${signing-record.best-effort.max-batch-size:200}") int maxBatchSize) {
        this.repository = repository;
        this.mapper = mapper;
        this.metrics = metrics;
        this.tx = new TransactionTemplate(txm);
        this.policy = policy;
        this.queue = queue;
        this.maxBatchSize = maxBatchSize;
    }

    @Override
    public void record(SigningRecordInput input) {
        if (!SigningRecordPolicy.hasAnyRecordableContent(input.getSigningProfile().recordPolicy())) {
            metrics.skippedNoContentPolicy().increment();
            return;
        }
        metrics.timed("BEST_EFFORT", () -> {
            if (enqueue(mapper.toRecord(input))) {
                metrics.queued("BEST_EFFORT").increment();
            }
        });
    }

    /**
     * Enqueues per the configured backpressure policy and reports whether the record was admitted. Oldest-eviction
     * still admits the new record (returns {@code true}); an interrupted {@code BLOCK} wait drops it (returns
     * {@code false}) after restoring the interrupt flag and counting the loss.
     */
    private boolean enqueue(SigningRecord signingRecord) {
        switch (policy) {
            case DROP_OLDEST -> {
                int evicted = queue.enqueueDropping(signingRecord);
                if (evicted > 0) {
                    metrics.bestEffortDropped("evicted_oldest").increment(evicted);
                }
            }
            case BLOCK -> {
                try {
                    queue.enqueueBlocking(signingRecord);
                } catch (InterruptedException e) {
                    Thread.currentThread().interrupt();
                    metrics.bestEffortDropped("interrupted").increment();
                    return false;
                }
            }
        }
        return true;
    }

    /**
     * Waits up to {@code timeoutMs} for queued records, then persists a single batch (up to the configured
     * {@code signing-record.best-effort.max-batch-size}) in one transaction. Returns immediately when the wait times out with
     * an empty queue. A persistence failure is counted and logged but not propagated — best-effort records
     * are allowed to be lost. {@link InterruptedException} is propagated so the caller owning the thread
     * lifecycle can decide whether to stop.
     */
    public void drainAndPersistBatch(long timeoutMs) throws InterruptedException {
        List<SigningRecord> batch = queue.pollBatch(maxBatchSize, timeoutMs);
        if (batch.isEmpty()) {
            return;
        }
        try {
            tx.executeWithoutResult(status -> repository.saveAll(batch));
            metrics.created("BEST_EFFORT").increment(batch.size());
        } catch (RuntimeException e) {
            metrics.persistFailed("BEST_EFFORT").increment(batch.size());
            metrics.bestEffortDropped("flush_failed").increment(batch.size());
            log.warn("BEST_EFFORT flush failed ({} records lost)", batch.size(), e);
        }
    }
}
