package com.czertainly.core.signing.record;

import com.czertainly.core.dao.entity.signing.SigningRecord;
import com.czertainly.core.dao.repository.signing.SigningRecordRepository;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;
import org.springframework.transaction.PlatformTransactionManager;
import org.springframework.transaction.support.TransactionTemplate;

import java.util.List;

@Slf4j
@Component
public class BestEffortSigningRecordWriter implements SigningRecordWriter {

    private static final int MAX_BATCH_SIZE = 200;

    private final SigningRecordRepository repository;
    private final SigningRecordMapper mapper;
    private final SigningRecordMetrics metrics;
    private final TransactionTemplate tx;
    private final BestEffortBackpressurePolicy policy;
    private final BestEffortSigningRecordQueue queue;

    public BestEffortSigningRecordWriter(
            SigningRecordRepository repository,
            SigningRecordMapper mapper,
            SigningRecordMetrics metrics,
            PlatformTransactionManager txm,
            BestEffortSigningRecordQueue queue,
            @Value("${signing-record.best-effort.backpressure-policy:DROP_OLDEST}") BestEffortBackpressurePolicy policy) {
        this.repository = repository;
        this.mapper = mapper;
        this.metrics = metrics;
        this.tx = new TransactionTemplate(txm);
        this.policy = policy;
        this.queue = queue;
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
     * Waits up to {@code timeoutMs} for queued records, then persists a single batch (up to
     * {@link #MAX_BATCH_SIZE} records) in one transaction. Returns immediately when the wait times out with
     * an empty queue. A persistence failure is counted and logged but not propagated — best-effort records
     * are allowed to be lost. {@link InterruptedException} is propagated so the caller owning the thread
     * lifecycle can decide whether to stop.
     */
    void drainAndPersistBatch(long timeoutMs) throws InterruptedException {
        List<SigningRecord> batch = queue.pollBatch(MAX_BATCH_SIZE, timeoutMs);
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
