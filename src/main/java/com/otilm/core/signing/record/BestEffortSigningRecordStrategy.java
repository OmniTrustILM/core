package com.otilm.core.signing.record;

import com.otilm.api.model.client.signing.profile.record.SigningRecordPersistenceMode;
import com.otilm.core.dao.entity.signing.SigningRecord;
import com.otilm.core.mapper.signing.SigningRecordInputMapper;
import com.otilm.core.service.writer.signingrecord.SigningRecordWriter;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Component;

import java.util.List;

/**
 * {@code BEST_EFFORT} mode: maps the record and admits it to an in-memory queue under the configured
 * backpressure policy, returning to the caller without touching the database. A background thread
 * ({@link SigningRecordBestEffortFlusher}) periodically drives {@link #drainAndPersistBatch(long)} to persist
 * batches via {@link SigningRecordWriter#insertBatch(List)}. Records may be lost (queue eviction, an
 * interrupted block, or a flush failure) — that is the trade for never blocking or failing the signing
 * operation on a record write.
 */
@Slf4j
@Component
public class BestEffortSigningRecordStrategy extends AbstractSigningRecordStrategy {

    private final SigningRecordWriter writer;
    private final SigningRecordInputMapper mapper;
    private final BestEffortBackpressurePolicy policy;
    private final BestEffortSigningRecordQueue queue;
    private final int maxBatchSize;

    public BestEffortSigningRecordStrategy(
            SigningRecordMetrics metrics,
            SigningRecordWriter writer,
            SigningRecordInputMapper mapper,
            BestEffortSigningRecordQueue queue,
            SigningRecordBestEffortProperties properties) {
        super(metrics);
        this.writer = writer;
        this.mapper = mapper;
        this.policy = properties.backpressurePolicy();
        this.queue = queue;
        this.maxBatchSize = properties.maxBatchSize();
    }

    @Override
    protected void doRecord(SigningRecordInput input) {
        enqueue(mapper.toRecord(input));
    }

    /**
     * Enqueues per the configured backpressure policy. Under DROP_OLDEST the new record is always admitted, and
     * any evicted older records are counted as a post-acceptance loss; with {@code BLOCK}, the addmission blocks
     * till the queue has empty space. If the wait is interrupted, the record is dropped and intake failure is recorded.
     */
    private void enqueue(SigningRecord signingRecord) {
        switch (policy) {
            case DROP_OLDEST -> {
                int evicted = queue.enqueueDropping(signingRecord);
                if (evicted > 0) {
                    metrics.bestEffortEvicted().increment(evicted);
                }
            }
            case BLOCK -> {
                try {
                    queue.enqueueBlocking(signingRecord);
                } catch (InterruptedException e) {
                    Thread.currentThread().interrupt();
                    metrics.intakeFailed(mode().name(), SigningRecordMetrics.REASON_INTERRUPTED).increment();
                }
            }
        }
    }

    /**
     * Waits up to {@code timeoutMs} for queued records, then persists a single batch (up to the configured
     * {@code signing-record.best-effort.max-batch-size}) in one transaction via the writer. Returns immediately
     * when the wait times out with an empty queue. A persistence failure is counted and logged but not
     * propagated — best-effort records are allowed to be lost. {@link InterruptedException} is propagated so the
     * caller owning the thread lifecycle can decide whether to stop.
     */
    public void drainAndPersistBatch(long timeoutMs) throws InterruptedException {
        List<SigningRecord> batch = queue.pollBatch(maxBatchSize, timeoutMs);
        if (batch.isEmpty()) {
            return;
        }
        metrics.persist(mode().name()).increment(batch.size());
        try {
            writer.insertBatch(batch);
        } catch (RuntimeException e) {
            metrics.persistFailed(mode().name()).increment(batch.size());
            log.warn("BEST_EFFORT flush failed ({} records lost)", batch.size(), e);
        }
    }

    @Override
    protected SigningRecordPersistenceMode mode() {
        return SigningRecordPersistenceMode.BEST_EFFORT;
    }
}
