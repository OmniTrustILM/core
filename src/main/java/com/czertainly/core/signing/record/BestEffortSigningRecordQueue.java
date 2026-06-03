package com.czertainly.core.signing.record;

import com.czertainly.core.dao.entity.signing.SigningRecord;
import com.czertainly.core.service.writer.signingrecord.BestEffortSigningRecordWriter;
import lombok.extern.slf4j.Slf4j;

import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.BlockingQueue;
import java.util.concurrent.TimeUnit;

/**
 * Wraps the bounded in-memory queue feeding {@link BestEffortSigningRecordWriter}, owning both backpressure
 * strategies. {@link #enqueueDropping} sheds the oldest records to admit a new one; {@link #enqueueBlocking}
 * waits for capacity. {@link #pollBatch} takes a bounded batch for persistence. Drop accounting is left to
 * the caller — the dropping path returns how many records it evicted.
 */
@Slf4j
public class BestEffortSigningRecordQueue {

    private final BlockingQueue<SigningRecord> queue;

    public BestEffortSigningRecordQueue(BlockingQueue<SigningRecord> queue) {
        this.queue = queue;
    }

    /**
     * Admits {@code signingRecord}, evicting the oldest queued records as needed until it fits — under
     * sustained pressure it is the oldest records that are lost. Returns the number of records evicted so the
     * caller can account for the loss.
     */
    public int enqueueDropping(SigningRecord signingRecord) {
        int evicted = 0;
        while (!queue.offer(signingRecord)) {
            SigningRecord removed = queue.poll();
            if (removed != null) {
                evicted++;
                log.warn("BEST_EFFORT queue full; evicted oldest {} to admit {}", removed.getUuid(), signingRecord.getUuid());
            }
        }
        return evicted;
    }

    /**
     * Admits {@code signingRecord}, blocking until the queue has capacity. Propagates
     * {@link InterruptedException} when interrupted while waiting — the caller owns the metrics and the
     * thread lifecycle, so it decides how to account for the dropped record and whether to stop.
     */
    public void enqueueBlocking(SigningRecord signingRecord) throws InterruptedException {
        queue.put(signingRecord);
    }

    /**
     * Waits up to {@code timeoutMs} for the first record, then drains up to {@code maxBatchSize} records
     * total into one batch. Returns an empty list if the wait times out with an empty queue.
     */
    public List<SigningRecord> pollBatch(int maxBatchSize, long timeoutMs) throws InterruptedException {
        SigningRecord first = queue.poll(timeoutMs, TimeUnit.MILLISECONDS);
        if (first == null) {
            return List.of();
        }
        List<SigningRecord> batch = new ArrayList<>();
        batch.add(first);
        queue.drainTo(batch, maxBatchSize - 1);
        return batch;
    }
}
