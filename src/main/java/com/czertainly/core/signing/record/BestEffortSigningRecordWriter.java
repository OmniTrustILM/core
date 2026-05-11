package com.czertainly.core.signing.record;

import com.czertainly.core.dao.entity.signing.SigningRecord;
import com.czertainly.core.dao.repository.signing.SigningRecordRepository;
import jakarta.annotation.PostConstruct;
import jakarta.annotation.PreDestroy;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;
import org.springframework.transaction.PlatformTransactionManager;
import org.springframework.transaction.support.TransactionTemplate;

import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.ArrayBlockingQueue;
import java.util.concurrent.BlockingQueue;
import java.util.concurrent.TimeUnit;

@Slf4j
@Component
public class BestEffortSigningRecordWriter extends AbstractSigningRecordWriter {

    private final SigningRecordRepository repository;
    private final TransactionTemplate tx;
    private final int capacity;
    private final BestEffortBackpressurePolicy policy;
    private final long flushIntervalMs;

    private BlockingQueue<SigningRecord> queue;
    private Thread flusher;
    private volatile boolean running = true;

    public BestEffortSigningRecordWriter(
            SigningRecordRepository repository,
            SigningRecordMetrics metrics,
            PlatformTransactionManager txm,
            @Value("${signing-record.best-effort.queue-capacity:10000}") int capacity,
            @Value("${signing-record.best-effort.backpressure-policy:DROP_OLDEST}") BestEffortBackpressurePolicy policy,
            @Value("${signing-record.best-effort.flush-interval-ms:200}") long flushIntervalMs) {
        super(metrics);
        this.repository = repository;
        this.tx = new TransactionTemplate(txm);
        this.capacity = capacity;
        this.policy = policy;
        this.flushIntervalMs = flushIntervalMs;
    }

    @PostConstruct
    public void start() {
        this.queue = new ArrayBlockingQueue<>(capacity);
        this.flusher = new Thread(this::flushLoop, "signing-record-best-effort-flusher");
        this.flusher.setDaemon(true);
        this.flusher.start();
    }

    @PreDestroy
    public void stop() {
        running = false;
        if (flusher != null) {
            flusher.interrupt();
        }
    }

    @Override
    public void record(SigningRecordInput input) {
        if (!hasAnyRecordableContent(input.getVersion())) {
            metrics.skippedNoContentPolicy().increment();
            return;
        }
        timed("BEST_EFFORT", () -> {
            SigningRecord r = buildSigningRecord(input);
            r.setSigningProfileUuid(input.getProfile().getUuid());
            offer(r);
            metrics.created("BEST_EFFORT").increment();
        });
    }

    private void offer(SigningRecord r) {
        if (queue.offer(r)) return;
        switch (policy) {
            case DROP_OLDEST -> {
                queue.poll();
                if (!queue.offer(r)) {
                    metrics.bestEffortDropped("queue_full").increment();
                    log.warn("BEST_EFFORT queue full; dropped record {}", r.getUuid());
                } else {
                    metrics.bestEffortDropped("queue_full").increment();
                    log.warn("BEST_EFFORT queue full; evicted oldest to admit {}", r.getUuid());
                }
            }
            case BLOCK -> {
                try {
                    queue.put(r);
                } catch (InterruptedException e) {
                    Thread.currentThread().interrupt();
                }
            }
        }
    }

    private void flushLoop() {
        while (running) {
            try {
                SigningRecord first = queue.poll(flushIntervalMs, TimeUnit.MILLISECONDS);
                if (first == null) continue;
                List<SigningRecord> batch = new ArrayList<>();
                batch.add(first);
                queue.drainTo(batch, 199);
                tx.executeWithoutResult(status -> repository.saveAll(batch));
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
            } catch (RuntimeException e) {
                metrics.bestEffortDropped("flush_failed").increment();
                log.warn("BEST_EFFORT flush failed (records lost)", e);
            }
        }
    }
}
