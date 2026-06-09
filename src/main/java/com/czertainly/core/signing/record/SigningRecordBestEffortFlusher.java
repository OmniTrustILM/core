package com.czertainly.core.signing.record;

import jakarta.annotation.PostConstruct;
import jakarta.annotation.PreDestroy;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Component;

/**
 * Owns the background thread that periodically drives {@link BestEffortSigningRecordStrategy} to drain its
 * in-memory queue and persist batched signing records. The strategy holds all queue/DB logic; this class
 * holds only the scheduling and thread lifecycle.
 */
@Slf4j
@Component
public class SigningRecordBestEffortFlusher {

    private final BestEffortSigningRecordStrategy strategy;
    private final long flushIntervalMs;

    private Thread flusher;
    private volatile boolean running = true;

    public SigningRecordBestEffortFlusher(
            BestEffortSigningRecordStrategy strategy,
            SigningRecordBestEffortProperties properties) {
        this.strategy = strategy;
        this.flushIntervalMs = properties.flushIntervalMs();
    }

    @PostConstruct
    public void start() {
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

    private void flushLoop() {
        while (running) {
            try {
                strategy.drainAndPersistBatch(flushIntervalMs);
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
            }
        }
    }
}
