package com.czertainly.core.signing.record;

import com.czertainly.core.service.writer.signingrecord.BestEffortSigningRecordWriter;
import jakarta.annotation.PostConstruct;
import jakarta.annotation.PreDestroy;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

/**
 * Owns the background thread that periodically drives {@link BestEffortSigningRecordWriter} to drain its
 * in-memory queue and persist batched signing records. The writer holds all queue/DB logic; this class
 * holds only the scheduling and thread lifecycle.
 */
@Slf4j
@Component
public class SigningRecordBestEffortFlusher {

    private final BestEffortSigningRecordWriter writer;
    private final long flushIntervalMs;

    private Thread flusher;
    private volatile boolean running = true;

    public SigningRecordBestEffortFlusher(
            BestEffortSigningRecordWriter writer,
            @Value("${signing-record.best-effort.flush-interval-ms:200}") long flushIntervalMs) {
        this.writer = writer;
        this.flushIntervalMs = flushIntervalMs;
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
                writer.drainAndPersistBatch(flushIntervalMs);
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
            }
        }
    }
}
