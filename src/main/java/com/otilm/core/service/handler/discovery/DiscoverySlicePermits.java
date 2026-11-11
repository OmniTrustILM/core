package com.otilm.core.service.handler.discovery;

import java.util.concurrent.Semaphore;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

/**
 * Bounds how many checkpointed drains this Core node has at their connectors at once, and so how many of its runs scan
 * at once: a checkpointed connector scans while it answers a drain. Configured as
 * {@code discovery.slice.max-concurrent-per-node}, documented in application.yml.
 */
@Component
public class DiscoverySlicePermits {

    private final Semaphore permits;

    public DiscoverySlicePermits(@Value("${discovery.slice.max-concurrent-per-node:8}") int maxConcurrentPerNode) {
        if (maxConcurrentPerNode < 1) {
            throw new IllegalArgumentException("discovery.slice.max-concurrent-per-node must be at least 1");
        }
        this.permits = new Semaphore(maxConcurrentPerNode);
    }

    /** Takes a permit when one is free, without waiting. */
    public boolean tryAcquire() {
        return permits.tryAcquire();
    }

    /** Returns a permit taken by {@link #tryAcquire()}. */
    public void release() {
        permits.release();
    }
}
