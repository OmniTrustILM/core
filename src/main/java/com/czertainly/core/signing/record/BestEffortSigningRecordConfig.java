package com.czertainly.core.signing.record;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import java.util.concurrent.ArrayBlockingQueue;

/**
 * Wires the bounded in-memory queue that {@link BestEffortSigningRecordStrategy} drains. Reading the capacity
 * config here keeps it in one place and lets the strategy stay agnostic of it — and lets tests construct the
 * queue with a capacity they can drive directly.
 */
@Configuration
public class BestEffortSigningRecordConfig {

    @Bean
    public BestEffortSigningRecordQueue bestEffortSigningRecordQueue(
            @Value("${signing-record.best-effort.queue-capacity:10000}") int capacity) {
        return new BestEffortSigningRecordQueue(new ArrayBlockingQueue<>(capacity));
    }
}
