package com.czertainly.core.signing.record;

import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import java.util.concurrent.ArrayBlockingQueue;

/**
 * Registers the signing-record configuration property records and wires the bounded in-memory queue that
 * {@link BestEffortSigningRecordStrategy} drains. Reading the capacity here keeps queue construction in one
 * place and lets the strategy stay agnostic of it — and lets tests construct the queue with a capacity they
 * can drive directly.
 */
@Configuration
@EnableConfigurationProperties({
        SigningRecordOutboxProperties.class,
        SigningRecordBestEffortProperties.class,
        SigningRecordRetentionProperties.class,
        SigningRecordDeleteAfterRetrievalProperties.class,
})
public class SigningRecordConfig {

    @Bean
    public BestEffortSigningRecordQueue bestEffortSigningRecordQueue(SigningRecordBestEffortProperties properties) {
        return new BestEffortSigningRecordQueue(new ArrayBlockingQueue<>(properties.queueCapacity()));
    }
}
