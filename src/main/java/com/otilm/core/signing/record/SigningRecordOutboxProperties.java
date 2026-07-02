package com.otilm.core.signing.record;

import jakarta.validation.constraints.Min;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.validation.annotation.Validated;

/**
 * Outbox drain tuning. {@code flushIntervalMs} is the drain cadence consumed by
 * {@link SigningRecordOutboxDrainScheduler}'s {@code @Scheduled} placeholder — an annotation constant resolves
 * it directly from the property source, so it is modelled here only as the typed, validated home for the key.
 */
@Validated
@ConfigurationProperties(prefix = "signing-record.outbox")
public record SigningRecordOutboxProperties(
        @Min(1) long flushIntervalMs,
        @Min(1) int maxBatchSize,
        @Min(1) int maxBatchesPerRun,
        @Min(1) int poisonThreshold
) {
}
