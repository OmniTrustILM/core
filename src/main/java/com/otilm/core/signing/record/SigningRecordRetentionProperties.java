package com.otilm.core.signing.record;

import jakarta.validation.constraints.Min;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.validation.annotation.Validated;

/**
 * Retention sweep tuning. {@code maxBatchesPerSweep} of 0 disables the sweep (see
 * {@link SigningRecordRetentionSweeper#sweep()}), hence {@code @Min(0)}. {@code sweepIntervalMinutes} is the
 * sweep cadence consumed by {@link SigningRecordRetentionScheduler}'s {@code @Scheduled} placeholder — an
 * annotation constant resolves it directly from the property source, so it is modelled here only as the typed,
 * validated home for the key.
 */
@Validated
@ConfigurationProperties(prefix = "signing-record.retention")
public record SigningRecordRetentionProperties(
        @Min(1) int sweepIntervalMinutes,
        @Min(1) int batchSize,
        @Min(0) int maxBatchesPerSweep
) {
}
