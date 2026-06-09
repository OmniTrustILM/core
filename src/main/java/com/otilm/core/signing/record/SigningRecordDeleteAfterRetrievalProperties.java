package com.otilm.core.signing.record;

import jakarta.validation.constraints.Min;
import jakarta.validation.constraints.NotBlank;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.validation.annotation.Validated;

/**
 * Delete-after-retrieval fallback-sweep tuning. {@code maxBatchesPerSweep} of 0 disables the sweep (see
 * {@link SigningRecordRetrievalHook#runFallbackSweep()}), hence {@code @Min(0)}. {@code fallbackCron} is the
 * cron consumed by {@link SigningRecordRetrievalDeletionScheduler}'s {@code @Scheduled} placeholder — an
 * annotation constant resolves it directly from the property source, so it is modelled here only as the typed,
 * validated home for the key.
 */
@Validated
@ConfigurationProperties(prefix = "signing-record.delete-after-retrieval")
public record SigningRecordDeleteAfterRetrievalProperties(
        @NotBlank String fallbackCron,
        @Min(1) int batchSize,
        @Min(0) int maxBatchesPerSweep
) {
}
