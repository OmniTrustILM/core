package com.czertainly.core.signing.record;

import jakarta.validation.constraints.Min;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.validation.annotation.Validated;

@Validated
@ConfigurationProperties(prefix = "signing-record.best-effort")
public record SigningRecordBestEffortProperties(
        @Min(1) int queueCapacity,
        BestEffortBackpressurePolicy backpressurePolicy,
        @Min(1) long flushIntervalMs,
        @Min(1) int maxBatchSize
) {
}
