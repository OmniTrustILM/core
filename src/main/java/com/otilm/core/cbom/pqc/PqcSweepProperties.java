package com.otilm.core.cbom.pqc;

import jakarta.validation.constraints.Min;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.validation.annotation.Validated;

/**
 * Sweep batching. {@code maxBatchesPerSweep} of 0 disables it, hence {@code @Min(0)}.
 *
 * <p>
 * Deploy-time rather than Settings because there is no policy knob here: which rows are due is
 * {@link PqcRuleset#VERSION}, not an operator's risk appetite. What an operator can reach is the schedule.
 */
@Validated
@ConfigurationProperties(prefix = "crypto-asset.pqc-sweep")
public record PqcSweepProperties(@Min(1) int batchSize, @Min(0) int maxBatchesPerSweep) {
}
