package com.otilm.core.cbom.pqc;

import jakarta.validation.constraints.Min;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.validation.annotation.Validated;

/**
 * Re-evaluation sweep tuning. {@code maxBatchesPerSweep} of 0 disables the sweep, hence {@code @Min(0)}.
 *
 * <p>
 * <b>Deploy-time properties rather than Settings, deliberately.</b> The platform draws the line at policy versus
 * mechanics, twice on {@code main}: certificate validation's {@code enabled} and {@code frequency} are Settings while
 * the same flow's batch size is {@code @Value}, and the Settings cache's own refresh tick is yml. This sweep has no
 * policy knob -- "which rows are due" is the shipped {@link PqcRuleset#VERSION}, not an operator's risk appetite -- so
 * what is left is batching mechanics. What an operator can reach is the schedule itself, through the Scheduler API on
 * the system job, which is the pause/resume that actually matters under SaaS.
 */
@Validated
@ConfigurationProperties(prefix = "crypto-asset.pqc-sweep")
public record PqcSweepProperties(@Min(1) int batchSize, @Min(0) int maxBatchesPerSweep) {
}
