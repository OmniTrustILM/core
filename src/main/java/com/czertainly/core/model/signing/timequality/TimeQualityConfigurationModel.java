package com.czertainly.core.model.signing.timequality;

import java.time.Duration;
import java.util.Optional;
import java.util.UUID;

/**
 * Sealed interface for all time-quality configuration model objects.
 *
 * <p>Use pattern matching to access variant-specific fields:</p>
 * <pre>{@code
 * switch (model) {
 *     case ExplicitTimeQualityConfiguration e -> e.ntpServers();
 *     case LocalClockTimeQualityConfiguration ignored -> /* use local clock *\/;
 * }
 * }</pre>
 */
public sealed interface TimeQualityConfigurationModel
        permits ExplicitTimeQualityConfiguration, LocalClockTimeQualityConfiguration {

    TimeQualitySource getSource();

    UUID getUuid();

    String getName();

    Optional<Duration> getAccuracy();
}
