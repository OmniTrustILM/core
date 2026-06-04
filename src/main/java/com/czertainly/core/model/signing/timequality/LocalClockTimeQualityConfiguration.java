package com.czertainly.core.model.signing.timequality;

import java.time.Duration;
import java.util.Optional;
import java.util.UUID;

/**
 * Time-quality configuration variant representing the absence of any user-provided
 * configuration — the local system clock is used as-is.
 */
public enum LocalClockTimeQualityConfiguration implements TimeQualityConfigurationModel {

    INSTANCE;

    private static final String NAME = "LocalTime";
    private static final UUID LOCAL_UUID = UUID.fromString("00000000-0000-0000-0000-000000000000");

    @Override
    public String getName() {
        return NAME;
    }

    @Override
    public UUID getUuid() {
        return LOCAL_UUID;
    }

    @Override
    public Optional<Duration> getAccuracy() {
        return Optional.empty();
    }

    @Override
    public TimeQualitySource getSource() {
        return TimeQualitySource.LOCAL_CLOCK;
    }
}