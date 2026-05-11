package com.czertainly.core.model.signing.timequality;

import java.time.Duration;
import java.util.List;
import java.util.Optional;
import java.util.UUID;

/**
 * Time-quality configuration explicitly provided by the user.
 *
 * @param uuid                   UUID of the underlying configuration entity.
 * @param name                   Human-readable name of the configuration.
 * @param accuracy               Required accuracy of the timestamp.
 * @param ntpServers             NTP servers used to verify clock quality.
 * @param ntpCheckInterval       Interval between NTP checks.
 * @param ntpSamplesPerServer    Number of samples taken per NTP server per check.
 * @param ntpCheckTimeout        Timeout for a single NTP check.
 * @param ntpServersMinReachable Minimum number of NTP servers that must be reachable.
 * @param maxClockDrift          Maximum tolerated drift of the local clock.
 * @param leapSecondGuard        Whether to guard against leap-second anomalies.
 */
public record ExplicitTimeQualityConfiguration(
        UUID uuid,
        String name,
        Duration accuracy,
        List<String> ntpServers,
        Duration ntpCheckInterval,
        Integer ntpSamplesPerServer,
        Duration ntpCheckTimeout,
        Integer ntpServersMinReachable,
        Duration maxClockDrift,
        Boolean leapSecondGuard
) implements TimeQualityConfigurationModel {

    @Override
    public TimeQualitySource getSource() {
        return TimeQualitySource.EXPLICIT;
    }

    @Override
    public UUID getUuid() {
        return uuid;
    }

    @Override
    public String getName() {
        return name;
    }

    @Override
    public Optional<Duration> getAccuracy() {
        return Optional.ofNullable(accuracy);
    }
}
