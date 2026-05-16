package com.czertainly.core.model.signing.timequality;

import java.time.Duration;
import java.util.List;
import java.util.UUID;

public final class ExplicitTimeQualityConfigurationBuilder {

    private UUID uuid;
    private String name;
    private Duration accuracy;
    private List<String> ntpServers;
    private Duration ntpCheckInterval;
    private Integer ntpSamplesPerServer;
    private Duration ntpCheckTimeout;
    private Integer ntpServersMinReachable;
    private Duration maxClockDrift;
    private Boolean leapSecondGuard;

    public static ExplicitTimeQualityConfigurationBuilder anExplicitTimeQualityConfiguration() {
        return new ExplicitTimeQualityConfigurationBuilder();
    }

    public static ExplicitTimeQualityConfiguration valid(String name) {
        return anExplicitTimeQualityConfiguration().withDefaults().name(name).build();
    }

    public ExplicitTimeQualityConfigurationBuilder withDefaults() {
        uuid = UUID.fromString("00000000-0000-0000-0000-000000000001");
        name = "rfc3161";
        accuracy = Duration.ofMinutes(5);
        ntpServers = List.of("pool.ntp.org");
        ntpCheckInterval = Duration.ofMinutes(5);
        ntpSamplesPerServer = 3;
        ntpCheckTimeout = Duration.ofSeconds(5);
        ntpServersMinReachable = 1;
        maxClockDrift = Duration.ofMillis(500);
        leapSecondGuard = false;
        return this;
    }

    public ExplicitTimeQualityConfigurationBuilder uuid(UUID uuid) {
        this.uuid = uuid;
        return this;
    }

    public ExplicitTimeQualityConfigurationBuilder name(String name) {
        this.name = name;
        return this;
    }

    public ExplicitTimeQualityConfigurationBuilder accuracy(Duration accuracy) {
        this.accuracy = accuracy;
        return this;
    }

    public ExplicitTimeQualityConfigurationBuilder ntpServers(List<String> ntpServers) {
        this.ntpServers = ntpServers;
        return this;
    }

    public ExplicitTimeQualityConfigurationBuilder ntpCheckInterval(Duration ntpCheckInterval) {
        this.ntpCheckInterval = ntpCheckInterval;
        return this;
    }

    public ExplicitTimeQualityConfigurationBuilder ntpSamplesPerServer(Integer ntpSamplesPerServer) {
        this.ntpSamplesPerServer = ntpSamplesPerServer;
        return this;
    }

    public ExplicitTimeQualityConfigurationBuilder ntpCheckTimeout(Duration ntpCheckTimeout) {
        this.ntpCheckTimeout = ntpCheckTimeout;
        return this;
    }

    public ExplicitTimeQualityConfigurationBuilder ntpServersMinReachable(Integer ntpServersMinReachable) {
        this.ntpServersMinReachable = ntpServersMinReachable;
        return this;
    }

    public ExplicitTimeQualityConfigurationBuilder maxClockDrift(Duration maxClockDrift) {
        this.maxClockDrift = maxClockDrift;
        return this;
    }

    public ExplicitTimeQualityConfigurationBuilder leapSecondGuard(Boolean leapSecondGuard) {
        this.leapSecondGuard = leapSecondGuard;
        return this;
    }

    public ExplicitTimeQualityConfiguration build() {
        return new ExplicitTimeQualityConfiguration(uuid, name, accuracy, ntpServers, ntpCheckInterval,
                ntpSamplesPerServer, ntpCheckTimeout, ntpServersMinReachable, maxClockDrift, leapSecondGuard);
    }
}
