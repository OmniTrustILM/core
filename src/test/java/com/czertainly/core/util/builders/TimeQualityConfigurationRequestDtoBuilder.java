package com.czertainly.core.util.builders;

import com.otilm.api.model.client.signing.timequality.TimeQualityConfigurationRequestDto;

import java.time.Duration;
import java.util.List;

public class TimeQualityConfigurationRequestDtoBuilder {

    private String name = "test-tqc";
    private Duration accuracy = Duration.ofSeconds(1);
    private List<String> ntpServers = List.of("pool.ntp.org", "time.google.com");
    private Duration ntpCheckInterval = Duration.ofSeconds(30);
    private int ntpSamplesPerServer = 4;
    private Duration ntpCheckTimeout = Duration.ofSeconds(5);
    private int ntpServersMinReachable = 1;
    private Duration maxClockDrift = Duration.ofSeconds(1);
    private boolean leapSecondGuard = true;

    public static TimeQualityConfigurationRequestDtoBuilder aTimeQualityConfigurationRequest() {
        return new TimeQualityConfigurationRequestDtoBuilder();
    }

    public TimeQualityConfigurationRequestDtoBuilder withName(String name) {
        this.name = name;
        return this;
    }

    public TimeQualityConfigurationRequestDtoBuilder withAccuracy(Duration accuracy) {
        this.accuracy = accuracy;
        return this;
    }

    public TimeQualityConfigurationRequestDtoBuilder withNtpServers(List<String> ntpServers) {
        this.ntpServers = ntpServers;
        return this;
    }

    public TimeQualityConfigurationRequestDtoBuilder withNtpCheckInterval(Duration interval) {
        this.ntpCheckInterval = interval;
        return this;
    }

    public TimeQualityConfigurationRequestDtoBuilder withNtpSamplesPerServer(int samples) {
        this.ntpSamplesPerServer = samples;
        return this;
    }

    public TimeQualityConfigurationRequestDtoBuilder withNtpCheckTimeout(Duration timeout) {
        this.ntpCheckTimeout = timeout;
        return this;
    }

    public TimeQualityConfigurationRequestDtoBuilder withNtpServersMinReachable(int min) {
        this.ntpServersMinReachable = min;
        return this;
    }

    public TimeQualityConfigurationRequestDtoBuilder withMaxClockDrift(Duration drift) {
        this.maxClockDrift = drift;
        return this;
    }

    public TimeQualityConfigurationRequestDtoBuilder withLeapSecondGuard(boolean guard) {
        this.leapSecondGuard = guard;
        return this;
    }

    public TimeQualityConfigurationRequestDto build() {
        TimeQualityConfigurationRequestDto dto = new TimeQualityConfigurationRequestDto();
        dto.setName(name);
        dto.setAccuracy(accuracy);
        dto.setNtpServers(ntpServers);
        dto.setNtpCheckInterval(ntpCheckInterval);
        dto.setNtpSamplesPerServer(ntpSamplesPerServer);
        dto.setNtpCheckTimeout(ntpCheckTimeout);
        dto.setNtpServersMinReachable(ntpServersMinReachable);
        dto.setMaxClockDrift(maxClockDrift);
        dto.setLeapSecondGuard(leapSecondGuard);
        return dto;
    }
}
