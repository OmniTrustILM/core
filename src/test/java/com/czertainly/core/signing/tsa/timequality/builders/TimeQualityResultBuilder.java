package com.czertainly.core.signing.tsa.timequality.builders;

import com.czertainly.api.model.messaging.timequality.LeapSecondWarning;
import com.czertainly.api.model.messaging.timequality.TimeQualityStatus;
import com.czertainly.core.signing.tsa.timequality.NtpServerResult;
import com.czertainly.core.signing.tsa.timequality.TimeQualityResult;

import java.time.Instant;
import java.util.List;
import java.util.UUID;

public final class TimeQualityResultBuilder {

    private static final UUID DEFAULT_UUID = UUID.fromString("00000000-0000-0000-0000-000000000001");

    private UUID configurationId;
    private String name;
    private Instant timestamp;
    private TimeQualityStatus status;
    private Double measuredDriftMs;
    private String reason;
    private int reachableServers;
    private LeapSecondWarning leapSecondWarning;
    private List<NtpServerResult> servers;

    public static TimeQualityResultBuilder aTimeQualityResult() {
        return new TimeQualityResultBuilder();
    }

    public TimeQualityResultBuilder withDefaults() {
        configurationId = DEFAULT_UUID;
        name = "rfc3161";
        timestamp = Instant.parse("2026-03-04T10:00:00Z");
        status = TimeQualityStatus.OK;
        measuredDriftMs = 0.;
        reachableServers = 3;
        leapSecondWarning = LeapSecondWarning.NONE;
        servers = List.of();
        return this;
    }

    public TimeQualityResultBuilder configurationId(UUID configurationId) {
        this.configurationId = configurationId;
        return this;
    }

    public TimeQualityResultBuilder name(String name) {
        this.name = name;
        return this;
    }

    public TimeQualityResultBuilder timestamp(Instant timestamp) {
        this.timestamp = timestamp;
        return this;
    }

    public TimeQualityResultBuilder status(TimeQualityStatus status) {
        this.status = status;
        return this;
    }

    public TimeQualityResultBuilder measuredDriftMs(Double measuredDriftMs) {
        this.measuredDriftMs = measuredDriftMs;
        return this;
    }

    public TimeQualityResultBuilder reason(String reason) {
        this.reason = reason;
        return this;
    }

    public TimeQualityResultBuilder reachableServers(int reachableServers) {
        this.reachableServers = reachableServers;
        return this;
    }

    public TimeQualityResultBuilder leapSecondWarning(LeapSecondWarning leapSecondWarning) {
        this.leapSecondWarning = leapSecondWarning;
        return this;
    }

    public TimeQualityResultBuilder servers(List<NtpServerResult> servers) {
        this.servers = servers;
        return this;
    }

    public TimeQualityResult build() {
        return new TimeQualityResult(
                configurationId,
                name,
                timestamp,
                status,
                measuredDriftMs,
                reachableServers,
                reason,
                leapSecondWarning,
                servers != null ? servers : List.of());
    }
}
