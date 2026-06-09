package com.czertainly.core.signing.tsa.timequality;

import com.czertainly.api.model.messaging.timequality.LeapSecondWarning;
import com.czertainly.api.model.messaging.timequality.TimeQualityStatus;

import java.time.Instant;
import java.util.List;
import java.util.UUID;

public record TimeQualityResult(
        UUID configurationId,
        String name,
        Instant timestamp,
        TimeQualityStatus status,
        Double measuredDriftMs,
        int reachableServers,
        String reason,
        LeapSecondWarning leapSecondWarning,
        List<NtpServerResult> servers) {
}
