package com.czertainly.core.signing.tsa.timequality;

public record NtpServerResult(
        String host,
        boolean reachable,
        Double offsetMs,
        Double rttMs,
        Integer stratum,
        Double precisionMs) {
}
