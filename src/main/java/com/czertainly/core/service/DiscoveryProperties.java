package com.czertainly.core.service;

import org.springframework.boot.context.properties.ConfigurationProperties;

@ConfigurationProperties(prefix = "discovery.provider")
public record DiscoveryProperties(
        int maxCertificatesPerPage,
        int maxParallelism,
        int sleepTimeMs,
        long maxWaitTimeSeconds
) {

    public DiscoveryProperties {
        if (maxCertificatesPerPage <= 0) maxCertificatesPerPage = 100;
        if (maxParallelism <= 0) maxParallelism = 5;
        if (sleepTimeMs <= 0) sleepTimeMs = 5000;
        if (maxWaitTimeSeconds <= 0) maxWaitTimeSeconds = 21600;
    }

}
