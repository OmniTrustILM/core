package com.czertainly.core.config;

import org.springframework.boot.context.properties.ConfigurationProperties;

@ConfigurationProperties(prefix = "caching.authentication")
public record AuthCacheProperties(
        int ttlMinutes,
        int maxSize
) {

    public AuthCacheProperties {
        if (ttlMinutes <= 0) ttlMinutes = 5;
        if (maxSize <= 0) maxSize = 500;
    }
}
