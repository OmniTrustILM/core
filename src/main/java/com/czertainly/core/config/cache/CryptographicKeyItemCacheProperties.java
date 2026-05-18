package com.czertainly.core.config.cache;

import org.springframework.boot.context.properties.ConfigurationProperties;

@ConfigurationProperties(prefix = "caching.crypto-keys")
public record CryptographicKeyItemCacheProperties(
        int ttlMinutes,
        int maxSize
) {

    public CryptographicKeyItemCacheProperties {
        if (ttlMinutes <= 0) ttlMinutes = 5;
        if (maxSize <= 0) maxSize = 10000;
    }
}
