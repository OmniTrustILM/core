package com.czertainly.core.config.cache;

import jakarta.validation.constraints.Min;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.validation.annotation.Validated;

@Validated
@ConfigurationProperties(prefix = "caching.connectors")
public record ConnectorApiClientCacheProperties(
        @Min(1) int ttlMinutes,
        @Min(1) int maxSize
) {
}
