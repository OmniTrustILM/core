package com.otilm.core.config.cache;

import jakarta.validation.constraints.Min;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.validation.annotation.Validated;

@Validated
@ConfigurationProperties(prefix = "caching.time-quality-configs")
public record TimeQualityConfigurationCacheProperties(
        @Min(1) int ttlMinutes,
        @Min(1) int maxSize
) {
}
