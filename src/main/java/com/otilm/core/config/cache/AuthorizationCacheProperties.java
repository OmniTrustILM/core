package com.otilm.core.config.cache;

import jakarta.validation.constraints.Min;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.validation.annotation.Validated;

@Validated
@ConfigurationProperties(prefix = "caching.authorization")
public record AuthorizationCacheProperties(boolean enabled, @Min(1) int ttlMinutes, @Min(1) int resourceMaxSize,
        @Min(1) int objectMaxSize, @Min(1) int principalDigestMaxSize) {
}
