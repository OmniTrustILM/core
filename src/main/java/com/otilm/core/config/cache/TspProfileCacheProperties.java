package com.otilm.core.config.cache;

import jakarta.validation.constraints.Min;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.validation.annotation.Validated;

/**
 * Configuration for the {@link CacheConfig#TSP_PROFILE_CACHE}.
 *
 * <p>Each TSP Profile is cached under two keys — its name (used by the protocol path {@code /tsp/{name}})
 * and its UUID (used by the signing-profile path). Size {@code maxSize} accordingly: a profile reached via
 * both paths occupies two entries, so the effective profile capacity is up to half of {@code maxSize}.</p>
 */
@Validated
@ConfigurationProperties(prefix = "caching.tsp-profiles")
public record TspProfileCacheProperties(
        @Min(1) int ttlMinutes,
        @Min(1) int maxSize
) {
}
