package com.otilm.core.config.cache;

import jakarta.validation.constraints.Min;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.validation.annotation.Validated;

/** Configuration for the {@link CacheConfig#ATTRIBUTE_SEARCH_FIELDS_CACHE}. */
@Validated
@ConfigurationProperties(prefix = "caching.attribute-search-fields")
public record AttributeSearchFieldsCacheProperties(@Min(1) int ttlMinutes, @Min(1) int maxSize) {
}
