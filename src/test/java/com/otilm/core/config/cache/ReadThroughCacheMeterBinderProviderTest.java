package com.otilm.core.config.cache;

import com.github.benmanes.caffeine.cache.Caffeine;
import io.micrometer.core.instrument.simple.SimpleMeterRegistry;
import java.util.List;
import org.junit.jupiter.api.Test;
import org.springframework.boot.cache.metrics.CacheMetricsRegistrar;

import static org.assertj.core.api.Assertions.assertThat;

class ReadThroughCacheMeterBinderProviderTest {

    private static final String CACHE_NAME = "test";

    private final SimpleMeterRegistry registry = new SimpleMeterRegistry();

    @Test
    void theRegistrarBindsTheHitsAndMissesOfAReadThroughCache() {
        // given
        ReadThroughCache cache = new ReadThroughCache(CACHE_NAME, Caffeine.newBuilder().recordStats().buildAsync());
        CacheMetricsRegistrar registrar = new CacheMetricsRegistrar(registry,
                List.of(new ReadThroughCacheMeterBinderProvider()));

        // when
        boolean bound = registrar.bindCacheToRegistry(cache);
        cache.getOrLoad("key", () -> "value");
        cache.getOrLoad("key", () -> "value");

        // then
        assertThat(bound).isTrue();
        assertThat(gets("miss")).isEqualTo(1);
        assertThat(gets("hit")).isEqualTo(1);
    }

    private double gets(String result) {
        return registry.get("cache.gets").tags("cache", CACHE_NAME, "result", result).functionCounter().count();
    }
}
