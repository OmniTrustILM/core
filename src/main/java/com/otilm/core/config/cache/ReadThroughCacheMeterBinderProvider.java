package com.otilm.core.config.cache;

import io.micrometer.core.instrument.Tag;
import io.micrometer.core.instrument.binder.MeterBinder;
import io.micrometer.core.instrument.binder.cache.CaffeineCacheMetrics;
import org.springframework.boot.cache.metrics.CacheMeterBinderProvider;
import org.springframework.stereotype.Component;

@Component
public class ReadThroughCacheMeterBinderProvider implements CacheMeterBinderProvider<ReadThroughCache> {

    @Override
    public MeterBinder getMeterBinder(ReadThroughCache cache, Iterable<Tag> tags) {
        return new CaffeineCacheMetrics<>(cache.getNativeCache().synchronous(), cache.getName(), tags);
    }
}
