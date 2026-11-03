package com.otilm.core.service.handler.key;

import com.otilm.core.attribute.engine.AttributeEngine;
import com.otilm.core.config.cache.CacheEvictor;
import com.otilm.core.util.cache.CacheManagerFixtures;
import org.springframework.cache.CacheManager;

/** A key operation cache over the configured caches. An adapter test sees what its operations would read again. */
public final class KeyOperationCacheFixtures {

    private KeyOperationCacheFixtures() {
    }

    public static KeyOperationCache keyOperationCache(AttributeEngine attributeEngine) {
        CacheManager cacheManager = CacheManagerFixtures.configured();
        CacheEvictor cacheEvictor = new CacheEvictor();
        cacheEvictor.setCacheManager(cacheManager);
        return new KeyOperationCache(attributeEngine, cacheManager, cacheEvictor);
    }
}
