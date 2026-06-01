package com.czertainly.core.config.cache;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.cache.Cache;
import org.springframework.cache.CacheManager;
import org.springframework.stereotype.Component;
import org.springframework.transaction.support.TransactionSynchronization;
import org.springframework.transaction.support.TransactionSynchronizationManager;

/**
 * Spring-managed helper for transaction-safe cache invalidation.
 *
 * <p>When a transaction is active, invalidation is deferred to {@code afterCommit} so a rollback leaves the
 * cache intact. Full clears ({@link #clear}) are deduped per cache name per transaction — bulk operations
 * that trigger multiple mutations result in at most one {@code cache.clear()} call per cache. Key-level
 * evictions ({@link #evict}) are not deduped because they target distinct entries.
 */
@Component
public class CacheEvictor {

    private CacheManager cacheManager;

    @Autowired
    public void setCacheManager(CacheManager cacheManager) {
        this.cacheManager = cacheManager;
    }

    /**
     * Evicts a single key from the named cache. Safe to call inside or outside a transaction.
     */
    public void evict(String cacheName, Object key) {
        Cache cache = cacheManager.getCache(cacheName);
        if (cache == null) return;
        if (TransactionSynchronizationManager.isActualTransactionActive()) {
            TransactionSynchronizationManager.registerSynchronization(new TransactionSynchronization() {
                @Override
                public void afterCommit() {
                    cache.evict(key);
                }
            });
        } else {
            cache.evict(key);
        }
    }

    /**
     * Clears the entire named cache. Safe to call inside or outside a transaction.
     */
    public void clear(String cacheName) {
        Cache cache = cacheManager.getCache(cacheName);
        if (cache == null) return;
        if (TransactionSynchronizationManager.isActualTransactionActive()) {
            boolean alreadyPending = TransactionSynchronizationManager.getSynchronizations()
                    .stream()
                    .filter(CacheEvictionSync.class::isInstance)
                    .map(CacheEvictionSync.class::cast)
                    .anyMatch(s -> s.cacheName.equals(cacheName));
            if (!alreadyPending) {
                TransactionSynchronizationManager.registerSynchronization(new CacheEvictionSync(cacheName, cache));
            }
        } else {
            cache.clear();
        }
    }

    private record CacheEvictionSync(String cacheName, Cache cache) implements TransactionSynchronization {
        @Override
        public void afterCommit() {
            cache.clear();
        }
    }
}
