package com.czertainly.core.config.cache;

import org.springframework.cache.Cache;
import org.springframework.transaction.support.TransactionSynchronization;
import org.springframework.transaction.support.TransactionSynchronizationManager;

/**
 * Helpers for cache eviction that respects transaction boundaries.
 *
 * <p>When a transaction is active the eviction is deferred to {@code afterCommit}, so the cache
 * entry survives until the mutating transaction commits and a concurrent reader cannot repopulate
 * it with not-yet-committed data. Outside a transaction the eviction happens immediately.
 */
public final class CacheEvictions {

    private CacheEvictions() {
    }

    /** Evict a single key. No-op when {@code cache} is {@code null}. */
    public static void evictAfterCommit(Cache cache, Object key) {
        if (cache == null) return;
        runAfterCommit(() -> cache.evict(key));
    }

    /** Clear the whole cache. No-op when {@code cache} is {@code null}. */
    public static void clearAfterCommit(Cache cache) {
        if (cache == null) return;
        runAfterCommit(cache::clear);
    }

    private static void runAfterCommit(Runnable eviction) {
        if (TransactionSynchronizationManager.isActualTransactionActive()) {
            TransactionSynchronizationManager.registerSynchronization(new TransactionSynchronization() {
                @Override
                public void afterCommit() {
                    eviction.run();
                }
            });
        } else {
            eviction.run();
        }
    }
}
