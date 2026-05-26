package com.czertainly.core.aop;

import com.czertainly.core.config.cache.CacheConfig;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.cache.Cache;
import org.springframework.cache.CacheManager;
import org.springframework.stereotype.Component;
import org.springframework.transaction.support.TransactionSynchronization;
import org.springframework.transaction.support.TransactionSynchronizationManager;

/**
 * Spring-managed helper that clears the {@link CacheConfig#CERTIFICATE_CHAIN_CACHE certificate-chain
 * cache}. Invoked from {@link CertificateRepositoryCacheEvictionAspect} after any mutation on
 * {@code CertificateRepository}.
 *
 * <p>The chain cache stores parsed {@code X509Certificate} chains keyed by leaf UUID. Any change to a
 * {@code Certificate} row — an issuer link rewired, AIA-discovered ancestor inserted, certificate
 * deleted — can invalidate one or more cached chains. The eviction strategy is conservative
 * ({@code cache.clear()}): mutations that don't affect chain shape still wipe the whole cache, which
 * is acceptable because the cache is small and cheap to repopulate.
 *
 * <p>When a transaction is active, eviction is deferred to {@code afterCommit}, so a rollback leaves
 * the cache intact. At most one {@link CacheEvictionSync} is registered per transaction, so bulk
 * operations that trigger multiple mutations still result in a single {@code cache.clear()} call.
 */
@Component
public class CertificateChainCacheEvictor {

    private CacheManager cacheManager;

    @Autowired
    public void setCacheManager(CacheManager cacheManager) {
        this.cacheManager = cacheManager;
    }

    /**
     * Invalidates the certificate-chain cache. Safe to call inside or outside a transaction.
     */
    public void evict() {
        Cache cache = cacheManager.getCache(CacheConfig.CERTIFICATE_CHAIN_CACHE);
        if (cache == null) return;
        if (TransactionSynchronizationManager.isActualTransactionActive()) {
            boolean alreadyPending = TransactionSynchronizationManager.getSynchronizations()
                    .stream().anyMatch(CacheEvictionSync.class::isInstance);
            if (!alreadyPending) {
                TransactionSynchronizationManager.registerSynchronization(new CacheEvictionSync(cache));
            }
        } else {
            cache.clear();
        }
    }

    private static final class CacheEvictionSync implements TransactionSynchronization {
        private final Cache cache;

        CacheEvictionSync(Cache cache) {
            this.cache = cache;
        }

        @Override
        public void afterCommit() {
            cache.clear();
        }
    }
}
