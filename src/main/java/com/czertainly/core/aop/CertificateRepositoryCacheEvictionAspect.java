package com.czertainly.core.aop;

import com.czertainly.core.config.cache.CacheConfig;
import com.czertainly.core.config.cache.CacheEvictor;
import com.czertainly.core.dao.repository.CertificateRepository;
import org.aspectj.lang.annotation.AfterReturning;
import org.aspectj.lang.annotation.Aspect;
import org.aspectj.lang.annotation.Pointcut;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

/**
 * Evicts the certificate-chain and signing-certificate caches after any mutation on {@link CertificateRepository}.
 * The intercepted verb prefixes are declared in the {@link #certificateMutation()} pointcut below.
 *
 * <p><strong>Eviction strategy.</strong> Every matched mutation triggers a full {@code cache.clear()}
 * (deferred to {@code afterCommit} and deduped per transaction by {@link CacheEvictor}).
 * The conservative full-wipe was chosen. The cache is cheap to repopulate (a single recursive CTE per signing request)
 * and because issuer-rewiring mutations invalidate every chain whose path contains the affected certificate — without
 * a reverse index (ancestor UUID → set of cached leaf UUIDs maintained on cache put) the full clear is the only safe move.
 * Finer-grained eviction* becomes worth the bookkeeping under sustained write-heavy traffic (e.g. ACME/SCEP mass issuance
 * or upload), where every commit currently wipes the cache while signing traffic refills it — at that point a targeted eviction
 * on {@code cert.uuid + "_true"/"_false"} for single {@code save(Certificate)} calls plus a reverse index for issuer rewiring would pay off.
 * {@code deleteAllInBatch} and other bulk paths should retain the full wipe.
 */
@Aspect
@Component
public class CertificateRepositoryCacheEvictionAspect {

    private CacheEvictor cacheEvictor;

    @Autowired
    public void setCacheEvictor(CacheEvictor cacheEvictor) {
        this.cacheEvictor = cacheEvictor;
    }

    @Pointcut("target(com.czertainly.core.dao.repository.CertificateRepository+) "
            + "&& (execution(* save*(..)) || execution(* delete*(..)) || execution(* insert*(..)) "
            + "|| execution(* update*(..)) || execution(* clear*(..)) || execution(* archive*(..)) "
            + "|| execution(* set*(..)) || execution(* transition*(..)))")
    private void certificateMutation() {}

    @AfterReturning("certificateMutation()")
    public void onMutation() {
        cacheEvictor.clear(CacheConfig.CERTIFICATE_CHAIN_CACHE);
        cacheEvictor.clear(CacheConfig.SIGNING_CERTIFICATE_CACHE);
    }
}
