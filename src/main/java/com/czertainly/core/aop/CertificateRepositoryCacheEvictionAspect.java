package com.czertainly.core.aop;

import com.czertainly.core.dao.repository.CertificateRepository;
import org.aspectj.lang.annotation.AfterReturning;
import org.aspectj.lang.annotation.Aspect;
import org.aspectj.lang.annotation.Pointcut;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

/**
 * Evicts the certificate-chain cache after any mutation on {@link CertificateRepository}.
 *
 * <p>Intercepts {@code save*}, {@code delete*} and {@code insert*} calls on {@link CertificateRepository} — covering
 * all Spring Data CRUD methods (save, saveAll, saveAndFlush, delete, deleteAll, deleteAllInBatch, etc.), the custom
 * {@code insertWithFingerprintConflictResolve} native upsert, and any future custom methods that follow the same naming convention.
 *
 * <p><strong>Eviction strategy.</strong> Every matched mutation triggers a full {@code cache.clear()}
 * (deferred to {@code afterCommit} and deduped per transaction by {@link CertificateChainCacheEvictor}).
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

    private CertificateChainCacheEvictor certChainCacheEvictor;

    @Autowired
    public void setCertChainCacheEvictor(CertificateChainCacheEvictor certChainCacheEvictor) {
        this.certChainCacheEvictor = certChainCacheEvictor;
    }

    @Pointcut("target(com.czertainly.core.dao.repository.CertificateRepository+) "
            + "&& (execution(* save*(..)) || execution(* delete*(..)) || execution(* insert*(..)))")
    private void certificateMutation() {}

    @AfterReturning("certificateMutation()")
    public void onMutation() {
        certChainCacheEvictor.evict();
    }
}
