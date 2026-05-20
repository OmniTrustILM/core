package com.czertainly.core.aop;

import org.aspectj.lang.annotation.AfterReturning;
import org.aspectj.lang.annotation.Aspect;
import org.aspectj.lang.annotation.Pointcut;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

/**
 * Evicts the certificate-chain cache after any mutation on {@code CertificateRepository}.
 *
 * <p>Intercepts {@code save*}, {@code delete*} and {@code insert*} calls on the
 * {@code certificateRepository} Spring bean — covering all Spring Data CRUD methods (save, saveAll,
 * saveAndFlush, delete, deleteAll, deleteAllInBatch, etc.), the custom
 * {@code insertWithFingerprintConflictResolve} native upsert, and any future custom methods that
 * follow the same naming convention.
 */
@Aspect
@Component
public class CertificateRepositoryCacheEvictionAspect {

    @Autowired
    private CertificateChainCacheEvictor certChainCacheEvictor;

    @Pointcut("bean(certificateRepository) && (execution(* save*(..)) || execution(* delete*(..)) || execution(* insert*(..)))")
    private void certificateMutation() {}

    @AfterReturning("certificateMutation()")
    public void onMutation() {
        certChainCacheEvictor.evict();
    }
}
