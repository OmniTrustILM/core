package com.czertainly.core.aop;

import com.czertainly.core.config.cache.CacheConfig;
import com.czertainly.core.config.cache.CacheEvictor;
import com.czertainly.core.dao.repository.CryptographicKeyItemRepository;
import com.czertainly.core.dao.repository.CryptographicKeyRepository;
import org.aspectj.lang.annotation.AfterReturning;
import org.aspectj.lang.annotation.Aspect;
import org.aspectj.lang.annotation.Pointcut;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

/**
 * Evicts the signing-certificate cache after any mutation on {@link CryptographicKeyRepository}
 * or {@link CryptographicKeyItemRepository}.
 *
 * <p>{@link com.czertainly.core.model.signing.SigningCertificate} caches key-level structural
 * references ({@code tokenInstanceReferenceUuid}, {@code tokenProfileUuid}, {@code keyItemUuids})
 * derived from the associated {@link com.czertainly.core.dao.entity.CryptographicKey}. When the
 * key is mutated (e.g. token-profile reassignment via
 * {@link com.czertainly.core.service.impl.CryptographicKeyServiceImpl#editKey}), those cached
 * values become stale and must be cleared.
 *
 * <p>Only {@link CacheConfig#SIGNING_CERTIFICATE_CACHE} is cleared — key mutations do not
 * affect the certificate chain.
 */
@Aspect
@Component
public class CryptographicKeyRepositoryCacheEvictionAspect {

    private CacheEvictor cacheEvictor;

    @Autowired
    public void setCacheEvictor(CacheEvictor cacheEvictor) {
        this.cacheEvictor = cacheEvictor;
    }

    @Pointcut("(target(com.czertainly.core.dao.repository.CryptographicKeyRepository+) "
            + "|| target(com.czertainly.core.dao.repository.CryptographicKeyItemRepository+)) "
            + "&& (execution(* save*(..)) || execution(* delete*(..)) || execution(* insert*(..)) "
            + "|| execution(* update*(..)) || execution(* clear*(..)))")
    private void cryptographicKeyMutation() {}

    @AfterReturning("cryptographicKeyMutation()")
    public void onMutation() {
        cacheEvictor.clear(CacheConfig.SIGNING_CERTIFICATE_CACHE);
    }
}
