package com.czertainly.core.security.authn.client;

import com.czertainly.core.config.CacheConfig;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.cache.Cache;
import org.springframework.cache.CacheManager;
import org.springframework.cache.annotation.Cacheable;
import org.springframework.stereotype.Component;

import java.util.Objects;
import java.util.Set;
import java.util.UUID;
import java.util.function.Supplier;

@Component
public class CzertainlyAuthenticationCache implements AuthenticationCache {

    private final CacheManager cacheManager;
    private final TokenJtiIndex tokenJtiIndex;
    private final UserCertificateIndex userCertificateIndex;
    private final Cache certCache;
    private final Cache tokenCache;

    @Autowired
    public CzertainlyAuthenticationCache(CacheManager cacheManager, TokenJtiIndex tokenJtiIndex, UserCertificateIndex userCertificateIndex) {
        this.cacheManager = cacheManager;
        this.tokenJtiIndex = tokenJtiIndex;
        this.userCertificateIndex = userCertificateIndex;
        this.certCache = Objects.requireNonNull(cacheManager.getCache(CacheConfig.CERTIFICATE_AUTH_CACHE));
        this.tokenCache = Objects.requireNonNull(cacheManager.getCache(CacheConfig.TOKEN_AUTH_CACHE));
    }

    @Override
    @Cacheable(value = CacheConfig.SYSTEM_USER_AUTH_CACHE, key = "#username", unless = "#result.anonymous")
    public AuthenticationInfo getOrAuthenticateSystemUser(String username, Supplier<AuthenticationInfo> loader) {
        return loader.get();
    }

    @Override
    @Cacheable(value = CacheConfig.USER_UUID_AUTH_CACHE, key = "#userUuid", unless = "#result.anonymous")
    public AuthenticationInfo getOrAuthenticateByUserUuid(UUID userUuid, Supplier<AuthenticationInfo> loader) {
        return loader.get();
    }

    // Manual caching (instead of @Cacheable) keeps userCertificateIndex in sync, enabling targeted
    // per-user certificate eviction via evictByUserUuid().
    @Override
    public AuthenticationInfo getOrAuthenticateByCertificate(String thumbprint, Supplier<AuthenticationInfo> loader) {
        Cache.ValueWrapper cached = certCache.get(thumbprint);
        if (cached != null) {
            return (AuthenticationInfo) cached.get();
        }
        AuthenticationInfo result = loader.get();
        if (!result.isAnonymous()) {
            certCache.put(thumbprint, result);
            userCertificateIndex.add(UUID.fromString(result.getUserUuid()), thumbprint);
        }
        return result;
    }

    // Manual caching (instead of @Cacheable) keeps tokenJtiIndex in sync, enabling targeted
    // per-user eviction via evictTokensByUserUuid().
    @Override
    public AuthenticationInfo getOrAuthenticateByToken(String jti, Supplier<AuthenticationInfo> loader) {
        if (jti == null) {
            return loader.get();
        }
        Cache.ValueWrapper cached = tokenCache.get(jti);
        if (cached != null) {
            return (AuthenticationInfo) cached.get();
        }
        AuthenticationInfo result = loader.get();
        if (!result.isAnonymous()) {
            tokenCache.put(jti, result);
            tokenJtiIndex.add(UUID.fromString(result.getUserUuid()), jti);
        }
        return result;
    }

    @Override
    public void evictByUserUuid(UUID userUuid) {
        Objects.requireNonNull(cacheManager.getCache(CacheConfig.USER_UUID_AUTH_CACHE)).evict(userUuid);
        evictTokensByUserUuid(userUuid);
        evictCertificateByUserUuid(userUuid);
    }

    @Override
    public void evictAll() {
        tokenJtiIndex.clear();
        userCertificateIndex.clear();
        Objects.requireNonNull(cacheManager.getCache(CacheConfig.SYSTEM_USER_AUTH_CACHE)).clear();
        Objects.requireNonNull(cacheManager.getCache(CacheConfig.USER_UUID_AUTH_CACHE)).clear();
        certCache.clear();
        tokenCache.clear();
    }

    // Looks up jtis for the user in the index and evicts each one from the token cache.
    // No-op if the user has no cached tokens.
    private void evictTokensByUserUuid(UUID userUuid) {
        Set<String> jtis = tokenJtiIndex.removeUser(userUuid);
        if (jtis == null) return;
        jtis.forEach(tokenCache::evict);
    }

    // Looks up the fingerprint for the user in the index and evicts it from the certificate cache.
    // No-op if the user has no cached certificate.
    private void evictCertificateByUserUuid(UUID userUuid) {
        String fingerprint = userCertificateIndex.removeUser(userUuid);
        if (fingerprint == null) return;
        certCache.evict(fingerprint);
    }

    @Override
    public void evictByCertificateFingerprint(String certFingerprint) {
        certCache.evict(certFingerprint);
    }
}
