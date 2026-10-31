package com.otilm.core.security.authn.client;

import com.otilm.core.config.cache.CacheConfig;
import com.otilm.core.config.cache.ReadThroughCache;
import java.util.Set;
import java.util.UUID;
import java.util.function.Supplier;
import org.apache.commons.lang3.StringUtils;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.cache.CacheManager;
import org.springframework.stereotype.Component;

@Component
public class PlatformAuthenticationCache implements AuthenticationCache {

    private final TokenJtiIndex tokenJtiIndex;
    private final UserCertificateIndex userCertificateIndex;
    private final ReadThroughCache systemUserCache;
    private final ReadThroughCache userUuidCache;
    private final ReadThroughCache certCache;
    private final ReadThroughCache tokenCache;

    @Autowired
    public PlatformAuthenticationCache(CacheManager cacheManager, TokenJtiIndex tokenJtiIndex,
            UserCertificateIndex userCertificateIndex) {
        this.tokenJtiIndex = tokenJtiIndex;
        this.userCertificateIndex = userCertificateIndex;
        this.systemUserCache = ReadThroughCache.from(cacheManager, CacheConfig.SYSTEM_USER_AUTH_CACHE);
        this.userUuidCache = ReadThroughCache.from(cacheManager, CacheConfig.USER_UUID_AUTH_CACHE);
        this.certCache = ReadThroughCache.from(cacheManager, CacheConfig.CERTIFICATE_AUTH_CACHE);
        this.tokenCache = ReadThroughCache.from(cacheManager, CacheConfig.TOKEN_AUTH_CACHE);
    }

    @Override
    public AuthenticationInfo getOrAuthenticateSystemUser(String username, Supplier<AuthenticationInfo> loader) {
        return systemUserCache.getOrLoad(username, loader::get, PlatformAuthenticationCache::authenticated);
    }

    @Override
    public AuthenticationInfo getOrAuthenticateByUserUuid(UUID userUuid, Supplier<AuthenticationInfo> loader) {
        return userUuidCache.getOrLoad(userUuid, loader::get, PlatformAuthenticationCache::authenticated);
    }

    @Override
    public AuthenticationInfo getOrAuthenticateByCertificate(String thumbprint, Supplier<AuthenticationInfo> loader) {
        return certCache
                .getOrLoad(thumbprint, loader::get, PlatformAuthenticationCache::authenticated,
                        result -> userCertificateIndex.add(thumbprint, result));
    }

    @Override
    public AuthenticationInfo getOrAuthenticateByToken(String issuer, String jti, long settingsGeneration,
            Supplier<AuthenticationInfo> loader) {
        if (jti == null || StringUtils.isBlank(issuer)) {
            return loader.get();
        }
        String cacheKey = tokenCacheKey(issuer, jti, settingsGeneration);
        return tokenCache
                .getOrLoad(cacheKey, loader::get, PlatformAuthenticationCache::authenticated,
                        result -> tokenJtiIndex.add(cacheKey, result));
    }

    private static boolean authenticated(AuthenticationInfo result) {
        return !result.isAnonymous();
    }

    /**
     * Builds the token cache key as {@code generation:issuerLength:issuer:jti}. The generation is decimal digits and
     * therefore self-delimiting, but an issuer URL contains colons and slashes and a {@code jti} is an opaque string
     * chosen by the issuer, so a plain separator would let one (generation, issuer, jti) triple render as the key of
     * another - issuer {@code https://a} with {@code jti} {@code x:y} and issuer {@code https://a:x} with {@code jti}
     * {@code y} would collide. Prefixing the issuer with its character length makes the split deterministic: the digits
     * before the second colon give the issuer length, the next that many characters are the issuer, and everything
     * after the following colon is the {@code jti}. Every distinct triple therefore yields a distinct key.
     */
    private static String tokenCacheKey(String issuer, String jti, long settingsGeneration) {
        return settingsGeneration + ":" + issuer.length() + ":" + issuer + ":" + jti;
    }

    @Override
    public void evictByUserUuid(UUID userUuid) {
        userUuidCache.evict(userUuid);
        evictTokensByUserUuid(userUuid);
        evictCertificatesByUserUuid(userUuid);
    }

    @Override
    public void evictAll() {
        tokenJtiIndex.clear();
        userCertificateIndex.clear();
        systemUserCache.clear();
        userUuidCache.clear();
        certCache.clear();
        tokenCache.clear();
    }

    private void evictTokensByUserUuid(UUID userUuid) {
        tokenCache.evictInFlight();
        Set<String> jtis = tokenJtiIndex.removeUser(userUuid);
        if (jtis == null) {
            return;
        }
        jtis.forEach(tokenCache::evict);
    }

    private void evictCertificatesByUserUuid(UUID userUuid) {
        certCache.evictInFlight();
        Set<String> fingerprints = userCertificateIndex.removeUser(userUuid);
        if (fingerprints == null) {
            return;
        }
        fingerprints.forEach(certCache::evict);
    }

    @Override
    public void evictByCertificateFingerprint(String certFingerprint) {
        certCache.evict(certFingerprint);
    }
}
