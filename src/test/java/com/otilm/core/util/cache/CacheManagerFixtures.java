package com.otilm.core.util.cache;

import com.github.benmanes.caffeine.cache.Caffeine;
import com.otilm.core.config.cache.AttributeSearchFieldsCacheProperties;
import com.otilm.core.config.cache.AuthCacheProperties;
import com.otilm.core.config.cache.AuthorizationCacheProperties;
import com.otilm.core.config.cache.CacheConfig;
import com.otilm.core.config.cache.CertificateChainCacheProperties;
import com.otilm.core.config.cache.ConnectorApiClientCacheProperties;
import com.otilm.core.config.cache.CryptographicKeyItemCacheProperties;
import com.otilm.core.config.cache.ReadThroughCache;
import com.otilm.core.config.cache.SigningCertificateCacheProperties;
import com.otilm.core.config.cache.SigningProfileCacheProperties;
import com.otilm.core.config.cache.TimeQualityConfigurationCacheProperties;
import com.otilm.core.config.cache.TspProfileCacheProperties;
import com.otilm.core.security.authn.client.TokenJtiIndex;
import com.otilm.core.security.authn.client.UserCertificateIndex;
import java.util.Arrays;
import org.springframework.cache.CacheManager;
import org.springframework.cache.support.SimpleCacheManager;

/** The cache manager {@link CacheConfig} builds, for tests that wire caching code by hand. */
public final class CacheManagerFixtures {

    private static final int TTL_MINUTES = 5;
    private static final int MAX_SIZE = 100;

    private CacheManagerFixtures() {
    }

    public static CacheManager configured() {
        return configured(new TokenJtiIndex(), new UserCertificateIndex());
    }

    /** The configured manager, with the indexes its authentication caches report their removals to. */
    public static CacheManager configured(TokenJtiIndex tokenJtiIndex, UserCertificateIndex userCertificateIndex) {
        return configured(MAX_SIZE, tokenJtiIndex, userCertificateIndex);
    }

    /** The configured manager, its authentication caches bounded to {@code authMaxSize} entries. */
    public static CacheManager configured(int authMaxSize, TokenJtiIndex tokenJtiIndex,
            UserCertificateIndex userCertificateIndex) {
        return new CacheConfig()
                .cacheManager(new AuthCacheProperties(TTL_MINUTES, authMaxSize),
                        new AuthorizationCacheProperties(true, TTL_MINUTES, MAX_SIZE, MAX_SIZE),
                        new CertificateChainCacheProperties(TTL_MINUTES, MAX_SIZE),
                        new ConnectorApiClientCacheProperties(TTL_MINUTES, MAX_SIZE),
                        new CryptographicKeyItemCacheProperties(TTL_MINUTES, MAX_SIZE),
                        new SigningCertificateCacheProperties(TTL_MINUTES, MAX_SIZE),
                        new SigningProfileCacheProperties(TTL_MINUTES, MAX_SIZE),
                        new TimeQualityConfigurationCacheProperties(TTL_MINUTES, MAX_SIZE), tokenJtiIndex,
                        new TspProfileCacheProperties(TTL_MINUTES, MAX_SIZE), userCertificateIndex,
                        new AttributeSearchFieldsCacheProperties(TTL_MINUTES, MAX_SIZE));
    }

    /** A manager of read-through caches built alike, for tests that control the caches' clock. */
    public static CacheManager readThrough(Caffeine<Object, Object> builder, String... names) {
        SimpleCacheManager manager = new SimpleCacheManager();
        manager.setCaches(Arrays.stream(names).map(name -> new ReadThroughCache(name, builder.buildAsync())).toList());
        manager.initializeCaches();
        return manager;
    }
}
