package com.otilm.core.config.cache;

import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

class CacheConfigTest {

    private static final AuthCacheProperties AUTHENTICATION_TTL_5 = new AuthCacheProperties(5, 500);

    @Test
    void certificateCacheUsesConfiguredExpireAfterWriteTtlAndCapacity() {
        var manager = new CacheConfig()
                .cacheManager(AUTHENTICATION_TTL_5, new AuthorizationCacheProperties(true, 5, 10, 10),
                        new CertificateChainCacheProperties(5, 10), new ConnectorApiClientCacheProperties(5, 10),
                        new CryptographicKeyItemCacheProperties(5, 10),
                        new com.otilm.core.security.authn.client.SecretRefIndex(),
                        new SigningCertificateCacheProperties(5, 10), new SigningProfileCacheProperties(5, 10),
                        new TimeQualityConfigurationCacheProperties(5, 10),
                        new com.otilm.core.security.authn.client.TokenJtiIndex(), new TspProfileCacheProperties(5, 10),
                        new com.otilm.core.security.authn.client.UserCertificateIndex(),
                        new AttributeSearchFieldsCacheProperties(5, 10));
        var certificateCache = (com.github.benmanes.caffeine.cache.Cache<?, ?>) manager
                .getCache(CacheConfig.CERTIFICATE_AUTH_CACHE)
                .getNativeCache();
        assertThat(certificateCache
                .policy()
                .expireAfterWrite()
                .orElseThrow()
                .getExpiresAfter(java.util.concurrent.TimeUnit.MINUTES)).isEqualTo(5);
        assertThat(certificateCache.policy().eviction().orElseThrow().getMaximum()).isEqualTo(500);
        assertThat(certificateCache.policy().expireAfterAccess()).isEmpty();
    }

    @Test
    void disabledAuthorizationCacheNeverWarnsAboutItsTtl() {
        AuthorizationCacheProperties disabledWithLongTtl = new AuthorizationCacheProperties(false, 60, 10, 10);

        assertThat(CacheConfig.authorizationTtlExceedsAuthenticationTtl(AUTHENTICATION_TTL_5, disabledWithLongTtl))
                .isFalse();
    }

    @Test
    void enabledAuthorizationCacheWarnsOnlyWhenItsTtlExceedsTheAuthenticationTtl() {
        AuthorizationCacheProperties longer = new AuthorizationCacheProperties(true, 6, 10, 10);
        AuthorizationCacheProperties equal = new AuthorizationCacheProperties(true, 5, 10, 10);

        assertThat(CacheConfig.authorizationTtlExceedsAuthenticationTtl(AUTHENTICATION_TTL_5, longer)).isTrue();
        assertThat(CacheConfig.authorizationTtlExceedsAuthenticationTtl(AUTHENTICATION_TTL_5, equal)).isFalse();
    }
}
