package com.otilm.core.config.cache;

import com.github.benmanes.caffeine.cache.Caffeine;
import com.otilm.core.security.authn.client.TokenJtiIndex;
import com.otilm.core.security.authn.client.UserCertificateIndex;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.TimeUnit;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.cache.CacheManager;
import org.springframework.cache.annotation.EnableCaching;
import org.springframework.cache.support.SimpleCacheManager;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.Ordered;

@Configuration
@EnableCaching(order = Ordered.HIGHEST_PRECEDENCE)
@EnableConfigurationProperties({
        AttributeSearchFieldsCacheProperties.class,
        AuthCacheProperties.class,
        AuthorizationCacheProperties.class,
        ConnectorApiClientCacheProperties.class,
        CertificateChainCacheProperties.class,
        CryptographicKeyItemCacheProperties.class,
        SigningCertificateCacheProperties.class,
        SigningProfileCacheProperties.class,
        TimeQualityConfigurationCacheProperties.class,
        TspProfileCacheProperties.class,})
public class CacheConfig {

    private static final Logger logger = LoggerFactory.getLogger(CacheConfig.class);

    public static final String ATTRIBUTE_SEARCH_FIELDS_CACHE = "attributeSearchFields";
    public static final String CERTIFICATE_AUTH_CACHE = "certificateAuth";
    public static final String CERTIFICATE_CHAIN_CACHE = "certificateChain";
    public static final String CONNECTOR_API_CLIENT_CACHE = "connectorApiClient";
    public static final String CRYPTOGRAPHIC_KEY_ITEM_CACHE = "cryptographicKeyItem";
    public static final String OBJECT_AUTHZ_CACHE = "objectAuthz";
    public static final String RESOURCE_AUTHZ_CACHE = "resourceAuthz";
    public static final String SIGNING_CERTIFICATE_CACHE = "signingCertificate";
    public static final String SIGNING_PROFILE_CACHE = "signingProfile";
    public static final String SYSTEM_USER_AUTH_CACHE = "systemUserAuth";
    public static final String TIME_QUALITY_CONFIGURATION_CACHE = "timeQualityConfiguration";
    public static final String TOKEN_AUTH_CACHE = "tokenAuth";
    public static final String TSP_PROFILE_CACHE = "tspProfile";
    public static final String USER_UUID_AUTH_CACHE = "userUuidAuth";

    @Bean
    public CacheManager cacheManager(AuthCacheProperties authCacheProperties,
            AuthorizationCacheProperties authorizationCacheProperties,
            CertificateChainCacheProperties certChainProperties,
            ConnectorApiClientCacheProperties connectorCacheProperties,
            CryptographicKeyItemCacheProperties cryptographicKeyItemCacheProperties,
            SigningCertificateCacheProperties signingCertificateCacheProperties,
            SigningProfileCacheProperties signingProfileCacheProperties,
            TimeQualityConfigurationCacheProperties tqcCacheProperties, TokenJtiIndex tokenJtiIndex,
            TspProfileCacheProperties tspProfileCacheProperties, UserCertificateIndex userCertificateIndex,
            AttributeSearchFieldsCacheProperties attributeSearchFieldsCacheProperties) {
        warnIfAuthorizationTtlExceedsAuthenticationTtl(authCacheProperties, authorizationCacheProperties);

        int authTtl = authCacheProperties.ttlMinutes();
        int authSize = authCacheProperties.maxSize();
        int authzTtl = authorizationCacheProperties.ttlMinutes();

        List<ReadThroughCache> caches = new ArrayList<>();
        caches.add(readThrough(SYSTEM_USER_AUTH_CACHE, boundedWithStats(authTtl, authSize)));
        caches.add(readThrough(USER_UUID_AUTH_CACHE, boundedWithStats(authTtl, authSize)));
        caches
                .add(readThrough(CERTIFICATE_AUTH_CACHE,
                        boundedWithStats(authTtl, authSize).removalListener(userCertificateIndex)));
        caches.add(readThrough(TOKEN_AUTH_CACHE, boundedWithStats(authTtl, authSize).removalListener(tokenJtiIndex)));
        caches
                .add(readThrough(CERTIFICATE_CHAIN_CACHE,
                        boundedWithStats(certChainProperties.ttlMinutes(), certChainProperties.maxSize())));
        caches
                .add(readThrough(CONNECTOR_API_CLIENT_CACHE,
                        boundedWithStats(connectorCacheProperties.ttlMinutes(), connectorCacheProperties.maxSize())));
        caches
                .add(readThrough(CRYPTOGRAPHIC_KEY_ITEM_CACHE,
                        boundedWithStats(cryptographicKeyItemCacheProperties.ttlMinutes(),
                                cryptographicKeyItemCacheProperties.maxSize())));
        caches
                .add(readThrough(RESOURCE_AUTHZ_CACHE,
                        boundedWithStats(authzTtl, authorizationCacheProperties.resourceMaxSize())));
        caches
                .add(readThrough(OBJECT_AUTHZ_CACHE,
                        boundedWithStats(authzTtl, authorizationCacheProperties.objectMaxSize())));
        caches
                .add(readThrough(SIGNING_CERTIFICATE_CACHE, boundedWithStats(
                        signingCertificateCacheProperties.ttlMinutes(), signingCertificateCacheProperties.maxSize())));
        caches
                .add(readThrough(SIGNING_PROFILE_CACHE, boundedWithStats(signingProfileCacheProperties.ttlMinutes(),
                        signingProfileCacheProperties.maxSize())));
        caches
                .add(readThrough(TIME_QUALITY_CONFIGURATION_CACHE,
                        boundedWithStats(tqcCacheProperties.ttlMinutes(), tqcCacheProperties.maxSize())));
        caches
                .add(readThrough(TSP_PROFILE_CACHE,
                        boundedWithStats(tspProfileCacheProperties.ttlMinutes(), tspProfileCacheProperties.maxSize())));
        caches
                .add(readThrough(ATTRIBUTE_SEARCH_FIELDS_CACHE,
                        boundedWithStats(attributeSearchFieldsCacheProperties.ttlMinutes(),
                                attributeSearchFieldsCacheProperties.maxSize())));
        SimpleCacheManager mgr = new SimpleCacheManager();
        mgr.setCaches(caches);
        mgr.initializeCaches();
        return mgr;
    }

    private static Caffeine<Object, Object> boundedWithStats(int ttlMinutes, int maxSize) {
        return Caffeine.newBuilder().expireAfterWrite(ttlMinutes, TimeUnit.MINUTES).maximumSize(maxSize).recordStats();
    }

    private static ReadThroughCache readThrough(String name, Caffeine<Object, Object> builder) {
        return new ReadThroughCache(name, builder.buildAsync());
    }

    // For authenticated callers authorization staleness is bounded by authentication staleness, but for
    // anonymous callers the authorization TTL is the only bound, so it must not exceed the authentication TTL.
    // A disabled cache serves nothing, so its TTL bounds nothing and there is nothing to warn about.
    static boolean authorizationTtlExceedsAuthenticationTtl(AuthCacheProperties authCacheProperties,
            AuthorizationCacheProperties authorizationCacheProperties) {
        return authorizationCacheProperties.enabled()
                && authorizationCacheProperties.ttlMinutes() > authCacheProperties.ttlMinutes();
    }

    private static void warnIfAuthorizationTtlExceedsAuthenticationTtl(AuthCacheProperties authCacheProperties,
            AuthorizationCacheProperties authorizationCacheProperties) {
        if (authorizationTtlExceedsAuthenticationTtl(authCacheProperties, authorizationCacheProperties)) {
            logger
                    .warn("caching.authorization.ttl-minutes ({}) exceeds caching.authentication.ttl-minutes ({}); "
                            + "anonymous callers may be served a stale authorization decision for longer than "
                            + "an authenticated caller's identity is trusted.",
                            authorizationCacheProperties.ttlMinutes(), authCacheProperties.ttlMinutes());
        }
    }
}
