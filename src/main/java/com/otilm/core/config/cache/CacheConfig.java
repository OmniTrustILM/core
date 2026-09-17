package com.otilm.core.config.cache;

import com.github.benmanes.caffeine.cache.Caffeine;
import com.otilm.core.security.authn.client.SecretRefIndex;
import com.otilm.core.security.authn.client.TokenJtiIndex;
import com.otilm.core.security.authn.client.UserCertificateIndex;
import java.util.concurrent.TimeUnit;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.cache.CacheManager;
import org.springframework.cache.annotation.EnableCaching;
import org.springframework.cache.caffeine.CaffeineCacheManager;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.Ordered;

@Configuration
@EnableCaching(order = Ordered.HIGHEST_PRECEDENCE)
@EnableConfigurationProperties({
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

    public static final String CERTIFICATE_AUTH_CACHE = "certificateAuth";
    public static final String CERTIFICATE_CHAIN_CACHE = "certificateChain";
    public static final String CONNECTOR_API_CLIENT_CACHE = "connectorApiClient";
    public static final String CREDENTIAL_VERIFICATION_CACHE = "credentialVerification";
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
            CryptographicKeyItemCacheProperties cryptographicKeyItemCacheProperties, SecretRefIndex secretRefIndex,
            SigningCertificateCacheProperties signingCertificateCacheProperties,
            SigningProfileCacheProperties signingProfileCacheProperties,
            TimeQualityConfigurationCacheProperties tqcCacheProperties, TokenJtiIndex tokenJtiIndex,
            TspProfileCacheProperties tspProfileCacheProperties, UserCertificateIndex userCertificateIndex) {
        warnIfAuthorizationTtlExceedsAuthenticationTtl(authCacheProperties, authorizationCacheProperties);
        CaffeineCacheManager mgr = new CaffeineCacheManager(SYSTEM_USER_AUTH_CACHE, USER_UUID_AUTH_CACHE);
        mgr
                .setCaffeine(Caffeine
                        .newBuilder()
                        .expireAfterWrite(authCacheProperties.ttlMinutes(), TimeUnit.MINUTES)
                        .maximumSize(authCacheProperties.maxSize())
                        .recordStats());
        mgr
                .registerCustomCache(CERTIFICATE_AUTH_CACHE,
                        Caffeine
                                .newBuilder()
                                .expireAfterWrite(authCacheProperties.ttlMinutes(), TimeUnit.MINUTES)
                                .maximumSize(authCacheProperties.maxSize())
                                .recordStats()
                                .removalListener(userCertificateIndex)
                                .build());
        mgr
                .registerCustomCache(TOKEN_AUTH_CACHE,
                        Caffeine
                                .newBuilder()
                                .expireAfterWrite(authCacheProperties.ttlMinutes(), TimeUnit.MINUTES)
                                .maximumSize(authCacheProperties.maxSize())
                                .recordStats()
                                .removalListener(tokenJtiIndex)
                                .build());
        mgr
                .registerCustomCache(CREDENTIAL_VERIFICATION_CACHE,
                        Caffeine
                                .newBuilder()
                                .expireAfterWrite(authCacheProperties.ttlMinutes(), TimeUnit.MINUTES)
                                .maximumSize(authCacheProperties.maxSize())
                                .recordStats()
                                .removalListener(secretRefIndex)
                                .build());

        mgr
                .registerCustomCache(CERTIFICATE_CHAIN_CACHE,
                        Caffeine
                                .newBuilder()
                                .expireAfterWrite(certChainProperties.ttlMinutes(), TimeUnit.MINUTES)
                                .maximumSize(certChainProperties.maxSize())
                                .recordStats()
                                .build());

        mgr
                .registerCustomCache(CONNECTOR_API_CLIENT_CACHE,
                        Caffeine
                                .newBuilder()
                                .expireAfterWrite(connectorCacheProperties.ttlMinutes(), TimeUnit.MINUTES)
                                .maximumSize(connectorCacheProperties.maxSize())
                                .recordStats()
                                .build());

        mgr
                .registerCustomCache(CRYPTOGRAPHIC_KEY_ITEM_CACHE,
                        Caffeine
                                .newBuilder()
                                .expireAfterWrite(cryptographicKeyItemCacheProperties.ttlMinutes(), TimeUnit.MINUTES)
                                .maximumSize(cryptographicKeyItemCacheProperties.maxSize())
                                .recordStats()
                                .build());

        mgr
                .registerCustomCache(RESOURCE_AUTHZ_CACHE,
                        Caffeine
                                .newBuilder()
                                .expireAfterWrite(authorizationCacheProperties.ttlMinutes(), TimeUnit.MINUTES)
                                .maximumSize(authorizationCacheProperties.resourceMaxSize())
                                .recordStats()
                                .build());

        mgr
                .registerCustomCache(OBJECT_AUTHZ_CACHE,
                        Caffeine
                                .newBuilder()
                                .expireAfterWrite(authorizationCacheProperties.ttlMinutes(), TimeUnit.MINUTES)
                                .maximumSize(authorizationCacheProperties.objectMaxSize())
                                .recordStats()
                                .build());

        mgr
                .registerCustomCache(SIGNING_CERTIFICATE_CACHE,
                        Caffeine
                                .newBuilder()
                                .expireAfterWrite(signingCertificateCacheProperties.ttlMinutes(), TimeUnit.MINUTES)
                                .maximumSize(signingCertificateCacheProperties.maxSize())
                                .recordStats()
                                .build());

        mgr
                .registerCustomCache(SIGNING_PROFILE_CACHE,
                        Caffeine
                                .newBuilder()
                                .expireAfterWrite(signingProfileCacheProperties.ttlMinutes(), TimeUnit.MINUTES)
                                .maximumSize(signingProfileCacheProperties.maxSize())
                                .recordStats()
                                .build());

        mgr
                .registerCustomCache(TIME_QUALITY_CONFIGURATION_CACHE,
                        Caffeine
                                .newBuilder()
                                .expireAfterWrite(tqcCacheProperties.ttlMinutes(), TimeUnit.MINUTES)
                                .maximumSize(tqcCacheProperties.maxSize())
                                .recordStats()
                                .build());

        mgr
                .registerCustomCache(TSP_PROFILE_CACHE,
                        Caffeine
                                .newBuilder()
                                .expireAfterWrite(tspProfileCacheProperties.ttlMinutes(), TimeUnit.MINUTES)
                                .maximumSize(tspProfileCacheProperties.maxSize())
                                .recordStats()
                                .build());

        return mgr;
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
