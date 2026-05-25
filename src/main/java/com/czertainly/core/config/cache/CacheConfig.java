package com.czertainly.core.config.cache;

import com.czertainly.core.security.authn.client.TokenJtiIndex;
import com.czertainly.core.security.authn.client.UserCertificateIndex;
import com.github.benmanes.caffeine.cache.Caffeine;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.cache.CacheManager;
import org.springframework.cache.annotation.EnableCaching;
import org.springframework.cache.caffeine.CaffeineCacheManager;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.Ordered;

import java.util.concurrent.TimeUnit;

@Configuration
@EnableCaching(order = Ordered.HIGHEST_PRECEDENCE)
@EnableConfigurationProperties({
        AuthCacheProperties.class,
        ConnectorApiClientCacheProperties.class,
        CertificateChainCacheProperties.class,
        CryptographicKeyItemCacheProperties.class,
})
public class CacheConfig {

    public static final String CONNECTOR_API_CLIENT_CACHE = "connectorApiClient";
    public static final String CRYPTOGRAPHIC_KEY_ITEM_CACHE = "cryptographicKeyItem";
    public static final String SYSTEM_USER_AUTH_CACHE = "systemUserAuth";
    public static final String USER_UUID_AUTH_CACHE = "userUuidAuth";
    public static final String CERTIFICATE_AUTH_CACHE = "certificateAuth";
    public static final String TOKEN_AUTH_CACHE = "tokenAuth";
    public static final String CERTIFICATE_CHAIN_CACHE = "certificateChain";

    @Bean
    public CacheManager cacheManager(
            AuthCacheProperties authCacheProperties,
            CertificateChainCacheProperties certChainProperties,
            ConnectorApiClientCacheProperties connectorCacheProperties,
            CryptographicKeyItemCacheProperties cryptographicKeyItemCacheProperties,
            TokenJtiIndex tokenJtiIndex,
            UserCertificateIndex userCertificateIndex) {
        CaffeineCacheManager mgr = new CaffeineCacheManager(SYSTEM_USER_AUTH_CACHE, USER_UUID_AUTH_CACHE);
        mgr.setCaffeine(Caffeine.newBuilder()
                .expireAfterWrite(authCacheProperties.ttlMinutes(), TimeUnit.MINUTES)
                .maximumSize(authCacheProperties.maxSize())
                .recordStats());
        mgr.registerCustomCache(CERTIFICATE_AUTH_CACHE, Caffeine.newBuilder()
                .expireAfterWrite(authCacheProperties.ttlMinutes(), TimeUnit.MINUTES)
                .maximumSize(authCacheProperties.maxSize())
                .recordStats()
                .removalListener(userCertificateIndex)
                .build());
        mgr.registerCustomCache(TOKEN_AUTH_CACHE, Caffeine.newBuilder()
                .expireAfterWrite(authCacheProperties.ttlMinutes(), TimeUnit.MINUTES)
                .maximumSize(authCacheProperties.maxSize())
                .recordStats()
                .removalListener(tokenJtiIndex)
                .build());

        mgr.registerCustomCache(CERTIFICATE_CHAIN_CACHE, Caffeine.newBuilder()
                .expireAfterWrite(certChainProperties.ttlMinutes(), TimeUnit.MINUTES)
                .maximumSize(certChainProperties.maxSize())
                .recordStats()
                .build());

        mgr.registerCustomCache(CONNECTOR_API_CLIENT_CACHE, Caffeine.newBuilder()
                .expireAfterWrite(connectorCacheProperties.ttlMinutes(), TimeUnit.MINUTES)
                .maximumSize(connectorCacheProperties.maxSize())
                .recordStats()
                .build());

        mgr.registerCustomCache(CRYPTOGRAPHIC_KEY_ITEM_CACHE, Caffeine.newBuilder()
                .expireAfterWrite(cryptographicKeyItemCacheProperties.ttlMinutes(), TimeUnit.MINUTES)
                .maximumSize(cryptographicKeyItemCacheProperties.maxSize())
                .recordStats()
                .build());

        return mgr;
    }
}
