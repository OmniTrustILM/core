package com.czertainly.core.config;

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
@EnableConfigurationProperties(AuthCacheProperties.class)
public class CacheConfig {

    public static final String SIGNING_PROFILES_CACHE = "signingProfiles";
    public static final String TSP_PROFILES_CACHE = "tspProfiles";
    public static final String CERTIFICATE_CHAIN_CACHE = "certificateChain";
    public static final String SYSTEM_USER_AUTH_CACHE = "systemUserAuth";
    public static final String USER_UUID_AUTH_CACHE = "userUuidAuth";
    public static final String CERTIFICATE_AUTH_CACHE = "certificateAuth";
    public static final String TOKEN_AUTH_CACHE = "tokenAuth";
    public static final String FORMATTER_CONNECTOR_CACHE = "formatterConnector";
    public static final String CRYPTOGRAPHIC_KEY_ITEM_CACHE = "cryptographicKeyItem";

    @Bean
    public CacheManager cacheManager(AuthCacheProperties cacheProperties, TokenJtiIndex tokenJtiIndex, UserCertificateIndex userCertificateIndex) {
        CaffeineCacheManager mgr = new CaffeineCacheManager(SIGNING_PROFILES_CACHE, TSP_PROFILES_CACHE, CERTIFICATE_CHAIN_CACHE, SYSTEM_USER_AUTH_CACHE, USER_UUID_AUTH_CACHE, FORMATTER_CONNECTOR_CACHE, CRYPTOGRAPHIC_KEY_ITEM_CACHE);
        mgr.setCaffeine(Caffeine.newBuilder()
                .expireAfterWrite(cacheProperties.ttlMinutes(), TimeUnit.MINUTES)
                .maximumSize(cacheProperties.maxSize())
                .recordStats());
        mgr.registerCustomCache(CERTIFICATE_AUTH_CACHE, Caffeine.newBuilder()
                .expireAfterWrite(cacheProperties.ttlMinutes(), TimeUnit.MINUTES)
                .maximumSize(cacheProperties.maxSize())
                .recordStats()
                .removalListener(userCertificateIndex)
                .build());
        mgr.registerCustomCache(TOKEN_AUTH_CACHE, Caffeine.newBuilder()
                .expireAfterWrite(cacheProperties.ttlMinutes(), TimeUnit.MINUTES)
                .maximumSize(cacheProperties.maxSize())
                .recordStats()
                .removalListener(tokenJtiIndex)
                .build());
        return mgr;
    }
}
