package com.otilm.core.security.authz.opa;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.otilm.core.config.cache.AuthorizationCacheProperties;
import com.otilm.core.config.cache.CacheConfig;
import com.otilm.core.security.authz.opa.dto.OpaObjectAccessResult;
import com.otilm.core.security.authz.opa.dto.OpaRequestDetails;
import com.otilm.core.security.authz.opa.dto.OpaRequestedResource;
import com.otilm.core.security.authz.opa.dto.OpaResourceAccessResult;
import java.util.Objects;
import java.util.function.Supplier;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.springframework.cache.Cache;
import org.springframework.cache.CacheManager;
import org.springframework.stereotype.Component;

@Component
public class PlatformAuthorizationCache implements AuthorizationCache {

    private final Log logger = LogFactory.getLog(this.getClass());

    private final ObjectMapper om;
    private final AuthorizationCacheProperties properties;
    private final Cache resourceCache;
    private final Cache objectCache;
    private final Cache principalDigestCache;

    public PlatformAuthorizationCache(CacheManager cacheManager, ObjectMapper om,
            AuthorizationCacheProperties properties) {
        this.om = om;
        this.properties = properties;
        this.resourceCache = Objects.requireNonNull(cacheManager.getCache(CacheConfig.RESOURCE_AUTHZ_CACHE));
        this.objectCache = Objects.requireNonNull(cacheManager.getCache(CacheConfig.OBJECT_AUTHZ_CACHE));
        this.principalDigestCache = Objects.requireNonNull(cacheManager.getCache(CacheConfig.PRINCIPAL_DIGEST_CACHE));
    }

    @Override
    public OpaResourceAccessResult getOrCheckResourceAccess(String policyName, OpaRequestedResource resource,
            String principal, OpaRequestDetails details, Supplier<OpaResourceAccessResult> loader) {
        return getOrLoad(resourceCache, OpaResourceAccessResult.class, policyName, resource, principal, details,
                loader);
    }

    @Override
    public OpaObjectAccessResult getOrCheckObjectAccess(String policyName, OpaRequestedResource resource,
            String principal, OpaRequestDetails details, Supplier<OpaObjectAccessResult> loader) {
        return getOrLoad(objectCache, OpaObjectAccessResult.class, policyName, resource, principal, details, loader);
    }

    @Override
    public void evictAll() {
        resourceCache.clear();
        objectCache.clear();
    }

    private <T> T getOrLoad(Cache cache, Class<T> type, String policyName, OpaRequestedResource resource,
            String principal, OpaRequestDetails details, Supplier<T> loader) {
        if (!properties.enabled()) {
            return loader.get();
        }
        String key = key(policyName, resource, principal, details);
        if (key == null) {
            return loader.get();
        }
        Cache.ValueWrapper cached = cache.get(key);
        if (cached != null) {
            return type.cast(cached.get());
        }
        T result = loader.get();
        cache.put(key, result);
        return result;
    }

    /** Returns {@code null} when the request cannot be reduced to a key, which sends the caller straight to OPA. */
    private String key(String policyName, OpaRequestedResource resource, String principal, OpaRequestDetails details) {
        if (principal == null) {
            return null;
        }
        try {
            return AuthorizationCacheKeys
                    .decisionKey(policyName, principalDigest(principal), om.writeValueAsString(resource),
                            om.writeValueAsString(details));
        } catch (JsonProcessingException e) {
            logger.debug("Cannot derive an authorization cache key; the decision will be fetched from OPA.", e);
            return null;
        }
    }

    private String principalDigest(String principal) throws JsonProcessingException {
        Cache.ValueWrapper cached = principalDigestCache.get(principal);
        if (cached != null) {
            return (String) cached.get();
        }
        String digest = AuthorizationCacheKeys.principalDigest(om, principal);
        principalDigestCache.put(principal, digest);
        return digest;
    }
}
