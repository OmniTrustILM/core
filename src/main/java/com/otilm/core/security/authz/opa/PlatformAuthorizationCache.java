package com.otilm.core.security.authz.opa;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.otilm.core.config.cache.AuthorizationCacheProperties;
import com.otilm.core.config.cache.CacheConfig;
import com.otilm.core.config.cache.ReadThroughCache;
import com.otilm.core.security.authz.opa.dto.OpaObjectAccessResult;
import com.otilm.core.security.authz.opa.dto.OpaRequestDetails;
import com.otilm.core.security.authz.opa.dto.OpaRequestedResource;
import com.otilm.core.security.authz.opa.dto.OpaResourceAccessResult;
import java.util.Objects;
import java.util.function.Supplier;
import java.util.function.UnaryOperator;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.springframework.cache.CacheManager;
import org.springframework.stereotype.Component;

@Component
public class PlatformAuthorizationCache implements AuthorizationCache {

    private final Log logger = LogFactory.getLog(this.getClass());

    private final ObjectMapper om;
    private final AuthorizationCacheProperties properties;
    private final ReadThroughCache resourceCache;
    private final ReadThroughCache objectCache;

    public PlatformAuthorizationCache(CacheManager cacheManager, ObjectMapper om,
            AuthorizationCacheProperties properties) {
        this.om = om;
        this.properties = properties;
        this.resourceCache = ReadThroughCache.from(cacheManager, CacheConfig.RESOURCE_AUTHZ_CACHE);
        this.objectCache = ReadThroughCache.from(cacheManager, CacheConfig.OBJECT_AUTHZ_CACHE);
    }

    @Override
    public OpaResourceAccessResult getOrCheckResourceAccess(String policyName, OpaRequestedResource resource,
            String principal, OpaRequestDetails details, Supplier<OpaResourceAccessResult> loader) {
        return checkThroughCache(resourceCache, OpaResourceAccessResult::new, policyName, resource, principal, details,
                loader);
    }

    @Override
    public OpaObjectAccessResult getOrCheckObjectAccess(String policyName, OpaRequestedResource resource,
            String principal, OpaRequestDetails details, Supplier<OpaObjectAccessResult> loader) {
        return checkThroughCache(objectCache, OpaObjectAccessResult::new, policyName, resource, principal, details,
                loader);
    }

    @Override
    public void evictAll() {
        resourceCache.clear();
        objectCache.clear();
    }

    private <T> T checkThroughCache(ReadThroughCache cache, UnaryOperator<T> copier, String policyName,
            OpaRequestedResource resource, String principal, OpaRequestDetails details, Supplier<T> loader) {
        if (!properties.enabled()) {
            return loader.get();
        }
        if (principal == null) {
            return loader.get();
        }
        String key = key(policyName, resource, principal, details);
        if (key == null) {
            return loader.get();
        }
        T result = cache.getOrLoad(key, loader::get, Objects::nonNull);
        return result == null ? null : copier.apply(result);
    }

    /** Returns {@code null} when the request cannot be reduced to a key, which sends the caller straight to OPA. */
    private String key(String policyName, OpaRequestedResource resource, String principal, OpaRequestDetails details) {
        try {
            return AuthorizationCacheKeys
                    .decisionKey(policyName, AuthorizationCacheKeys.principalDigest(om, principal),
                            AuthorizationCacheKeys.canonicalResourceJson(om, resource), om.writeValueAsString(details));
        } catch (JsonProcessingException | IllegalArgumentException e) {
            logger
                    .warn("Cannot derive an authorization cache key; the decision will be fetched from OPA and every "
                            + "further check of this shape will miss.", e);
            return null;
        }
    }
}
