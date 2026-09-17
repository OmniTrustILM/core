package com.otilm.core.security.authz.opa;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.github.benmanes.caffeine.cache.Caffeine;
import com.otilm.core.config.cache.AuthorizationCacheProperties;
import com.otilm.core.config.cache.CacheConfig;
import com.otilm.core.security.authz.opa.dto.OpaObjectAccessResult;
import com.otilm.core.security.authz.opa.dto.OpaRequestDetails;
import com.otilm.core.security.authz.opa.dto.OpaRequestedResource;
import com.otilm.core.security.authz.opa.dto.OpaResourceAccessResult;
import java.util.List;
import java.util.Map;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.function.Supplier;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.cache.caffeine.CaffeineCacheManager;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class PlatformAuthorizationCacheTest {

    private static final String PERMISSIONS = """
            {"allowAllResources":false,"resources":[\
            {"name":"certificates","allowAllActions":false,"actions":["detail"],"objects":[]}]}""";

    private static final OpaRequestDetails DETAILS = new OpaRequestDetails(null);

    private AtomicInteger loads;
    private PlatformAuthorizationCache cache;

    @BeforeEach
    void setUp() {
        loads = new AtomicInteger();
        cache = newCache(true);
    }

    private static PlatformAuthorizationCache newCache(boolean enabled) {
        CaffeineCacheManager mgr = new CaffeineCacheManager();
        mgr.registerCustomCache(CacheConfig.RESOURCE_AUTHZ_CACHE, Caffeine.newBuilder().maximumSize(100).build());
        mgr.registerCustomCache(CacheConfig.OBJECT_AUTHZ_CACHE, Caffeine.newBuilder().maximumSize(100).build());
        mgr.registerCustomCache(CacheConfig.PRINCIPAL_DIGEST_CACHE, Caffeine.newBuilder().maximumSize(100).build());
        return new PlatformAuthorizationCache(mgr, new ObjectMapper(),
                new AuthorizationCacheProperties(enabled, 5, 100, 100, 100));
    }

    private static String profile(String userUuid, String username) {
        return """
                {"user":{"uuid":"%s","username":"%s"},"roles":[],"permissions":%s}"""
                .formatted(userUuid, username, PERMISSIONS);
    }

    private static OpaRequestedResource certificateDetail() {
        return new OpaRequestedResource(Map.of("name", "certificates", "action", "detail"));
    }

    private OpaResourceAccessResult load() {
        loads.incrementAndGet();
        return new OpaResourceAccessResult(true, List.of("ActionAllowedOnResource"));
    }

    private OpaResourceAccessResult resourceAccess(String principal, OpaRequestedResource resource) {
        return cache.getOrCheckResourceAccess("method", resource, principal, DETAILS, this::load);
    }

    @Test
    void secondCallIsServedFromCache() {
        OpaResourceAccessResult first = resourceAccess(profile("1111", "alice"), certificateDetail());
        OpaResourceAccessResult second = resourceAccess(profile("1111", "alice"), certificateDetail());

        assertThat(loads).hasValue(1);
        assertThat(second).isSameAs(first);
    }

    @Test
    void differentUsersWithEqualPermissionsShareAnEntry() {
        resourceAccess(profile("1111", "alice"), certificateDetail());
        resourceAccess(profile("2222", "bob"), certificateDetail());

        assertThat(loads).hasValue(1);
    }

    @Test
    void differentPermissionsDoNotShareAnEntry() {
        String operator = profile("1111", "alice");
        String admin = """
                {"user":{"uuid":"2222","username":"bob"},"roles":[],\
                "permissions":{"allowAllResources":true,"resources":[]}}""";

        resourceAccess(operator, certificateDetail());
        resourceAccess(admin, certificateDetail());

        assertThat(loads).hasValue(2);
    }

    @Test
    void nullPrincipalBypassesTheCacheWithoutThrowing() {
        resourceAccess(null, certificateDetail());
        resourceAccess(null, certificateDetail());

        assertThat(loads).hasValue(2);
    }

    @Test
    void differentObjectUuidsMiss() {
        OpaRequestedResource first = certificateDetail();
        first.setObjectUUIDs(List.of("abc-123"));
        OpaRequestedResource second = certificateDetail();
        second.setObjectUUIDs(List.of("def-456"));

        resourceAccess(profile("1111", "alice"), first);
        resourceAccess(profile("1111", "alice"), second);

        assertThat(loads).hasValue(2);
    }

    @Test
    void theTwoPolicyCachesAreSeparate() {
        resourceAccess(profile("1111", "alice"), certificateDetail());
        cache.getOrCheckObjectAccess("method", certificateDetail(), profile("1111", "alice"), DETAILS, () -> {
            loads.incrementAndGet();
            return new OpaObjectAccessResult();
        });

        assertThat(loads).hasValue(2);
    }

    @Test
    void disabledCacheAlwaysInvokesTheLoader() {
        cache = newCache(false);

        resourceAccess(profile("1111", "alice"), certificateDetail());
        resourceAccess(profile("1111", "alice"), certificateDetail());

        assertThat(loads).hasValue(2);
    }

    @Test
    void aThrowingLoaderCachesNothing() {
        assertThatThrownBy(() -> cache
                .getOrCheckResourceAccess("method", certificateDetail(), profile("1111", "alice"), DETAILS, () -> {
                    throw new IllegalStateException("OPA is down");
                })).isInstanceOf(IllegalStateException.class);

        resourceAccess(profile("1111", "alice"), certificateDetail());

        assertThat(loads).hasValue(1);
    }

    @Test
    void aNullResultIsNotCached() {
        Supplier<OpaResourceAccessResult> nullLoader = () -> {
            loads.incrementAndGet();
            return null;
        };

        cache.getOrCheckResourceAccess("method", certificateDetail(), profile("1111", "alice"), DETAILS, nullLoader);
        cache.getOrCheckResourceAccess("method", certificateDetail(), profile("1111", "alice"), DETAILS, nullLoader);

        assertThat(loads).hasValue(2);
    }

    @Test
    void evictAllForcesAReload() {
        resourceAccess(profile("1111", "alice"), certificateDetail());
        cache.evictAll();
        resourceAccess(profile("1111", "alice"), certificateDetail());

        assertThat(loads).hasValue(2);
    }
}
