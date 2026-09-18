package com.otilm.core.security.authz.opa;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.github.benmanes.caffeine.cache.Caffeine;
import com.otilm.core.config.cache.AuthorizationCacheProperties;
import com.otilm.core.config.cache.CacheConfig;
import com.otilm.core.security.authz.opa.dto.OpaObjectAccessResult;
import com.otilm.core.security.authz.opa.dto.OpaRequestDetails;
import com.otilm.core.security.authz.opa.dto.OpaRequestedResource;
import com.otilm.core.security.authz.opa.dto.OpaResourceAccessResult;
import com.otilm.core.util.PrincipalFixtures;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.Callable;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.function.Supplier;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.cache.caffeine.CaffeineCacheManager;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class PlatformAuthorizationCacheTest {

    private static final OpaRequestDetails DETAILS = new OpaRequestDetails(null);

    private static final long TIMEOUT_SECONDS = 5;

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
        return new PlatformAuthorizationCache(mgr, new ObjectMapper(),
                new AuthorizationCacheProperties(enabled, 5, 100, 100));
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
        OpaResourceAccessResult first = resourceAccess(PrincipalFixtures.operator("1111", "alice"),
                certificateDetail());
        OpaResourceAccessResult second = resourceAccess(PrincipalFixtures.operator("1111", "alice"),
                certificateDetail());

        assertThat(loads).hasValue(1);
        assertThat(second.isAuthorized()).isEqualTo(first.isAuthorized());
        assertThat(second.getAllow()).isEqualTo(first.getAllow());
    }

    @Test
    void differentUsersWithEqualPermissionsShareAnEntry() {
        resourceAccess(PrincipalFixtures.operator("1111", "alice"), certificateDetail());
        resourceAccess(PrincipalFixtures.operator("2222", "bob"), certificateDetail());

        assertThat(loads).hasValue(1);
    }

    @Test
    void differentPermissionsDoNotShareAnEntry() {
        resourceAccess(PrincipalFixtures.operator("1111", "alice"), certificateDetail());
        resourceAccess(PrincipalFixtures.admin("2222", "bob"), certificateDetail());

        assertThat(loads).hasValue(2);
    }

    @Test
    void nullPrincipalBypassesTheCacheWithoutThrowing() {
        resourceAccess(null, certificateDetail());
        resourceAccess(null, certificateDetail());

        assertThat(loads).hasValue(2);
    }

    @Test
    void aPrincipalWithTrailingContentBypassesTheCacheWithoutThrowing() {
        // Deliberately malformed: a complete profile followed by a second one, which no fixture can produce.
        String twoDocuments = PrincipalFixtures.operator("1111", "alice") + PrincipalFixtures.admin("2222", "bob");

        resourceAccess(twoDocuments, certificateDetail());
        resourceAccess(twoDocuments, certificateDetail());

        assertThat(loads).hasValue(2);
    }

    @Test
    void aPrincipalCarryingAnUnpairedSurrogateBypassesTheCacheWithoutThrowing() {
        // Deliberately malformed: a lone high surrogate inside the permissions document. Jackson admits the escape
        // and no fixture can produce it.
        String loneSurrogate = """
                {"user":{"username":"alice"},"permissions":{"allowAllResources":false,\
                "resources":[{"name":"certificates\\ud800"}]}}""";

        resourceAccess(loneSurrogate, certificateDetail());
        resourceAccess(loneSurrogate, certificateDetail());

        assertThat(loads).hasValue(2);
    }

    @Test
    void differentObjectUuidsMiss() {
        OpaRequestedResource first = certificateDetail();
        first.setObjectUUIDs(List.of("abc-123"));
        OpaRequestedResource second = certificateDetail();
        second.setObjectUUIDs(List.of("def-456"));

        resourceAccess(PrincipalFixtures.operator("1111", "alice"), first);
        resourceAccess(PrincipalFixtures.operator("1111", "alice"), second);

        assertThat(loads).hasValue(2);
    }

    @Test
    void reorderedObjectUuidsShareAnEntry() {
        OpaRequestedResource first = certificateDetail();
        first.setObjectUUIDs(List.of("abc-123", "def-456"));
        OpaRequestedResource second = certificateDetail();
        second.setObjectUUIDs(List.of("def-456", "abc-123"));

        resourceAccess(PrincipalFixtures.operator("1111", "alice"), first);
        resourceAccess(PrincipalFixtures.operator("1111", "alice"), second);

        assertThat(loads).hasValue(1);
    }

    @Test
    void reorderedPropertiesShareAnEntry() {
        Map<String, String> reversed = new LinkedHashMap<>();
        reversed.put("action", "detail");
        reversed.put("name", "certificates");

        resourceAccess(PrincipalFixtures.operator("1111", "alice"), certificateDetail());
        resourceAccess(PrincipalFixtures.operator("1111", "alice"), new OpaRequestedResource(reversed));

        assertThat(loads).hasValue(1);
    }

    @Test
    void absentObjectUuidsDoNotShareAnEntryWithAnEmptyList() {
        OpaRequestedResource empty = certificateDetail();
        empty.setObjectUUIDs(List.of());

        resourceAccess(PrincipalFixtures.operator("1111", "alice"), certificateDetail());
        resourceAccess(PrincipalFixtures.operator("1111", "alice"), empty);

        assertThat(loads).hasValue(2);
    }

    @Test
    void theTwoPolicyCachesAreSeparate() {
        String principal = PrincipalFixtures.operator("1111", "alice");

        resourceAccess(principal, certificateDetail());
        cache.getOrCheckObjectAccess("method", certificateDetail(), principal, DETAILS, () -> {
            loads.incrementAndGet();
            return new OpaObjectAccessResult();
        });

        assertThat(loads).hasValue(2);
    }

    @Test
    void disabledCacheAlwaysInvokesTheLoader() {
        cache = newCache(false);

        resourceAccess(PrincipalFixtures.operator("1111", "alice"), certificateDetail());
        resourceAccess(PrincipalFixtures.operator("1111", "alice"), certificateDetail());

        assertThat(loads).hasValue(2);
    }

    @Test
    void aThrowingLoaderCachesNothing() {
        OpaRequestedResource resource = certificateDetail();
        String principal = PrincipalFixtures.operator("1111", "alice");
        Supplier<OpaResourceAccessResult> failingLoader = () -> {
            throw new IllegalStateException("OPA is down");
        };

        assertThatThrownBy(() -> cache.getOrCheckResourceAccess("method", resource, principal, DETAILS, failingLoader))
                .isInstanceOf(IllegalStateException.class);

        resourceAccess(PrincipalFixtures.operator("1111", "alice"), certificateDetail());

        assertThat(loads).hasValue(1);
    }

    @Test
    void aNullResultIsNotCached() {
        String principal = PrincipalFixtures.operator("1111", "alice");
        Supplier<OpaResourceAccessResult> nullLoader = () -> {
            loads.incrementAndGet();
            return null;
        };

        cache.getOrCheckResourceAccess("method", certificateDetail(), principal, DETAILS, nullLoader);
        cache.getOrCheckResourceAccess("method", certificateDetail(), principal, DETAILS, nullLoader);

        assertThat(loads).hasValue(2);
    }

    @Test
    void theCallerCannotMutateTheCachedDecision() {
        OpaResourceAccessResult first = resourceAccess(PrincipalFixtures.operator("1111", "alice"),
                certificateDetail());
        first.setAuthorized(false);
        first.setAllow(List.of());

        OpaResourceAccessResult second = resourceAccess(PrincipalFixtures.operator("1111", "alice"),
                certificateDetail());

        assertThat(loads).hasValue(1);
        assertThat(second.isAuthorized()).isTrue();
        assertThat(second.getAllow()).containsExactly("ActionAllowedOnResource");
    }

    private OpaObjectAccessResult objectAccess(String principal, OpaRequestedResource resource) {
        return cache.getOrCheckObjectAccess("objects", resource, principal, DETAILS, () -> {
            loads.incrementAndGet();
            OpaObjectAccessResult filter = new OpaObjectAccessResult();
            filter.setAllowedObjects(List.of("allowed-1"));
            filter.setForbiddenObjects(List.of("forbidden-1"));
            filter.setActionAllowedForGroupOfObjects(true);
            return filter;
        });
    }

    @Test
    void theCallerCannotMutateTheCachedObjectFilter() {
        OpaObjectAccessResult first = objectAccess(PrincipalFixtures.operator("1111", "alice"), certificateDetail());
        first.setAllowedObjects(List.of());
        first.setForbiddenObjects(List.of("allowed-1"));
        first.setActionAllowedForGroupOfObjects(false);

        OpaObjectAccessResult second = objectAccess(PrincipalFixtures.operator("1111", "alice"), certificateDetail());

        assertThat(loads).hasValue(1);
        assertThat(second.getAllowedObjects()).containsExactly("allowed-1");
        assertThat(second.getForbiddenObjects()).containsExactly("forbidden-1");
        assertThat(second.isActionAllowedForGroupOfObjects()).isTrue();
    }

    @Test
    void concurrentMissesOnOneKeyRunTheLoaderOnce() throws Exception {
        CountDownLatch loaderEntered = new CountDownLatch(1);
        CountDownLatch releaseLoader = new CountDownLatch(1);
        CountDownLatch secondCallerStarted = new CountDownLatch(1);
        Supplier<OpaResourceAccessResult> blockingLoader = () -> {
            loads.incrementAndGet();
            loaderEntered.countDown();
            awaitQuietly(releaseLoader);
            return new OpaResourceAccessResult(true, List.of("ActionAllowedOnResource"));
        };
        Callable<OpaResourceAccessResult> check = () -> cache
                .getOrCheckResourceAccess("method", certificateDetail(), PrincipalFixtures.operator("1111", "alice"),
                        DETAILS, blockingLoader);

        ExecutorService pool = Executors.newFixedThreadPool(2);
        try {
            Future<OpaResourceAccessResult> first = pool.submit(check);
            assertThat(loaderEntered.await(TIMEOUT_SECONDS, TimeUnit.SECONDS)).isTrue();
            Future<OpaResourceAccessResult> second = pool.submit(() -> {
                secondCallerStarted.countDown();
                return check.call();
            });
            assertThat(secondCallerStarted.await(TIMEOUT_SECONDS, TimeUnit.SECONDS)).isTrue();
            releaseLoader.countDown();

            assertThat(first.get(TIMEOUT_SECONDS, TimeUnit.SECONDS)).isNotNull();
            assertThat(second.get(TIMEOUT_SECONDS, TimeUnit.SECONDS)).isNotNull();
        } finally {
            pool.shutdownNow();
        }

        assertThat(loads).hasValue(1);
    }

    @Test
    void evictAllForcesAReload() {
        resourceAccess(PrincipalFixtures.operator("1111", "alice"), certificateDetail());
        cache.evictAll();
        resourceAccess(PrincipalFixtures.operator("1111", "alice"), certificateDetail());

        assertThat(loads).hasValue(2);
    }

    private static void awaitQuietly(CountDownLatch latch) {
        try {
            latch.await(TIMEOUT_SECONDS, TimeUnit.SECONDS);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        }
    }
}
