package com.otilm.core.integration.security.authn.client;

import com.otilm.api.model.core.logging.enums.AuthMethod;
import com.otilm.core.security.authn.client.AuthenticationCache;
import com.otilm.core.security.authn.client.AuthenticationInfo;
import com.otilm.core.util.BaseSpringBootTest;
import java.util.List;
import java.util.UUID;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.function.Supplier;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.authority.SimpleGrantedAuthority;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

class PlatformAuthenticationCacheITest extends BaseSpringBootTest {

    private static final String ISSUER = "https://issuer.example.com";
    private static final String OTHER_ISSUER = "https://other-issuer.example.com";

    @Autowired
    private AuthenticationCache authenticationCache;

    @BeforeEach
    void clearCache() {
        authenticationCache.evictAll();
    }

    // --- getOrAuthenticateSystemUser ---

    @Test
    void getOrAuthenticateSystemUser_cacheMiss_callsLoader() {
        // given - the cache is empty
        AuthenticationInfo expected = authenticatedInfo(UUID.randomUUID().toString(), "superadmin");
        Supplier<AuthenticationInfo> loader = loaderReturning(expected);

        // when - first call to authenticate the user
        AuthenticationInfo result = authenticationCache.getOrAuthenticateSystemUser("superadmin", loader);

        // then - verify that the loader was called and the result is as expected
        assertEquals(expected, result);
        verify(loader, times(1)).get();
    }

    @Test
    void getOrAuthenticateSystemUser_cacheHit_loaderNotCalledAgain() {
        // given
        AuthenticationInfo expected = authenticatedInfo(UUID.randomUUID().toString(), "superadmin");
        Supplier<AuthenticationInfo> loader = loaderReturning(expected);
        // first call to authenticate the user - this will populate the cache
        authenticationCache.getOrAuthenticateSystemUser("superadmin", loader);

        // when - second call to authenticate the user - the cache should be used
        AuthenticationInfo result = authenticationCache.getOrAuthenticateSystemUser("superadmin", loader);

        // then - verify that the loader was not called again and the result is the same as expected
        assertEquals(expected, result);
        verify(loader, times(1)).get();
    }

    @Test
    void getOrAuthenticateSystemUser_anonymousResult_notCached() {
        // given - anonymous results must not be stored, so the user can authenticate on the next request
        Supplier<AuthenticationInfo> loader = loaderReturning(AuthenticationInfo.getAnonymousAuthenticationInfo());

        // when - call twice to verify that the loader is called both times due to the non-caching of anonymous results
        authenticationCache.getOrAuthenticateSystemUser("superadmin", loader);
        authenticationCache.getOrAuthenticateSystemUser("superadmin", loader);

        // then - verify that the loader was called twice and the result is anonymous
        verify(loader, times(2)).get();
    }

    // --- getOrAuthenticateByUserUuid ---

    @Test
    void getOrAuthenticateByUserUuid_cacheMiss_callsLoader() {
        // given - the cache is empty
        UUID userUuid = UUID.randomUUID();
        AuthenticationInfo expected = authenticatedInfo(userUuid.toString(), "user1");
        Supplier<AuthenticationInfo> loader = loaderReturning(expected);

        // when - first call to authenticate the user by UUID
        AuthenticationInfo result = authenticationCache.getOrAuthenticateByUserUuid(userUuid, loader);

        // then - verify that the loader was called and the result is as expected
        assertEquals(expected, result);
        verify(loader, times(1)).get();
    }

    @Test
    void getOrAuthenticateByUserUuid_cacheHit_loaderNotCalledAgain() {
        // given
        UUID userUuid = UUID.randomUUID();
        AuthenticationInfo expected = authenticatedInfo(userUuid.toString(), "user1");
        Supplier<AuthenticationInfo> loader = loaderReturning(expected);
        // first call to authenticate the user - this will populate the cache
        authenticationCache.getOrAuthenticateByUserUuid(userUuid, loader);

        // when - second call to authenticate the same user UUID - the cache should be used
        AuthenticationInfo result = authenticationCache.getOrAuthenticateByUserUuid(userUuid, loader);

        // then - verify that the loader was not called again and the result is the same as expected
        assertEquals(expected, result);
        verify(loader, times(1)).get();
    }

    @Test
    void getOrAuthenticateByUserUuid_anonymousResult_notCached() {
        // given - anonymous results must not be stored, so the user can authenticate on the next request
        UUID userUuid = UUID.randomUUID();
        Supplier<AuthenticationInfo> loader = loaderReturning(AuthenticationInfo.getAnonymousAuthenticationInfo());

        // when - call twice to verify that the loader is called both times due to the non-caching of anonymous results
        authenticationCache.getOrAuthenticateByUserUuid(userUuid, loader);
        authenticationCache.getOrAuthenticateByUserUuid(userUuid, loader);

        // then - verify that the loader was called twice because anonymous results bypass the cache
        verify(loader, times(2)).get();
    }

    // --- getOrAuthenticateByCertificate ---

    @Test
    void getOrAuthenticateByCertificate_cacheMiss_callsLoader() {
        // given - the cache is empty
        AuthenticationInfo expected = authenticatedInfo(UUID.randomUUID().toString(), "certUser");
        Supplier<AuthenticationInfo> loader = loaderReturning(expected);

        // when - first call to authenticate by certificate fingerprint
        AuthenticationInfo result = authenticationCache.getOrAuthenticateByCertificate("fingerprint-abc", loader);

        // then - verify that the loader was called and the result is as expected
        assertEquals(expected, result);
        verify(loader, times(1)).get();
    }

    @Test
    void getOrAuthenticateByCertificate_cacheHit_loaderNotCalledAgain() {
        // given
        AuthenticationInfo expected = authenticatedInfo(UUID.randomUUID().toString(), "certUser");
        Supplier<AuthenticationInfo> loader = loaderReturning(expected);
        // first call to authenticate the user - this will populate the cache
        authenticationCache.getOrAuthenticateByCertificate("fingerprint-abc", loader);

        // when - second call with the same certificate fingerprint - the cache should be used
        AuthenticationInfo result = authenticationCache.getOrAuthenticateByCertificate("fingerprint-abc", loader);

        // then - verify that the loader was not called again and the result is the same as expected
        assertEquals(expected, result);
        verify(loader, times(1)).get();
    }

    @Test
    void getOrAuthenticateByCertificate_anonymousResult_notCached() {
        // given - anonymous results must not be stored, so the user can authenticate on the next request
        Supplier<AuthenticationInfo> loader = loaderReturning(AuthenticationInfo.getAnonymousAuthenticationInfo());

        // when - call twice to verify that the loader is called both times due to the non-caching of anonymous results
        authenticationCache.getOrAuthenticateByCertificate("fingerprint-abc", loader);
        authenticationCache.getOrAuthenticateByCertificate("fingerprint-abc", loader);

        // then - verify that the loader was called twice because anonymous results bypass the cache
        verify(loader, times(2)).get();
    }

    // --- getOrAuthenticateByToken ---

    @Test
    void getOrAuthenticateByToken_nullJti_loaderAlwaysCalled() {
        // given - tokens without a jti cannot be uniquely identified, so they are never cached
        Supplier<AuthenticationInfo> loader = loaderReturning(
                authenticatedInfo(UUID.randomUUID().toString(), "tokenUser"));

        // when - call twice with a null jti to verify that caching is always skipped
        authenticationCache.getOrAuthenticateByToken(ISSUER, null, 1L, loader);
        authenticationCache.getOrAuthenticateByToken(ISSUER, null, 1L, loader);

        // then - verify that the loader was called both times because null-jti tokens bypass the cache
        verify(loader, times(2)).get();
    }

    @Test
    void getOrAuthenticateByToken_cacheMiss_callsLoader() {
        // given - the cache is empty
        AuthenticationInfo expected = authenticatedInfo(UUID.randomUUID().toString(), "tokenUser");
        Supplier<AuthenticationInfo> loader = loaderReturning(expected);

        // when - first call to authenticate by token jti
        AuthenticationInfo result = authenticationCache.getOrAuthenticateByToken(ISSUER, "jti-123", 1L, loader);

        // then - verify that the loader was called and the result is as expected
        assertEquals(expected, result);
        verify(loader, times(1)).get();
    }

    @Test
    void getOrAuthenticateByToken_cacheHit_loaderNotCalledAgain() {
        // given
        AuthenticationInfo expected = authenticatedInfo(UUID.randomUUID().toString(), "tokenUser");
        Supplier<AuthenticationInfo> loader = loaderReturning(expected);
        // first call to authenticate the user - this will populate the cache
        authenticationCache.getOrAuthenticateByToken(ISSUER, "jti-123", 1L, loader);

        // when - second call with the same jti - the cache should be used
        AuthenticationInfo result = authenticationCache.getOrAuthenticateByToken(ISSUER, "jti-123", 1L, loader);

        // then - verify that the loader was not called again and the result is the same as expected
        assertEquals(expected, result);
        verify(loader, times(1)).get();
    }

    @Test
    void getOrAuthenticateByToken_anonymousResult_notCached() {
        // given - anonymous results must not be stored, so the user can authenticate on the next request
        Supplier<AuthenticationInfo> loader = loaderReturning(AuthenticationInfo.getAnonymousAuthenticationInfo());

        // when - call twice to verify that the loader is called both times due to the non-caching of anonymous results
        authenticationCache.getOrAuthenticateByToken(ISSUER, "jti-anon", 1L, loader);
        authenticationCache.getOrAuthenticateByToken(ISSUER, "jti-anon", 1L, loader);

        // then - verify that the loader was called twice because anonymous results bypass the cache
        verify(loader, times(2)).get();
    }

    @Test
    void tokenEntriesBecomeUnreachableWhenSettingsGenerationChanges() {
        AuthenticationInfo expected = authenticatedInfo(UUID.randomUUID().toString(), "user1");
        AtomicInteger loaderCalls = new AtomicInteger();
        Supplier<AuthenticationInfo> loader = () -> {
            loaderCalls.incrementAndGet();
            return expected;
        };

        authenticationCache.getOrAuthenticateByToken(ISSUER, "jti-gen", 1L, loader);
        authenticationCache.getOrAuthenticateByToken(ISSUER, "jti-gen", 1L, loader);
        assertEquals(1, loaderCalls.get()); // second call under the same generation is a cache hit

        authenticationCache.getOrAuthenticateByToken(ISSUER, "jti-gen", 2L, loader);
        assertEquals(2, loaderCalls.get()); // new generation misses and reloads
    }

    @Test
    void getOrAuthenticateByToken_sameJtiFromDifferentIssuers_resolvedIndependently() {
        // given - a jti is only unique within its issuer, so two providers can mint the same one
        AuthenticationInfo aliceAtOneIssuer = authenticatedInfo(UUID.randomUUID().toString(), "alice");
        AuthenticationInfo bobAtOtherIssuer = authenticatedInfo(UUID.randomUUID().toString(), "bob");
        Supplier<AuthenticationInfo> aliceLoader = loaderReturning(aliceAtOneIssuer);
        Supplier<AuthenticationInfo> bobLoader = loaderReturning(bobAtOtherIssuer);

        // when - the same jti under the same generation arrives from each issuer
        AuthenticationInfo first = authenticationCache.getOrAuthenticateByToken(ISSUER, "jti-shared", 1L, aliceLoader);
        AuthenticationInfo second = authenticationCache
                .getOrAuthenticateByToken(OTHER_ISSUER, "jti-shared", 1L, bobLoader);

        // then - neither token is served the other issuer's identity
        assertEquals(aliceAtOneIssuer, first);
        assertEquals(bobAtOtherIssuer, second);
        verify(aliceLoader, times(1)).get();
        verify(bobLoader, times(1)).get();

        // and - each issuer keeps its own entry, so a repeat of either is a hit
        assertEquals(aliceAtOneIssuer,
                authenticationCache.getOrAuthenticateByToken(ISSUER, "jti-shared", 1L, aliceLoader));
        assertEquals(bobAtOtherIssuer,
                authenticationCache.getOrAuthenticateByToken(OTHER_ISSUER, "jti-shared", 1L, bobLoader));
        verify(aliceLoader, times(1)).get();
        verify(bobLoader, times(1)).get();
    }

    @Test
    void getOrAuthenticateByToken_missingIssuer_loaderAlwaysCalled() {
        // given - without an issuer the key cannot distinguish one issuer's jti from another's, so caching is skipped
        Supplier<AuthenticationInfo> nullIssuerLoader = loaderReturning(
                authenticatedInfo(UUID.randomUUID().toString(), "tokenUser"));
        Supplier<AuthenticationInfo> blankIssuerLoader = loaderReturning(
                authenticatedInfo(UUID.randomUUID().toString(), "tokenUser"));

        // when
        authenticationCache.getOrAuthenticateByToken(null, "jti-no-issuer", 1L, nullIssuerLoader);
        authenticationCache.getOrAuthenticateByToken(null, "jti-no-issuer", 1L, nullIssuerLoader);
        authenticationCache.getOrAuthenticateByToken("  ", "jti-blank-issuer", 1L, blankIssuerLoader);
        authenticationCache.getOrAuthenticateByToken("  ", "jti-blank-issuer", 1L, blankIssuerLoader);

        // then
        verify(nullIssuerLoader, times(2)).get();
        verify(blankIssuerLoader, times(2)).get();
    }

    @Test
    void getOrAuthenticateByToken_issuerAndJtiWithAmbiguousSplit_doNotShareEntry() {
        // given - two triples that a plain "generation:issuer:jti" key would render identically
        AuthenticationInfo shortIssuerUser = authenticatedInfo(UUID.randomUUID().toString(), "shortIssuerUser");
        AuthenticationInfo longIssuerUser = authenticatedInfo(UUID.randomUUID().toString(), "longIssuerUser");
        Supplier<AuthenticationInfo> shortIssuerLoader = loaderReturning(shortIssuerUser);
        Supplier<AuthenticationInfo> longIssuerLoader = loaderReturning(longIssuerUser);

        // when
        AuthenticationInfo first = authenticationCache
                .getOrAuthenticateByToken("https://a", "x:y", 1L, shortIssuerLoader);
        AuthenticationInfo second = authenticationCache
                .getOrAuthenticateByToken("https://a:x", "y", 1L, longIssuerLoader);

        // then - the length-prefixed issuer keeps the two keys apart
        assertEquals(shortIssuerUser, first);
        assertEquals(longIssuerUser, second);
        verify(shortIssuerLoader, times(1)).get();
        verify(longIssuerLoader, times(1)).get();
    }

    // --- evictByUserUuid ---

    @Test
    void evictByUserUuid_evictsUserUuidEntry() {
        // given - the user UUID cache is populated
        UUID userUuid = UUID.randomUUID();
        Supplier<AuthenticationInfo> loader = loaderReturning(authenticatedInfo(userUuid.toString(), "user"));
        authenticationCache.getOrAuthenticateByUserUuid(userUuid, loader);

        // when - evict the cache entry for this user
        authenticationCache.evictByUserUuid(userUuid);

        // then - verify that the next call reaches the loader again because the entry was evicted
        authenticationCache.getOrAuthenticateByUserUuid(userUuid, loader);
        verify(loader, times(2)).get();
    }

    @Test
    void evictByUserUuid_evictsAllTokensForUser() {
        // given - the same jti cached under two different settings generations for the same user; each
        // generation produces a distinct composite cache key, and both must be tracked in the jti index
        UUID userUuid = UUID.randomUUID();
        AuthenticationInfo info = authenticatedInfo(userUuid.toString(), "user");
        Supplier<AuthenticationInfo> loaderA = loaderReturning(info);
        Supplier<AuthenticationInfo> loaderB = loaderReturning(info);
        authenticationCache.getOrAuthenticateByToken(ISSUER, "jti-A", 1L, loaderA);
        authenticationCache.getOrAuthenticateByToken(ISSUER, "jti-A", 2L, loaderB);

        // when - evict all cache entries for this user
        authenticationCache.evictByUserUuid(userUuid);

        // then - verify that both generation-keyed entries were evicted via the jti index and the loaders are called
        // again
        authenticationCache.getOrAuthenticateByToken(ISSUER, "jti-A", 1L, loaderA);
        authenticationCache.getOrAuthenticateByToken(ISSUER, "jti-A", 2L, loaderB);
        verify(loaderA, times(2)).get();
        verify(loaderB, times(2)).get();
    }

    @Test
    void evictByUserUuid_evictsCertificateEntry() {
        // given - the certificate cache is populated, so the user-certificate index has recorded the mapping
        UUID userUuid = UUID.randomUUID();
        String fingerprint = "cert-fingerprint";
        Supplier<AuthenticationInfo> loader = loaderReturning(authenticatedInfo(userUuid.toString(), "certUser"));
        authenticationCache.getOrAuthenticateByCertificate(fingerprint, loader);

        // when - evict by user UUID; the cache resolves the fingerprint from the index internally
        authenticationCache.evictByUserUuid(userUuid);

        // then - verify that the certificate entry was evicted and the loader is called again
        authenticationCache.getOrAuthenticateByCertificate(fingerprint, loader);
        verify(loader, times(2)).get();
    }

    @Test
    void evictByUserUuid_doesNotEvictCertificateWhenNoneWasCached() {
        // given - no certificate has been cached for this user, so the index has no entry
        UUID userUuid = UUID.randomUUID();
        String fingerprint = "cert-fingerprint";
        // populate with a different user so the fingerprint is in the cache but not mapped to this user
        Supplier<AuthenticationInfo> loader = loaderReturning(
                authenticatedInfo(UUID.randomUUID().toString(), "certUser"));
        authenticationCache.getOrAuthenticateByCertificate(fingerprint, loader);

        // when - evict a user who has no certificate cache entry
        authenticationCache.evictByUserUuid(userUuid);

        // then - the certificate entry for the other user is unaffected
        authenticationCache.getOrAuthenticateByCertificate(fingerprint, loader);
        verify(loader, times(1)).get();
    }

    @Test
    void evictByUserUuid_doesNotEvictOtherUsersTokens() {
        // given - two different users each have a token cached
        UUID userUuidA = UUID.randomUUID();
        UUID userUuidB = UUID.randomUUID();
        Supplier<AuthenticationInfo> loaderA = loaderReturning(authenticatedInfo(userUuidA.toString(), "userA"));
        Supplier<AuthenticationInfo> loaderB = loaderReturning(authenticatedInfo(userUuidB.toString(), "userB"));
        authenticationCache.getOrAuthenticateByToken(ISSUER, "jti-userA", 1L, loaderA);
        authenticationCache.getOrAuthenticateByToken(ISSUER, "jti-userB", 1L, loaderB);

        // when - evict only userA
        authenticationCache.evictByUserUuid(userUuidA);

        // then - verify that userA token was evicted and userB token is still cached
        authenticationCache.getOrAuthenticateByToken(ISSUER, "jti-userA", 1L, loaderA);
        authenticationCache.getOrAuthenticateByToken(ISSUER, "jti-userB", 1L, loaderB);
        verify(loaderA, times(2)).get();
        verify(loaderB, times(1)).get();
    }

    // --- evictAll ---

    @Test
    void evictAll_clearsAllCaches() {
        // given - all four cache types are populated
        String userUuid = UUID.randomUUID().toString();
        AuthenticationInfo info = authenticatedInfo(userUuid, "user");
        Supplier<AuthenticationInfo> systemUserLoader = loaderReturning(info);
        Supplier<AuthenticationInfo> uuidLoader = loaderReturning(info);
        Supplier<AuthenticationInfo> certLoader = loaderReturning(info);
        Supplier<AuthenticationInfo> tokenLoader = loaderReturning(info);

        authenticationCache.getOrAuthenticateSystemUser("superadmin", systemUserLoader);
        authenticationCache.getOrAuthenticateByUserUuid(UUID.fromString(userUuid), uuidLoader);
        authenticationCache.getOrAuthenticateByCertificate("fingerprint", certLoader);
        authenticationCache.getOrAuthenticateByToken(ISSUER, "jti-all", 1L, tokenLoader);

        // when - evict all entries across all caches
        authenticationCache.evictAll();

        // then - verify that every loader is called again because all entries were evicted
        authenticationCache.getOrAuthenticateSystemUser("superadmin", systemUserLoader);
        authenticationCache.getOrAuthenticateByUserUuid(UUID.fromString(userUuid), uuidLoader);
        authenticationCache.getOrAuthenticateByCertificate("fingerprint", certLoader);
        authenticationCache.getOrAuthenticateByToken(ISSUER, "jti-all", 1L, tokenLoader);

        verify(systemUserLoader, times(2)).get();
        verify(uuidLoader, times(2)).get();
        verify(certLoader, times(2)).get();
        verify(tokenLoader, times(2)).get();
    }

    // --- helpers ---

    private static AuthenticationInfo authenticatedInfo(String userUuid, String username) {
        return new AuthenticationInfo(AuthMethod.CERTIFICATE, userUuid, username,
                List.of(new SimpleGrantedAuthority("ROLE_USER")));
    }

    @SuppressWarnings("unchecked")
    private static Supplier<AuthenticationInfo> loaderReturning(AuthenticationInfo info) {
        Supplier<AuthenticationInfo> loader = mock(Supplier.class);
        when(loader.get()).thenReturn(info);
        return loader;
    }
}
