package com.otilm.core.security.authn.client;

import com.otilm.api.model.core.logging.enums.AuthMethod;
import com.otilm.core.config.cache.CacheConfig;
import com.otilm.core.config.cache.ReadThroughCache;
import com.otilm.core.util.cache.CacheManagerFixtures;
import com.otilm.core.util.cache.Caller;
import com.otilm.core.util.cache.HeldLoad;
import java.util.List;
import java.util.Objects;
import java.util.Set;
import java.util.UUID;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ForkJoinPool;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.function.Supplier;
import java.util.stream.Collectors;
import java.util.stream.Stream;
import org.junit.jupiter.api.Named;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;
import org.springframework.cache.CacheManager;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.junit.jupiter.api.Named.named;

class PlatformAuthenticationCacheTest {

    private static final UUID ALICE = UUID.fromString("00000000-0000-0000-0000-000000000001");
    private static final UUID BOB = UUID.fromString("00000000-0000-0000-0000-000000000002");
    private static final String THUMBPRINT = "thumbprint";
    private static final String ISSUER = "https://issuer.example";
    private static final String JTI = "jti";
    private static final long SETTINGS_GENERATION = 0;

    private final TokenJtiIndex tokenJtiIndex = new TokenJtiIndex();
    private final UserCertificateIndex userCertificateIndex = new UserCertificateIndex();
    private final CacheManager cacheManager = CacheManagerFixtures.configured(tokenJtiIndex, userCertificateIndex);
    private final PlatformAuthenticationCache cache = new PlatformAuthenticationCache(cacheManager, tokenJtiIndex,
            userCertificateIndex);
    private final AtomicInteger authentications = new AtomicInteger();

    static Stream<Named<Lookup>> indexedLookups() {
        return Stream
                .of(named("by certificate",
                        (cache, loader) -> cache.getOrAuthenticateByCertificate(THUMBPRINT, loader)),
                        named("by token", (cache, loader) -> cache
                                .getOrAuthenticateByToken(ISSUER, JTI, SETTINGS_GENERATION, loader)));
    }

    @ParameterizedTest
    @MethodSource("indexedLookups")
    void anEvictionOfTheUserDuringALookupMakesTheNextLookupAuthenticateAgain(Lookup lookup) {
        // given
        HeldLoad held = new HeldLoad();
        CompletableFuture<AuthenticationInfo> during = held
                .start(() -> lookup.call(cache, held.holding(this::authenticate)));

        // when
        cache.evictByUserUuid(ALICE);
        held.release(during);
        lookup.call(cache, this::authenticate);

        // then
        assertThat(authentications).hasValue(2);
    }

    @ParameterizedTest
    @MethodSource("indexedLookups")
    void aLookupOverlappingADroppedOneStaysEvictableByUser(Lookup lookup) {
        // given
        HeldLoad held = new HeldLoad();
        CompletableFuture<AuthenticationInfo> dropped = held
                .start(() -> lookup.call(cache, held.holding(this::authenticate)));
        cache.evictByUserUuid(ALICE);
        lookup.call(cache, this::authenticate);
        held.release(dropped);
        awaitRemovalNotices();

        // when
        cache.evictByUserUuid(ALICE);
        lookup.call(cache, this::authenticate);

        // then
        assertThat(authentications).hasValue(3);
    }

    @Test
    void aLookupWithAnotherCertificateOverlappingADroppedOneStaysEvictableByUser() {
        // given — a lookup with the user's old certificate is dropped while one with the new certificate is cached
        HeldLoad held = new HeldLoad();
        CompletableFuture<AuthenticationInfo> dropped = held
                .start(() -> cache.getOrAuthenticateByCertificate("old-thumbprint", held.holding(this::authenticate)));
        cache.evictByUserUuid(ALICE);
        cache.getOrAuthenticateByCertificate("new-thumbprint", this::authenticate);
        held.release(dropped);
        awaitRemovalNotices();

        // when
        cache.evictByUserUuid(ALICE);
        cache.getOrAuthenticateByCertificate("new-thumbprint", this::authenticate);

        // then
        assertThat(authentications).hasValue(3);
    }

    @ParameterizedTest
    @MethodSource("indexedLookups")
    void aLoadAnotherUsersEvictionDropsLeavesNoKeyListed(Lookup lookup) {
        // given
        HeldLoad held = new HeldLoad();
        CompletableFuture<AuthenticationInfo> dropped = held
                .start(() -> lookup.call(cache, held.holding(this::authenticate)));

        // when
        cache.evictByUserUuid(BOB);
        held.release(dropped);
        awaitRemovalNotices();

        // then
        assertThat(tokenJtiIndex.removeUser(ALICE)).isNull();
        assertThat(userCertificateIndex.removeUser(ALICE)).isNull();
    }

    @ParameterizedTest
    @MethodSource("indexedLookups")
    void aLookupLoadingUncachedLeavesNoKeyListed(Lookup lookup) throws Exception {
        // given — two lookups wait on a failing one, so one of them loads uncached
        HeldLoad failing = new HeldLoad();
        CompletableFuture<AuthenticationInfo> failed = failing
                .start(() -> lookup.call(cache, failing.holding(this::failToAuthenticate)));
        HeldLoad retries = new HeldLoad(2);
        Caller<AuthenticationInfo> first = parkedLookup(lookup, retries);
        Caller<AuthenticationInfo> second = parkedLookup(lookup, retries);
        assertThatThrownBy(() -> failing.release(failed)).hasRootCauseInstanceOf(IllegalStateException.class);
        retries.awaitStarted();
        retries.release(first.result());
        second.value();

        // when
        removeEveryCachedEntry();

        // then
        assertThat(tokenJtiIndex.removeUser(ALICE)).isNull();
        assertThat(userCertificateIndex.removeUser(ALICE)).isNull();
    }

    @Test
    void aTokenEntryTheSizeBoundPushesOutIsUnlisted() {
        // given — a token cache bounded to one entry
        CacheManager boundedCacheManager = CacheManagerFixtures.configured(1, tokenJtiIndex, userCertificateIndex);
        PlatformAuthenticationCache bounded = new PlatformAuthenticationCache(boundedCacheManager, tokenJtiIndex,
                userCertificateIndex);
        bounded.getOrAuthenticateByToken(ISSUER, "first", SETTINGS_GENERATION, this::authenticate);
        bounded.getOrAuthenticateByToken(ISSUER, "second", SETTINGS_GENERATION, this::authenticate);

        // when
        Set<String> kept = keptAfterCleanUp(boundedCacheManager, CacheConfig.TOKEN_AUTH_CACHE);

        // then — the index lists exactly the one key the cache kept
        assertThat(kept).hasSize(1);
        assertThat(tokenJtiIndex.removeUser(ALICE)).containsExactlyInAnyOrderElementsOf(kept);
    }

    @Test
    void aCertificateEntryTheSizeBoundPushesOutIsUnlisted() {
        // given — a certificate cache bounded to one entry, filled for two users
        CacheManager boundedCacheManager = CacheManagerFixtures.configured(1, tokenJtiIndex, userCertificateIndex);
        PlatformAuthenticationCache bounded = new PlatformAuthenticationCache(boundedCacheManager, tokenJtiIndex,
                userCertificateIndex);
        bounded.getOrAuthenticateByCertificate("alice-thumbprint", this::authenticate);
        bounded.getOrAuthenticateByCertificate("bob-thumbprint", () -> authenticateAs(BOB));

        // when
        Set<String> kept = keptAfterCleanUp(boundedCacheManager, CacheConfig.CERTIFICATE_AUTH_CACHE);

        // then — only the user whose entry the cache kept stays listed
        assertThat(kept).hasSize(1);
        assertThat(Stream
                .of(ALICE, BOB)
                .map(userCertificateIndex::removeUser)
                .filter(Objects::nonNull)
                .flatMap(Set::stream)).containsExactlyInAnyOrderElementsOf(kept);
    }

    private Caller<AuthenticationInfo> parkedLookup(Lookup lookup, HeldLoad held) {
        Caller<AuthenticationInfo> caller = Caller.start(() -> lookup.call(cache, held.holding(this::authenticate)));
        caller.awaitParked();
        return caller;
    }

    private void removeEveryCachedEntry() {
        Stream
                .of(CacheConfig.CERTIFICATE_AUTH_CACHE, CacheConfig.TOKEN_AUTH_CACHE)
                .forEach(name -> ReadThroughCache.from(cacheManager, name).clear());
        awaitRemovalNotices();
    }

    /** Runs the cache's pending evictions, waits for their removal notices and returns the keys it kept. */
    private static Set<String> keptAfterCleanUp(CacheManager cacheManager, String cacheName) {
        var nativeCache = ReadThroughCache.from(cacheManager, cacheName).getNativeCache();
        nativeCache.synchronous().cleanUp();
        awaitRemovalNotices();
        return nativeCache.asMap().keySet().stream().map(String.class::cast).collect(Collectors.toUnmodifiableSet());
    }

    private static void awaitRemovalNotices() {
        assertThat(ForkJoinPool.commonPool().awaitQuiescence(5, TimeUnit.SECONDS))
                .as("removal notices delivered")
                .isTrue();
    }

    private AuthenticationInfo authenticate() {
        return authenticateAs(ALICE);
    }

    private AuthenticationInfo failToAuthenticate() {
        throw new IllegalStateException("authentication service unavailable");
    }

    private AuthenticationInfo authenticateAs(UUID user) {
        authentications.incrementAndGet();
        return new AuthenticationInfo(AuthMethod.CERTIFICATE, user.toString(), user.toString(), List.of());
    }

    @FunctionalInterface
    private interface Lookup {
        AuthenticationInfo call(PlatformAuthenticationCache cache, Supplier<AuthenticationInfo> loader);
    }
}
