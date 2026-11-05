package com.otilm.core.service.handler.key;

import com.github.benmanes.caffeine.cache.Caffeine;
import com.otilm.api.clients.ApiClientConnectorInfo;
import com.otilm.api.exception.ConnectorException;
import com.otilm.api.model.common.attribute.common.BaseAttribute;
import com.otilm.api.model.core.auth.Resource;
import com.otilm.api.model.core.connector.AuthType;
import com.otilm.api.model.core.connector.ConnectorStatus;
import com.otilm.core.attribute.engine.AttributeEngine;
import com.otilm.core.attribute.engine.records.ObjectAttributeContentInfo;
import com.otilm.core.config.cache.CacheConfig;
import com.otilm.core.config.cache.CacheEvictor;
import com.otilm.core.model.connector.ImmutableConnectorInfo;
import com.otilm.core.model.crypto.KeyOperationScope;
import com.otilm.core.util.cache.CacheManagerFixtures;
import java.time.Duration;
import java.util.ArrayList;
import java.util.List;
import java.util.UUID;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicLong;
import org.assertj.core.api.ThrowableAssert.ThrowingCallable;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.EnumSource;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.cache.CacheManager;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.assertj.core.api.Assertions.catchThrowable;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class KeyOperationCacheTest {

    private static final Duration TIMEOUT = Duration.ofSeconds(5);
    private static final Duration TTL = Duration.ofMinutes(5);

    @Mock
    private AttributeEngine attributeEngine;

    private KeyOperationCache cache;
    private final AtomicLong ticker = new AtomicLong();
    private final UUID connectorUuid = UUID.randomUUID();
    private final ApiClientConnectorInfo connector = connectorAt("http://connector.test");
    private final KeyOperationScope scope = new KeyOperationScope(UUID.randomUUID(), UUID.randomUUID());

    @BeforeEach
    void wireCacheOnAManualClock() {
        CacheManager cacheManager = CacheManagerFixtures
                .readThrough(Caffeine.newBuilder().expireAfterWrite(TTL).ticker(ticker::get),
                        CacheConfig.TOKEN_SCOPE_ATTRIBUTES_CACHE, CacheConfig.SIGN_ATTRIBUTE_DEFINITIONS_CACHE);
        CacheEvictor cacheEvictor = new CacheEvictor();
        cacheEvictor.setCacheManager(cacheManager);
        cache = new KeyOperationCache(attributeEngine, cacheManager, cacheEvictor);
    }

    // ── StoredAttributes ─────────────────────────────────────────────────────

    @Nested
    class StoredAttributes {

        @Test
        void throwsTheEnginesOwnFailure() {
            // given
            IllegalStateException failure = new IllegalStateException("database unavailable");
            when(attributeEngine.getStoredObjectDataAttributesContent(any())).thenThrow(failure);
            UUID tokenUuid = UUID.randomUUID();

            // when
            ThrowingCallable read = () -> cache.storedAttributes(Resource.TOKEN, tokenUuid, connectorUuid);

            // then
            assertThatThrownBy(read).isSameAs(failure);
        }

        @Test
        void readsThatObjectAgain_afterItsAttributesAreForgotten_andKeepsTheOthers() {
            // given
            when(attributeEngine.getStoredObjectDataAttributesContent(any())).thenAnswer(read -> new ArrayList<>());
            UUID forgottenToken = UUID.randomUUID();
            UUID keptToken = UUID.randomUUID();
            cache.storedAttributes(Resource.TOKEN, forgottenToken, connectorUuid);
            cache.storedAttributes(Resource.TOKEN, keptToken, connectorUuid);

            // when
            cache.forgetAttributesOf(Resource.TOKEN, forgottenToken, connectorUuid);
            cache.storedAttributes(Resource.TOKEN, forgottenToken, connectorUuid);
            cache.storedAttributes(Resource.TOKEN, keptToken, connectorUuid);

            // then
            verify(attributeEngine, times(2)).getStoredObjectDataAttributesContent(attributeScope(forgottenToken));
            verify(attributeEngine).getStoredObjectDataAttributesContent(attributeScope(keptToken));
        }

        @Test
        void readsAgainOnlyTheObjectsOfTheForgottenConnector() {
            // given
            when(attributeEngine.getStoredObjectDataAttributesContent(any())).thenAnswer(read -> new ArrayList<>());
            UUID tokenUuid = UUID.randomUUID();
            UUID otherConnectorUuid = UUID.randomUUID();
            UUID otherConnectorsToken = UUID.randomUUID();
            cache.storedAttributes(Resource.TOKEN, tokenUuid, connectorUuid);
            cache.storedAttributes(Resource.TOKEN, otherConnectorsToken, otherConnectorUuid);

            // when
            cache.forgetConnector(connectorUuid);
            cache.storedAttributes(Resource.TOKEN, tokenUuid, connectorUuid);
            cache.storedAttributes(Resource.TOKEN, otherConnectorsToken, otherConnectorUuid);

            // then
            verify(attributeEngine, times(2)).getStoredObjectDataAttributesContent(attributeScope(tokenUuid));
            verify(attributeEngine)
                    .getStoredObjectDataAttributesContent(attributeScope(otherConnectorsToken, otherConnectorUuid));
        }

        // ── Helpers ───────────────────────────────────────────────────────────

        private ObjectAttributeContentInfo attributeScope(UUID tokenUuid) {
            return attributeScope(tokenUuid, connectorUuid);
        }

        private static ObjectAttributeContentInfo attributeScope(UUID tokenUuid, UUID tokenConnectorUuid) {
            return ObjectAttributeContentInfo.builder(Resource.TOKEN, tokenUuid).connector(tokenConnectorUuid).build();
        }
    }

    // ── SignAttributeDefinitions ─────────────────────────────────────────────

    @Nested
    class SignAttributeDefinitions {

        @Test
        void asksTheLoaderOncePerKeyItem() throws Exception {
            // given
            UUID firstKeyItem = UUID.randomUUID();
            UUID secondKeyItem = UUID.randomUUID();
            KeyOperationCache.DefinitionsLoader firstLoader = mock(KeyOperationCache.DefinitionsLoader.class);
            KeyOperationCache.DefinitionsLoader secondLoader = mock(KeyOperationCache.DefinitionsLoader.class);
            when(firstLoader.load()).thenReturn(List.of());
            when(secondLoader.load()).thenReturn(List.of());

            // when
            signDefinitions(firstKeyItem, scope, firstLoader);
            signDefinitions(firstKeyItem, scope, firstLoader);
            signDefinitions(secondKeyItem, scope, secondLoader);

            // then
            verify(firstLoader).load();
            verify(secondLoader).load();
        }

        @Test
        void asksAgainInAnotherScope_andKeepsBoth() throws Exception {
            // given — the key item moved to another token profile
            UUID keyItemUuid = UUID.randomUUID();
            KeyOperationScope movedTo = new KeyOperationScope(UUID.randomUUID(), scope.tokenInstanceReferenceUuid());
            KeyOperationCache.DefinitionsLoader loader = mock(KeyOperationCache.DefinitionsLoader.class);
            when(loader.load()).thenReturn(List.of());
            signDefinitions(keyItemUuid, scope, loader);

            // when
            signDefinitions(keyItemUuid, movedTo, loader);
            signDefinitions(keyItemUuid, movedTo, loader);
            signDefinitions(keyItemUuid, scope, loader);

            // then
            verify(loader, times(2)).load();
        }

        @Test
        void asksAgain_forTheConnectorReloadedAfterAnEdit() throws Exception {
            // given — an operation that captured the connector before an edit loads after the edit cleared the caches
            UUID keyItemUuid = UUID.randomUUID();
            KeyOperationCache.ScopeRows rowsReadAfterTheEdit = cache.scopeRows(scope, connectorUuid);
            KeyOperationCache.DefinitionsLoader loader = mock(KeyOperationCache.DefinitionsLoader.class);
            when(loader.load()).thenReturn(List.of());
            cache
                    .signAttributeDefinitions(keyItemUuid, connectorAt("http://before-edit.test"), rowsReadAfterTheEdit,
                            loader);

            // when
            cache
                    .signAttributeDefinitions(keyItemUuid, connectorAt("http://after-edit.test"), rowsReadAfterTheEdit,
                            loader);

            // then
            verify(loader, times(2)).load();
        }

        @ParameterizedTest
        @EnumSource(value = Resource.class, names = {"TOKEN", "TOKEN_PROFILE"})
        void asksAgain_onceTheRowsItWasLoadedForExpire(Resource expiringObject) throws Exception {
            // given — the expiring object's rows are read a minute before the definitions
            when(attributeEngine.getStoredObjectDataAttributesContent(any())).thenAnswer(read -> new ArrayList<>());
            cache.storedAttributes(expiringObject, uuidOf(expiringObject), connectorUuid);
            ticker.set(Duration.ofMinutes(1).toNanos());
            UUID keyItemUuid = UUID.randomUUID();
            KeyOperationCache.DefinitionsLoader loader = mock(KeyOperationCache.DefinitionsLoader.class);
            when(loader.load()).thenReturn(List.of());
            signDefinitions(keyItemUuid, scope, loader);

            // when — those rows expire a minute before the definitions do
            ticker.set(TTL.toNanos());
            signDefinitions(keyItemUuid, scope, loader);

            // then
            verify(loader, times(2)).load();
        }

        @Test
        void asksAgain_afterTheLoaderFailed() throws Exception {
            // given
            UUID keyItemUuid = UUID.randomUUID();
            KeyOperationCache.DefinitionsLoader loader = mock(KeyOperationCache.DefinitionsLoader.class);
            List<BaseAttribute> definitions = List.of();
            when(loader.load()).thenThrow(new ConnectorException("Provider unavailable")).thenReturn(definitions);
            Throwable failure = catchThrowable(() -> signDefinitions(keyItemUuid, scope, loader));

            // when
            List<BaseAttribute> loaded = signDefinitions(keyItemUuid, scope, loader);

            // then
            assertThat(failure).isInstanceOf(ConnectorException.class);
            assertThat(loaded).isSameAs(definitions);
            verify(loader, times(2)).load();
        }

        @Test
        void asksAgain_afterAnObjectsAttributesAreForgotten() throws Exception {
            // given
            UUID keyItemUuid = UUID.randomUUID();
            KeyOperationCache.DefinitionsLoader loader = mock(KeyOperationCache.DefinitionsLoader.class);
            when(loader.load()).thenReturn(List.of());
            signDefinitions(keyItemUuid, scope, loader);

            // when
            cache.forgetAttributesOf(Resource.TOKEN_PROFILE, UUID.randomUUID(), connectorUuid);
            signDefinitions(keyItemUuid, scope, loader);

            // then
            verify(loader, times(2)).load();
        }

        @Test
        void asksAgain_afterTheDefinitionsAreForgotten() throws Exception {
            // given
            UUID keyItemUuid = UUID.randomUUID();
            KeyOperationCache.DefinitionsLoader loader = mock(KeyOperationCache.DefinitionsLoader.class);
            when(loader.load()).thenReturn(List.of());
            signDefinitions(keyItemUuid, scope, loader);

            // when
            cache.forgetSignAttributeDefinitions();
            signDefinitions(keyItemUuid, scope, loader);

            // then
            verify(loader, times(2)).load();
        }

        @Test
        void asksAgainOnlyForTheForgottenConnector() throws Exception {
            // given
            UUID keyItemUuid = UUID.randomUUID();
            ApiClientConnectorInfo otherConnector = connectorOf(UUID.randomUUID(), "http://other.test");
            KeyOperationCache.DefinitionsLoader loader = mock(KeyOperationCache.DefinitionsLoader.class);
            KeyOperationCache.DefinitionsLoader otherConnectorsLoader = mock(KeyOperationCache.DefinitionsLoader.class);
            when(loader.load()).thenReturn(List.of());
            when(otherConnectorsLoader.load()).thenReturn(List.of());
            signDefinitions(keyItemUuid, scope, loader);
            signDefinitions(otherConnector, keyItemUuid, otherConnectorsLoader);

            // when
            cache.forgetConnector(connectorUuid);
            signDefinitions(keyItemUuid, scope, loader);
            signDefinitions(otherConnector, keyItemUuid, otherConnectorsLoader);

            // then
            verify(loader, times(2)).load();
            verify(otherConnectorsLoader).load();
        }

        @Test
        void asksAgain_whenAnObjectsAttributesAreForgottenDuringALoad() throws Exception {
            // given
            UUID keyItemUuid = UUID.randomUUID();
            GatedLoader loader = new GatedLoader();
            CompletableFuture<List<BaseAttribute>> loading = loadInBackground(keyItemUuid, loader);
            loader.awaitEntered();

            // when
            cache.forgetAttributesOf(Resource.TOKEN, UUID.randomUUID(), connectorUuid);
            loader.open();
            loading.get(TIMEOUT.toSeconds(), TimeUnit.SECONDS);
            signDefinitions(keyItemUuid, scope, loader);

            // then
            assertThat(loader.loads()).isEqualTo(2);
        }

        @Test
        void asksAgain_whenItsConnectorIsForgottenDuringALoad() throws Exception {
            // given
            UUID keyItemUuid = UUID.randomUUID();
            GatedLoader loader = new GatedLoader();
            CompletableFuture<List<BaseAttribute>> loading = loadInBackground(keyItemUuid, loader);
            loader.awaitEntered();

            // when
            cache.forgetConnector(connectorUuid);
            loader.open();
            loading.get(TIMEOUT.toSeconds(), TimeUnit.SECONDS);
            signDefinitions(keyItemUuid, scope, loader);

            // then
            assertThat(loader.loads()).isEqualTo(2);
        }

        // ── Helpers ───────────────────────────────────────────────────────────

        /** Reads the scope's current rows for each call, as an operation does. */
        private List<BaseAttribute> signDefinitions(UUID keyItemUuid, KeyOperationScope keyScope,
                KeyOperationCache.DefinitionsLoader loader) throws ConnectorException {
            return cache
                    .signAttributeDefinitions(keyItemUuid, connector, cache.scopeRows(keyScope, connectorUuid), loader);
        }

        private List<BaseAttribute> signDefinitions(ApiClientConnectorInfo through, UUID keyItemUuid,
                KeyOperationCache.DefinitionsLoader loader) throws ConnectorException {
            KeyOperationCache.ScopeRows rows = cache.scopeRows(scope, UUID.fromString(through.getUuid()));
            return cache.signAttributeDefinitions(keyItemUuid, through, rows, loader);
        }

        private UUID uuidOf(Resource object) {
            return object == Resource.TOKEN ? scope.tokenInstanceReferenceUuid() : scope.tokenProfileUuid();
        }

        private CompletableFuture<List<BaseAttribute>> loadInBackground(UUID keyItemUuid, GatedLoader loader) {
            return CompletableFuture.supplyAsync(() -> {
                try {
                    return signDefinitions(keyItemUuid, scope, loader);
                } catch (ConnectorException e) {
                    throw new IllegalStateException(e);
                }
            });
        }

        /** A loader whose loads block until the test opens it, so an eviction can land while one runs. */
        private static final class GatedLoader implements KeyOperationCache.DefinitionsLoader {

            private final CountDownLatch entered = new CountDownLatch(1);
            private final CountDownLatch opened = new CountDownLatch(1);
            private final AtomicInteger loads = new AtomicInteger();

            @Override
            public List<BaseAttribute> load() {
                loads.incrementAndGet();
                entered.countDown();
                await(opened, "gate opened");
                return List.of();
            }

            void awaitEntered() {
                await(entered, "load started");
            }

            void open() {
                opened.countDown();
            }

            int loads() {
                return loads.get();
            }

            private static void await(CountDownLatch latch, String event) {
                try {
                    assertThat(latch.await(TIMEOUT.toSeconds(), TimeUnit.SECONDS)).as(event).isTrue();
                } catch (InterruptedException e) {
                    Thread.currentThread().interrupt();
                    throw new IllegalStateException(e);
                }
            }
        }
    }

    // ── Helpers ───────────────────────────────────────────────────────────────

    private ApiClientConnectorInfo connectorAt(String url) {
        return connectorOf(connectorUuid, url);
    }

    private static ApiClientConnectorInfo connectorOf(UUID uuid, String url) {
        return new ImmutableConnectorInfo(uuid.toString(), "connector", url, ConnectorStatus.CONNECTED, AuthType.NONE,
                List.of(), null);
    }
}
