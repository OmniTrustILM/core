package com.otilm.core.service.handler.key;

import com.otilm.api.exception.ConnectorException;
import com.otilm.api.model.common.attribute.common.BaseAttribute;
import com.otilm.api.model.core.auth.Resource;
import com.otilm.core.attribute.engine.AttributeEngine;
import com.otilm.core.attribute.engine.records.ObjectAttributeContentInfo;
import com.otilm.core.model.crypto.KeyOperationScope;
import java.time.Duration;
import java.util.ArrayList;
import java.util.List;
import java.util.UUID;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;
import org.assertj.core.api.ThrowableAssert.ThrowingCallable;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

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

    @Mock
    private AttributeEngine attributeEngine;

    private KeyOperationCache cache;
    private final UUID connectorUuid = UUID.randomUUID();
    private final KeyOperationScope scope = new KeyOperationScope(UUID.randomUUID(), UUID.randomUUID());

    @BeforeEach
    void wireCache() {
        cache = KeyOperationCacheFixtures.inMemory(attributeEngine);
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
        void readsEveryObjectAgain_afterAllAttributesAreForgotten() {
            // given
            when(attributeEngine.getStoredObjectDataAttributesContent(any())).thenAnswer(read -> new ArrayList<>());
            UUID tokenUuid = UUID.randomUUID();
            cache.storedAttributes(Resource.TOKEN, tokenUuid, connectorUuid);

            // when
            cache.forgetAllAttributes();
            cache.storedAttributes(Resource.TOKEN, tokenUuid, connectorUuid);

            // then
            verify(attributeEngine, times(2)).getStoredObjectDataAttributesContent(attributeScope(tokenUuid));
        }

        private ObjectAttributeContentInfo attributeScope(UUID tokenUuid) {
            return ObjectAttributeContentInfo.builder(Resource.TOKEN, tokenUuid).connector(connectorUuid).build();
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
            cache.signAttributeDefinitions(firstKeyItem, scope, firstLoader);
            cache.signAttributeDefinitions(firstKeyItem, scope, firstLoader);
            cache.signAttributeDefinitions(secondKeyItem, scope, secondLoader);

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
            cache.signAttributeDefinitions(keyItemUuid, scope, loader);

            // when
            cache.signAttributeDefinitions(keyItemUuid, movedTo, loader);
            cache.signAttributeDefinitions(keyItemUuid, movedTo, loader);
            cache.signAttributeDefinitions(keyItemUuid, scope, loader);

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
            Throwable failure = catchThrowable(() -> cache.signAttributeDefinitions(keyItemUuid, scope, loader));

            // when
            List<BaseAttribute> loaded = cache.signAttributeDefinitions(keyItemUuid, scope, loader);

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
            cache.signAttributeDefinitions(keyItemUuid, scope, loader);

            // when
            cache.forgetAttributesOf(Resource.TOKEN_PROFILE, UUID.randomUUID(), connectorUuid);
            cache.signAttributeDefinitions(keyItemUuid, scope, loader);

            // then
            verify(loader, times(2)).load();
        }

        @Test
        void asksAgain_afterTheDefinitionsAreForgotten() throws Exception {
            // given
            UUID keyItemUuid = UUID.randomUUID();
            KeyOperationCache.DefinitionsLoader loader = mock(KeyOperationCache.DefinitionsLoader.class);
            when(loader.load()).thenReturn(List.of());
            cache.signAttributeDefinitions(keyItemUuid, scope, loader);

            // when
            cache.forgetSignAttributeDefinitions();
            cache.signAttributeDefinitions(keyItemUuid, scope, loader);

            // then
            verify(loader, times(2)).load();
        }

        @Test
        void asksAgain_afterAllAttributesAreForgotten() throws Exception {
            // given
            UUID keyItemUuid = UUID.randomUUID();
            KeyOperationCache.DefinitionsLoader loader = mock(KeyOperationCache.DefinitionsLoader.class);
            when(loader.load()).thenReturn(List.of());
            cache.signAttributeDefinitions(keyItemUuid, scope, loader);

            // when
            cache.forgetAllAttributes();
            cache.signAttributeDefinitions(keyItemUuid, scope, loader);

            // then
            verify(loader, times(2)).load();
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
            cache.signAttributeDefinitions(keyItemUuid, scope, loader);

            // then
            assertThat(loader.loads()).isEqualTo(2);
        }

        @Test
        void asksAgain_whenAllAttributesAreForgottenDuringALoad() throws Exception {
            // given
            UUID keyItemUuid = UUID.randomUUID();
            GatedLoader loader = new GatedLoader();
            CompletableFuture<List<BaseAttribute>> loading = loadInBackground(keyItemUuid, loader);
            loader.awaitEntered();

            // when
            cache.forgetAllAttributes();
            loader.open();
            loading.get(TIMEOUT.toSeconds(), TimeUnit.SECONDS);
            cache.signAttributeDefinitions(keyItemUuid, scope, loader);

            // then
            assertThat(loader.loads()).isEqualTo(2);
        }

        private CompletableFuture<List<BaseAttribute>> loadInBackground(UUID keyItemUuid, GatedLoader loader) {
            return CompletableFuture.supplyAsync(() -> {
                try {
                    return cache.signAttributeDefinitions(keyItemUuid, scope, loader);
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
}
