package com.otilm.core.service.impl;

import com.otilm.api.exception.ConnectorException;
import com.otilm.api.model.connector.cryptography.enums.TokenInstanceStatus;
import com.otilm.api.model.core.auth.Resource;
import com.otilm.api.model.core.logging.enums.AuthMethod;
import com.otilm.core.config.cache.CacheConfig;
import com.otilm.core.config.cache.CacheEvictor;
import com.otilm.core.dao.entity.CryptographicKey;
import com.otilm.core.dao.entity.CryptographicKeyItem;
import com.otilm.core.dao.entity.CryptographicKey_;
import com.otilm.core.dao.entity.TokenInstanceReference;
import com.otilm.core.dao.repository.CryptographicKeyItemRepository;
import com.otilm.core.dao.repository.CryptographicKeyRepository;
import com.otilm.core.messaging.jms.producers.NotificationProducer;
import com.otilm.core.model.crypto.CryptographicKeyFullModel;
import com.otilm.core.model.crypto.CryptographicKeyItemBasicModel;
import com.otilm.core.model.crypto.ImmutableCryptographicKeyFullModel;
import com.otilm.core.security.authn.PlatformAuthenticationToken;
import com.otilm.core.security.authn.PlatformUserDetails;
import com.otilm.core.security.authn.client.AuthenticationInfo;
import com.otilm.core.security.authz.ObjectFilterAspect;
import com.otilm.core.security.authz.SecurityFilter;
import com.otilm.core.service.handler.key.KeyProviderAdapter;
import com.otilm.core.service.handler.key.KeyProviderAdapterFactory;
import com.otilm.core.service.writer.CryptographicKeyWriter;
import jakarta.persistence.metamodel.SingularAttribute;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Optional;
import java.util.UUID;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.mockito.ArgumentCaptor;
import org.mockito.InOrder;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.test.util.ReflectionTestUtils;

import static com.otilm.core.util.builders.CryptographicKeyBuilder.aCryptographicKey;
import static com.otilm.core.util.builders.CryptographicKeyItemBuilder.aKeyItem;
import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.argThat;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.ArgumentMatchers.isNull;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.inOrder;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.verifyNoMoreInteractions;
import static org.mockito.Mockito.when;

class CryptographicKeyServiceImplBulkDeleteTest {

    private final CryptographicKeyRepository keys = mock(CryptographicKeyRepository.class);
    private final CryptographicKeyItemRepository items = mock(CryptographicKeyItemRepository.class);
    private final CryptographicKeyWriter writer = mock(CryptographicKeyWriter.class);
    private final KeyProviderAdapterFactory adapters = mock(KeyProviderAdapterFactory.class);
    private final KeyProviderAdapter adapter = mock(KeyProviderAdapter.class);
    private final CacheEvictor cache = mock(CacheEvictor.class);
    private final NotificationProducer notifications = mock(NotificationProducer.class);
    private final CryptographicKeyServiceImpl service = new CryptographicKeyServiceImpl();
    private final UUID userUuid = UUID.randomUUID();
    private final SecurityFilter tokenFilter = SecurityFilter.create();
    private final CryptographicKeyFullModel key = remoteKey();
    private final List<UUID> selectedUuids = key.items().stream().map(CryptographicKeyItemBasicModel::uuid).toList();
    private final List<String> selectedUuidStrings = selectedUuids.stream().map(UUID::toString).toList();
    private SingularAttribute<CryptographicKey, UUID> previousTokenReferenceAttribute;
    private SingularAttribute<CryptographicKey, UUID> previousTokenProfileAttribute;

    @BeforeEach
    void setUp() throws Exception {
        previousTokenReferenceAttribute = CryptographicKey_.tokenInstanceReferenceUuid;
        previousTokenProfileAttribute = CryptographicKey_.tokenProfileUuid;
        CryptographicKey_.tokenInstanceReferenceUuid = uuidAttribute("tokenInstanceReferenceUuid");
        CryptographicKey_.tokenProfileUuid = uuidAttribute("tokenProfileUuid");
        service.setCryptographicKeyRepository(keys);
        service.setCryptographicKeyItemRepository(items);
        service.setCryptographicKeyWriter(writer);
        service.setKeyProviderAdapterFactory(adapters);
        service.setCacheEvictor(cache);
        service.setNotificationProducer(notifications);
        service.setObjectFilterAspect(mock(ObjectFilterAspect.class));
        ReflectionTestUtils.setField(service, "bulkDeleteBatchSize", selectedUuids.size());
        AuthenticationInfo operator = new AuthenticationInfo(AuthMethod.USER_PROXY, userUuid.toString(), "operator",
                List.of());
        SecurityContextHolder
                .getContext()
                .setAuthentication(new PlatformAuthenticationToken(new PlatformUserDetails(operator)));
        when(items.findUuidsUsingSecurityFilter(any(), any(), isNull(), isNull())).thenReturn(selectedUuids);
        when(items.findBasicModelsByUuidIn(selectedUuids)).thenReturn(key.items());
        when(keys.findFullModelByUuid(key.uuid())).thenReturn(Optional.of(key));
        when(adapters.forToken(key.tokenInstance())).thenReturn(adapter);
        for (UUID itemUuid : selectedUuids) {
            when(writer.deleteKeyItemsWithAssociations(List.of(itemUuid))).thenReturn(1);
        }
    }

    @AfterEach
    void clearAuthentication() {
        SecurityContextHolder.clearContext();
        CryptographicKey_.tokenInstanceReferenceUuid = previousTokenReferenceAttribute;
        CryptographicKey_.tokenProfileUuid = previousTokenProfileAttribute;
    }

    @Test
    void deleteKeyItems_success_cleansAndEvictsEachItemBeforeDestroyingNext() throws Exception {
        // given
        List<CryptographicKeyItemBasicModel> selectedItems = key.items();

        // when
        service.deleteKeyItems(tokenFilter, selectedUuidStrings);

        // then
        InOrder deletion = inOrder(adapter, writer, cache);
        for (CryptographicKeyItemBasicModel item : selectedItems) {
            deletion.verify(adapter).destroyKeyItem(key, item.reference());
            deletion.verify(writer).deleteKeyItemsWithAssociations(List.of(item.uuid()));
            deletion.verify(cache).evict(CacheConfig.CRYPTOGRAPHIC_KEY_ITEM_CACHE, item.uuid());
        }
        deletion.verifyNoMoreInteractions();
        verifyNoInteractions(notifications);
    }

    @ParameterizedTest
    @ValueSource(ints = {0, 1})
    void deleteKeyItems_writerFailure_preservesEarlierCleanupWithoutEvictingFailedItem(int failingItemIndex)
            throws Exception {
        // given
        String sensitiveFailure = "SQL delete from cryptographic_key_item failed for internal_column";
        CryptographicKeyItemBasicModel failingItem = key.items().get(failingItemIndex);
        doThrow(new IllegalStateException(sensitiveFailure))
                .when(writer)
                .deleteKeyItemsWithAssociations(List.of(failingItem.uuid()));

        // when
        service.deleteKeyItems(tokenFilter, selectedUuidStrings);

        // then
        for (CryptographicKeyItemBasicModel item : key.items().subList(0, failingItemIndex)) {
            verify(adapter).destroyKeyItem(key, item.reference());
            verify(writer).deleteKeyItemsWithAssociations(List.of(item.uuid()));
            verify(cache).evict(CacheConfig.CRYPTOGRAPHIC_KEY_ITEM_CACHE, item.uuid());
        }
        verify(adapter).destroyKeyItem(key, failingItem.reference());
        verify(writer).deleteKeyItemsWithAssociations(List.of(failingItem.uuid()));
        verifyNoMoreInteractions(adapter, writer, cache);
        assertSafeBatchFailure(sensitiveFailure);
    }

    @Test
    void deleteKeyItems_connectorFailure_reportsSafeFailureWithoutLocalDeletion() throws Exception {
        // given
        String sensitiveFailure = "Connector credential secret-token at private-host";
        CryptographicKeyItemBasicModel failingItem = key.items().getFirst();
        doThrow(new ConnectorException(sensitiveFailure)).when(adapter).destroyKeyItem(key, failingItem.reference());

        // when
        service.deleteKeyItems(tokenFilter, selectedUuidStrings);

        // then
        verify(adapter).destroyKeyItem(key, failingItem.reference());
        verifyNoInteractions(writer, cache);
        assertSafeBatchFailure(sensitiveFailure);
    }

    @Test
    void deleteKeyItems_laterConnectorFailure_preservesEarlierCleanupAndEviction() throws Exception {
        // given
        String sensitiveFailure = "Connector credential secret-token at private-host";
        CryptographicKeyItemBasicModel deletedItem = key.items().getFirst();
        CryptographicKeyItemBasicModel failingItem = key.items().getLast();
        doThrow(new ConnectorException(sensitiveFailure)).when(adapter).destroyKeyItem(key, failingItem.reference());

        // when
        service.deleteKeyItems(tokenFilter, selectedUuidStrings);

        // then
        InOrder deletion = inOrder(adapter, writer, cache);
        deletion.verify(adapter).destroyKeyItem(key, deletedItem.reference());
        deletion.verify(writer).deleteKeyItemsWithAssociations(List.of(deletedItem.uuid()));
        deletion.verify(cache).evict(CacheConfig.CRYPTOGRAPHIC_KEY_ITEM_CACHE, deletedItem.uuid());
        deletion.verify(adapter).destroyKeyItem(key, failingItem.reference());
        deletion.verifyNoMoreInteractions();
        assertSafeBatchFailure(sensitiveFailure);
    }

    @Test
    void deleteKeyItems_noAuthorizedItems_skipsRemoteAndLocalDeletion() {
        // given
        List<UUID> noAuthorizedItems = List.of();
        when(items.findUuidsUsingSecurityFilter(any(), any(), isNull(), isNull())).thenReturn(noAuthorizedItems);

        // when
        service.deleteKeyItems(tokenFilter, selectedUuidStrings);

        // then
        verifyNoInteractions(keys, adapters, adapter, writer, cache);
    }

    private void assertSafeBatchFailure(String sensitiveFailure) {
        ArgumentCaptor<String> detail = ArgumentCaptor.forClass(String.class);
        String expectedTitle = "Batch key deletion failed for " + selectedUuids.size() + " key items";
        verify(notifications)
                .produceInternalNotificationMessage(eq(Resource.CRYPTOGRAPHIC_KEY_ITEM), eq(selectedUuids.getFirst()),
                        argThat(recipients -> recipients.size() == 1
                                && recipients.getFirst().getRecipientUuid().equals(userUuid)),
                        eq(expectedTitle), detail.capture());
        assertThat(detail.getValue()).isNotBlank().doesNotContain(sensitiveFailure);
    }

    @SuppressWarnings("unchecked")
    private static SingularAttribute<CryptographicKey, UUID> uuidAttribute(String name) {
        SingularAttribute<CryptographicKey, UUID> attribute = mock(SingularAttribute.class);
        when(attribute.getName()).thenReturn(name);
        return attribute;
    }

    private static CryptographicKeyFullModel remoteKey() {
        CryptographicKey key = aCryptographicKey().build();
        key.setUuid(UUID.randomUUID());
        TokenInstanceReference token = new TokenInstanceReference();
        token.setUuid(UUID.randomUUID());
        token.setTokenInstanceUuid(UUID.randomUUID().toString());
        token.setStatus(TokenInstanceStatus.CONNECTED);
        key.setTokenInstanceReference(token);
        key.setItems(new LinkedHashSet<>(List.of(item(key, "first-item"), item(key, "second-item"))));
        return ImmutableCryptographicKeyFullModel.from(key);
    }

    private static CryptographicKeyItem item(CryptographicKey key, String name) {
        CryptographicKeyItem item = aKeyItem().withName(name).build();
        item.setUuid(UUID.randomUUID());
        item.setKey(key);
        item.setKeyReferenceUuid(UUID.randomUUID());
        item.setUsage(List.of());
        return item;
    }
}
