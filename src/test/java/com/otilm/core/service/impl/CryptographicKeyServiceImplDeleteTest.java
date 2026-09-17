package com.otilm.core.service.impl;

import com.otilm.api.exception.ConnectorException;
import com.otilm.api.exception.ValidationException;
import com.otilm.api.model.common.enums.cryptography.KeyAlgorithm;
import com.otilm.api.model.common.enums.cryptography.KeyType;
import com.otilm.api.model.connector.cryptography.enums.TokenInstanceStatus;
import com.otilm.api.model.core.auth.Resource;
import com.otilm.api.model.core.cryptography.key.KeyState;
import com.otilm.core.config.cache.CacheConfig;
import com.otilm.core.config.cache.CacheEvictor;
import com.otilm.core.dao.repository.CryptographicKeyRepository;
import com.otilm.core.model.auth.ResourceAction;
import com.otilm.core.model.crypto.CryptographicKeyFullModel;
import com.otilm.core.model.crypto.CryptographicKeyItemBasicModel;
import com.otilm.core.model.crypto.ImmutableCryptographicKeyFullModel;
import com.otilm.core.model.crypto.ImmutableTokenInstanceFullModel;
import com.otilm.core.model.crypto.RemoteKeyReference;
import com.otilm.core.model.crypto.TokenInstanceFullModel;
import com.otilm.core.security.authz.AuthorizationEnforcer;
import com.otilm.core.security.authz.SecuredUUID;
import com.otilm.core.service.handler.key.KeyProviderAdapter;
import com.otilm.core.service.handler.key.KeyProviderAdapterFactory;
import com.otilm.core.service.writer.CryptographicKeyWriter;
import java.util.List;
import java.util.Optional;
import java.util.Set;
import java.util.UUID;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.function.Executable;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.mockito.InOrder;
import org.springframework.security.access.AccessDeniedException;

import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.inOrder;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.verifyNoMoreInteractions;
import static org.mockito.Mockito.when;

class CryptographicKeyServiceImplDeleteTest {

    private final CryptographicKeyRepository repository = mock(CryptographicKeyRepository.class);
    private final CryptographicKeyWriter writer = mock(CryptographicKeyWriter.class);
    private final KeyProviderAdapterFactory adapterFactory = mock(KeyProviderAdapterFactory.class);
    private final KeyProviderAdapter adapter = mock(KeyProviderAdapter.class);
    private final CacheEvictor cacheEvictor = mock(CacheEvictor.class);
    private final AuthorizationEnforcer authorization = mock(AuthorizationEnforcer.class);
    private final CryptographicKeyServiceImpl service = new CryptographicKeyServiceImpl();
    private final UUID keyUuid = UUID.randomUUID();
    private final CryptographicKeyItemBasicModel firstItem = keyItem(keyUuid);
    private final CryptographicKeyItemBasicModel secondItem = keyItem(keyUuid);

    @BeforeEach
    void setUp() {
        service.setCryptographicKeyRepository(repository);
        service.setCryptographicKeyWriter(writer);
        service.setKeyProviderAdapterFactory(adapterFactory);
        service.setCacheEvictor(cacheEvictor);
        service.setAuthorizationEnforcer(authorization);
    }

    @ParameterizedTest
    @ValueSource(booleans = {true, false})
    void deleteKey_laterRemoteFailure_preservesEarlierItemCleanup(boolean selectedItems) throws Exception {
        // given
        CryptographicKeyFullModel key = remoteKey();
        ConnectorException remoteFailure = new ConnectorException("Second item destruction failed");
        doThrow(remoteFailure).when(adapter).destroyKeyItem(key, secondItem.reference());

        // when
        Executable delete = () -> {
            if (selectedItems) {
                service.deleteKey(key.uuid(), List.of(firstItem.uuid().toString(), secondItem.uuid().toString()));
            } else {
                service.deleteKey(List.of(key.uuid().toString()));
            }
        };

        // then
        assertSame(remoteFailure, assertThrows(ConnectorException.class, delete));
        verify(writer).deleteKeyItem(firstItem.uuid());
        verify(cacheEvictor).evict(CacheConfig.CRYPTOGRAPHIC_KEY_ITEM_CACHE, firstItem.uuid());
        verifyNoMoreInteractions(writer, cacheEvictor);
    }

    @Test
    void deleteKey_cleansEachItemBeforeDestroyingNextAndDeletesParentLast() throws Exception {
        // given
        CryptographicKeyFullModel key = remoteKey();

        // when
        service.deleteKey(List.of(key.uuid().toString()));

        // then
        InOrder deletion = inOrder(adapter, writer, cacheEvictor);
        for (CryptographicKeyItemBasicModel item : key.items()) {
            deletion.verify(adapter).destroyKeyItem(key, item.reference());
            deletion.verify(writer).deleteKeyItem(item.uuid());
            deletion.verify(cacheEvictor).evict(CacheConfig.CRYPTOGRAPHIC_KEY_ITEM_CACHE, item.uuid());
        }
        deletion.verify(writer).deleteKeyWithAssociations(key);
        deletion.verifyNoMoreInteractions();
    }

    @Test
    void deleteKey_withoutToken_deletesLocalItemsAndParent() throws Exception {
        // given
        CryptographicKeyFullModel key = key(null);

        // when
        service.deleteKey(List.of(key.uuid().toString()));

        // then
        verify(writer).deleteKeyItem(firstItem.uuid());
        verify(writer).deleteKeyItem(secondItem.uuid());
        verify(writer).deleteKeyWithAssociations(key);
        verifyNoInteractions(adapterFactory, adapter);
    }

    @ParameterizedTest
    @ValueSource(booleans = {true, false})
    void deleteKey_deniedTokenPreventsCleanupIncludingEmptyParents(boolean emptyParent) throws Exception {
        // given
        CryptographicKeyFullModel key = remoteKey();
        if (emptyParent) {
            key = key(key.tokenInstance(), List.of());
        }
        List<String> selectedParents = List.of(key.uuid().toString());
        doThrow(new AccessDeniedException("Token detail denied"))
                .when(authorization)
                .enforce(eq(Resource.TOKEN), eq(ResourceAction.DETAIL), any(SecuredUUID.class));

        // when
        Executable delete = () -> service.deleteKey(selectedParents);

        // then
        assertThrows(AccessDeniedException.class, delete);
        verifyNoInteractions(adapterFactory, adapter, writer, cacheEvictor);
    }

    @Test
    void deleteKey_authorizesEmptyParentBeforeRemovingIt() throws Exception {
        // given
        CryptographicKeyFullModel key = key(remoteKey().tokenInstance(), List.of());

        // when
        service.deleteKey(List.of(key.uuid().toString()));

        // then
        InOrder deletion = inOrder(authorization, writer);
        deletion.verify(authorization).enforce(eq(Resource.TOKEN), eq(ResourceAction.DETAIL), any(SecuredUUID.class));
        deletion.verify(writer).deleteKeyWithAssociations(key);
        verifyNoInteractions(adapterFactory, adapter, cacheEvictor);
    }

    @ParameterizedTest
    @ValueSource(booleans = {true, false})
    void selectedDeletion_rejectsForeignItemBeforeAnyRemoteOrLocalDeletion(boolean destroy) throws Exception {
        // given
        CryptographicKeyFullModel key = remoteKey();
        UUID otherParentUuid = UUID.randomUUID();
        CryptographicKeyItemBasicModel foreignItem = keyItem(otherParentUuid);
        List<String> selectedUuids = List.of(firstItem.uuid().toString(), foreignItem.uuid().toString());

        // when
        Executable delete = () -> {
            if (destroy) {
                service.destroyKey(key.uuid(), selectedUuids);
            } else {
                service.deleteKey(key.uuid(), selectedUuids);
            }
        };

        // then
        ValidationException failure = assertThrows(ValidationException.class, delete);
        assertThat(failure.getMessage()).contains(key.uuid().toString(), foreignItem.uuid().toString());
        verifyNoInteractions(adapterFactory, adapter, writer, cacheEvictor);
    }

    private CryptographicKeyFullModel remoteKey() throws Exception {
        TokenInstanceFullModel token = new ImmutableTokenInstanceFullModel(UUID.randomUUID(),
                UUID.randomUUID().toString(), "token", TokenInstanceStatus.CONNECTED, null, UUID.randomUUID(),
                "connector", null, null, Set.of());
        when(adapterFactory.forToken(token)).thenReturn(adapter);
        return key(token);
    }

    private CryptographicKeyFullModel key(TokenInstanceFullModel token) {
        return key(token, List.of(firstItem, secondItem));
    }

    private CryptographicKeyFullModel key(TokenInstanceFullModel token, List<CryptographicKeyItemBasicModel> items) {
        CryptographicKeyFullModel key = new ImmutableCryptographicKeyFullModel(keyUuid, "key", null, null,
                token == null ? null : token.uuid(), null, token, Set.of(), null, null, null, items, List.of());
        when(repository.findFullModelByUuid(key.uuid())).thenReturn(Optional.of(key));
        return key;
    }

    private static CryptographicKeyItemBasicModel keyItem(UUID keyUuid) {
        RemoteKeyReference reference = new RemoteKeyReference.UuidReference(UUID.randomUUID());
        return new CryptographicKeyItemBasicModel(UUID.randomUUID(), keyUuid, "item", reference, KeyType.PRIVATE_KEY,
                KeyAlgorithm.RSA, null, null, 2048, KeyState.ACTIVE, true, List.of(), null, null);
    }
}
