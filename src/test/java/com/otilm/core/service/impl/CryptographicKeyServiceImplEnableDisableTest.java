package com.otilm.core.service.impl;

import com.otilm.api.exception.NotFoundException;
import com.otilm.api.exception.ValidationException;
import com.otilm.api.model.core.auth.Resource;
import com.otilm.core.config.cache.CacheConfig;
import com.otilm.core.config.cache.CacheEvictor;
import com.otilm.core.dao.entity.CryptographicKey;
import com.otilm.core.dao.entity.CryptographicKeyItem;
import com.otilm.core.dao.repository.CryptographicKeyItemRepository;
import com.otilm.core.dao.repository.CryptographicKeyRepository;
import com.otilm.core.model.auth.ResourceAction;
import com.otilm.core.model.crypto.CryptographicKeyItemBasicModel;
import com.otilm.core.model.crypto.ImmutableCryptographicKeyFullModel;
import com.otilm.core.security.authz.AuthorizationEnforcer;
import com.otilm.core.security.authz.SecuredUUID;
import com.otilm.core.service.CryptographicKeyEventHistoryService;
import com.otilm.core.service.writer.CryptographicKeyWriter;
import java.util.List;
import java.util.Optional;
import java.util.UUID;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.function.Executable;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.springframework.security.access.AccessDeniedException;

import static com.otilm.core.util.builders.CryptographicKeyBuilder.aCryptographicKey;
import static com.otilm.core.util.builders.CryptographicKeyItemBuilder.aKeyItem;
import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.ArgumentMatchers.argThat;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.verifyNoMoreInteractions;
import static org.mockito.Mockito.when;

class CryptographicKeyServiceImplEnableDisableTest {

    private final CryptographicKeyRepository keyRepository = mock(CryptographicKeyRepository.class);
    private final CryptographicKeyItemRepository itemRepository = mock(CryptographicKeyItemRepository.class);
    private final CryptographicKeyWriter writer = mock(CryptographicKeyWriter.class);
    private final CacheEvictor cacheEvictor = mock(CacheEvictor.class);
    private final CryptographicKeyEventHistoryService history = mock(CryptographicKeyEventHistoryService.class);
    private final CryptographicKeyServiceImpl service = new CryptographicKeyServiceImpl();
    private final CryptographicKey parent = key();
    private final CryptographicKeyItemBasicModel selectedItem = item(parent);
    private final CryptographicKeyItemBasicModel unselectedItem = item(parent);

    @BeforeEach
    void setUp() {
        service.setCryptographicKeyRepository(keyRepository);
        service.setCryptographicKeyItemRepository(itemRepository);
        service.setCryptographicKeyWriter(writer);
        service.setCacheEvictor(cacheEvictor);
        service.setKeyEventHistoryService(history);
        when(keyRepository.findFullModelByUuid(parent.getUuid()))
                .thenReturn(Optional.of(ImmutableCryptographicKeyFullModel.from(parent)));
    }

    @ParameterizedTest
    @ValueSource(booleans = {true, false})
    void setEnabled_rejectsEntireSelection_whenAnItemBelongsToAnotherParent(boolean enabled) {
        // given
        CryptographicKey otherParent = key();
        CryptographicKeyItemBasicModel foreignItem = item(otherParent);
        List<String> requestedUuids = List.of(selectedItem.uuid().toString(), foreignItem.uuid().toString());

        // when
        Executable update = () -> setEnabled(requestedUuids, enabled);

        // then
        ValidationException failure = assertThrows(ValidationException.class, update);
        assertThat(failure.getMessage())
                .contains(parent.getUuid().toString(), foreignItem.uuid().toString(), "No key items were updated")
                .doesNotContain(otherParent.getUuid().toString());
        verifyNoInteractions(writer, cacheEvictor, history);
    }

    @ParameterizedTest
    @ValueSource(booleans = {true, false})
    void setEnabled_rejectsEntireSelection_whenAnItemDoesNotExist(boolean enabled) {
        // given
        UUID missingItemUuid = UUID.randomUUID();
        List<String> requestedUuids = List.of(selectedItem.uuid().toString(), missingItemUuid.toString());

        // when
        Executable update = () -> setEnabled(requestedUuids, enabled);

        // then
        ValidationException failure = assertThrows(ValidationException.class, update);
        assertThat(failure.getMessage())
                .contains(parent.getUuid().toString(), missingItemUuid.toString(), "No key items were updated");
        verifyNoInteractions(writer, cacheEvictor, history);
    }

    @ParameterizedTest
    @ValueSource(booleans = {true, false})
    void setEnabled_updatesOnlySelectedItem_whenSelectionIsAValidSubset(boolean enabled) throws NotFoundException {
        // given
        List<String> requestedUuids = List.of(selectedItem.uuid().toString());
        when(writer.setKeyItemEnabled(selectedItem.uuid(), enabled)).thenReturn(true);

        // when
        setEnabled(requestedUuids, enabled);

        // then
        verify(writer).setKeyItemEnabled(selectedItem.uuid(), enabled);
        verifyNoMoreInteractions(writer);
        verify(cacheEvictor).evict(CacheConfig.CRYPTOGRAPHIC_KEY_ITEM_CACHE, selectedItem.uuid());
        assertThat(parent.getItems())
                .extracting(CryptographicKeyItem::getUuid)
                .containsExactlyInAnyOrder(selectedItem.uuid(), unselectedItem.uuid());
    }

    @ParameterizedTest
    @ValueSource(booleans = {true, false})
    void setEnabled_doesNotEvictCache_whenWriterReportsNoChange(boolean enabled) throws NotFoundException {
        // given
        List<String> requestedUuids = List.of(selectedItem.uuid().toString());
        boolean stateChanged = false;
        when(writer.setKeyItemEnabled(selectedItem.uuid(), enabled)).thenReturn(stateChanged);

        // when
        setEnabled(requestedUuids, enabled);

        // then
        verify(writer).setKeyItemEnabled(selectedItem.uuid(), enabled);
        verifyNoInteractions(cacheEvictor);
    }

    @ParameterizedTest
    @ValueSource(booleans = {true, false})
    void setEnabled_updatesItemOnce_whenSelectionContainsDuplicates(boolean enabled) throws NotFoundException {
        // given
        String selectedUuid = selectedItem.uuid().toString();
        List<String> requestedUuids = List.of(selectedUuid, selectedUuid);

        // when
        setEnabled(requestedUuids, enabled);

        // then
        verify(writer).setKeyItemEnabled(selectedItem.uuid(), enabled);
        verifyNoMoreInteractions(writer);
    }

    @ParameterizedTest
    @ValueSource(booleans = {true, false})
    void bulkSetEnabled_deduplicatesParentsAndContinuesAfterMissingParent(boolean enabled) {
        // given
        String missingParentUuid = UUID.randomUUID().toString();
        String existingParentUuid = parent.getUuid().toString();
        List<String> requestedParents = List.of(missingParentUuid, existingParentUuid, existingParentUuid);

        // when
        setParentsEnabled(requestedParents, enabled);

        // then
        verify(writer).setKeyItemEnabled(selectedItem.uuid(), enabled);
        verify(writer).setKeyItemEnabled(unselectedItem.uuid(), enabled);
        verifyNoMoreInteractions(writer);
    }

    @ParameterizedTest
    @ValueSource(booleans = {true, false})
    void bulkSetEnabled_deniedTokenPreventsItemMutation(boolean enabled) {
        // given
        UUID deniedTokenUuid = UUID.randomUUID();
        parent.setTokenInstanceReferenceUuid(deniedTokenUuid);
        when(keyRepository.findFullModelByUuid(parent.getUuid()))
                .thenReturn(Optional.of(ImmutableCryptographicKeyFullModel.from(parent)));
        AuthorizationEnforcer authorization = mock(AuthorizationEnforcer.class);
        service.setAuthorizationEnforcer(authorization);
        doThrow(new AccessDeniedException("Token access denied"))
                .when(authorization)
                .enforce(eq(Resource.TOKEN), eq(ResourceAction.DETAIL),
                        argThat((SecuredUUID uuid) -> uuid.getValue().equals(deniedTokenUuid)));

        // when
        Executable update = () -> setParentsEnabled(List.of(parent.getUuid().toString()), enabled);

        // then
        assertThrows(AccessDeniedException.class, update);
        verifyNoInteractions(writer, cacheEvictor, history);
    }

    private void setParentsEnabled(List<String> parentUuids, boolean enabled) {
        if (enabled) {
            service.enableKey(parentUuids);
        } else {
            service.disableKey(parentUuids);
        }
    }

    private void setEnabled(List<String> itemUuids, boolean enabled) throws NotFoundException {
        if (enabled) {
            service.enableKey(parent.getUuid(), itemUuids);
        } else {
            service.disableKey(parent.getUuid(), itemUuids);
        }
    }

    private static CryptographicKey key() {
        CryptographicKey key = aCryptographicKey().build();
        key.setUuid(UUID.randomUUID());
        return key;
    }

    private static CryptographicKeyItemBasicModel item(CryptographicKey key) {
        CryptographicKeyItem item = aKeyItem().build();
        item.setUuid(UUID.randomUUID());
        item.setKey(key);
        item.setKeyReferenceUuid(UUID.randomUUID());
        item.setUsage(List.of());
        key.getItems().add(item);
        return CryptographicKeyItemBasicModel.from(item);
    }
}
