package com.otilm.core.service.impl;

import com.otilm.api.exception.NotFoundException;
import com.otilm.api.exception.ValidationError;
import com.otilm.api.exception.ValidationException;
import com.otilm.api.model.client.cryptography.key.BulkCompromiseKeyItemRequestDto;
import com.otilm.api.model.client.cryptography.key.BulkKeyItemUsageRequestDto;
import com.otilm.api.model.client.cryptography.key.KeyCompromiseReason;
import com.otilm.api.model.core.auth.Resource;
import com.otilm.api.model.core.cryptography.key.KeyState;
import com.otilm.api.model.core.cryptography.key.KeyUsage;
import com.otilm.core.config.cache.CacheEvictor;
import com.otilm.core.dao.entity.CryptographicKey;
import com.otilm.core.dao.entity.CryptographicKeyItem;
import com.otilm.core.dao.repository.CryptographicKeyItemRepository;
import com.otilm.core.dao.repository.CryptographicKeyRepository;
import com.otilm.core.model.auth.ResourceAction;
import com.otilm.core.model.crypto.CryptographicKeyItemBasicModel;
import com.otilm.core.model.crypto.ImmutableCryptographicKeyBasicModel;
import com.otilm.core.model.crypto.ImmutableCryptographicKeyFullModel;
import com.otilm.core.security.authz.AuthorizationEnforcer;
import com.otilm.core.security.authz.SecuredUUID;
import com.otilm.core.service.CryptographicKeyEventHistoryService;
import com.otilm.core.service.writer.CryptographicKeyWriter;
import java.util.List;
import java.util.Optional;
import java.util.UUID;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.function.Executable;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.EnumSource;
import org.mockito.InOrder;
import org.springframework.security.access.AccessDeniedException;

import static com.otilm.core.util.builders.CryptographicKeyBuilder.aCryptographicKey;
import static com.otilm.core.util.builders.CryptographicKeyItemBuilder.aKeyItem;
import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.argThat;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.inOrder;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.verifyNoMoreInteractions;
import static org.mockito.Mockito.when;

class CryptographicKeyServiceImplParentAccessTest {

    private final CryptographicKeyRepository keys = mock(CryptographicKeyRepository.class);
    private final CryptographicKeyItemRepository items = mock(CryptographicKeyItemRepository.class);
    private final CryptographicKeyWriter writer = mock(CryptographicKeyWriter.class);
    private final CryptographicKeyEventHistoryService history = mock(CryptographicKeyEventHistoryService.class);
    private final AuthorizationEnforcer authorization = mock(AuthorizationEnforcer.class);
    private final CryptographicKeyServiceImpl service = new CryptographicKeyServiceImpl();
    private final CryptographicKey firstParent = key();
    private final CryptographicKey secondParent = key();
    private final CryptographicKeyItem firstItem = item(firstParent);
    private final CryptographicKeyItem secondItem = item(secondParent);
    private final List<KeyUsage> requestedUsages = List.of(KeyUsage.SIGN);

    @BeforeEach
    void setUp() {
        service.setCryptographicKeyRepository(keys);
        service.setCryptographicKeyItemRepository(items);
        service.setCryptographicKeyWriter(writer);
        service.setKeyEventHistoryService(history);
        service.setAuthorizationEnforcer(authorization);
        service.setCacheEvictor(mock(CacheEvictor.class));
        loadParents();
    }

    private void loadParents() {
        for (CryptographicKey parent : List.of(firstParent, secondParent)) {
            when(keys.findBasicModelByUuid(parent.getUuid()))
                    .thenReturn(Optional.of(ImmutableCryptographicKeyBasicModel.from(parent)));
            when(keys.findFullModelByUuid(parent.getUuid()))
                    .thenReturn(Optional.of(ImmutableCryptographicKeyFullModel.from(parent)));
        }
    }

    @Test
    void history_rejectsForeignItemWithoutReadingItsHistory() {
        // given
        UUID parentUuid = firstParent.getUuid();
        UUID foreignItemUuid = secondItem.getUuid();
        when(items.findByUuidAndKeyUuid(foreignItemUuid, parentUuid)).thenReturn(Optional.empty());

        // when
        Executable readHistory = () -> service.getEventHistory(parentUuid, foreignItemUuid);

        // then
        assertThrows(NotFoundException.class, readHistory);
        verifyNoInteractions(history);
    }

    @Test
    void history_checksParentAndTokenBeforeReadingHistory() throws Exception {
        // given
        UUID itemUuid = firstItem.getUuid();
        when(items.findByUuidAndKeyUuid(itemUuid, firstParent.getUuid())).thenReturn(Optional.of(firstItem));
        when(history.getKeyEventHistory(itemUuid)).thenReturn(List.of());

        // when
        var result = service.getEventHistory(firstParent.getUuid(), itemUuid);

        // then
        assertThat(result).isEmpty();
        InOrder access = inOrder(authorization, items, history);
        access
                .verify(authorization)
                .enforce(eq(Resource.TOKEN), eq(ResourceAction.MEMBERS), matchingToken(firstParent));
        access.verify(items).findByUuidAndKeyUuid(itemUuid, firstParent.getUuid());
        access.verify(history).getKeyEventHistory(itemUuid);
    }

    @ParameterizedTest
    @EnumSource(BulkOperation.class)
    void bulk_checksBothActualParentsBeforeMutatingTheirItems(BulkOperation operation) throws Exception {
        // given
        List<UUID> selectedUuids = stubBulkSelection();

        // when
        mutate(operation, selectedUuids);

        // then
        InOrder access = inOrder(authorization, writer);
        access.verify(authorization).enforce(eq(Resource.TOKEN), eq(ResourceAction.DETAIL), matchingToken(firstParent));
        access
                .verify(authorization)
                .enforce(eq(Resource.TOKEN), eq(ResourceAction.DETAIL), matchingToken(secondParent));
        verifyMutation(access, operation, firstItem.getUuid());
        verifyMutation(access, operation, secondItem.getUuid());
        verifyNoMoreInteractions(writer);
    }

    @ParameterizedTest
    @EnumSource(BulkOperation.class)
    void bulk_rejectsMissingItemsBeforeMutatingValidItems(BulkOperation operation) {
        // given
        UUID missingUuid = UUID.randomUUID();
        List<UUID> selectedUuids = List.of(firstItem.getUuid(), missingUuid);
        when(items.findBasicModelsByUuidIn(selectedUuids))
                .thenReturn(List.of(CryptographicKeyItemBasicModel.from(firstItem)));

        // when
        Executable mutate = () -> mutate(operation, selectedUuids);

        // then
        ValidationException failure = assertThrows(ValidationException.class, mutate);
        assertThat(failure.getErrors())
                .extracting(ValidationError::getErrorDescription)
                .containsExactly("Key items were not found or are not authorized. No key items were updated.");
        verifyNoInteractions(writer, history);
    }

    @ParameterizedTest
    @EnumSource(BulkOperation.class)
    void bulk_allowsTokenAuthorizedItemsWithoutProfileDetail(BulkOperation operation) throws Exception {
        // given
        firstParent.setTokenProfileUuid(UUID.randomUUID());
        secondParent.setTokenProfileUuid(UUID.randomUUID());
        loadParents();
        List<UUID> selectedUuids = stubBulkSelection();
        doThrow(new AccessDeniedException("Profile detail denied"))
                .when(authorization)
                .enforce(eq(Resource.TOKEN_PROFILE), eq(ResourceAction.DETAIL), any(SecuredUUID.class));

        // when
        mutate(operation, selectedUuids);

        // then
        InOrder access = inOrder(authorization, writer);
        access.verify(authorization).enforce(eq(Resource.TOKEN), eq(ResourceAction.DETAIL), matchingToken(firstParent));
        access
                .verify(authorization)
                .enforce(eq(Resource.TOKEN), eq(ResourceAction.DETAIL), matchingToken(secondParent));
        verifyMutation(access, operation, firstItem.getUuid());
        verifyMutation(access, operation, secondItem.getUuid());
        verify(authorization, never()).enforce(eq(Resource.TOKEN_PROFILE), any(), any(SecuredUUID.class));
    }

    @ParameterizedTest
    @EnumSource(BulkOperation.class)
    void bulk_doesNotMutateAnyItemWhenAnotherParentIsDenied(BulkOperation operation) {
        // given
        List<UUID> selectedUuids = stubBulkSelection();
        doThrow(new AccessDeniedException("Denied for test"))
                .when(authorization)
                .enforce(eq(Resource.TOKEN), eq(ResourceAction.DETAIL), matchingToken(secondParent));

        // when
        Executable mutate = () -> mutate(operation, selectedUuids);

        // then
        ValidationException failure = assertThrows(ValidationException.class, mutate);
        assertThat(failure.getErrors())
                .extracting(ValidationError::getErrorDescription)
                .containsExactly("Key items were not found or are not authorized. No key items were updated.");
        verifyNoInteractions(writer, history);
    }

    @Test
    void updateUsages_rejectsMissingParentBeforeMutatingAnyItem() {
        // given
        List<UUID> selectedUuids = stubBulkSelection();
        when(keys.findBasicModelByUuid(secondParent.getUuid())).thenReturn(Optional.empty());

        // when
        Executable update = () -> mutate(BulkOperation.UPDATE_USAGES, selectedUuids);

        // then
        NotFoundException failure = assertThrows(NotFoundException.class, update);
        assertThat(failure.getMessage()).contains(secondParent.getUuid().toString());
        verifyNoInteractions(writer, history);
    }

    private List<UUID> stubBulkSelection() {
        List<UUID> selectedUuids = List.of(firstItem.getUuid(), secondItem.getUuid());
        List<CryptographicKeyItemBasicModel> selectedItems = List
                .of(CryptographicKeyItemBasicModel.from(firstItem), CryptographicKeyItemBasicModel.from(secondItem));
        when(items.findBasicModelsByUuidIn(selectedUuids)).thenReturn(selectedItems);
        return selectedUuids;
    }

    private void mutate(BulkOperation operation, List<UUID> selectedUuids) throws Exception {
        List<String> stringUuids = selectedUuids.stream().map(UUID::toString).toList();
        switch (operation) {
            case ENABLE -> service.enableKeyItems(stringUuids);
            case DISABLE -> service.disableKeyItems(stringUuids);
            case DESTROY -> service.destroyKeyItems(stringUuids);
            case COMPROMISE -> {
                BulkCompromiseKeyItemRequestDto request = new BulkCompromiseKeyItemRequestDto();
                request.setUuids(selectedUuids);
                request.setReason(KeyCompromiseReason.UNAUTHORIZED_DISCLOSURE);
                service.compromiseKeyItems(request);
            }
            case UPDATE_USAGES -> {
                BulkKeyItemUsageRequestDto request = new BulkKeyItemUsageRequestDto();
                request.setUuids(selectedUuids);
                request.setUsage(requestedUsages);
                service.updateKeyItemUsages(request);
            }
        }
    }

    private void verifyMutation(InOrder access, BulkOperation operation, UUID itemUuid) throws Exception {
        switch (operation) {
            case ENABLE -> access.verify(writer).setKeyItemEnabled(itemUuid, true);
            case DISABLE -> access.verify(writer).setKeyItemEnabled(itemUuid, false);
            case DESTROY -> access.verify(writer).finalizeKeyItemDestruction(itemUuid);
            case COMPROMISE ->
                access.verify(writer).setKeyItemCompromised(itemUuid, KeyCompromiseReason.UNAUTHORIZED_DISCLOSURE);
            case UPDATE_USAGES -> access.verify(writer).updateUsage(itemUuid, requestedUsages);
        }
    }

    private static SecuredUUID matchingToken(CryptographicKey key) {
        return argThat(
                (SecuredUUID uuid) -> uuid != null && key.getTokenInstanceReferenceUuid().equals(uuid.getValue()));
    }

    private static CryptographicKey key() {
        CryptographicKey key = aCryptographicKey().build();
        key.setUuid(UUID.randomUUID());
        key.setTokenInstanceReferenceUuid(UUID.randomUUID());
        return key;
    }

    private static CryptographicKeyItem item(CryptographicKey parent) {
        CryptographicKeyItem item = aKeyItem().withState(KeyState.PRE_ACTIVE).build();
        item.setUuid(UUID.randomUUID());
        item.setKey(parent);
        item.setKeyReferenceUuid(UUID.randomUUID());
        item.setUsage(List.of());
        parent.getItems().add(item);
        return item;
    }

    private enum BulkOperation {
        ENABLE,
        DISABLE,
        DESTROY,
        COMPROMISE,
        UPDATE_USAGES
    }
}
