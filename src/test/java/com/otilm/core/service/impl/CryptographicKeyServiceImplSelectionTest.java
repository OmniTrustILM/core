package com.otilm.core.service.impl;

import com.otilm.api.exception.ValidationException;
import com.otilm.api.model.client.cryptography.key.CompromiseKeyRequestDto;
import com.otilm.api.model.client.cryptography.key.KeyCompromiseReason;
import com.otilm.api.model.client.cryptography.key.UpdateKeyUsageRequestDto;
import com.otilm.api.model.core.cryptography.key.KeyState;
import com.otilm.api.model.core.cryptography.key.KeyUsage;
import com.otilm.core.config.cache.CacheEvictor;
import com.otilm.core.dao.entity.CryptographicKey;
import com.otilm.core.dao.entity.CryptographicKeyItem;
import com.otilm.core.dao.repository.CryptographicKeyRepository;
import com.otilm.core.model.crypto.ImmutableCryptographicKeyFullModel;
import com.otilm.core.service.CryptographicKeyEventHistoryService;
import com.otilm.core.service.handler.key.KeyProviderAdapterFactory;
import com.otilm.core.service.writer.CryptographicKeyWriter;
import java.util.List;
import java.util.Optional;
import java.util.UUID;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.function.Executable;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.EnumSource;

import static com.otilm.core.util.builders.CryptographicKeyBuilder.aCryptographicKey;
import static com.otilm.core.util.builders.CryptographicKeyItemBuilder.aKeyItem;
import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.verifyNoMoreInteractions;
import static org.mockito.Mockito.when;

class CryptographicKeyServiceImplSelectionTest {

    private final CryptographicKeyRepository repository = mock(CryptographicKeyRepository.class);
    private final CryptographicKeyWriter writer = mock(CryptographicKeyWriter.class);
    private final KeyProviderAdapterFactory adapters = mock(KeyProviderAdapterFactory.class);
    private final CryptographicKeyEventHistoryService history = mock(CryptographicKeyEventHistoryService.class);
    private final CacheEvictor cache = mock(CacheEvictor.class);
    private final CryptographicKeyServiceImpl service = new CryptographicKeyServiceImpl();
    private final CryptographicKey parent = key();
    private final CryptographicKeyItem first = item(parent);
    private final CryptographicKeyItem second = item(parent);
    private final KeyCompromiseReason reason = KeyCompromiseReason.UNAUTHORIZED_DISCLOSURE;
    private final List<KeyUsage> usages = List.of(KeyUsage.SIGN);

    @BeforeEach
    void setUp() {
        service.setCryptographicKeyRepository(repository);
        service.setCryptographicKeyWriter(writer);
        service.setKeyProviderAdapterFactory(adapters);
        service.setKeyEventHistoryService(history);
        service.setCacheEvictor(cache);
        loadParent();
    }

    @ParameterizedTest
    @EnumSource(Operation.class)
    void selection_rejectsForeignItemEvenWhenAllOwnedItemsArePresent(Operation operation) {
        // given
        CryptographicKey otherParent = key();
        CryptographicKeyItem foreignItem = item(otherParent);
        List<UUID> selection = List.of(first.getUuid(), second.getUuid(), foreignItem.getUuid());

        // when
        Executable mutate = () -> mutate(operation, selection);

        // then
        ValidationException failure = assertThrows(ValidationException.class, mutate);
        assertThat(failure.getMessage())
                .contains(parent.getUuid().toString(), foreignItem.getUuid().toString())
                .doesNotContain(otherParent.getUuid().toString());
        verifyNoInteractions(writer, adapters, history, cache);
    }

    @ParameterizedTest
    @EnumSource(Operation.class)
    void selection_rejectsMissingItemBeforeMutatingValidItems(Operation operation) {
        // given
        UUID missingItemUuid = UUID.randomUUID();
        List<UUID> selection = List.of(first.getUuid(), missingItemUuid);

        // when
        Executable mutate = () -> mutate(operation, selection);

        // then
        ValidationException failure = assertThrows(ValidationException.class, mutate);
        assertThat(failure.getMessage()).contains(missingItemUuid.toString(), "No key items were updated");
        verifyNoInteractions(writer, adapters, history, cache);
    }

    @ParameterizedTest
    @EnumSource(Operation.class)
    void selection_rejectsForeignItemWhenParentIsEmpty(Operation operation) {
        // given
        UUID foreignItemUuid = first.getUuid();
        parent.getItems().clear();
        loadParent();

        // when
        Executable mutate = () -> mutate(operation, List.of(foreignItemUuid));

        // then
        ValidationException failure = assertThrows(ValidationException.class, mutate);
        assertThat(failure.getMessage()).contains(parent.getUuid().toString(), foreignItemUuid.toString());
        verifyNoInteractions(writer, adapters, history, cache);
    }

    @ParameterizedTest
    @EnumSource(Operation.class)
    void selection_mutatesOnlyRequestedSubsetAndDeduplicates(Operation operation) throws Exception {
        // given
        List<UUID> selection = List.of(first.getUuid(), first.getUuid());

        // when
        mutate(operation, selection);

        // then
        verifyItemMutation(operation, first.getUuid());
        if (operation == Operation.DELETE) {
            verify(writer).deleteKeyIfEmpty(ImmutableCryptographicKeyFullModel.from(parent));
        }
        verifyNoMoreInteractions(writer);
    }

    @ParameterizedTest
    @EnumSource(Operation.class)
    void selection_mutatesAllItemsWhenEmpty(Operation operation) throws Exception {
        // given
        List<UUID> emptySelection = List.of();

        // when
        mutate(operation, emptySelection);

        // then
        verifyItemMutation(operation, first.getUuid());
        verifyItemMutation(operation, second.getUuid());
        if (operation == Operation.DELETE) {
            verify(writer).deleteKeyWithAssociations(ImmutableCryptographicKeyFullModel.from(parent));
        }
        verifyNoMoreInteractions(writer);
    }

    @ParameterizedTest
    @EnumSource(Operation.class)
    void selection_mutatesAllItemsWhenNull(Operation operation) throws Exception {
        // given
        List<UUID> omittedSelection = null;

        // when
        mutate(operation, omittedSelection);

        // then
        verifyItemMutation(operation, first.getUuid());
        verifyItemMutation(operation, second.getUuid());
        if (operation == Operation.DELETE) {
            verify(writer).deleteKeyWithAssociations(ImmutableCryptographicKeyFullModel.from(parent));
        }
        verifyNoMoreInteractions(writer);
    }

    private void mutate(Operation operation, List<UUID> selection) throws Exception {
        List<String> stringUuids = selection == null ? null : selection.stream().map(UUID::toString).toList();
        switch (operation) {
            case ENABLE -> service.enableKey(parent.getUuid(), stringUuids);
            case DISABLE -> service.disableKey(parent.getUuid(), stringUuids);
            case DELETE -> service.deleteKey(parent.getUuid(), stringUuids);
            case DESTROY -> service.destroyKey(parent.getUuid(), stringUuids);
            case COMPROMISE -> service.compromiseKey(parent.getUuid(), new CompromiseKeyRequestDto(reason, selection));
            case USAGE -> {
                UpdateKeyUsageRequestDto request = new UpdateKeyUsageRequestDto();
                request.setUuids(selection);
                request.setUsage(usages);
                service.updateKeyUsages(parent.getUuid(), request);
            }
        }
    }

    private void verifyItemMutation(Operation operation, UUID itemUuid) throws Exception {
        switch (operation) {
            case ENABLE -> verify(writer).setKeyItemEnabled(itemUuid, true);
            case DISABLE -> verify(writer).setKeyItemEnabled(itemUuid, false);
            case DELETE -> verify(writer).deleteKeyItem(itemUuid);
            case DESTROY -> verify(writer).finalizeKeyItemDestruction(itemUuid);
            case COMPROMISE -> verify(writer).setKeyItemCompromised(itemUuid, reason);
            case USAGE -> verify(writer).updateUsage(itemUuid, usages);
        }
    }

    private void loadParent() {
        when(repository.findFullModelByUuid(parent.getUuid()))
                .thenReturn(Optional.of(ImmutableCryptographicKeyFullModel.from(parent)));
    }

    private static CryptographicKey key() {
        CryptographicKey key = aCryptographicKey().build();
        key.setUuid(UUID.randomUUID());
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

    private enum Operation {
        ENABLE,
        DISABLE,
        DELETE,
        DESTROY,
        COMPROMISE,
        USAGE
    }
}
