package com.otilm.core.service.impl;

import com.otilm.api.exception.ConnectorException;
import com.otilm.api.exception.NotFoundException;
import com.otilm.api.exception.ValidationException;
import com.otilm.api.model.connector.cryptography.enums.TokenInstanceStatus;
import com.otilm.api.model.core.auth.Resource;
import com.otilm.api.model.core.cryptography.key.KeyEvent;
import com.otilm.api.model.core.cryptography.key.KeyEventStatus;
import com.otilm.api.model.core.cryptography.key.KeyState;
import com.otilm.core.config.cache.CacheConfig;
import com.otilm.core.config.cache.CacheEvictor;
import com.otilm.core.dao.entity.CryptographicKey;
import com.otilm.core.dao.entity.CryptographicKeyItem;
import com.otilm.core.dao.entity.TokenInstanceReference;
import com.otilm.core.dao.repository.CryptographicKeyItemRepository;
import com.otilm.core.dao.repository.CryptographicKeyRepository;
import com.otilm.core.model.auth.ResourceAction;
import com.otilm.core.model.crypto.CryptographicKeyFullModel;
import com.otilm.core.model.crypto.CryptographicKeyItemBasicModel;
import com.otilm.core.model.crypto.ImmutableCryptographicKeyFullModel;
import com.otilm.core.security.authz.AuthorizationEnforcer;
import com.otilm.core.security.authz.SecuredUUID;
import com.otilm.core.service.CryptographicKeyEventHistoryService;
import com.otilm.core.service.handler.key.KeyProviderAdapter;
import com.otilm.core.service.handler.key.KeyProviderAdapterFactory;
import com.otilm.core.service.writer.CryptographicKeyWriter;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Optional;
import java.util.UUID;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.function.Executable;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.EnumSource;
import org.springframework.security.access.AccessDeniedException;

import static com.otilm.core.util.builders.CryptographicKeyBuilder.aCryptographicKey;
import static com.otilm.core.util.builders.CryptographicKeyItemBuilder.aKeyItem;
import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.argThat;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.ArgumentMatchers.isNull;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.verifyNoMoreInteractions;
import static org.mockito.Mockito.when;

class CryptographicKeyServiceImplDestroyTest {

    private final CryptographicKeyRepository keys = mock(CryptographicKeyRepository.class);
    private final CryptographicKeyItemRepository items = mock(CryptographicKeyItemRepository.class);
    private final CryptographicKeyWriter writer = mock(CryptographicKeyWriter.class);
    private final KeyProviderAdapterFactory adapters = mock(KeyProviderAdapterFactory.class);
    private final KeyProviderAdapter adapter = mock(KeyProviderAdapter.class);
    private final CryptographicKeyEventHistoryService history = mock(CryptographicKeyEventHistoryService.class);
    private final CacheEvictor cache = mock(CacheEvictor.class);
    private final AuthorizationEnforcer authorization = mock(AuthorizationEnforcer.class);
    private final CryptographicKeyServiceImpl service = new CryptographicKeyServiceImpl();
    private final CryptographicKey firstParent = key("first-parent");
    private final CryptographicKey secondParent = key("second-parent");
    private final CryptographicKeyItem firstItem = item(firstParent, "first-item");
    private final CryptographicKeyItem siblingItem = item(firstParent, "sibling-item");
    private final CryptographicKeyItem laterParentItem = item(secondParent, "later-parent-item");

    @BeforeEach
    void setUp() throws Exception {
        service.setCryptographicKeyRepository(keys);
        service.setCryptographicKeyItemRepository(items);
        service.setCryptographicKeyWriter(writer);
        service.setKeyProviderAdapterFactory(adapters);
        service.setKeyEventHistoryService(history);
        service.setCacheEvictor(cache);
        service.setAuthorizationEnforcer(authorization);
        loadParents();
    }

    @ParameterizedTest
    @EnumSource(Operation.class)
    void destroy_connectorFailure_reportsSafeFailureAfterProcessingRemainingSelection(Operation operation)
            throws Exception {
        // given
        String sensitiveFailure = "Connector credential secret-token at private-host";
        CryptographicKeyFullModel parent = model(firstParent);
        doThrow(new ConnectorException(sensitiveFailure))
                .when(adapter)
                .destroyKeyItem(parent, model(firstItem).reference());

        // when
        Executable destroy = () -> destroy(operation);

        // then
        ValidationException failure = assertThrows(ValidationException.class, destroy);
        assertFailureSummary(failure, operation, sensitiveFailure);
        verify(writer, never()).finalizeKeyItemDestruction(firstItem.getUuid());
        verifyCompletedRemainder(operation);
    }

    @ParameterizedTest
    @EnumSource(Operation.class)
    void destroy_invalidState_reportsRejectionAfterProcessingRemainingSelection(Operation operation) throws Exception {
        // given
        KeyState forbiddenState = KeyState.ACTIVE;
        firstItem.setState(forbiddenState);
        loadParents();

        // when
        Executable destroy = () -> destroy(operation);

        // then
        ValidationException failure = assertThrows(ValidationException.class, destroy);
        assertFailureSummary(failure, operation);
        assertThat(failure.getMessage()).contains(forbiddenState.getLabel());
        verify(adapter, never()).destroyKeyItem(model(firstParent), model(firstItem).reference());
        verify(writer, never()).finalizeKeyItemDestruction(firstItem.getUuid());
        verifyCompletedRemainder(operation);
    }

    @ParameterizedTest
    @EnumSource(Operation.class)
    void destroy_localFailureAfterRemoteDestruction_reportsPartialOutcomeAndContinues(Operation operation)
            throws Exception {
        // given
        String sensitiveFailure = "SQL insert into key_event_history failed for internal_column";
        doThrow(new IllegalStateException(sensitiveFailure))
                .when(writer)
                .finalizeKeyItemDestruction(firstItem.getUuid());

        // when
        Executable destroy = () -> destroy(operation);

        // then
        ValidationException failure = assertThrows(ValidationException.class, destroy);
        assertFailureSummary(failure, operation, sensitiveFailure);
        assertThat(failure.getMessage()).contains("destroyed remotely", "local");
        verify(adapter).destroyKeyItem(model(firstParent), model(firstItem).reference());
        verify(cache, never()).evict(CacheConfig.CRYPTOGRAPHIC_KEY_ITEM_CACHE, firstItem.getUuid());
        verifyCompletedRemainder(operation);
    }

    @ParameterizedTest
    @EnumSource(Operation.class)
    void destroy_failureWritingRejectedStateHistory_reportsFailureAndContinues(Operation operation) throws Exception {
        // given
        String sensitiveFailure = "SQL insert into audit_history leaked_table failed";
        firstItem.setState(KeyState.ACTIVE);
        loadParents();
        doThrow(new IllegalStateException(sensitiveFailure))
                .when(history)
                .addEventHistory(eq(KeyEvent.DESTROY), eq(KeyEventStatus.FAILED), anyString(), isNull(),
                        eq(firstItem.getUuid()));

        // when
        Executable destroy = () -> destroy(operation);

        // then
        ValidationException failure = assertThrows(ValidationException.class, destroy);
        assertFailureSummary(failure, operation, sensitiveFailure);
        verify(adapter, never()).destroyKeyItem(model(firstParent), model(firstItem).reference());
        verifyCompletedRemainder(operation);
    }

    @Test
    void destroy_localOnlyWriterFailure_reportsSafeFailureAndContinues() throws Exception {
        // given
        String sensitiveFailure = "SQL delete from cryptographic_key_item internal details";
        firstParent.setTokenInstanceReference(null);
        loadParents();
        doThrow(new IllegalStateException(sensitiveFailure))
                .when(writer)
                .finalizeKeyItemDestruction(firstItem.getUuid());

        // when
        Executable destroy = () -> destroy(Operation.SELECTED_ITEMS);

        // then
        ValidationException failure = assertThrows(ValidationException.class, destroy);
        assertFailureSummary(failure, Operation.SELECTED_ITEMS, sensitiveFailure);
        assertThat(failure.getMessage()).doesNotContain("destroyed remotely");
        verify(writer).finalizeKeyItemDestruction(siblingItem.getUuid());
        verify(cache).evict(CacheConfig.CRYPTOGRAPHIC_KEY_ITEM_CACHE, siblingItem.getUuid());
        verifyNoInteractions(adapter);
    }

    @Test
    void destroy_cacheFailureAfterRemoteDestruction_reportsPartialOutcomeAndContinues() throws Exception {
        // given
        String sensitiveFailure = "Redis password secret at internal-host";
        doThrow(new IllegalStateException(sensitiveFailure))
                .when(cache)
                .evict(CacheConfig.CRYPTOGRAPHIC_KEY_ITEM_CACHE, firstItem.getUuid());

        // when
        Executable destroy = () -> destroy(Operation.SELECTED_ITEMS);

        // then
        ValidationException failure = assertThrows(ValidationException.class, destroy);
        assertFailureSummary(failure, Operation.SELECTED_ITEMS, sensitiveFailure);
        assertThat(failure.getMessage()).contains("was destroyed", "cache invalidation failed");
        verify(writer).finalizeKeyItemDestruction(firstItem.getUuid());
        verifyCompletedRemainder(Operation.SELECTED_ITEMS);
    }

    @Test
    void destroyParents_mixedFailures_reportsBothCategoriesAndCountsSuccessesAcrossParents() throws Exception {
        // given
        String sensitiveFailure = "Connector response exposes private-system-details";
        int completedItemsAcrossParents = 2;
        firstItem.setState(KeyState.ACTIVE);
        CryptographicKey thirdParent = key("third-parent");
        CryptographicKeyItem thirdParentItem = item(thirdParent, "third-parent-item");
        loadParents();
        loadParent(thirdParent);
        doThrow(new ConnectorException(sensitiveFailure))
                .when(adapter)
                .destroyKeyItem(model(secondParent), model(laterParentItem).reference());
        List<String> selectedParents = List
                .of(firstParent.getUuid().toString(), secondParent.getUuid().toString(),
                        thirdParent.getUuid().toString());

        // when
        Executable destroy = () -> service.destroyKey(selectedParents);

        // then
        ValidationException failure = assertThrows(ValidationException.class, destroy);
        assertThat(failure.getMessage())
                .contains(firstItem.getUuid().toString(), KeyState.ACTIVE.getLabel(),
                        laterParentItem.getUuid().toString(),
                        "Successfully destroyed key items in this batch: %d.".formatted(completedItemsAcrossParents))
                .doesNotContain(sensitiveFailure);
        verify(writer).finalizeKeyItemDestruction(siblingItem.getUuid());
        verify(writer).finalizeKeyItemDestruction(thirdParentItem.getUuid());
        verify(cache).evict(CacheConfig.CRYPTOGRAPHIC_KEY_ITEM_CACHE, siblingItem.getUuid());
        verify(cache).evict(CacheConfig.CRYPTOGRAPHIC_KEY_ITEM_CACHE, thirdParentItem.getUuid());
    }

    @Test
    void destroyParents_duplicateParent_destroysEachItemOnce() throws Exception {
        // given
        String selectedParentUuid = firstParent.getUuid().toString();
        List<String> duplicateSelection = List.of(selectedParentUuid, selectedParentUuid);

        // when
        service.destroyKey(duplicateSelection);

        // then
        verifyCompletedRemainder(Operation.SELECTED_ITEMS);
        verify(adapter).destroyKeyItem(model(firstParent), model(firstItem).reference());
        verify(writer).finalizeKeyItemDestruction(firstItem.getUuid());
        verify(cache).evict(CacheConfig.CRYPTOGRAPHIC_KEY_ITEM_CACHE, firstItem.getUuid());
        verifyNoMoreInteractions(adapter, writer, cache);
    }

    @ParameterizedTest
    @EnumSource(Operation.class)
    void destroy_validSelection_finalizesEveryEligibleItem(Operation operation) throws Exception {
        // given
        KeyState compromisedState = KeyState.COMPROMISED;
        siblingItem.setState(compromisedState);
        laterParentItem.setState(KeyState.DEACTIVATED);
        loadParents();

        // when
        destroy(operation);

        // then
        verify(writer).finalizeKeyItemDestruction(firstItem.getUuid());
        verify(writer).finalizeKeyItemDestruction(siblingItem.getUuid());
        for (CryptographicKeyItem item : selectedItems(operation)) {
            verify(adapter).destroyKeyItem(model(item.getKey()), model(item).reference());
            verify(cache).evict(CacheConfig.CRYPTOGRAPHIC_KEY_ITEM_CACHE, item.getUuid());
        }
        if (operation != Operation.SELECTED_ITEMS) {
            verify(writer).finalizeKeyItemDestruction(laterParentItem.getUuid());
        }
    }

    @Test
    void destroyParents_deniedLaterParent_preventsDestructionOfEverySelectedParent() {
        // given
        UUID deniedTokenUuid = secondParent.getTokenInstanceReferenceUuid();
        doThrow(new AccessDeniedException("Denied for test"))
                .when(authorization)
                .enforce(eq(Resource.TOKEN), eq(ResourceAction.DETAIL),
                        argThat((SecuredUUID uuid) -> deniedTokenUuid.equals(uuid.getValue())));

        // when
        Executable destroy = () -> destroy(Operation.PARENTS);

        // then
        assertThrows(AccessDeniedException.class, destroy);
        verifyNoInteractions(adapter, writer, history, cache);
    }

    @Test
    void destroyParents_missingLaterParent_preventsDestructionOfEverySelectedParent() {
        // given
        UUID missingParentUuid = secondParent.getUuid();
        when(keys.findFullModelByUuid(missingParentUuid)).thenReturn(Optional.empty());

        // when
        Executable destroy = () -> destroy(Operation.PARENTS);

        // then
        assertThrows(NotFoundException.class, destroy);
        verifyNoInteractions(adapter, writer, history, cache);
    }

    @ParameterizedTest
    @EnumSource(value = Operation.class, names = {"PARENTS", "BULK_ITEMS"})
    void destroy_emptyBulkSelection_hasNoSideEffects(Operation operation) throws Exception {
        // given
        List<String> emptySelection = List.of();

        // when
        if (operation == Operation.PARENTS) {
            service.destroyKey(emptySelection);
        } else {
            service.destroyKeyItems(emptySelection);
        }

        // then
        verifyNoInteractions(keys, items, authorization, adapter, writer, history, cache);
    }

    private void destroy(Operation operation) throws Exception {
        List<CryptographicKeyItem> selectedItems = selectedItems(operation);
        List<String> selectedItemUuids = selectedItems.stream().map(item -> item.getUuid().toString()).toList();
        switch (operation) {
            case SELECTED_ITEMS -> service.destroyKey(firstParent.getUuid(), selectedItemUuids);
            case PARENTS ->
                service.destroyKey(List.of(firstParent.getUuid().toString(), secondParent.getUuid().toString()));
            case BULK_ITEMS -> {
                List<UUID> selectedUuids = selectedItems.stream().map(CryptographicKeyItem::getUuid).toList();
                when(items.findBasicModelsByUuidIn(selectedUuids))
                        .thenReturn(selectedItems.stream().map(CryptographicKeyItemBasicModel::from).toList());
                service.destroyKeyItems(selectedItemUuids);
            }
        }
    }

    private List<CryptographicKeyItem> selectedItems(Operation operation) {
        return operation == Operation.SELECTED_ITEMS
                ? List.of(firstItem, siblingItem)
                : List.of(firstItem, siblingItem, laterParentItem);
    }

    private void assertFailureSummary(ValidationException failure, Operation operation) {
        int completedItems = selectedItems(operation).size() - 1;
        String completionSummary = "Successfully destroyed key items in this batch: %d.".formatted(completedItems);
        assertThat(failure.getMessage()).contains(firstItem.getUuid().toString(), completionSummary);
    }

    private void assertFailureSummary(ValidationException failure, Operation operation, String sensitiveDetail) {
        assertFailureSummary(failure, operation);
        assertThat(failure.getMessage()).doesNotContain(sensitiveDetail);
    }

    private void verifyCompletedRemainder(Operation operation) throws Exception {
        for (CryptographicKeyItem item : selectedItems(operation).subList(1, selectedItems(operation).size())) {
            verify(adapter).destroyKeyItem(model(item.getKey()), model(item).reference());
            verify(writer).finalizeKeyItemDestruction(item.getUuid());
            verify(cache).evict(CacheConfig.CRYPTOGRAPHIC_KEY_ITEM_CACHE, item.getUuid());
        }
    }

    private void loadParents() throws Exception {
        for (CryptographicKey parent : List.of(firstParent, secondParent)) {
            loadParent(parent);
        }
    }

    private void loadParent(CryptographicKey parent) throws Exception {
        CryptographicKeyFullModel key = model(parent);
        when(keys.findFullModelByUuid(key.uuid())).thenReturn(Optional.of(key));
        if (key.tokenInstance() != null) {
            when(adapters.forToken(key.tokenInstance())).thenReturn(adapter);
        }
    }

    private static CryptographicKey key(String name) {
        CryptographicKey key = aCryptographicKey().withName(name).build();
        key.setUuid(UUID.randomUUID());
        key.setItems(new LinkedHashSet<>());
        TokenInstanceReference token = new TokenInstanceReference();
        token.setUuid(UUID.randomUUID());
        token.setTokenInstanceUuid(UUID.randomUUID().toString());
        token.setStatus(TokenInstanceStatus.CONNECTED);
        key.setTokenInstanceReference(token);
        return key;
    }

    private static CryptographicKeyItem item(CryptographicKey parent, String name) {
        CryptographicKeyItem item = aKeyItem().withName(name).withState(KeyState.PRE_ACTIVE).build();
        item.setUuid(UUID.randomUUID());
        item.setKey(parent);
        item.setKeyReferenceUuid(UUID.randomUUID());
        item.setUsage(List.of());
        parent.getItems().add(item);
        return item;
    }

    private static CryptographicKeyFullModel model(CryptographicKey key) {
        return ImmutableCryptographicKeyFullModel.from(key);
    }

    private static CryptographicKeyItemBasicModel model(CryptographicKeyItem item) {
        return CryptographicKeyItemBasicModel.from(item);
    }

    private enum Operation {
        SELECTED_ITEMS,
        PARENTS,
        BULK_ITEMS
    }
}
