package com.otilm.core.service.impl;

import com.otilm.api.exception.ValidationError;
import com.otilm.api.exception.ValidationException;
import com.otilm.api.model.client.connector.v2.FeatureFlag;
import com.otilm.api.model.common.BulkActionMessageDto;
import com.otilm.api.model.common.enums.cryptography.KeyType;
import com.otilm.api.model.core.auth.Resource;
import com.otilm.api.model.core.cryptography.key.KeyState;
import com.otilm.core.config.cache.CacheConfig;
import com.otilm.core.config.cache.CacheEvictor;
import com.otilm.core.dao.repository.CryptographicKeyRepository;
import com.otilm.core.model.auth.ResourceAction;
import com.otilm.core.model.crypto.CryptographicKeyFullModel;
import com.otilm.core.model.crypto.CryptographicKeyItemBasicModel;
import com.otilm.core.model.crypto.KeyRemovalCandidate;
import com.otilm.core.security.authz.AuthorizationEnforcer;
import com.otilm.core.security.authz.SecuredUUID;
import com.otilm.core.service.handler.ConnectorCapabilityService;
import com.otilm.core.service.handler.KeyImportGates;
import com.otilm.core.service.handler.KeyListGates;
import com.otilm.core.service.handler.KeyRemovalGates;
import com.otilm.core.service.handler.key.KeyProviderAdapterFactory;
import com.otilm.core.service.writer.CryptographicKeyWriter;
import com.otilm.core.util.builders.CryptographicKeyFullModelBuilder;
import java.util.Arrays;
import java.util.Collection;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import java.util.stream.Collectors;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.EnumSource;
import org.springframework.security.access.AccessDeniedException;

import static com.otilm.core.service.handler.KeyRemovalGates.COMPROMISED;
import static com.otilm.core.service.handler.KeyRemovalGates.NO_PRIVATE_KEY_IN_TOKEN;
import static com.otilm.core.service.handler.KeyRemovalGates.TOKEN_NOT_LISTABLE;
import static com.otilm.core.service.impl.CryptographicKeyServiceImpl.NOT_REMOVABLE;
import static com.otilm.core.util.builders.CryptographicKeyFullModelBuilder.aKeySnapshot;
import static com.otilm.core.util.builders.CryptographicKeyItemBasicModelBuilder.aKeyItemSnapshot;
import static com.otilm.core.util.builders.TokenInstanceFullModelBuilder.aTokenSnapshot;
import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.anyCollection;
import static org.mockito.ArgumentMatchers.argThat;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.verifyNoMoreInteractions;
import static org.mockito.Mockito.when;

class CryptographicKeyServiceImplRemoveFromInventoryTest {

    private final CryptographicKeyRepository keys = mock(CryptographicKeyRepository.class);
    private final CryptographicKeyWriter writer = mock(CryptographicKeyWriter.class);
    private final KeyProviderAdapterFactory adapters = mock(KeyProviderAdapterFactory.class);
    private final CacheEvictor cache = mock(CacheEvictor.class);
    private final AuthorizationEnforcer authorization = mock(AuthorizationEnforcer.class);
    private final CryptographicKeyServiceImpl service = new CryptographicKeyServiceImpl();
    private final Map<UUID, KeyRemovalCandidate> inventory = new HashMap<>();

    @BeforeEach
    void wireService() {
        service.setCryptographicKeyRepository(keys);
        service.setCryptographicKeyWriter(writer);
        service.setKeyProviderAdapterFactory(adapters);
        service.setCacheEvictor(cache);
        service.setAuthorizationEnforcer(authorization);
        service
                .setKeyRemovalGates(new KeyRemovalGates(
                        new KeyListGates(mock(KeyImportGates.class), new ConnectorCapabilityService())));
        when(keys.findRemovalCandidatesByUuidIn(anyCollection()))
                .thenAnswer(read -> read
                        .<Collection<UUID>>getArgument(0)
                        .stream()
                        .filter(inventory::containsKey)
                        .map(inventory::get)
                        .toList());
    }

    // ── Helpers ───────────────────────────────────────────────────────────────

    /** A key pair with both items active, on a token whose connector lists keys, so it is removable. */
    private static CryptographicKeyFullModelBuilder aKeyPair(String name) {
        return aKeySnapshot()
                .withName(name)
                .withTokenInstance(aTokenSnapshot().withConnectorFeatures(FeatureFlag.KEY_LIST).build())
                .withItems(pairItems(KeyState.ACTIVE, KeyState.ACTIVE));
    }

    private static List<CryptographicKeyItemBasicModel> pairItems(KeyState privateKeyState, KeyState publicKeyState) {
        var privateKey = aKeyItemSnapshot().withType(KeyType.PRIVATE_KEY).withState(privateKeyState).build();
        var publicKey = aKeyItemSnapshot().withType(KeyType.PUBLIC_KEY).withState(publicKeyState).build();
        return List.of(privateKey, publicKey);
    }

    private void inventoryHolds(CryptographicKeyFullModel... held) {
        for (CryptographicKeyFullModel key : held) {
            inventory.put(key.uuid(), KeyRemovalCandidate.from(key));
        }
    }

    private void denyOnTheKey(ResourceAction action, CryptographicKeyFullModel key) {
        denyOn(Resource.CRYPTOGRAPHIC_KEY, action, key.uuid());
    }

    private void denyOnItsToken(ResourceAction action, CryptographicKeyFullModel key) {
        denyOn(Resource.TOKEN, action, key.tokenInstanceReferenceUuid());
    }

    private void denyOn(Resource resource, ResourceAction action, UUID deniedUuid) {
        doThrow(new AccessDeniedException("Denied for test"))
                .when(authorization)
                .enforce(eq(resource), eq(action), argThat((SecuredUUID uuid) -> deniedUuid.equals(uuid.getValue())));
    }

    private static void assertReported(List<BulkActionMessageDto> report, CryptographicKeyFullModel key,
            String reason) {
        assertThat(report).singleElement().satisfies(entry -> {
            assertThat(entry.getUuid()).isEqualTo(key.uuid().toString());
            assertThat(entry.getName()).isEqualTo(key.name());
            assertThat(entry.getMessage()).isEqualTo(reason);
        });
    }

    private void verifyRemoved(CryptographicKeyFullModel key) {
        verify(writer).removeFromInventoryAsRead(key, itemStatesOf(key));
        for (CryptographicKeyItemBasicModel item : key.items()) {
            verify(cache).evict(CacheConfig.CRYPTOGRAPHIC_KEY_ITEM_CACHE, item.uuid());
        }
    }

    private static Map<UUID, KeyState> itemStatesOf(CryptographicKeyFullModel key) {
        return key
                .items()
                .stream()
                .collect(Collectors.toMap(CryptographicKeyItemBasicModel::uuid, CryptographicKeyItemBasicModel::state));
    }

    private static List<String> uuidsOf(CryptographicKeyFullModel... selected) {
        return Arrays.stream(selected).map(key -> key.uuid().toString()).toList();
    }

    // ── RemoveKeysFromInventory ───────────────────────────────────────────────

    @Nested
    class RemoveKeysFromInventory {

        @Test
        void removesEachKeyWithoutTheConnector_whenTheirTokensListKeys() {
            // given
            var first = aKeyPair("first-pair").build();
            var second = aKeyPair("second-pair").build();
            inventoryHolds(first, second);

            // when
            List<BulkActionMessageDto> report = service.removeKeysFromInventory(uuidsOf(first, second));

            // then
            assertThat(report).isEmpty();
            verifyRemoved(first);
            verifyRemoved(second);
            verifyNoInteractions(adapters);
        }

        @Test
        void reportsAndKeepsTheKey_whenItHoldsNoPrivateKeyInAToken() {
            // given
            var removable = aKeyPair("removable-pair").build();
            var publicKeyOnly = aKeySnapshot()
                    .withName("public-key-only")
                    .withItems(List.of(aKeyItemSnapshot().withType(KeyType.PUBLIC_KEY).build()))
                    .build();
            inventoryHolds(removable, publicKeyOnly);

            // when
            List<BulkActionMessageDto> report = service.removeKeysFromInventory(uuidsOf(removable, publicKeyOnly));

            // then
            assertReported(report, publicKeyOnly, NO_PRIVATE_KEY_IN_TOKEN);
            verifyRemoved(removable);
            verifyNoMoreInteractions(writer, cache);
        }

        @Test
        void reportsAndKeepsTheKey_whenItsConnectorListsNoKeys() {
            // given
            var removable = aKeyPair("removable-pair").build();
            var tokenListingNoKeys = aTokenSnapshot().build();
            var unlistable = aKeyPair("unlistable-pair").withTokenInstance(tokenListingNoKeys).build();
            inventoryHolds(removable, unlistable);

            // when
            List<BulkActionMessageDto> report = service.removeKeysFromInventory(uuidsOf(removable, unlistable));

            // then
            assertReported(report, unlistable, TOKEN_NOT_LISTABLE);
            verifyRemoved(removable);
            verifyNoMoreInteractions(writer, cache);
        }

        @Test
        void reportsAndKeepsTheKey_whenAnItemIsCompromised() {
            // given
            var removable = aKeyPair("removable-pair").build();
            var compromised = aKeyPair("compromised-pair")
                    .withItems(pairItems(KeyState.COMPROMISED, KeyState.ACTIVE))
                    .build();
            inventoryHolds(removable, compromised);

            // when
            List<BulkActionMessageDto> report = service.removeKeysFromInventory(uuidsOf(removable, compromised));

            // then
            assertReported(report, compromised, COMPROMISED);
            verifyRemoved(removable);
            verifyNoMoreInteractions(writer, cache);
        }

        @ParameterizedTest
        @EnumSource(value = KeyState.class, names = {"DESTROYED", "DESTROYED_COMPROMISED"})
        void reportsNoPrivateKeyInAToken_whenThePrivateKeyWasDestroyed(KeyState destroyedState) {
            // given
            var destroyed = aKeyPair("destroyed-pair").withItems(pairItems(destroyedState, KeyState.ACTIVE)).build();
            inventoryHolds(destroyed);

            // when
            List<BulkActionMessageDto> report = service.removeKeysFromInventory(uuidsOf(destroyed));

            // then
            assertReported(report, destroyed, NO_PRIVATE_KEY_IN_TOKEN);
            verifyNoInteractions(writer, cache);
        }

        @Test
        void reportsItCompromised_whenThePublicKeyWasDestroyedAsCompromised() {
            // given
            var publicKeyDestroyed = aKeyPair("public-key-destroyed-pair")
                    .withItems(pairItems(KeyState.ACTIVE, KeyState.DESTROYED_COMPROMISED))
                    .build();
            inventoryHolds(publicKeyDestroyed);

            // when
            List<BulkActionMessageDto> report = service.removeKeysFromInventory(uuidsOf(publicKeyDestroyed));

            // then
            assertReported(report, publicKeyDestroyed, COMPROMISED);
            verifyNoInteractions(writer, cache);
        }

        @Test
        void reportsItNotFound_whenTheKeyIsUnknown() {
            // given
            var removable = aKeyPair("removable-pair").build();
            inventoryHolds(removable);
            var unknownUuid = UUID.randomUUID().toString();

            // when
            List<BulkActionMessageDto> report = service
                    .removeKeysFromInventory(List.of(unknownUuid, removable.uuid().toString()));

            // then
            assertThat(report).singleElement().satisfies(entry -> {
                assertThat(entry.getUuid()).isEqualTo(unknownUuid);
                assertThat(entry.getName()).isEqualTo(unknownUuid);
                assertThat(entry.getMessage()).isEqualTo("Key not found");
            });
            verifyRemoved(removable);
        }

        @Test
        void removesTheKeyOnce_whenTheSelectionRepeatsIt() {
            // given
            var removable = aKeyPair("removable-pair").build();
            inventoryHolds(removable);

            // when
            List<BulkActionMessageDto> report = service.removeKeysFromInventory(uuidsOf(removable, removable));

            // then
            assertThat(report).isEmpty();
            verifyRemoved(removable);
            verifyNoMoreInteractions(writer, cache);
        }

        @Test
        void refusesTheSelectionAndRemovesNothing_whenALaterKeyMayNotBeDeleted() {
            // given
            var first = aKeyPair("first-pair").build();
            var undeletable = aKeyPair("undeletable-pair").build();
            inventoryHolds(first, undeletable);
            denyOnTheKey(ResourceAction.DELETE, undeletable);
            List<String> selection = uuidsOf(first, undeletable);

            // when / then
            assertThatThrownBy(() -> service.removeKeysFromInventory(selection))
                    .isInstanceOf(AccessDeniedException.class);
            verifyNoInteractions(writer, cache);
        }

        @Test
        void refusesTheSelectionAndRemovesNothing_whenALaterKeysTokenMembersMayNotBeManaged() {
            // given
            var first = aKeyPair("first-pair").build();
            var onAForbiddenToken = aKeyPair("forbidden-token-pair").build();
            inventoryHolds(first, onAForbiddenToken);
            denyOnItsToken(ResourceAction.MEMBERS, onAForbiddenToken);
            List<String> selection = uuidsOf(first, onAForbiddenToken);

            // when / then
            assertThatThrownBy(() -> service.removeKeysFromInventory(selection))
                    .isInstanceOf(AccessDeniedException.class);
            verifyNoInteractions(writer, cache);
        }

        @Test
        void reportsTheFailureSafelyAndRemovesTheOthers_whenTheWriterFails() {
            // given
            var failing = aKeyPair("failing-pair").build();
            var removable = aKeyPair("removable-pair").build();
            inventoryHolds(failing, removable);
            var sensitiveFailure = "SQL delete from cryptographic_key failed for internal_column";
            doThrow(new IllegalStateException(sensitiveFailure))
                    .when(writer)
                    .removeFromInventoryAsRead(failing, itemStatesOf(failing));

            // when
            List<BulkActionMessageDto> report = service.removeKeysFromInventory(uuidsOf(failing, removable));

            // then
            assertThat(report).singleElement().satisfies(entry -> {
                assertThat(entry.getUuid()).isEqualTo(failing.uuid().toString());
                assertThat(entry.getName()).isEqualTo(failing.name());
                assertThat(entry.getMessage()).isNotBlank().doesNotContain(sensitiveFailure);
            });
            for (CryptographicKeyItemBasicModel item : failing.items()) {
                verify(cache, never()).evict(CacheConfig.CRYPTOGRAPHIC_KEY_ITEM_CACHE, item.uuid());
            }
            verifyRemoved(removable);
        }

        @Test
        void reportsTheRejectionAndRemovesTheOthers_whenTheWriterRejects() {
            // given
            var changed = aKeyPair("changed-pair").build();
            var removable = aKeyPair("removable-pair").build();
            inventoryHolds(changed, removable);
            var keyChanged = "Key %s changed meanwhile. Try again.".formatted(changed.uuid());
            doThrow(new ValidationException(ValidationError.create(keyChanged)))
                    .when(writer)
                    .removeFromInventoryAsRead(changed, itemStatesOf(changed));

            // when
            List<BulkActionMessageDto> report = service.removeKeysFromInventory(uuidsOf(changed, removable));

            // then
            assertThat(report).singleElement().satisfies(entry -> {
                assertThat(entry.getUuid()).isEqualTo(changed.uuid().toString());
                assertThat(entry.getMessage()).isEqualTo(keyChanged);
            });
            verifyRemoved(removable);
        }
    }

    // ── RemoveKeyFromInventory ────────────────────────────────────────────────

    @Nested
    class RemoveKeyFromInventory {

        @Test
        void removesTheKeyWithoutTheConnector_whenItsTokenListsKeys() throws Exception {
            // given
            var removable = aKeyPair("removable-pair").build();
            inventoryHolds(removable);

            // when
            service.removeKeyFromInventory(SecuredUUID.fromUUID(removable.uuid()));

            // then
            verifyRemoved(removable);
            verifyNoInteractions(adapters);
        }

        @Test
        void refusesWithTheReason_whenAnItemIsCompromised() {
            // given
            var compromised = aKeyPair("compromised-pair")
                    .withItems(pairItems(KeyState.COMPROMISED, KeyState.ACTIVE))
                    .build();
            inventoryHolds(compromised);
            SecuredUUID compromisedUuid = SecuredUUID.fromUUID(compromised.uuid());

            // when / then
            assertThatThrownBy(() -> service.removeKeyFromInventory(compromisedUuid))
                    .isInstanceOf(ValidationException.class)
                    .hasMessageContaining(NOT_REMOVABLE.formatted(compromised.name(), COMPROMISED));
            verifyNoInteractions(writer, cache);
        }
    }
}
