package com.otilm.core.service.impl;

import com.otilm.api.exception.ValidationError;
import com.otilm.api.exception.ValidationException;
import com.otilm.api.model.client.connector.v2.FeatureFlag;
import com.otilm.api.model.common.BulkActionMessageDto;
import com.otilm.api.model.common.enums.cryptography.KeyType;
import com.otilm.api.model.connector.cryptography.enums.TokenInstanceStatus;
import com.otilm.api.model.core.auth.Resource;
import com.otilm.api.model.core.cryptography.key.KeyState;
import com.otilm.core.config.cache.CacheConfig;
import com.otilm.core.config.cache.CacheEvictor;
import com.otilm.core.dao.entity.ConnectorInterfaceEntity;
import com.otilm.core.dao.entity.CryptographicKey;
import com.otilm.core.dao.entity.CryptographicKeyItem;
import com.otilm.core.dao.entity.TokenInstanceReference;
import com.otilm.core.dao.repository.CryptographicKeyRepository;
import com.otilm.core.model.auth.ResourceAction;
import com.otilm.core.model.crypto.CryptographicKeyFullModel;
import com.otilm.core.model.crypto.CryptographicKeyItemBasicModel;
import com.otilm.core.model.crypto.ImmutableCryptographicKeyFullModel;
import com.otilm.core.security.authz.AuthorizationEnforcer;
import com.otilm.core.security.authz.SecuredUUID;
import com.otilm.core.service.handler.ConnectorCapabilityService;
import com.otilm.core.service.handler.KeyImportGates;
import com.otilm.core.service.handler.KeyListGates;
import com.otilm.core.service.handler.key.KeyProviderAdapterFactory;
import com.otilm.core.service.writer.CryptographicKeyWriter;
import java.util.Arrays;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.UUID;
import java.util.stream.Collectors;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.function.Executable;
import org.springframework.security.access.AccessDeniedException;

import static com.otilm.core.util.builders.CryptographicKeyBuilder.aCryptographicKey;
import static com.otilm.core.util.builders.CryptographicKeyItemBuilder.aKeyItem;
import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.tuple;
import static org.junit.jupiter.api.Assertions.assertThrows;
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

    private static final List<FeatureFlag> LISTS_KEYS = List.of(FeatureFlag.KEY_LIST);
    private static final List<FeatureFlag> LISTS_NO_KEYS = List.of();

    private final CryptographicKeyRepository keys = mock(CryptographicKeyRepository.class);
    private final CryptographicKeyWriter writer = mock(CryptographicKeyWriter.class);
    private final KeyProviderAdapterFactory adapters = mock(KeyProviderAdapterFactory.class);
    private final CacheEvictor cache = mock(CacheEvictor.class);
    private final AuthorizationEnforcer authorization = mock(AuthorizationEnforcer.class);
    private final CryptographicKeyServiceImpl service = new CryptographicKeyServiceImpl();
    private final CryptographicKeyFullModel firstPair = keyPair("first-pair", LISTS_KEYS, KeyState.ACTIVE);
    private final CryptographicKeyFullModel secondPair = keyPair("second-pair", LISTS_KEYS, KeyState.ACTIVE);
    private final CryptographicKeyFullModel unlistablePair = keyPair("unlistable-pair", LISTS_NO_KEYS, KeyState.ACTIVE);
    private final CryptographicKeyFullModel compromisedPair = keyPair("compromised-pair", LISTS_KEYS,
            KeyState.COMPROMISED);
    private final CryptographicKeyFullModel publicKeyOnly = publicKeyOnly("public-key-only");

    @BeforeEach
    void setUp() {
        service.setCryptographicKeyRepository(keys);
        service.setCryptographicKeyWriter(writer);
        service.setKeyProviderAdapterFactory(adapters);
        service.setCacheEvictor(cache);
        service.setAuthorizationEnforcer(authorization);
        service.setKeyListGates(new KeyListGates(mock(KeyImportGates.class), new ConnectorCapabilityService()));
        for (CryptographicKeyFullModel key : List
                .of(firstPair, secondPair, unlistablePair, compromisedPair, publicKeyOnly)) {
            when(keys.findFullModelByUuid(key.uuid())).thenReturn(Optional.of(key));
        }
    }

    @Test
    void removeKeys_keyPairsOnTokensThatListKeys_removesEachWithoutCallingTheConnector() {
        // given
        List<String> selection = uuidsOf(firstPair, secondPair);

        // when
        List<BulkActionMessageDto> report = service.removeKeysFromInventory(selection);

        // then
        assertThat(report).isEmpty();
        verifyRemoved(firstPair);
        verifyRemoved(secondPair);
        verifyNoInteractions(adapters);
    }

    @Test
    void removeKeys_keyWithoutAPrivateKeyInAToken_reportsItsNameAndReasonAndLeavesIt() {
        // when
        List<BulkActionMessageDto> report = service.removeKeysFromInventory(uuidsOf(firstPair, publicKeyOnly));

        // then
        assertReported(report, publicKeyOnly, CryptographicKeyServiceImpl.NO_PRIVATE_KEY_IN_TOKEN);
        verifyRemoved(firstPair);
        verifyNoMoreInteractions(writer, cache);
    }

    @Test
    void removeKeys_keyOnATokenWhoseConnectorListsNoKeys_reportsItAndLeavesIt() {
        // when
        List<BulkActionMessageDto> report = service.removeKeysFromInventory(uuidsOf(firstPair, unlistablePair));

        // then
        assertReported(report, unlistablePair, CryptographicKeyServiceImpl.TOKEN_NOT_LISTABLE);
        verifyRemoved(firstPair);
        verifyNoMoreInteractions(writer, cache);
    }

    @Test
    void removeKeys_keyWithACompromisedItem_reportsItAndLeavesIt() {
        // when
        List<BulkActionMessageDto> report = service.removeKeysFromInventory(uuidsOf(firstPair, compromisedPair));

        // then
        assertReported(report, compromisedPair, CryptographicKeyServiceImpl.COMPROMISED);
        verifyRemoved(firstPair);
        verifyNoMoreInteractions(writer, cache);
    }

    @Test
    void removeKeys_keyWhosePrivateKeyWasDestroyed_reportsItWithoutAPrivateKeyInAToken() {
        // given
        CryptographicKeyFullModel destroyed = keyPair("destroyed-pair", LISTS_KEYS, KeyState.DESTROYED);
        CryptographicKeyFullModel destroyedCompromised = keyPair("destroyed-compromised-pair", LISTS_KEYS,
                KeyState.DESTROYED_COMPROMISED);
        for (CryptographicKeyFullModel key : List.of(destroyed, destroyedCompromised)) {
            when(keys.findFullModelByUuid(key.uuid())).thenReturn(Optional.of(key));
        }

        // when
        List<BulkActionMessageDto> report = service.removeKeysFromInventory(uuidsOf(destroyed, destroyedCompromised));

        // then
        assertThat(report)
                .extracting(BulkActionMessageDto::getName, BulkActionMessageDto::getMessage)
                .containsExactly(tuple(destroyed.name(), CryptographicKeyServiceImpl.NO_PRIVATE_KEY_IN_TOKEN),
                        tuple(destroyedCompromised.name(), CryptographicKeyServiceImpl.NO_PRIVATE_KEY_IN_TOKEN));
        verifyNoInteractions(writer, cache);
    }

    @Test
    void removeKeys_keyWhosePublicKeyWasDestroyedAsCompromised_reportsItCompromised() {
        // given
        CryptographicKeyFullModel publicKeyDestroyed = keyPair("public-key-destroyed-pair", LISTS_KEYS, KeyState.ACTIVE,
                KeyState.DESTROYED_COMPROMISED);
        when(keys.findFullModelByUuid(publicKeyDestroyed.uuid())).thenReturn(Optional.of(publicKeyDestroyed));

        // when
        List<BulkActionMessageDto> report = service.removeKeysFromInventory(uuidsOf(publicKeyDestroyed));

        // then
        assertReported(report, publicKeyDestroyed, CryptographicKeyServiceImpl.COMPROMISED);
        verifyNoInteractions(writer, cache);
    }

    @Test
    void removeKeys_unknownKey_reportsItNotFound() {
        // given
        String unknown = UUID.randomUUID().toString();
        when(keys.findFullModelByUuid(UUID.fromString(unknown))).thenReturn(Optional.empty());
        List<String> selection = List.of(unknown, firstPair.uuid().toString());

        // when
        List<BulkActionMessageDto> report = service.removeKeysFromInventory(selection);

        // then
        assertThat(report).singleElement().satisfies(entry -> {
            assertThat(entry.getUuid()).isEqualTo(unknown);
            assertThat(entry.getName()).isEqualTo(unknown);
            assertThat(entry.getMessage()).isEqualTo("Key not found");
        });
        verifyRemoved(firstPair);
    }

    @Test
    void removeKeys_duplicateKey_removesItOnce() {
        // given
        String selected = firstPair.uuid().toString();
        List<String> duplicateSelection = List.of(selected, selected);

        // when
        List<BulkActionMessageDto> report = service.removeKeysFromInventory(duplicateSelection);

        // then
        assertThat(report).isEmpty();
        verifyRemoved(firstPair);
        verifyNoMoreInteractions(writer, cache);
    }

    @Test
    void removeKeys_keyDeleteDeniedOnALaterKey_refusesTheRequestAndRemovesNothing() {
        // given
        UUID deniedKeyUuid = secondPair.uuid();
        doThrow(new AccessDeniedException("Denied for test"))
                .when(authorization)
                .enforce(eq(Resource.CRYPTOGRAPHIC_KEY), eq(ResourceAction.DELETE),
                        argThat((SecuredUUID uuid) -> deniedKeyUuid.equals(uuid.getValue())));

        // when
        Executable remove = () -> service.removeKeysFromInventory(uuidsOf(firstPair, secondPair));

        // then
        assertThrows(AccessDeniedException.class, remove);
        verifyNoInteractions(writer, cache);
    }

    @Test
    void removeKeys_tokenMembersDeniedOnALaterKey_refusesTheRequestAndRemovesNothing() {
        // given
        UUID deniedTokenUuid = secondPair.tokenInstanceReferenceUuid();
        doThrow(new AccessDeniedException("Denied for test"))
                .when(authorization)
                .enforce(eq(Resource.TOKEN), eq(ResourceAction.MEMBERS),
                        argThat((SecuredUUID uuid) -> deniedTokenUuid.equals(uuid.getValue())));

        // when
        Executable remove = () -> service.removeKeysFromInventory(uuidsOf(firstPair, secondPair));

        // then
        assertThrows(AccessDeniedException.class, remove);
        verifyNoInteractions(writer, cache);
    }

    @Test
    void removeKeys_writerFailure_reportsTheKeySafelyAndRemovesTheOthers() {
        // given
        String sensitiveFailure = "SQL delete from cryptographic_key failed for internal_column";
        doThrow(new IllegalStateException(sensitiveFailure))
                .when(writer)
                .removeFromInventoryAsRead(firstPair, itemStatesOf(firstPair));

        // when
        List<BulkActionMessageDto> report = service.removeKeysFromInventory(uuidsOf(firstPair, secondPair));

        // then
        assertThat(report).singleElement().satisfies(entry -> {
            assertThat(entry.getUuid()).isEqualTo(firstPair.uuid().toString());
            assertThat(entry.getName()).isEqualTo(firstPair.name());
            assertThat(entry.getMessage()).isNotBlank().doesNotContain(sensitiveFailure);
        });
        for (CryptographicKeyItemBasicModel item : firstPair.items()) {
            verify(cache, never()).evict(CacheConfig.CRYPTOGRAPHIC_KEY_ITEM_CACHE, item.uuid());
        }
        verifyRemoved(secondPair);
    }

    @Test
    void removeKeys_writerRejection_reportsTheRejectionAndRemovesTheOthers() {
        // given
        String keyChanged = "Key %s changed meanwhile. Try again.".formatted(firstPair.uuid());
        doThrow(new ValidationException(ValidationError.create(keyChanged)))
                .when(writer)
                .removeFromInventoryAsRead(firstPair, itemStatesOf(firstPair));

        // when
        List<BulkActionMessageDto> report = service.removeKeysFromInventory(uuidsOf(firstPair, secondPair));

        // then
        assertThat(report).singleElement().satisfies(entry -> {
            assertThat(entry.getUuid()).isEqualTo(firstPair.uuid().toString());
            assertThat(entry.getMessage()).isEqualTo(keyChanged);
        });
        verifyRemoved(secondPair);
    }

    @Test
    void removeKey_keyPairOnATokenThatListsKeys_isRemoved() throws Exception {
        // when
        service.removeKeyFromInventory(SecuredUUID.fromUUID(firstPair.uuid()));

        // then
        verifyRemoved(firstPair);
        verifyNoInteractions(adapters);
    }

    @Test
    void removeKey_keyWithACompromisedItem_isRefusedWithTheReason() {
        // when
        Executable remove = () -> service.removeKeyFromInventory(SecuredUUID.fromUUID(compromisedPair.uuid()));

        // then
        ValidationException refusal = assertThrows(ValidationException.class, remove);
        assertThat(refusal.getMessage())
                .contains(CryptographicKeyServiceImpl.NOT_REMOVABLE
                        .formatted(compromisedPair.name(), CryptographicKeyServiceImpl.COMPROMISED));
        verifyNoInteractions(writer, cache);
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

    private static List<String> uuidsOf(CryptographicKeyFullModel... keys) {
        return Arrays.stream(keys).map(key -> key.uuid().toString()).toList();
    }

    private static CryptographicKeyFullModel keyPair(String name, List<FeatureFlag> connectorFeatures,
            KeyState privateKeyState) {
        return keyPair(name, connectorFeatures, privateKeyState, KeyState.ACTIVE);
    }

    private static CryptographicKeyFullModel keyPair(String name, List<FeatureFlag> connectorFeatures,
            KeyState privateKeyState, KeyState publicKeyState) {
        CryptographicKey key = aCryptographicKey().withName(name).build();
        key.setUuid(UUID.randomUUID());
        key.setTokenInstanceReference(token(connectorFeatures));
        key
                .setItems(new LinkedHashSet<>(List
                        .of(item(key, name + "-private", KeyType.PRIVATE_KEY, privateKeyState),
                                item(key, name + "-public", KeyType.PUBLIC_KEY, publicKeyState))));
        return ImmutableCryptographicKeyFullModel.from(key);
    }

    private static CryptographicKeyFullModel publicKeyOnly(String name) {
        CryptographicKey key = aCryptographicKey().withName(name).build();
        key.setUuid(UUID.randomUUID());
        key.setItems(new LinkedHashSet<>(List.of(item(key, name, KeyType.PUBLIC_KEY, KeyState.ACTIVE))));
        return ImmutableCryptographicKeyFullModel.from(key);
    }

    private static TokenInstanceReference token(List<FeatureFlag> connectorFeatures) {
        ConnectorInterfaceEntity connectorInterface = new ConnectorInterfaceEntity();
        connectorInterface.setFeatures(connectorFeatures);
        TokenInstanceReference token = new TokenInstanceReference();
        token.setUuid(UUID.randomUUID());
        token.setTokenInstanceUuid(UUID.randomUUID().toString());
        token.setStatus(TokenInstanceStatus.CONNECTED);
        token.setConnectorInterface(connectorInterface);
        return token;
    }

    private static CryptographicKeyItem item(CryptographicKey key, String name, KeyType type, KeyState state) {
        CryptographicKeyItem item = aKeyItem().withName(name).withType(type).withState(state).build();
        item.setUuid(UUID.randomUUID());
        item.setKey(key);
        item.setKeyReferenceUuid(UUID.randomUUID());
        item.setUsage(List.of());
        return item;
    }
}
