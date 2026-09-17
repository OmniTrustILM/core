package com.otilm.core.service.impl;

import com.otilm.api.exception.NotFoundException;
import com.otilm.api.exception.ValidationException;
import com.otilm.api.model.client.cryptography.key.KeyRequestDto;
import com.otilm.api.model.common.enums.cryptography.KeyFormat;
import com.otilm.api.model.connector.cryptography.enums.TokenInstanceStatus;
import com.otilm.core.config.cache.CacheEvictor;
import com.otilm.core.dao.entity.CryptographicKeyItem;
import com.otilm.core.dao.repository.CryptographicKeyItemRepository;
import com.otilm.core.dao.repository.TokenInstanceReferenceRepository;
import com.otilm.core.model.crypto.ImmutableCryptographicKeyBasicModel;
import com.otilm.core.model.crypto.ImmutableTokenInstanceFullModel;
import com.otilm.core.model.crypto.KeyMaterial;
import com.otilm.core.model.crypto.ProviderKeyItem;
import com.otilm.core.model.crypto.RemoteKeyReference;
import com.otilm.core.security.authz.SecuredParentUUID;
import com.otilm.core.service.handler.key.KeyProviderAdapter;
import com.otilm.core.service.handler.key.KeyProviderAdapterFactory;
import com.otilm.core.service.writer.CryptographicKeyWriter;
import com.otilm.core.util.CryptographyUtil;
import java.util.List;
import java.util.Optional;
import java.util.Set;
import java.util.UUID;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.function.Executable;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.mockito.ArgumentCaptor;

import static com.otilm.core.util.builders.CryptographicKeyBuilder.aCryptographicKey;
import static com.otilm.core.util.builders.CryptographicKeyItemBuilder.aKeyItem;
import static com.otilm.core.util.builders.ProviderKeyItemBuilder.aProviderKeyItem;
import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyList;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.ArgumentMatchers.isNull;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;

class CryptographicKeyServiceImplSyncTest {

    private final TokenInstanceReferenceRepository tokens = mock(TokenInstanceReferenceRepository.class);
    private final CryptographicKeyItemRepository items = mock(CryptographicKeyItemRepository.class);
    private final CryptographicKeyWriter writer = mock(CryptographicKeyWriter.class);
    private final KeyProviderAdapterFactory adapters = mock(KeyProviderAdapterFactory.class);
    private final KeyProviderAdapter adapter = mock(KeyProviderAdapter.class);
    private final CryptographicKeyServiceImpl service = new CryptographicKeyServiceImpl();
    private final ImmutableTokenInstanceFullModel token = token(null);

    @BeforeEach
    void setUp() throws Exception {
        service.setTokenInstanceReferenceRepository(tokens);
        service.setCryptographicKeyItemRepository(items);
        service.setCryptographicKeyWriter(writer);
        service.setKeyProviderAdapterFactory(adapters);
        service.setCacheEvictor(mock(CacheEvictor.class));
        when(tokens.findFullModelByUuid(token.uuid())).thenReturn(Optional.of(token));
        when(adapters.forToken(token)).thenReturn(adapter);
        when(writer.createKeyWithItems(any(), isNull(), eq(token), anyList(), eq(true), eq(false)))
                .thenReturn(new ImmutableCryptographicKeyBasicModel(UUID.randomUUID(), "discovered-key", null, null,
                        token.uuid(), Set.of()));
    }

    @Test
    void syncKeys_skipsProvidersWithoutDiscovery() throws Exception {
        // given
        UUID v2InterfaceUuid = UUID.randomUUID();
        var v2Token = token(v2InterfaceUuid);
        when(tokens.findFullModelByUuid(v2Token.uuid())).thenReturn(Optional.of(v2Token));

        // when
        service.syncKeys(SecuredParentUUID.fromUUID(v2Token.uuid()));

        // then
        verifyNoInteractions(adapters, adapter, writer, items);
    }

    @Test
    void syncKeys_rejectsMissingToken() {
        // given
        UUID missingTokenUuid = UUID.randomUUID();

        // when
        Executable sync = () -> service.syncKeys(SecuredParentUUID.fromUUID(missingTokenUuid));

        // then
        assertThat(assertThrows(NotFoundException.class, sync)).hasMessageContaining(missingTokenUuid.toString());
        verifyNoInteractions(adapters, adapter, writer, items);
    }

    @Test
    void syncKeys_groupsAssociatedItemsAndKeepsStandaloneItemsSeparate() throws Exception {
        // given
        String pairName = "signing-pair";
        ProviderKeyItem first = aProviderKeyItem().withName("private").withAssociation(pairName).build();
        ProviderKeyItem second = aProviderKeyItem().withName("public").withAssociation(pairName).build();
        ProviderKeyItem standalone = aProviderKeyItem().withName("standalone-secret").build();
        ProviderKeyItem unassociated = aProviderKeyItem().withName("unassociated-secret").withAssociation("").build();
        when(adapter.listKeys(token)).thenReturn(List.of(first, standalone, second, unassociated));

        // when
        service.syncKeys(securedTokenUuid());

        // then
        ArgumentCaptor<KeyRequestDto> requests = ArgumentCaptor.forClass(KeyRequestDto.class);
        verify(writer, times(3))
                .createKeyWithItems(requests.capture(), isNull(), eq(token), anyList(), eq(true), eq(false));
        assertThat(requests.getAllValues())
                .extracting(KeyRequestDto::getName)
                .containsExactlyInAnyOrder(pairName, standalone.name(), unassociated.name());
        verify(writer).createKeyWithItems(any(), isNull(), eq(token), eq(List.of(first, second)), eq(true), eq(false));
        verify(writer).createKeyWithItems(any(), isNull(), eq(token), eq(List.of(standalone)), eq(true), eq(false));
        verify(writer).createKeyWithItems(any(), isNull(), eq(token), eq(List.of(unassociated)), eq(true), eq(false));
    }

    @ParameterizedTest
    @ValueSource(ints = {0, 1})
    void syncKeys_skipsAssociationWhenAnyRemoteReferenceAlreadyExists(int knownReferenceIndex) throws Exception {
        // given
        String association = "existing-key-pair";
        List<ProviderKeyItem> pair = List
                .of(aProviderKeyItem().withName("private").withAssociation(association).build(),
                        aProviderKeyItem().withName("public").withAssociation(association).build());
        UUID knownReference = ((RemoteKeyReference.UuidReference) pair.get(knownReferenceIndex).reference()).uuid();
        when(items.findKeyReferenceUuidsByTokenInstanceUuid(token.uuid())).thenReturn(Set.of(knownReference));
        when(adapter.listKeys(token)).thenReturn(pair);

        // when
        service.syncKeys(securedTokenUuid());

        // then
        verifyNoInteractions(writer);
        verify(items, never()).findByFingerprint(any());
    }

    @Test
    void syncKeys_ignoresMaterialOfAlreadyDiscoveredGroups() throws Exception {
        // given
        KeyMaterial existingMaterial = material();
        ProviderKeyItem knownItem = aProviderKeyItem().withMaterial(existingMaterial).build();
        UUID knownReference = ((RemoteKeyReference.UuidReference) knownItem.reference()).uuid();
        when(items.findKeyReferenceUuidsByTokenInstanceUuid(token.uuid())).thenReturn(Set.of(knownReference));
        when(adapter.listKeys(token)).thenReturn(List.of(knownItem));

        // when
        service.syncKeys(securedTokenUuid());

        // then
        verifyNoInteractions(writer);
        verify(items, never()).findByFingerprint(any());
    }

    @Test
    void syncKeys_rejectsRepeatedReturnedMaterialBeforePersistence() throws Exception {
        // given
        KeyMaterial repeatedMaterial = material();
        when(adapter.listKeys(token))
                .thenReturn(List
                        .of(aProviderKeyItem().withName("first").withMaterial(repeatedMaterial).build(),
                                aProviderKeyItem().withName("second").withMaterial(repeatedMaterial).build()));

        // when
        Executable sync = () -> service.syncKeys(securedTokenUuid());

        // then
        assertThat(assertThrows(ValidationException.class, sync)).hasMessageContaining("same fingerprint");
        verifyNoInteractions(writer);
    }

    @Test
    void syncKeys_rejectsExistingMaterialBeforePersistence() throws Exception {
        // given
        KeyMaterial existingMaterial = material();
        CryptographicKeyItem storedItem = aKeyItem().build();
        storedItem.setKey(aCryptographicKey().build());
        storedItem.getKey().setUuid(UUID.randomUUID());
        when(items.findByFingerprint(CryptographyUtil.calculateKeyFingerprint(existingMaterial)))
                .thenReturn(Optional.of(storedItem));
        when(adapter.listKeys(token)).thenReturn(List.of(aProviderKeyItem().withMaterial(existingMaterial).build()));

        // when
        Executable sync = () -> service.syncKeys(securedTokenUuid());

        // then
        assertThat(assertThrows(ValidationException.class, sync))
                .hasMessageContaining(storedItem.getKey().getUuid().toString());
        verifyNoInteractions(writer);
    }

    private SecuredParentUUID securedTokenUuid() {
        return SecuredParentUUID.fromUUID(token.uuid());
    }

    private static ImmutableTokenInstanceFullModel token(UUID interfaceUuid) {
        return new ImmutableTokenInstanceFullModel(UUID.randomUUID(), UUID.randomUUID().toString(), "token",
                TokenInstanceStatus.ACTIVATED, null, UUID.randomUUID(), "connector", interfaceUuid, null, Set.of());
    }

    private static KeyMaterial material() {
        return new KeyMaterial(KeyFormat.RAW, "{\"value\":\"test-key-material\"}");
    }
}
