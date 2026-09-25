package com.otilm.core.service.impl;

import com.otilm.api.clients.ApiClientConnectorInfo;
import com.otilm.api.exception.AttributeException;
import com.otilm.api.exception.ConnectorException;
import com.otilm.api.exception.ValidationException;
import com.otilm.api.interfaces.client.v1.KeyManagementSyncApiClient;
import com.otilm.api.model.client.attribute.RequestAttribute;
import com.otilm.api.model.client.attribute.RequestAttributeV2;
import com.otilm.api.model.client.connector.v2.ConnectorInterface;
import com.otilm.api.model.client.connector.v2.FeatureFlag;
import com.otilm.api.model.client.cryptography.key.KeyRequestDto;
import com.otilm.api.model.client.cryptography.key.KeyRequestType;
import com.otilm.api.model.common.attribute.common.BaseAttribute;
import com.otilm.api.model.common.attribute.common.content.AttributeContentType;
import com.otilm.api.model.common.attribute.v2.DataAttributeV2;
import com.otilm.api.model.common.attribute.v2.content.StringAttributeContentV2;
import com.otilm.api.model.common.enums.cryptography.KeyAlgorithm;
import com.otilm.api.model.common.enums.cryptography.KeyFormat;
import com.otilm.api.model.connector.cryptography.enums.TokenInstanceStatus;
import com.otilm.api.model.connector.cryptography.key.CreateKeyRequestDto;
import com.otilm.core.attribute.engine.AttributeEngine;
import com.otilm.core.client.ConnectorApiFactory;
import com.otilm.core.dao.repository.CryptographicKeyItemRepository;
import com.otilm.core.dao.repository.CryptographicKeyRepository;
import com.otilm.core.dao.repository.TokenProfileRepository;
import com.otilm.core.model.connector.ImmutableConnectorInterface;
import com.otilm.core.model.crypto.ImmutableTokenInstanceFullModel;
import com.otilm.core.model.crypto.ImmutableTokenProfileFullModel;
import com.otilm.core.model.crypto.KeyMaterial;
import com.otilm.core.model.crypto.ProviderKeyItem;
import com.otilm.core.model.crypto.TokenProfileFullModel;
import com.otilm.core.security.authz.SecuredParentUUID;
import com.otilm.core.service.handler.ConnectorCapabilityService;
import com.otilm.core.service.handler.KeyTransferCapabilityService;
import com.otilm.core.service.handler.key.KeyProviderAdapter;
import com.otilm.core.service.handler.key.KeyProviderAdapterFactory;
import com.otilm.core.service.handler.key.KeyProviderV1Adapter;
import com.otilm.core.service.writer.CryptographicKeyWriter;
import com.otilm.core.util.CryptographyUtil;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.UUID;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.function.Executable;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.EnumSource;
import org.mockito.InOrder;

import static com.otilm.core.util.builders.CryptographicKeyBuilder.aCryptographicKey;
import static com.otilm.core.util.builders.CryptographicKeyItemBuilder.aKeyItem;
import static com.otilm.core.util.builders.ProviderKeyItemBuilder.aProviderKeyItem;
import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.ArgumentMatchers.isNull;
import static org.mockito.ArgumentMatchers.same;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.inOrder;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.verifyNoMoreInteractions;
import static org.mockito.Mockito.when;

class CryptographicKeyServiceImplCreationValidationTest {

    private final ApiClientConnectorInfo connector = mock(ApiClientConnectorInfo.class);
    private final KeyManagementSyncApiClient client = mock(KeyManagementSyncApiClient.class);
    private final AttributeEngine attributeEngine = mock(AttributeEngine.class);
    private final KeyProviderAdapterFactory adapters = mock(KeyProviderAdapterFactory.class);
    private final CryptographicKeyWriter writer = mock(CryptographicKeyWriter.class);
    private final CryptographicKeyItemRepository items = mock(CryptographicKeyItemRepository.class);
    private final KeyTransferCapabilityService keyTransfer = mock(KeyTransferCapabilityService.class);
    private final CryptographicKeyServiceImpl service = new CryptographicKeyServiceImpl();
    private final ImmutableTokenProfileFullModel profile = tokenProfile();
    private final KeyRequestDto request = keyRequest();
    private final List<BaseAttribute> definitions = List.of(new DataAttributeV2());

    @BeforeEach
    void setUp() throws Exception {
        ConnectorApiFactory apiFactory = mock(ConnectorApiFactory.class);
        when(apiFactory.getKeyManagementApiClient(connector)).thenReturn(client);
        KeyProviderV1Adapter adapter = new KeyProviderV1Adapter(apiFactory, connector, attributeEngine);
        when(adapters.forToken(profile.tokenInstance())).thenReturn(adapter);
        TokenProfileRepository profiles = mock(TokenProfileRepository.class);
        when(profiles.findFullModelByUuidAndTokenInstanceReferenceUuid(profile.uuid(), tokenUuid()))
                .thenReturn(Optional.of(profile));
        service.setTokenProfileRepository(profiles);
        service.setCryptographicKeyRepository(mock(CryptographicKeyRepository.class));
        service.setCryptographicKeyItemRepository(items);
        service.setCryptographicKeyWriter(writer);
        service.setKeyProviderAdapterFactory(adapters);
        service.setAttributeEngine(attributeEngine);
        service.setConnectorCapabilityService(new ConnectorCapabilityService());
        when(keyTransfer.exportableKeyTypes(any()))
                .thenAnswer(invocation -> Optional
                        .ofNullable(invocation.<TokenProfileFullModel>getArgument(0).exportableKeyTypes()));
        service.setKeyTransferCapabilityService(keyTransfer);
    }

    @ParameterizedTest
    @EnumSource(KeyRequestType.class)
    void createKey_v1ValidatesWithProviderBeforeDefinitionsLocalValidationAndCreation(KeyRequestType type)
            throws Exception {
        // given
        ConnectorException creationReached = new ConnectorException("Creation endpoint reached");
        stubDefinitions(type);
        failAtProviderCreation(type, creationReached);

        // when
        Executable create = () -> createKey(type);

        // then
        assertSame(creationReached, assertThrows(ConnectorException.class, create));
        InOrder order = inOrder(client, attributeEngine);
        verifyProviderValidation(order.verify(client), type);
        verifyDefinitionListing(order.verify(client), type);
        order
                .verify(attributeEngine)
                .validateUpdateDataAttributes(eq(profile.connectorUuid()), isNull(), same(definitions),
                        same(request.getAttributes()));
        verifyProviderCreation(order.verify(client), type);
        verifyNoMoreInteractions(client);
        verifyNoInteractions(writer);
    }

    @ParameterizedTest
    @EnumSource(KeyRequestType.class)
    void createKey_abortsWhenV1ProviderRejectsAttributes(KeyRequestType type) throws Exception {
        // given
        ValidationException rejection = new ValidationException("Requested key size is unsupported by this token");
        verifyProviderValidation(doThrow(rejection).when(client), type);

        // when
        Executable create = () -> createKey(type);

        // then
        assertSame(rejection, assertThrows(ValidationException.class, create));
        verifyProviderValidation(verify(client), type);
        verifyNoDownstreamCreationWork();
    }

    @ParameterizedTest
    @EnumSource(KeyRequestType.class)
    void createKey_abortsWhenV1ValidationCannotReachProvider(KeyRequestType type) throws Exception {
        // given
        ConnectorException unavailable = new ConnectorException("Provider validation is unavailable");
        verifyProviderValidation(doThrow(unavailable).when(client), type);

        // when
        Executable create = () -> createKey(type);

        // then
        assertSame(unavailable, assertThrows(ConnectorException.class, create));
        verifyProviderValidation(verify(client), type);
        verifyNoDownstreamCreationWork();
    }

    @ParameterizedTest
    @EnumSource(KeyRequestType.class)
    void createKey_withoutProviderValidationCapabilityStillValidatesLocallyBeforeCreation(KeyRequestType type)
            throws Exception {
        // given
        KeyProviderAdapter adapter = mock(KeyProviderAdapter.class);
        when(adapters.forToken(profile.tokenInstance())).thenReturn(adapter);
        when(adapter.listCreateKeyAttributes(profile, type)).thenReturn(definitions);
        ConnectorException creationReached = new ConnectorException("Creation endpoint reached");
        when(adapter.createKey(profile, type, request.getAttributes(), request.getName(), false))
                .thenThrow(creationReached);

        // when
        Executable create = () -> createKey(type);

        // then
        assertSame(creationReached, assertThrows(ConnectorException.class, create));
        InOrder order = inOrder(adapter, attributeEngine);
        order.verify(adapter).listCreateKeyAttributes(profile, type);
        order
                .verify(attributeEngine)
                .validateUpdateDataAttributes(eq(profile.connectorUuid()), isNull(), same(definitions),
                        same(request.getAttributes()));
        order.verify(adapter).createKey(profile, type, request.getAttributes(), request.getName(), false);
        verifyNoInteractions(client, writer);
    }

    @ParameterizedTest
    @EnumSource(KeyRequestType.class)
    void listCreateKeyAttributes_onlyListsProviderDefinitions(KeyRequestType type) throws Exception {
        // given
        stubDefinitions(type);

        // when
        List<BaseAttribute> result = service.listCreateKeyAttributes(tokenUuid(), securedProfileUuid(), type);

        // then
        assertSame(definitions, result);
        verifyDefinitionListing(verify(client), type);
        verifyNoMoreInteractions(client);
        verifyNoInteractions(attributeEngine, writer);
    }

    @Test
    void createKey_rejectsRepeatedReturnedMaterialBeforePersistence() throws Exception {
        // given
        KeyMaterial repeatedMaterial = new KeyMaterial(KeyFormat.RAW, "{\"value\":\"same-secret\"}");
        stubCreatedItems(List
                .of(aProviderKeyItem().withName("first").withMaterial(repeatedMaterial).build(),
                        aProviderKeyItem().withName("second").withMaterial(repeatedMaterial).build()));

        // when
        Executable create = () -> createKey(KeyRequestType.KEY_PAIR);

        // then
        assertThat(assertThrows(ValidationException.class, create)).hasMessageContaining("same fingerprint");
        verifyNoInteractions(writer);
    }

    @Test
    void createKey_rejectsExistingMaterialBeforePersistence() throws Exception {
        // given
        KeyMaterial existingMaterial = new KeyMaterial(KeyFormat.RAW, "{\"value\":\"stored-secret\"}");
        var storedItem = aKeyItem().build();
        storedItem.setKey(aCryptographicKey().build());
        storedItem.getKey().setUuid(UUID.randomUUID());
        when(items.findByFingerprint(CryptographyUtil.calculateKeyFingerprint(existingMaterial)))
                .thenReturn(Optional.of(storedItem));
        stubCreatedItems(List.of(aProviderKeyItem().withMaterial(existingMaterial).build()));

        // when
        Executable create = () -> createKey(KeyRequestType.KEY_PAIR);

        // then
        assertThat(assertThrows(ValidationException.class, create))
                .hasMessageContaining(storedItem.getKey().getUuid().toString());
        verifyNoInteractions(writer);
    }

    @Test
    void createKey_acceptsMissingMaterial() throws Exception {
        // given
        List<ProviderKeyItem> nonExportableItems = List.of(aProviderKeyItem().withMaterial(null).build());
        stubCreatedItems(nonExportableItems);
        AttributeException persistenceReached = new AttributeException("Persistence reached");
        when(writer.createKeyWithItems(request, profile, profile.tokenInstance(), nonExportableItems, false, false))
                .thenThrow(persistenceReached);

        // when
        Executable create = () -> createKey(KeyRequestType.KEY_PAIR);

        // then
        assertSame(persistenceReached, assertThrows(AttributeException.class, create));
        verify(items, never()).findByFingerprint(any());
    }

    private void stubCreatedItems(List<ProviderKeyItem> createdItems) throws Exception {
        KeyProviderAdapter adapter = mock(KeyProviderAdapter.class);
        when(adapters.forToken(profile.tokenInstance())).thenReturn(adapter);
        when(adapter.listCreateKeyAttributes(profile, KeyRequestType.KEY_PAIR)).thenReturn(definitions);
        when(adapter.createKey(profile, KeyRequestType.KEY_PAIR, request.getAttributes(), request.getName(), false))
                .thenReturn(createdItems);
    }

    private void createKey(KeyRequestType type) throws Exception {
        service.createKey(tokenUuid(), securedProfileUuid(), type, request);
    }

    private void verifyNoDownstreamCreationWork() throws Exception {
        verifyNoMoreInteractions(client);
        verify(attributeEngine, never()).validateUpdateDataAttributes(any(), any(), any(), any());
        verifyNoInteractions(writer);
    }

    private void stubDefinitions(KeyRequestType type) throws ConnectorException {
        if (type == KeyRequestType.KEY_PAIR) {
            when(client.listCreateKeyPairAttributes(connector, remoteTokenUuid())).thenReturn(definitions);
        } else {
            when(client.listCreateSecretKeyAttributes(connector, remoteTokenUuid())).thenReturn(definitions);
        }
    }

    private void failAtProviderCreation(KeyRequestType type, ConnectorException failure) throws ConnectorException {
        if (type == KeyRequestType.KEY_PAIR) {
            when(client.createKeyPair(eq(connector), eq(remoteTokenUuid()), any(CreateKeyRequestDto.class)))
                    .thenThrow(failure);
        } else {
            when(client.createSecretKey(eq(connector), eq(remoteTokenUuid()), any(CreateKeyRequestDto.class)))
                    .thenThrow(failure);
        }
    }

    private void verifyProviderValidation(KeyManagementSyncApiClient expected, KeyRequestType type)
            throws ConnectorException {
        if (type == KeyRequestType.KEY_PAIR) {
            expected
                    .validateCreateKeyPairAttributes(eq(connector), eq(remoteTokenUuid()),
                            same(request.getAttributes()));
        } else {
            expected
                    .validateCreateSecretKeyAttributes(eq(connector), eq(remoteTokenUuid()),
                            same(request.getAttributes()));
        }
    }

    private void verifyDefinitionListing(KeyManagementSyncApiClient expected, KeyRequestType type)
            throws ConnectorException {
        if (type == KeyRequestType.KEY_PAIR) {
            expected.listCreateKeyPairAttributes(connector, remoteTokenUuid());
        } else {
            expected.listCreateSecretKeyAttributes(connector, remoteTokenUuid());
        }
    }

    private void verifyProviderCreation(KeyManagementSyncApiClient expected, KeyRequestType type)
            throws ConnectorException {
        if (type == KeyRequestType.KEY_PAIR) {
            expected.createKeyPair(eq(connector), eq(remoteTokenUuid()), any(CreateKeyRequestDto.class));
        } else {
            expected.createSecretKey(eq(connector), eq(remoteTokenUuid()), any(CreateKeyRequestDto.class));
        }
    }

    private UUID tokenUuid() {
        return profile.tokenInstance().uuid();
    }

    private String remoteTokenUuid() {
        return profile.tokenInstance().tokenInstanceUuid();
    }

    private SecuredParentUUID securedProfileUuid() {
        return SecuredParentUUID.fromUUID(profile.uuid());
    }

    @Test
    void createKey_refusesAnExportableKeyOnAConnectorThatCannotExport() {
        // given
        request.setExportable(true);

        // when
        Executable create = () -> createKey(KeyRequestType.KEY_PAIR);

        // then
        ValidationException refused = assertThrows(ValidationException.class, create);
        assertTrue(refused.getMessage().contains("does not support key export"));
        verifyNoInteractions(client);
    }

    @Test
    void createKey_refusesAnExportableKeyOfATypeTheProfileCannotExport() {
        // given
        ConnectorCapabilityService capabilities = mock(ConnectorCapabilityService.class);
        when(capabilities.supports(profile.tokenInstance().connectorInterface(), FeatureFlag.KEY_EXPORT))
                .thenReturn(true);
        service.setConnectorCapabilityService(capabilities);
        request.setExportable(true);

        // when
        Executable create = () -> createKey(KeyRequestType.SECRET);

        // then
        ValidationException refused = assertThrows(ValidationException.class, create);
        assertTrue(refused.getMessage().contains("does not support exporting a secret key"));
        verifyNoInteractions(client);
    }

    @Test
    void createKey_failsWithTheConnectorErrorWhenWhatTheProfileExportsCannotBeLearned() throws Exception {
        // given
        ConnectorCapabilityService capabilities = mock(ConnectorCapabilityService.class);
        when(capabilities.supports(profile.tokenInstance().connectorInterface(), FeatureFlag.KEY_EXPORT))
                .thenReturn(true);
        service.setConnectorCapabilityService(capabilities);
        ConnectorException unreachable = new ConnectorException("Connector is down");
        when(keyTransfer.exportableKeyTypes(profile)).thenThrow(unreachable);
        request.setExportable(true);

        // when
        Executable create = () -> createKey(KeyRequestType.KEY_PAIR);

        // then
        assertSame(unreachable, assertThrows(ConnectorException.class, create));
        verifyNoInteractions(client, writer);
    }

    @Test
    void createKey_refusesToDecideWhenTheProfileChangedWhileItsCapabilityWasChecked() throws Exception {
        // given
        ConnectorCapabilityService capabilities = mock(ConnectorCapabilityService.class);
        when(capabilities.supports(profile.tokenInstance().connectorInterface(), FeatureFlag.KEY_EXPORT))
                .thenReturn(true);
        service.setConnectorCapabilityService(capabilities);
        when(keyTransfer.exportableKeyTypes(profile)).thenReturn(Optional.empty());
        request.setExportable(true);

        // when
        Executable create = () -> createKey(KeyRequestType.KEY_PAIR);

        // then
        ValidationException refused = assertThrows(ValidationException.class, create);
        assertTrue(refused.getMessage().contains("changed while its export capability was being checked"));
        verifyNoInteractions(client, writer);
    }

    @Test
    void createKey_acceptsAnExportableKeyOnAConnectorThatCanExport() throws Exception {
        // given
        ConnectorCapabilityService capabilities = mock(ConnectorCapabilityService.class);
        when(capabilities.supports(profile.tokenInstance().connectorInterface(), FeatureFlag.KEY_EXPORT))
                .thenReturn(true);
        service.setConnectorCapabilityService(capabilities);
        request.setExportable(true);
        ConnectorException creationReached = new ConnectorException("Creation endpoint reached");
        stubDefinitions(KeyRequestType.KEY_PAIR);
        failAtProviderCreation(KeyRequestType.KEY_PAIR, creationReached);

        // when
        Executable create = () -> createKey(KeyRequestType.KEY_PAIR);

        // then
        assertSame(creationReached, assertThrows(ConnectorException.class, create));
    }

    @Test
    void createKey_acceptsANonExportableKeyOnAConnectorThatCannotExport() throws Exception {
        // given
        ConnectorException creationReached = new ConnectorException("Creation endpoint reached");
        stubDefinitions(KeyRequestType.KEY_PAIR);
        failAtProviderCreation(KeyRequestType.KEY_PAIR, creationReached);

        // when
        Executable create = () -> createKey(KeyRequestType.KEY_PAIR);

        // then
        assertSame(creationReached, assertThrows(ConnectorException.class, create));
    }

    private static ImmutableTokenProfileFullModel tokenProfile() {
        UUID connectorUuid = UUID.randomUUID();
        ImmutableConnectorInterface connectorInterface = new ImmutableConnectorInterface(UUID.randomUUID(),
                ConnectorInterface.CRYPTOGRAPHY, "v2", List.of());
        ImmutableTokenInstanceFullModel token = new ImmutableTokenInstanceFullModel(UUID.randomUUID(),
                UUID.randomUUID().toString(), "token", TokenInstanceStatus.ACTIVATED, null, connectorUuid, "connector",
                connectorInterface.uuid(), connectorInterface, Set.of());
        return new ImmutableTokenProfileFullModel(UUID.randomUUID(), "profile", null, token.name(), token.uuid(), true,
                List.of(), token, connectorUuid, Map.of(KeyRequestType.KEY_PAIR, Set.of(KeyAlgorithm.RSA)), 0);
    }

    private static KeyRequestDto keyRequest() {
        RequestAttribute attributes = new RequestAttributeV2(UUID.randomUUID(), "key-size", AttributeContentType.STRING,
                List.of(new StringAttributeContentV2("256")));
        KeyRequestDto request = new KeyRequestDto();
        request.setName("new cryptographic key");
        request.setAttributes(List.of(attributes));
        return request;
    }
}
