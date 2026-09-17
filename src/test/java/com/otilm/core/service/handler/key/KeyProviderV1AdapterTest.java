package com.otilm.core.service.handler.key;

import com.otilm.api.clients.ApiClientConnectorInfo;
import com.otilm.api.exception.ConnectorEntityNotFoundException;
import com.otilm.api.exception.ConnectorException;
import com.otilm.api.exception.ValidationException;
import com.otilm.api.interfaces.client.v1.KeyManagementSyncApiClient;
import com.otilm.api.model.client.attribute.RequestAttribute;
import com.otilm.api.model.client.attribute.RequestAttributeV2;
import com.otilm.api.model.client.cryptography.key.KeyRequestType;
import com.otilm.api.model.common.attribute.common.BaseAttribute;
import com.otilm.api.model.common.attribute.common.MetadataAttribute;
import com.otilm.api.model.common.attribute.v2.DataAttributeV2;
import com.otilm.api.model.common.attribute.v2.MetadataAttributeV2;
import com.otilm.api.model.common.enums.cryptography.KeyAlgorithm;
import com.otilm.api.model.common.enums.cryptography.KeyFormat;
import com.otilm.api.model.common.enums.cryptography.KeyType;
import com.otilm.api.model.connector.cryptography.enums.TokenInstanceStatus;
import com.otilm.api.model.connector.cryptography.key.CreateKeyRequestDto;
import com.otilm.api.model.connector.cryptography.key.KeyData;
import com.otilm.api.model.connector.cryptography.key.KeyDataResponseDto;
import com.otilm.api.model.connector.cryptography.key.KeyPairDataResponseDto;
import com.otilm.api.model.connector.cryptography.key.value.RawKeyValue;
import com.otilm.api.model.core.auth.Resource;
import com.otilm.core.attribute.engine.AttributeEngine;
import com.otilm.core.attribute.engine.records.ObjectAttributeContentInfo;
import com.otilm.core.client.ConnectorApiFactory;
import com.otilm.core.model.crypto.ImmutableCryptographicKeyFullModel;
import com.otilm.core.model.crypto.ImmutableTokenInstanceFullModel;
import com.otilm.core.model.crypto.ImmutableTokenProfileFullModel;
import com.otilm.core.model.crypto.ProviderKeyItem;
import com.otilm.core.model.crypto.RemoteKeyReference;
import java.util.List;
import java.util.Set;
import java.util.UUID;
import java.util.stream.Stream;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.function.Executable;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.EnumSource;
import org.junit.jupiter.params.provider.MethodSource;
import org.junit.jupiter.params.provider.NullAndEmptySource;
import org.junit.jupiter.params.provider.ValueSource;
import org.mockito.ArgumentCaptor;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;

class KeyProviderV1AdapterTest {

    private ApiClientConnectorInfo connector;
    private KeyManagementSyncApiClient client;
    private KeyProviderV1Adapter adapter;
    private ImmutableTokenProfileFullModel profile;
    private ImmutableCryptographicKeyFullModel cryptographicKey;
    private AttributeEngine attributeEngine;

    @BeforeEach
    void setUp() {
        connector = mock(ApiClientConnectorInfo.class);
        client = mock(KeyManagementSyncApiClient.class);
        ConnectorApiFactory factory = mock(ConnectorApiFactory.class);
        when(factory.getKeyManagementApiClient(connector)).thenReturn(client);
        attributeEngine = mock(AttributeEngine.class);
        adapter = new KeyProviderV1Adapter(factory, connector, attributeEngine);
        UUID connectorUuid = UUID.randomUUID();
        ImmutableTokenInstanceFullModel token = new ImmutableTokenInstanceFullModel(UUID.randomUUID(),
                UUID.randomUUID().toString(), "token", TokenInstanceStatus.ACTIVATED, null, connectorUuid, "connector",
                null, null, Set.of());
        profile = new ImmutableTokenProfileFullModel(UUID.randomUUID(), "profile", null, token.name(), token.uuid(),
                true, List.of(), token, connectorUuid);
        cryptographicKey = new ImmutableCryptographicKeyFullModel(UUID.randomUUID(), "key", null, profile.uuid(),
                token.uuid(), profile, token, Set.of(), null, null, null, List.of(), List.of());
    }

    @ParameterizedTest
    @NullAndEmptySource
    @ValueSource(strings = {"signing-key-pair", "split-key-parts"})
    void listKeys_preservesProviderDataAndAssociation(String association) throws Exception {
        // given
        UUID remoteKeyUuid = UUID.randomUUID();
        String keyName = "remote secret key";
        String serializedValue = "c2VjcmV0";
        int keyLength = 256;
        List<MetadataAttribute> metadata = List.of(new MetadataAttributeV2());
        KeyData data = new KeyData(KeyType.SECRET_KEY, KeyAlgorithm.UNKNOWN, KeyFormat.RAW,
                new RawKeyValue(serializedValue), keyLength, metadata);
        KeyDataResponseDto response = new KeyDataResponseDto(association, data);
        response.setUuid(remoteKeyUuid.toString());
        response.setName(keyName);
        String remoteTokenUuid = profile.tokenInstance().tokenInstanceUuid();
        when(client.listKeys(connector, remoteTokenUuid)).thenReturn(List.of(response));

        // when
        List<ProviderKeyItem> items = adapter.listKeys(profile.tokenInstance());

        // then
        assertEquals(1, items.size());
        ProviderKeyItem item = items.getFirst();
        assertEquals(keyName, item.name());
        assertEquals(association, item.association());
        assertEquals(new RemoteKeyReference.UuidReference(remoteKeyUuid), item.reference());
        assertEquals(KeyType.SECRET_KEY, item.type());
        assertEquals(KeyAlgorithm.UNKNOWN, item.algorithm());
        assertEquals(keyLength, item.length());
        assertEquals(KeyFormat.RAW, item.material().format());
        assertEquals(serializedValue, item.material().serializedValue());
        assertEquals(metadata, item.metadata());
        verify(client).listKeys(connector, remoteTokenUuid);
    }

    @Test
    void listKeys_returnsEmpty_whenProviderHasNoKeys() throws Exception {
        // given
        when(client.listKeys(connector, profile.tokenInstance().tokenInstanceUuid())).thenReturn(List.of());

        // when
        List<ProviderKeyItem> items = adapter.listKeys(profile.tokenInstance());

        // then
        assertTrue(items.isEmpty());
    }

    @Test
    void destroyKey_usesRemoteKeyUuidAndRemoteTokenUuid() throws Exception {
        // given
        UUID remoteKeyUuid = UUID.randomUUID();
        RemoteKeyReference reference = new RemoteKeyReference.UuidReference(remoteKeyUuid);
        String remoteTokenUuid = profile.tokenInstance().tokenInstanceUuid();

        // when
        adapter.destroyKeyItem(cryptographicKey, reference);

        // then
        verify(client).destroyKey(connector, remoteTokenUuid, remoteKeyUuid.toString());
    }

    @ParameterizedTest
    @MethodSource("invalidReferences")
    void destroyKey_rejectsInvalidReference_withoutCallingConnector(RemoteKeyReference reference) {
        // given
        RemoteKeyReference invalidReference = reference;

        // when
        Executable destroy = () -> adapter.destroyKeyItem(cryptographicKey, invalidReference);

        // then
        assertThrows(IllegalArgumentException.class, destroy);
        verifyNoInteractions(client);
    }

    @Test
    void destroyKey_propagatesConnectorFailure() throws Exception {
        // given
        UUID remoteKeyUuid = UUID.randomUUID();
        RemoteKeyReference reference = new RemoteKeyReference.UuidReference(remoteKeyUuid);
        ConnectorException failure = new ConnectorException("Destruction failed");
        doThrow(failure)
                .when(client)
                .destroyKey(connector, profile.tokenInstance().tokenInstanceUuid(), remoteKeyUuid.toString());

        // when
        Executable destroy = () -> adapter.destroyKeyItem(cryptographicKey, reference);

        // then
        assertSame(failure, assertThrows(ConnectorException.class, destroy));
    }

    @Test
    void destroyKey_succeeds_whenRemoteKeyIsAlreadyAbsent() throws Exception {
        // given
        UUID remoteKeyUuid = UUID.randomUUID();
        RemoteKeyReference reference = new RemoteKeyReference.UuidReference(remoteKeyUuid);
        doThrow(new ConnectorEntityNotFoundException("Key was already deleted"))
                .when(client)
                .destroyKey(connector, profile.tokenInstance().tokenInstanceUuid(), remoteKeyUuid.toString());

        // when
        Executable destroy = () -> adapter.destroyKeyItem(cryptographicKey, reference);

        // then
        assertDoesNotThrow(destroy);
        verify(client).destroyKey(connector, profile.tokenInstance().tokenInstanceUuid(), remoteKeyUuid.toString());
    }

    @Test
    void destroyKey_toleratesConnectorFailure_forDeactivatedToken() throws Exception {
        // given
        UUID remoteKeyUuid = UUID.randomUUID();
        RemoteKeyReference reference = new RemoteKeyReference.UuidReference(remoteKeyUuid);
        ImmutableCryptographicKeyFullModel key = keyWithTokenStatus(TokenInstanceStatus.DEACTIVATED);
        doThrow(new ConnectorException("Token is offline"))
                .when(client)
                .destroyKey(connector, profile.tokenInstance().tokenInstanceUuid(), remoteKeyUuid.toString());

        // when
        Executable destroy = () -> adapter.destroyKeyItem(key, reference);

        // then
        assertDoesNotThrow(destroy);
        verify(client).destroyKey(connector, profile.tokenInstance().tokenInstanceUuid(), remoteKeyUuid.toString());
    }

    @ParameterizedTest
    @EnumSource(KeyRequestType.class)
    void createKey_preservesProviderResultsAndProfileContext(KeyRequestType type) throws Exception {
        // given
        List<RequestAttribute> creationAttributes = List.of(requestAttribute("creation"));
        List<RequestAttribute> profileAttributes = List.of(requestAttribute("profile"));
        List<KeyDataResponseDto> providerKeys = stubCreatedKeys(type);
        ObjectAttributeContentInfo profileScope = ObjectAttributeContentInfo
                .builder(Resource.TOKEN_PROFILE, profile.uuid())
                .connector(profile.connectorUuid())
                .build();
        when(attributeEngine.getRequestObjectDataAttributesContent(profileScope)).thenReturn(profileAttributes);

        // when
        List<ProviderKeyItem> items = adapter.createKey(profile, type, creationAttributes, profile.name());

        // then
        assertEquals(providerKeys.stream().map(KeyDataResponseDto::getName).toList(),
                items.stream().map(ProviderKeyItem::name).toList());
        assertEquals(providerKeys
                .stream()
                .map(key -> new RemoteKeyReference.UuidReference(UUID.fromString(key.getUuid())))
                .toList(), items.stream().map(ProviderKeyItem::reference).toList());
        assertEquals(providerKeys.stream().map(key -> key.getKeyData().getType()).toList(),
                items.stream().map(ProviderKeyItem::type).toList());
        assertEquals(providerKeys.stream().map(KeyDataResponseDto::getAssociation).toList(),
                items.stream().map(ProviderKeyItem::association).toList());
        CreateKeyRequestDto sentRequest = capturedCreateRequest(type);
        assertEquals(creationAttributes, sentRequest.getCreateKeyAttributes());
        assertEquals(profileAttributes, sentRequest.getTokenProfileAttributes());
    }

    @ParameterizedTest
    @EnumSource(KeyRequestType.class)
    void validateCreateKeyAttributes_routesByRequestType(KeyRequestType type) throws Exception {
        // given
        List<RequestAttribute> attributes = List.of(requestAttribute("creation"));
        String remoteTokenUuid = profile.tokenInstance().tokenInstanceUuid();

        // when
        adapter.validateCreateKeyAttributes(profile.tokenInstance(), type, attributes);

        // then
        if (type == KeyRequestType.KEY_PAIR) {
            verify(client).validateCreateKeyPairAttributes(connector, remoteTokenUuid, attributes);
            verify(client, never()).validateCreateSecretKeyAttributes(any(), any(), any());
        } else {
            verify(client).validateCreateSecretKeyAttributes(connector, remoteTokenUuid, attributes);
            verify(client, never()).validateCreateKeyPairAttributes(any(), any(), any());
        }
    }

    @ParameterizedTest
    @EnumSource(KeyRequestType.class)
    void validateCreateKeyAttributes_propagatesRejection(KeyRequestType type) throws Exception {
        // given
        List<RequestAttribute> invalidAttributes = List.of(requestAttribute("invalid-key-size"));
        ValidationException rejection = new ValidationException("Unsupported key size");
        if (type == KeyRequestType.KEY_PAIR) {
            doThrow(rejection)
                    .when(client)
                    .validateCreateKeyPairAttributes(connector, profile.tokenInstance().tokenInstanceUuid(),
                            invalidAttributes);
        } else {
            doThrow(rejection)
                    .when(client)
                    .validateCreateSecretKeyAttributes(connector, profile.tokenInstance().tokenInstanceUuid(),
                            invalidAttributes);
        }

        // when
        Executable validate = () -> adapter
                .validateCreateKeyAttributes(profile.tokenInstance(), type, invalidAttributes);

        // then
        assertSame(rejection, assertThrows(ValidationException.class, validate));
    }

    @ParameterizedTest
    @EnumSource(KeyRequestType.class)
    void listCreateKeyAttributes_routesByRequestType(KeyRequestType type) throws Exception {
        // given
        List<BaseAttribute> pairDefinitions = List.of(new DataAttributeV2());
        List<BaseAttribute> secretDefinitions = List.of(new DataAttributeV2());
        String remoteTokenUuid = profile.tokenInstance().tokenInstanceUuid();
        when(client.listCreateKeyPairAttributes(connector, remoteTokenUuid)).thenReturn(pairDefinitions);
        when(client.listCreateSecretKeyAttributes(connector, remoteTokenUuid)).thenReturn(secretDefinitions);
        List<BaseAttribute> expectedDefinitions = type == KeyRequestType.KEY_PAIR ? pairDefinitions : secretDefinitions;

        // when
        List<BaseAttribute> definitions = adapter.listCreateKeyAttributes(profile, type);

        // then
        assertSame(expectedDefinitions, definitions);
    }

    private static RequestAttribute requestAttribute(String name) {
        RequestAttributeV2 attribute = new RequestAttributeV2();
        attribute.setName(name);
        return attribute;
    }

    private List<KeyDataResponseDto> stubCreatedKeys(KeyRequestType type) throws Exception {
        if (type == KeyRequestType.KEY_PAIR) {
            KeyDataResponseDto publicKey = providerKey("provider public key", KeyType.PUBLIC_KEY);
            KeyDataResponseDto privateKey = providerKey("provider private key", KeyType.PRIVATE_KEY);
            when(client.createKeyPair(eq(connector), eq(profile.tokenInstance().tokenInstanceUuid()), any()))
                    .thenReturn(new KeyPairDataResponseDto(publicKey, privateKey));
            return List.of(publicKey, privateKey);
        }
        KeyDataResponseDto secretKey = providerKey("provider secret key", KeyType.SECRET_KEY);
        when(client.createSecretKey(eq(connector), eq(profile.tokenInstance().tokenInstanceUuid()), any()))
                .thenReturn(secretKey);
        return List.of(secretKey);
    }

    private static KeyDataResponseDto providerKey(String name, KeyType type) {
        KeyData data = new KeyData(type, KeyAlgorithm.RSA, KeyFormat.RAW, new RawKeyValue("c2VjcmV0"), 2048, List.of());
        KeyDataResponseDto response = new KeyDataResponseDto("provider-group", data);
        response.setUuid(UUID.randomUUID().toString());
        response.setName(name);
        return response;
    }

    private CreateKeyRequestDto capturedCreateRequest(KeyRequestType type) throws Exception {
        ArgumentCaptor<CreateKeyRequestDto> request = ArgumentCaptor.forClass(CreateKeyRequestDto.class);
        if (type == KeyRequestType.KEY_PAIR) {
            verify(client)
                    .createKeyPair(eq(connector), eq(profile.tokenInstance().tokenInstanceUuid()), request.capture());
            verify(client, never()).createSecretKey(any(), any(), any());
        } else {
            verify(client)
                    .createSecretKey(eq(connector), eq(profile.tokenInstance().tokenInstanceUuid()), request.capture());
            verify(client, never()).createKeyPair(any(), any(), any());
        }
        return request.getValue();
    }

    private ImmutableCryptographicKeyFullModel keyWithTokenStatus(TokenInstanceStatus status) {
        var currentToken = profile.tokenInstance();
        var token = new ImmutableTokenInstanceFullModel(currentToken.uuid(), currentToken.tokenInstanceUuid(),
                currentToken.name(), status, currentToken.kind(), currentToken.connectorUuid(),
                currentToken.connectorName(), null, null, Set.of());
        return new ImmutableCryptographicKeyFullModel(cryptographicKey.uuid(), cryptographicKey.name(), null,
                profile.uuid(), token.uuid(), profile, token, Set.of(), null, null, null, List.of(), List.of());
    }

    private static Stream<RemoteKeyReference> invalidReferences() {
        return Stream
                .of(null, new RemoteKeyReference.UuidReference(null),
                        new RemoteKeyReference.MetadataReference(List.of()));
    }
}
