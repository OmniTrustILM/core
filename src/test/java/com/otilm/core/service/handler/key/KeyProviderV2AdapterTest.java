package com.otilm.core.service.handler.key;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.otilm.api.exception.ConnectorEntityNotFoundException;
import com.otilm.api.exception.ConnectorException;
import com.otilm.api.interfaces.client.v2.KeySyncApiClient;
import com.otilm.api.model.client.attribute.RequestAttribute;
import com.otilm.api.model.client.attribute.RequestAttributeV2;
import com.otilm.api.model.client.connector.v2.ConnectorVersion;
import com.otilm.api.model.client.cryptography.key.KeyRequestType;
import com.otilm.api.model.common.attribute.common.BaseAttribute;
import com.otilm.api.model.common.attribute.common.MetadataAttribute;
import com.otilm.api.model.common.attribute.common.content.data.SecretAttributeContentData;
import com.otilm.api.model.common.attribute.v2.DataAttributeV2;
import com.otilm.api.model.common.attribute.v2.MetadataAttributeV2;
import com.otilm.api.model.common.attribute.v2.content.SecretAttributeContentV2;
import com.otilm.api.model.common.attribute.v2.content.StringAttributeContentV2;
import com.otilm.api.model.common.enums.cryptography.KeyAlgorithm;
import com.otilm.api.model.common.enums.cryptography.KeyFormat;
import com.otilm.api.model.common.enums.cryptography.KeyType;
import com.otilm.api.model.connector.common.v2.OperationExecutionMode;
import com.otilm.api.model.connector.cryptography.enums.TokenInstanceStatus;
import com.otilm.api.model.connector.cryptography.v2.key.CreateKeyAttributesRequestV2Dto;
import com.otilm.api.model.connector.cryptography.v2.key.CreateKeyRequestV2Dto;
import com.otilm.api.model.connector.cryptography.v2.key.DestroyKeyRequestV2Dto;
import com.otilm.api.model.connector.cryptography.v2.key.KeyCreationResponseV2Dto;
import com.otilm.api.model.connector.cryptography.v2.key.KeyOperationResponseV2Dto;
import com.otilm.api.model.connector.cryptography.v2.key.KeyPairDataResponseV2Dto;
import com.otilm.api.model.connector.cryptography.v2.key.PrivateKeyDataResponseV2Dto;
import com.otilm.api.model.connector.cryptography.v2.key.PrivateKeyDataV2Dto;
import com.otilm.api.model.connector.cryptography.v2.key.PublicKeyDataResponseV2Dto;
import com.otilm.api.model.connector.cryptography.v2.key.PublicKeyDataV2Dto;
import com.otilm.api.model.connector.cryptography.v2.key.SecretKeyDataResponseV2Dto;
import com.otilm.api.model.connector.cryptography.v2.key.SecretKeyDataV2Dto;
import com.otilm.api.model.core.auth.Resource;
import com.otilm.api.model.core.connector.ConnectorStatus;
import com.otilm.api.model.core.cryptography.key.KeyUsage;
import com.otilm.core.attribute.engine.AttributeEngine;
import com.otilm.core.attribute.engine.OutboundSecretContainment;
import com.otilm.core.attribute.engine.OutboundSecretLeakException;
import com.otilm.core.attribute.engine.records.ObjectAttributeContentInfo;
import com.otilm.core.client.ConnectorApiFactory;
import com.otilm.core.model.connector.ImmutableConnectorFullModel;
import com.otilm.core.model.crypto.ImmutableCryptographicKeyFullModel;
import com.otilm.core.model.crypto.ImmutableTokenInstanceFullModel;
import com.otilm.core.model.crypto.ImmutableTokenProfileFullModel;
import com.otilm.core.model.crypto.ProviderKeyItem;
import com.otilm.core.model.crypto.RemoteKeyReference;
import com.otilm.core.model.crypto.TokenInstanceBasicModel;
import com.otilm.core.service.handler.OperationAttributeResolver;
import java.security.KeyPairGenerator;
import java.util.Base64;
import java.util.List;
import java.util.Set;
import java.util.UUID;
import java.util.stream.Stream;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.function.Executable;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.EnumSource;
import org.junit.jupiter.params.provider.MethodSource;
import org.mockito.ArgumentCaptor;
import org.springframework.http.ResponseEntity;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Named.named;
import static org.junit.jupiter.params.provider.Arguments.arguments;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;

class KeyProviderV2AdapterTest {

    private KeySyncApiClient client;
    private KeyProviderV2Adapter adapter;
    private ImmutableTokenProfileFullModel profile;
    private ImmutableCryptographicKeyFullModel cryptographicKey;
    private AttributeEngine attributes;
    private OperationAttributeResolver resolver;

    @BeforeEach
    void setUp() throws Exception {
        UUID connectorUuid = UUID.randomUUID();
        ImmutableConnectorFullModel connector = new ImmutableConnectorFullModel(connectorUuid, "connector",
                ConnectorVersion.V2, "http://connector.test", null, List.of(), ConnectorStatus.CONNECTED, null,
                List.of(), List.of());
        var token = new ImmutableTokenInstanceFullModel(UUID.randomUUID(), null, "token", TokenInstanceStatus.ACTIVATED,
                null, connectorUuid, connector.name(), null, null, Set.of());
        profile = new ImmutableTokenProfileFullModel(UUID.randomUUID(), "profile", null, token.name(), token.uuid(),
                true, List.of(KeyUsage.SIGN), token, connectorUuid);
        cryptographicKey = new ImmutableCryptographicKeyFullModel(UUID.randomUUID(), "key", null, profile.uuid(),
                profile.tokenInstanceReferenceUuid(), profile, profile.tokenInstance(), Set.of(), null, null, null,
                List.of(), List.of());
        ConnectorApiFactory factory = mock(ConnectorApiFactory.class);
        attributes = mock(AttributeEngine.class);
        resolver = mock(OperationAttributeResolver.class);
        client = mock(KeySyncApiClient.class);
        when(factory.getKeyManagementApiClientV2(connector)).thenReturn(client);
        when(attributes.getRequestObjectDataAttributesContent(any())).thenReturn(List.of());
        when(resolver.resolveForConnectorRequestAsSystem(connectorUuid, List.of())).thenReturn(List.of());
        adapter = new KeyProviderV2Adapter(factory, connector, attributes, resolver,
                new OutboundSecretContainment(new ObjectMapper()));
    }

    @Test
    void listKeys_throwsUnsupportedOperationException_withoutCallingConnector() {
        // given
        TokenInstanceBasicModel token = mock(TokenInstanceBasicModel.class);

        // when
        Executable listKeys = () -> adapter.listKeys(token);

        // then
        assertThrows(UnsupportedOperationException.class, listKeys);
        verifyNoInteractions(client, attributes, resolver, token);
    }

    @Test
    void destroyKey_preservesMetadataAndResolvesContext_forSynchronousRequest() throws Exception {
        // given
        List<MetadataAttribute> keyMeta = metadata("durable-key-handle");
        List<RequestAttribute> storedToken = List.of(requestAttribute("stored-token"));
        List<RequestAttribute> storedProfile = List.of(requestAttribute("stored-profile"));
        List<RequestAttribute> resolvedToken = List.of(requestAttribute("resolved-token"));
        List<RequestAttribute> resolvedProfile = List.of(requestAttribute("resolved-profile"));
        stubAttributes(Resource.TOKEN, profile.tokenInstanceReferenceUuid(), storedToken, resolvedToken);
        stubAttributes(Resource.TOKEN_PROFILE, profile.uuid(), storedProfile, resolvedProfile);
        when(client.destroyKey(any(), any())).thenReturn(ResponseEntity.ok(new KeyOperationResponseV2Dto()));

        // when
        adapter.destroyKeyItem(cryptographicKey, new RemoteKeyReference.MetadataReference(keyMeta));

        // then
        ArgumentCaptor<DestroyKeyRequestV2Dto> request = ArgumentCaptor.forClass(DestroyKeyRequestV2Dto.class);
        verify(client).destroyKey(any(), request.capture());
        assertSame(keyMeta, request.getValue().getKeyMeta());
        assertSame(resolvedToken, request.getValue().getTokenAttributes());
        assertSame(resolvedProfile, request.getValue().getTokenProfileAttributes());
        assertEquals(Set.copyOf(profile.usages()), request.getValue().getKeyUsages());
        assertEquals(OperationExecutionMode.SYNCHRONOUS, request.getValue().getExecutionMode());
    }

    @ParameterizedTest
    @MethodSource("incompleteDestructionResponses")
    void destroyKey_rejectsUnconfirmedCompletion(ResponseEntity<KeyOperationResponseV2Dto> response) throws Exception {
        // given
        RemoteKeyReference reference = new RemoteKeyReference.MetadataReference(metadata("key-handle"));
        when(client.destroyKey(any(), any())).thenReturn(response);

        // when
        Executable destroy = () -> adapter.destroyKeyItem(cryptographicKey, reference);

        // then
        ConnectorException exception = assertThrows(ConnectorException.class, destroy);
        assertEquals("Connector did not confirm synchronous key destruction.", exception.getMessage());
    }

    @ParameterizedTest
    @MethodSource("invalidDestructionReferences")
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
        RemoteKeyReference reference = new RemoteKeyReference.MetadataReference(metadata("key-handle"));
        ConnectorException failure = new ConnectorException("Destruction failed");
        when(client.destroyKey(any(), any())).thenThrow(failure);

        // when
        Executable destroy = () -> adapter.destroyKeyItem(cryptographicKey, reference);

        // then
        assertSame(failure, assertThrows(ConnectorException.class, destroy));
    }

    @ParameterizedTest
    @EnumSource(value = TokenInstanceStatus.class, names = {"ACTIVATED", "DEACTIVATED"})
    void destroyKey_succeeds_whenRemoteKeyIsAlreadyAbsent(TokenInstanceStatus status) throws Exception {
        // given
        RemoteKeyReference reference = new RemoteKeyReference.MetadataReference(metadata("deleted-key-handle"));
        ImmutableCryptographicKeyFullModel key = keyWithTokenStatus(status);
        when(client.destroyKey(any(), any()))
                .thenThrow(new ConnectorEntityNotFoundException("Key was already deleted"));

        // when
        Executable destroy = () -> adapter.destroyKeyItem(key, reference);

        // then
        assertDoesNotThrow(destroy);
        verify(client).destroyKey(any(), any());
    }

    @Test
    void destroyKey_toleratesConnectorFailure_forDeactivatedToken() throws Exception {
        // given
        RemoteKeyReference reference = new RemoteKeyReference.MetadataReference(metadata("offline-key-handle"));
        ImmutableCryptographicKeyFullModel key = keyWithTokenStatus(TokenInstanceStatus.DEACTIVATED);
        ConnectorException failure = new ConnectorException("Token is offline");
        when(client.destroyKey(any(), any())).thenThrow(failure);

        // when
        Executable destroy = () -> adapter.destroyKeyItem(key, reference);

        // then
        assertDoesNotThrow(destroy);
        verify(client).destroyKey(any(), any());
    }

    @ParameterizedTest
    @MethodSource("incompleteDestructionResponses")
    void destroyKey_toleratesUnconfirmedCompletion_forDeactivatedToken(
            ResponseEntity<KeyOperationResponseV2Dto> response) throws Exception {
        // given
        RemoteKeyReference reference = new RemoteKeyReference.MetadataReference(metadata("offline-key-handle"));
        ImmutableCryptographicKeyFullModel key = keyWithTokenStatus(TokenInstanceStatus.DEACTIVATED);
        when(client.destroyKey(any(), any())).thenReturn(response);

        // when
        Executable destroy = () -> adapter.destroyKeyItem(key, reference);

        // then
        assertDoesNotThrow(destroy);
        verify(client).destroyKey(any(), any());
    }

    @Test
    void destroyKey_propagatesRuntimeFailure_forDeactivatedToken() throws Exception {
        // given
        RemoteKeyReference reference = new RemoteKeyReference.MetadataReference(metadata("offline-key-handle"));
        ImmutableCryptographicKeyFullModel key = keyWithTokenStatus(TokenInstanceStatus.DEACTIVATED);
        RuntimeException failure = new IllegalStateException("Unexpected connector client failure");
        when(client.destroyKey(any(), any())).thenThrow(failure);

        // when
        Executable destroy = () -> adapter.destroyKeyItem(key, reference);

        // then
        assertSame(failure, assertThrows(IllegalStateException.class, destroy));
    }

    private static RequestAttribute requestAttribute(String name) {
        RequestAttributeV2 attribute = new RequestAttributeV2();
        attribute.setName(name);
        return attribute;
    }

    private void stubAttributes(Resource resource, UUID uuid, List<RequestAttribute> stored,
            List<RequestAttribute> resolved) throws ConnectorException {
        ObjectAttributeContentInfo info = ObjectAttributeContentInfo
                .builder(resource, uuid)
                .connector(profile.connectorUuid())
                .build();
        when(attributes.getRequestObjectDataAttributesContent(info)).thenReturn(stored);
        when(resolver.resolveForConnectorRequestAsSystem(profile.connectorUuid(), stored)).thenReturn(resolved);
    }

    private static Stream<ResponseEntity<KeyOperationResponseV2Dto>> incompleteDestructionResponses() {
        KeyOperationResponseV2Dto trackingResponse = new KeyOperationResponseV2Dto();
        trackingResponse.setOperationMeta(metadata("operation-handle"));
        return Stream
                .of(ResponseEntity.accepted().body(trackingResponse), ResponseEntity.ok().build(),
                        ResponseEntity.ok(trackingResponse));
    }

    private static Stream<RemoteKeyReference> invalidDestructionReferences() {
        return Stream
                .of(null, new RemoteKeyReference.UuidReference(UUID.randomUUID()),
                        new RemoteKeyReference.MetadataReference(null),
                        new RemoteKeyReference.MetadataReference(List.of()));
    }

    @Test
    void createKey_preservesSeparateHandlesAndPublicMaterial_forKeyPair() throws Exception {
        // given
        KeyPairDataResponseV2Dto response = keyPairResponse();
        String wrapperName = "Signing";
        byte[] expectedSpki = response.getPublicKeyData().getKeyData().getPublicKeySpki();
        when(client.createKey(any(), any())).thenReturn(ResponseEntity.ok(response));

        // when
        List<ProviderKeyItem> items = adapter.createKey(profile, KeyRequestType.KEY_PAIR, List.of(), wrapperName);

        // then
        assertEquals(2, items.size());
        ProviderKeyItem publicKey = items.get(0);
        ProviderKeyItem privateKey = items.get(1);
        assertEquals(wrapperName + " public key", publicKey.name());
        assertEquals(wrapperName + " private key", privateKey.name());
        assertEquals(KeyType.PUBLIC_KEY, publicKey.type());
        assertEquals(KeyFormat.SPKI, publicKey.material().format());
        assertArrayEquals(expectedSpki, Base64.getDecoder().decode(publicKey.material().serializedValue()));
        assertEquals(new RemoteKeyReference.MetadataReference(response.getPublicKeyData().getKeyMeta()),
                publicKey.reference());
        assertEquals(KeyType.PRIVATE_KEY, privateKey.type());
        assertNull(privateKey.material());
        assertEquals(new RemoteKeyReference.MetadataReference(response.getPrivateKeyData().getKeyMeta()),
                privateKey.reference());
    }

    @Test
    void createKey_preservesSecretDescriptorAndRequestsSynchronousExecution() throws Exception {
        // given
        SecretKeyDataResponseV2Dto response = secretKeyResponse();
        String wrapperName = "Encryption";
        RequestAttribute creationAttribute = new RequestAttributeV2();
        List<RequestAttribute> creationAttributes = List.of(creationAttribute);
        when(client.createKey(any(), any())).thenReturn(ResponseEntity.ok(response));

        // when
        List<ProviderKeyItem> items = adapter
                .createKey(profile, KeyRequestType.SECRET, creationAttributes, wrapperName);

        // then
        assertEquals(1, items.size());
        ProviderKeyItem key = items.getFirst();
        assertEquals(KeyType.SECRET_KEY, key.type());
        assertEquals(response.getKeyData().getAlgorithm(), key.algorithm());
        assertEquals(response.getKeyData().getLength().intValue(), key.length());
        assertEquals(response.getKeyData().getMetadata(), key.metadata());
        assertEquals(new RemoteKeyReference.MetadataReference(response.getKeyMeta()), key.reference());
        assertNull(key.material());
        assertEquals(wrapperName, key.name());
        ArgumentCaptor<CreateKeyRequestV2Dto> request = ArgumentCaptor.forClass(CreateKeyRequestV2Dto.class);
        verify(client).createKey(any(), request.capture());
        assertEquals(OperationExecutionMode.SYNCHRONOUS, request.getValue().getExecutionMode());
        assertEquals(KeyRequestType.SECRET, request.getValue().getKeyRequestType());
        assertEquals(creationAttributes, request.getValue().getCreateKeyAttributes());
        assertDoesNotThrow(() -> UUID.fromString(request.getValue().getKeyCreationId()));
    }

    @Test
    void createKey_rejectsAsynchronousAcceptance() throws Exception {
        // given
        when(client.createKey(any(), any())).thenReturn(ResponseEntity.accepted().build());

        // when
        Executable createKey = () -> adapter.createKey(profile, KeyRequestType.SECRET, List.of(), profile.name());

        // then
        ConnectorException exception = assertThrows(ConnectorException.class, createKey);
        assertTrue(exception.getMessage().contains("synchronous key creation result"));
    }

    @Test
    void createKey_resolvesTokenAndProfileContext() throws Exception {
        // given
        List<RequestAttribute> resolvedToken = List.of(requestAttribute("resolved-token"));
        List<RequestAttribute> resolvedProfile = List.of(requestAttribute("resolved-profile"));
        stubAttributes(Resource.TOKEN, profile.tokenInstanceReferenceUuid(), List.of(requestAttribute("stored-token")),
                resolvedToken);
        stubAttributes(Resource.TOKEN_PROFILE, profile.uuid(), List.of(requestAttribute("stored-profile")),
                resolvedProfile);
        when(client.createKey(any(), any())).thenReturn(ResponseEntity.ok(secretKeyResponse()));

        // when
        adapter.createKey(profile, KeyRequestType.SECRET, List.of(), profile.name());

        // then
        ArgumentCaptor<CreateKeyRequestV2Dto> request = ArgumentCaptor.forClass(CreateKeyRequestV2Dto.class);
        verify(client).createKey(any(), request.capture());
        assertEquals(resolvedToken, request.getValue().getTokenAttributes());
        assertEquals(resolvedProfile, request.getValue().getTokenProfileAttributes());
        assertEquals(Set.copyOf(profile.usages()), request.getValue().getKeyUsages());
    }

    @ParameterizedTest(name = "{0}")
    @MethodSource("invalidCreationResults")
    void createKey_rejectsInvalidSynchronousResult(ResponseEntity<KeyCreationResponseV2Dto> response) throws Exception {
        // given
        when(client.createKey(any(), any())).thenReturn(response);

        // when
        Executable create = () -> adapter.createKey(profile, KeyRequestType.SECRET, List.of(), profile.name());

        // then
        ConnectorException exception = assertThrows(ConnectorException.class, create);
        assertEquals("Connector did not return the requested synchronous key creation result.", exception.getMessage());
    }

    @Test
    void createKey_propagatesConnectorFailure() throws Exception {
        // given
        ConnectorException failure = new ConnectorException("Key creation failed");
        when(client.createKey(any(), any())).thenThrow(failure);

        // when
        Executable create = () -> adapter.createKey(profile, KeyRequestType.SECRET, List.of(), profile.name());

        // then
        assertSame(failure, assertThrows(ConnectorException.class, create));
    }

    @ParameterizedTest
    @EnumSource(KeyRequestType.class)
    void listCreateKeyAttributes_resolvesContextAndPreservesRequestType(KeyRequestType type) throws Exception {
        // given
        List<RequestAttribute> resolvedToken = List.of(requestAttribute("resolved-token"));
        List<RequestAttribute> resolvedProfile = List.of(requestAttribute("resolved-profile"));
        stubAttributes(Resource.TOKEN, profile.tokenInstanceReferenceUuid(), List.of(requestAttribute("stored-token")),
                resolvedToken);
        stubAttributes(Resource.TOKEN_PROFILE, profile.uuid(), List.of(requestAttribute("stored-profile")),
                resolvedProfile);
        List<BaseAttribute> expectedDefinitions = List.of(new DataAttributeV2());
        when(client.listCreateKeyAttributes(any(), any())).thenReturn(expectedDefinitions);

        // when
        List<BaseAttribute> definitions = adapter.listCreateKeyAttributes(profile, type);

        // then
        assertSame(expectedDefinitions, definitions);
        ArgumentCaptor<CreateKeyAttributesRequestV2Dto> request = ArgumentCaptor
                .forClass(CreateKeyAttributesRequestV2Dto.class);
        verify(client).listCreateKeyAttributes(any(), request.capture());
        assertEquals(type, request.getValue().getKeyRequestType());
        assertEquals(resolvedToken, request.getValue().getTokenAttributes());
        assertEquals(resolvedProfile, request.getValue().getTokenProfileAttributes());
        assertEquals(Set.copyOf(profile.usages()), request.getValue().getKeyUsages());
    }

    @Test
    void listCreateKeyAttributes_stopsWhenAttributeResolutionFails() throws Exception {
        // given
        ConnectorException failure = new ConnectorException("Stored credential cannot be resolved");
        when(resolver.resolveForConnectorRequestAsSystem(profile.connectorUuid(), List.of())).thenThrow(failure);

        // when
        Executable listDefinitions = () -> adapter.listCreateKeyAttributes(profile, KeyRequestType.SECRET);

        // then
        assertSame(failure, assertThrows(ConnectorException.class, listDefinitions));
        verifyNoInteractions(client);
    }

    @ParameterizedTest
    @EnumSource(value = Resource.class, names = {"TOKEN", "TOKEN_PROFILE"})
    void listCreateKeyAttributes_rejectsSecretEchoFromEitherScope(Resource secretScope) throws Exception {
        // given
        String expandedSecret = "resolved-provider-password";
        stubExpandedSecret(secretScope, expandedSecret);
        List<BaseAttribute> echoedDefinitions = definitionsWithDefault(expandedSecret);
        when(client.listCreateKeyAttributes(any(), any())).thenReturn(echoedDefinitions);

        // when
        Executable listDefinitions = () -> adapter.listCreateKeyAttributes(profile, KeyRequestType.SECRET);

        // then
        assertThrows(OutboundSecretLeakException.class, listDefinitions);
    }

    @Test
    void listCreateKeyAttributes_allowsOrdinaryDefaultsAfterSecretExpansion() throws Exception {
        // given
        stubExpandedSecret(Resource.TOKEN, "resolved-token-password");
        stubExpandedSecret(Resource.TOKEN_PROFILE, "resolved-profile-password");
        List<BaseAttribute> expectedDefinitions = definitionsWithDefault("RSA");
        when(client.listCreateKeyAttributes(any(), any())).thenReturn(expectedDefinitions);

        // when
        List<BaseAttribute> definitions = adapter.listCreateKeyAttributes(profile, KeyRequestType.KEY_PAIR);

        // then
        assertSame(expectedDefinitions, definitions);
    }

    private void stubExpandedSecret(Resource resource, String secret) throws Exception {
        RequestAttributeV2 resolved = new RequestAttributeV2();
        resolved.setName("credential");
        resolved
                .setContent(List
                        .of(new SecretAttributeContentV2("credential-reference",
                                new SecretAttributeContentData(secret))));
        UUID resourceUuid = resource == Resource.TOKEN ? profile.tokenInstanceReferenceUuid() : profile.uuid();
        stubAttributes(resource, resourceUuid, List.of(requestAttribute(resource.name())), List.of(resolved));
    }

    private static List<BaseAttribute> definitionsWithDefault(String value) {
        DataAttributeV2 definition = new DataAttributeV2();
        definition.setName("algorithm");
        definition.setContent(List.of(new StringAttributeContentV2(value)));
        return List.of(definition);
    }

    private static Stream<Arguments> invalidCreationResults() {
        return Stream
                .of(arguments(named("successful HTTP response without body", ResponseEntity.ok().build())), arguments(
                        named("pair returned for secret request", ResponseEntity.ok(new KeyPairDataResponseV2Dto()))));
    }

    private ImmutableCryptographicKeyFullModel keyWithTokenStatus(TokenInstanceStatus status) {
        var currentToken = profile.tokenInstance();
        var token = new ImmutableTokenInstanceFullModel(currentToken.uuid(), currentToken.tokenInstanceUuid(),
                currentToken.name(), status, currentToken.kind(), currentToken.connectorUuid(),
                currentToken.connectorName(), null, null, Set.of());
        return new ImmutableCryptographicKeyFullModel(cryptographicKey.uuid(), cryptographicKey.name(), null,
                profile.uuid(), token.uuid(), profile, token, Set.of(), null, null, null, List.of(), List.of());
    }

    private static SecretKeyDataResponseV2Dto secretKeyResponse() {
        SecretKeyDataV2Dto data = new SecretKeyDataV2Dto();
        data.setAlgorithm(KeyAlgorithm.UNKNOWN);
        data.setLength(256);
        data.setMetadata(metadata("description"));
        SecretKeyDataResponseV2Dto response = new SecretKeyDataResponseV2Dto();
        response.setKeyData(data);
        response.setKeyMeta(metadata("secret-handle"));
        return response;
    }

    private static KeyPairDataResponseV2Dto keyPairResponse() throws Exception {
        KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
        generator.initialize(2048);
        byte[] publicKeySpki = generator.generateKeyPair().getPublic().getEncoded();
        PublicKeyDataV2Dto publicData = new PublicKeyDataV2Dto();
        publicData.setAlgorithm(KeyAlgorithm.RSA);
        publicData.setLength(2048);
        publicData.setPublicKeySpki(publicKeySpki);
        PublicKeyDataResponseV2Dto publicKey = new PublicKeyDataResponseV2Dto();
        publicKey.setKeyData(publicData);
        publicKey.setKeyMeta(metadata("public-handle"));
        PrivateKeyDataV2Dto privateData = new PrivateKeyDataV2Dto();
        privateData.setAlgorithm(KeyAlgorithm.RSA);
        privateData.setLength(2048);
        PrivateKeyDataResponseV2Dto privateKey = new PrivateKeyDataResponseV2Dto();
        privateKey.setKeyData(privateData);
        privateKey.setKeyMeta(metadata("private-handle"));
        KeyPairDataResponseV2Dto response = new KeyPairDataResponseV2Dto();
        response.setPublicKeyData(publicKey);
        response.setPrivateKeyData(privateKey);
        response.setKeyPairMeta(metadata("pair-handle"));
        return response;
    }

    private static List<MetadataAttribute> metadata(String name) {
        MetadataAttributeV2 attribute = new MetadataAttributeV2();
        attribute.setName(name);
        return List.of(attribute);
    }
}
