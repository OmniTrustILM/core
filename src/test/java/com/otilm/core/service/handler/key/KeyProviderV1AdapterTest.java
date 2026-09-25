package com.otilm.core.service.handler.key;

import com.otilm.api.clients.ApiClientConnectorInfo;
import com.otilm.api.exception.ConnectorEntityNotFoundException;
import com.otilm.api.exception.ConnectorException;
import com.otilm.api.exception.ValidationException;
import com.otilm.api.interfaces.client.v1.CryptographicOperationsSyncApiClient;
import com.otilm.api.interfaces.client.v1.KeyManagementSyncApiClient;
import com.otilm.api.model.client.attribute.RequestAttribute;
import com.otilm.api.model.client.attribute.RequestAttributeV2;
import com.otilm.api.model.client.cryptography.key.KeyRequestType;
import com.otilm.api.model.client.cryptography.operations.CipherDataRequestDto;
import com.otilm.api.model.client.cryptography.operations.CipherRequestData;
import com.otilm.api.model.client.cryptography.operations.DecryptDataResponseDto;
import com.otilm.api.model.client.cryptography.operations.EncryptDataResponseDto;
import com.otilm.api.model.client.cryptography.operations.SignDataRequestDto;
import com.otilm.api.model.client.cryptography.operations.SignDataResponseDto;
import com.otilm.api.model.client.cryptography.operations.SignatureRequestData;
import com.otilm.api.model.client.cryptography.operations.VerifyDataRequestDto;
import com.otilm.api.model.client.cryptography.operations.VerifyDataResponseDto;
import com.otilm.api.model.common.attribute.common.BaseAttribute;
import com.otilm.api.model.common.attribute.common.MetadataAttribute;
import com.otilm.api.model.common.attribute.v2.DataAttributeV2;
import com.otilm.api.model.common.attribute.v2.MetadataAttributeV2;
import com.otilm.api.model.common.attribute.v2.content.ObjectAttributeContentV2;
import com.otilm.api.model.common.enums.cryptography.DigestAlgorithm;
import com.otilm.api.model.common.enums.cryptography.KeyAlgorithm;
import com.otilm.api.model.common.enums.cryptography.KeyFormat;
import com.otilm.api.model.common.enums.cryptography.KeyType;
import com.otilm.api.model.common.enums.cryptography.RsaSignatureScheme;
import com.otilm.api.model.common.enums.cryptography.SignatureAlgorithm;
import com.otilm.api.model.connector.cryptography.enums.TokenInstanceStatus;
import com.otilm.api.model.connector.cryptography.key.CreateKeyRequestDto;
import com.otilm.api.model.connector.cryptography.key.KeyData;
import com.otilm.api.model.connector.cryptography.key.KeyDataResponseDto;
import com.otilm.api.model.connector.cryptography.key.KeyPairDataResponseDto;
import com.otilm.api.model.connector.cryptography.key.value.RawKeyValue;
import com.otilm.api.model.core.auth.Resource;
import com.otilm.api.model.core.cryptography.key.KeyState;
import com.otilm.api.model.core.cryptography.key.KeyUsage;
import com.otilm.api.model.core.secret.Passphrase;
import com.otilm.core.attribute.RsaSignatureAttributes;
import com.otilm.core.attribute.engine.AttributeEngine;
import com.otilm.core.attribute.engine.records.ObjectAttributeContentInfo;
import com.otilm.core.client.ConnectorApiFactory;
import com.otilm.core.model.crypto.CryptographicKeyItemModelFixtures;
import com.otilm.core.model.crypto.CryptographicKeyItemOperationModel;
import com.otilm.core.model.crypto.ImmutableCryptographicKeyFullModel;
import com.otilm.core.model.crypto.ImmutableTokenInstanceFullModel;
import com.otilm.core.model.crypto.ImmutableTokenProfileFullModel;
import com.otilm.core.model.crypto.ProviderKeyItem;
import com.otilm.core.model.crypto.RemoteKeyReference;
import com.otilm.core.model.crypto.TransferableKeyType;
import com.otilm.core.service.handler.LegacyOperationFixtures;
import java.util.Base64;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
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
import org.junit.jupiter.params.provider.NullAndEmptySource;
import org.junit.jupiter.params.provider.ValueSource;
import org.mockito.ArgumentCaptor;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
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
    private CryptographicOperationsSyncApiClient operationsClient;
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
        operationsClient = mock(CryptographicOperationsSyncApiClient.class);
        when(factory.getCryptographicOperationsApiClient(connector)).thenReturn(operationsClient);
        attributeEngine = mock(AttributeEngine.class);
        adapter = new KeyProviderV1Adapter(factory, connector, attributeEngine);
        UUID connectorUuid = UUID.randomUUID();
        ImmutableTokenInstanceFullModel token = new ImmutableTokenInstanceFullModel(UUID.randomUUID(),
                UUID.randomUUID().toString(), "token", TokenInstanceStatus.ACTIVATED, null, connectorUuid, "connector",
                null, null, Set.of());
        profile = new ImmutableTokenProfileFullModel(UUID.randomUUID(), "profile", null, token.name(), token.uuid(),
                true, List.of(), token, connectorUuid, Map.of(), null, 0);
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
    void listExportKeyAttributes_offersNothingForAV1Connector() {
        // given
        OperationKeyContext context = OperationKeyContext
                .legacy(keyItem(KeyAlgorithm.RSA, new RemoteKeyReference.UuidReference(UUID.randomUUID()),
                        UUID.randomUUID()));

        // when
        // then
        assertEquals(List.of(), adapter.listExportKeyAttributes(context));
    }

    @Test
    void exportKey_isRefusedForAV1Connector() {
        // given
        OperationKeyContext context = OperationKeyContext
                .legacy(keyItem(KeyAlgorithm.RSA, new RemoteKeyReference.UuidReference(UUID.randomUUID()),
                        UUID.randomUUID()));
        HeldKey heldKey = new HeldKey(KeyRequestType.KEY_PAIR, KeyAlgorithm.RSA, 2048, new byte[]{1}, null);
        Passphrase passphrase = new Passphrase("correct horse battery staple".toCharArray());

        // when
        // then
        List<RequestAttribute> noAttributes = List.of();
        assertThrows(ValidationException.class, () -> adapter.exportKey(context, heldKey, passphrase, noAttributes));
    }

    @Test
    void listExportableKeyTypes_isEmptyForAV1Connector() {
        // when
        List<TransferableKeyType> exportable = adapter.listExportableKeyTypes(profile);

        // then
        assertTrue(exportable.isEmpty());
    }

    @Test
    void listImportableKeyTypes_isEmptyForAV1Connector() {
        // when
        List<TransferableKeyType> importable = adapter.listImportableKeyTypes(profile);

        // then
        assertTrue(importable.isEmpty());
    }

    @Test
    void listImportKeyAttributes_isEmptyForAV1Connector() {
        // when
        List<BaseAttribute> attributes = adapter.listImportKeyAttributes(profile, KeyRequestType.KEY_PAIR);

        // then
        assertTrue(attributes.isEmpty());
        verifyNoInteractions(client);
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
        List<ProviderKeyItem> items = adapter.createKey(profile, type, creationAttributes, profile.name(), false);

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

    @Test
    void signData_forwardsRemoteUuids_andMapsSignatures() throws Exception {
        // given
        UUID remoteUuid = UUID.randomUUID();
        UUID remoteToken = UUID.randomUUID();
        OperationKeyContext context = OperationKeyContext
                .legacy(keyItem(KeyAlgorithm.MLDSA, new RemoteKeyReference.UuidReference(remoteUuid), remoteToken));
        SignDataRequestDto request = new SignDataRequestDto();
        request.setSignatureAttributes(List.of());
        SignatureRequestData item = new SignatureRequestData();
        item.setData(Base64.getEncoder().encodeToString(new byte[]{1, 2}));
        item.setIdentifier("a");
        request.setData(List.of(item));
        when(operationsClient.signData(eq(connector), eq(remoteToken.toString()), eq(remoteUuid.toString()), any()))
                .thenReturn(LegacyOperationFixtures.signResponse(new byte[]{9}, "a"));

        // when
        SignDataResponseDto response = adapter.signData(context, request);

        // then
        assertEquals("a", response.getSignatures().get(0).getIdentifier());
        assertEquals(Base64.getEncoder().encodeToString(new byte[]{9}), response.getSignatures().get(0).getData());
    }

    @ParameterizedTest(name = "{0} / {1}")
    @MethodSource("unsupportedV1Keys")
    void operation_rejectsKeyWithoutV1Remotes_beforeCallingConnector(String operation, String reason,
            RemoteKeyReference reference, UUID remoteTokenUuid, String expectedMessage, OperationCall call) {
        // given
        OperationKeyContext context = OperationKeyContext
                .legacy(keyItem(KeyAlgorithm.MLDSA, reference, remoteTokenUuid));

        // when
        Executable operate = () -> call.run(adapter, context);

        // then
        ConnectorException failure = assertThrows(ConnectorException.class, operate);
        assertEquals(expectedMessage, failure.getMessage());
        verifyNoInteractions(operationsClient);
    }

    private static Stream<Arguments> unsupportedV1Keys() {
        String keyMessage = "This cryptographic operation requires a v1 remote key UUID; "
                + "metadata references are not supported.";
        String tokenMessage = "This cryptographic operation requires a v1 remote token UUID.";
        List<Arguments> references = List
                .of(Arguments
                        .of("metadata handle", new RemoteKeyReference.MetadataReference(List.of(metadataHandle())),
                                UUID.randomUUID(), keyMessage),
                        Arguments
                                .of("empty metadata handle", new RemoteKeyReference.MetadataReference(List.of()),
                                        UUID.randomUUID(), keyMessage),
                        Arguments.of("missing reference", null, UUID.randomUUID(), keyMessage),
                        Arguments
                                .of("reference without a UUID", new RemoteKeyReference.UuidReference(null),
                                        UUID.randomUUID(), keyMessage),
                        Arguments
                                .of("missing token UUID", new RemoteKeyReference.UuidReference(UUID.randomUUID()), null,
                                        tokenMessage));
        return operationCalls()
                .entrySet()
                .stream()
                .flatMap(operation -> references
                        .stream()
                        .map(reference -> Arguments
                                .of(operation.getKey(), reference.get()[0], reference.get()[1], reference.get()[2],
                                        reference.get()[3], operation.getValue())));
    }

    private static Map<String, OperationCall> operationCalls() {
        CipherDataRequestDto cipherRequest = new CipherDataRequestDto();
        cipherRequest.setCipherAttributes(List.of());
        cipherRequest.setCipherData(List.of());
        SignDataRequestDto signRequest = new SignDataRequestDto();
        signRequest.setSignatureAttributes(List.of());
        signRequest.setData(List.of());
        VerifyDataRequestDto verifyRequest = new VerifyDataRequestDto();
        verifyRequest.setSignatureAttributes(List.of());
        verifyRequest.setData(List.of());
        verifyRequest.setSignatures(List.of());
        return new LinkedHashMap<>(Map
                .of("encrypt", (adapter, context) -> adapter.encryptData(context, cipherRequest), "decrypt",
                        (adapter, context) -> adapter.decryptData(context, cipherRequest), "sign",
                        (adapter, context) -> adapter.signData(context, signRequest), "verify",
                        (adapter, context) -> adapter.verifyData(context, verifyRequest)));
    }

    private static MetadataAttribute metadataHandle() {
        MetadataAttributeV2 handle = new MetadataAttributeV2();
        handle.setName("provider-key-handle");
        return handle;
    }

    @FunctionalInterface
    interface OperationCall {
        void run(KeyProviderV1Adapter adapter, OperationKeyContext context) throws ConnectorException;
    }

    @Test
    void signData_rejectsUnknownSignatureAttribute_forRsaKey() {
        // given
        OperationKeyContext context = OperationKeyContext
                .legacy(keyItem(KeyAlgorithm.RSA, new RemoteKeyReference.UuidReference(UUID.randomUUID()),
                        UUID.randomUUID()));
        SignDataRequestDto request = new SignDataRequestDto();
        RequestAttributeV2 unknown = new RequestAttributeV2();
        unknown.setName("not-an-rsa-attribute");
        request.setSignatureAttributes(List.of(unknown));
        request.setData(List.of());

        // when
        Executable sign = () -> adapter.signData(context, request);

        // then
        assertThrows(ValidationException.class, sign);
        verifyNoInteractions(operationsClient);
    }

    @Test
    void encryptData_mapsEncryptedItems() throws Exception {
        // given
        OperationKeyContext context = OperationKeyContext
                .legacy(keyItem(KeyAlgorithm.RSA, new RemoteKeyReference.UuidReference(UUID.randomUUID()),
                        UUID.randomUUID()));
        CipherDataRequestDto request = new CipherDataRequestDto();
        request.setCipherAttributes(List.of());
        CipherRequestData item = new CipherRequestData();
        item.setData("AQ==");
        item.setIdentifier("c");
        request.setCipherData(List.of(item));
        when(operationsClient.encryptData(any(), any(), any(), any()))
                .thenReturn(LegacyOperationFixtures.encryptResponse(new byte[]{5}, "c"));

        // when
        EncryptDataResponseDto response = adapter.encryptData(context, request);

        // then
        assertEquals("c", response.getEncryptedData().get(0).getIdentifier());
        assertEquals(Base64.getEncoder().encodeToString(new byte[]{5}), response.getEncryptedData().get(0).getData());
    }

    @Test
    void decryptData_mapsDecryptedItems() throws Exception {
        // given
        OperationKeyContext context = OperationKeyContext
                .legacy(keyItem(KeyAlgorithm.RSA, new RemoteKeyReference.UuidReference(UUID.randomUUID()),
                        UUID.randomUUID()));
        CipherDataRequestDto request = new CipherDataRequestDto();
        request.setCipherAttributes(List.of());
        CipherRequestData item = new CipherRequestData();
        item.setData("AQ==");
        item.setIdentifier("c");
        request.setCipherData(List.of(item));
        when(operationsClient.decryptData(any(), any(), any(), any()))
                .thenReturn(LegacyOperationFixtures.decryptResponse(new byte[]{5}, "c"));

        // when
        DecryptDataResponseDto response = adapter.decryptData(context, request);

        // then
        assertEquals("c", response.getDecryptedData().get(0).getIdentifier());
        assertEquals(Base64.getEncoder().encodeToString(new byte[]{5}), response.getDecryptedData().get(0).getData());
    }

    @Test
    void verifyData_mapsVerificationResult() throws Exception {
        // given
        OperationKeyContext context = OperationKeyContext
                .legacy(keyItem(KeyAlgorithm.MLDSA, new RemoteKeyReference.UuidReference(UUID.randomUUID()),
                        UUID.randomUUID()));
        VerifyDataRequestDto request = new VerifyDataRequestDto();
        request.setSignatureAttributes(List.of());
        SignatureRequestData signature = new SignatureRequestData();
        signature.setData("AQ==");
        signature.setIdentifier("v");
        request.setSignatures(List.of(signature));
        when(operationsClient.verifyData(any(), any(), any(), any()))
                .thenReturn(LegacyOperationFixtures.verifyResponse(true, "v"));

        // when
        VerifyDataResponseDto response = adapter.verifyData(context, request);

        // then
        assertTrue(response.getVerifications().get(0).isResult());
        assertEquals("v", response.getVerifications().get(0).getIdentifier());
    }

    @Test
    void encryptData_leavesDataNull_whenConnectorOmitsIt() throws Exception {
        // given
        OperationKeyContext context = OperationKeyContext
                .legacy(keyItem(KeyAlgorithm.RSA, new RemoteKeyReference.UuidReference(UUID.randomUUID()),
                        UUID.randomUUID()));
        CipherDataRequestDto request = new CipherDataRequestDto();
        request.setCipherAttributes(List.of());
        request.setCipherData(List.of());
        when(operationsClient.encryptData(any(), any(), any(), any()))
                .thenReturn(LegacyOperationFixtures.encryptResponseWithoutData());

        // when
        EncryptDataResponseDto response = adapter.encryptData(context, request);

        // then
        assertNull(response.getEncryptedData());
    }

    @Test
    void signData_leavesSignaturesNull_whenConnectorOmitsThem() throws Exception {
        // given
        OperationKeyContext context = OperationKeyContext
                .legacy(keyItem(KeyAlgorithm.MLDSA, new RemoteKeyReference.UuidReference(UUID.randomUUID()),
                        UUID.randomUUID()));
        SignDataRequestDto request = new SignDataRequestDto();
        request.setSignatureAttributes(List.of());
        request.setData(List.of());
        when(operationsClient.signData(any(), any(), any(), any()))
                .thenReturn(LegacyOperationFixtures.signResponseWithoutSignatures());

        // when
        SignDataResponseDto response = adapter.signData(context, request);

        // then
        assertNull(response.getSignatures());
    }

    @Test
    void verifyData_leavesVerificationsNull_whenConnectorOmitsThem() throws Exception {
        // given
        OperationKeyContext context = OperationKeyContext
                .legacy(keyItem(KeyAlgorithm.MLDSA, new RemoteKeyReference.UuidReference(UUID.randomUUID()),
                        UUID.randomUUID()));
        VerifyDataRequestDto request = new VerifyDataRequestDto();
        request.setSignatureAttributes(List.of());
        request.setSignatures(List.of());
        when(operationsClient.verifyData(any(), any(), any(), any()))
                .thenReturn(LegacyOperationFixtures.verifyResponseWithoutVerifications());

        // when
        VerifyDataResponseDto response = adapter.verifyData(context, request);

        // then
        assertNull(response.getVerifications());
    }

    @Test
    void listSignAttributes_returnsCoreSchema_byAlgorithm() {
        // given
        OperationKeyContext rsa = OperationKeyContext
                .legacy(keyItem(KeyAlgorithm.RSA, new RemoteKeyReference.UuidReference(UUID.randomUUID()),
                        UUID.randomUUID()));
        OperationKeyContext mldsa = OperationKeyContext
                .legacy(keyItem(KeyAlgorithm.MLDSA, new RemoteKeyReference.UuidReference(UUID.randomUUID()),
                        UUID.randomUUID()));

        // when
        List<BaseAttribute> rsaSchema = adapter.listSignAttributes(rsa);
        List<BaseAttribute> mldsaSchema = adapter.listSignAttributes(mldsa);

        // then
        // DataAttributeV2.equals() delegates to DataAttributeProperties, which has no equals/hashCode override in
        // the interfaces library, so independently built schemas are never equal by value; toString() carries the
        // same field data and does compare by value.
        assertEquals(RsaSignatureAttributes.getRsaSignatureAttributes().toString(), rsaSchema.toString());
        assertTrue(mldsaSchema.isEmpty());
        verifyNoInteractions(operationsClient);
    }

    @Test
    void resolveSignatureAlgorithm_readsCoreRegistry_withoutTouchingTheConnector() {
        // given
        List<RequestAttribute> attributes = List
                .of(RsaSignatureAttributes.buildRequestRsaSigScheme(RsaSignatureScheme.PKCS1_v1_5),
                        RsaSignatureAttributes.buildRequestDigest(DigestAlgorithm.SHA_384));

        // when
        ResolvedSignatureAlgorithm resolved = adapter
                .resolveSignatureAlgorithm(CryptographicKeyItemModelFixtures.activeSigningPrivateKey(KeyAlgorithm.RSA),
                        CryptographicKeyItemModelFixtures.publicKey(KeyAlgorithm.RSA), attributes);

        // then
        assertEquals(SignatureAlgorithm.SHA384_WITH_RSA, resolved.platformAlgorithm());
        verifyNoInteractions(operationsClient);
    }

    @Test
    void resolveSignatureAlgorithm_namesTheAlgorithmEvenWithoutAPlatformEntry() {
        // given
        List<RequestAttribute> attributes = List
                .of(RsaSignatureAttributes.buildRequestRsaSigScheme(RsaSignatureScheme.PKCS1_v1_5),
                        RsaSignatureAttributes.buildRequestDigest(DigestAlgorithm.SHA_1));

        // when
        ResolvedSignatureAlgorithm resolved = adapter
                .resolveSignatureAlgorithm(CryptographicKeyItemModelFixtures.activeSigningPrivateKey(KeyAlgorithm.RSA),
                        CryptographicKeyItemModelFixtures.publicKey(KeyAlgorithm.RSA), attributes);

        // then
        assertEquals("SHA1WITHRSA", resolved.name());
        assertNull(resolved.platformAlgorithm());
        assertThrows(ValidationException.class, resolved::requirePlatformAlgorithm);
    }

    @Test
    void resolveSignatureAlgorithm_refusesADigestAndSchemeNoPlatformEntryCovers() {
        // given
        List<RequestAttribute> attributes = List
                .of(RsaSignatureAttributes.buildRequestRsaSigScheme(RsaSignatureScheme.PSS),
                        RsaSignatureAttributes.buildRequestDigest(DigestAlgorithm.MD5));

        // when
        ResolvedSignatureAlgorithm resolved = adapter
                .resolveSignatureAlgorithm(CryptographicKeyItemModelFixtures.activeSigningPrivateKey(KeyAlgorithm.RSA),
                        CryptographicKeyItemModelFixtures.publicKey(KeyAlgorithm.RSA), attributes);

        // then
        assertEquals("MD5WITHRSAANDMGF1", resolved.name());
        assertNull(resolved.platformAlgorithm());
        assertThrows(ValidationException.class, resolved::requirePlatformAlgorithm);
    }

    @Test
    void resolveSignatureAlgorithm_refusesAnAttributeOfTheWrongContentType_asInvalidInput() {
        // given
        RequestAttributeV2 objectDigest = RsaSignatureAttributes.buildRequestDigest(DigestAlgorithm.SHA_256);
        objectDigest.setContent(List.of(new ObjectAttributeContentV2(new HashMap<>(Map.of("digest", "SHA-256")))));
        List<RequestAttribute> attributes = List
                .of(RsaSignatureAttributes.buildRequestRsaSigScheme(RsaSignatureScheme.PKCS1_v1_5), objectDigest);

        // when
        Executable resolve = () -> adapter
                .resolveSignatureAlgorithm(CryptographicKeyItemModelFixtures.activeSigningPrivateKey(KeyAlgorithm.RSA),
                        CryptographicKeyItemModelFixtures.publicKey(KeyAlgorithm.RSA), attributes);

        // then
        assertThrows(ValidationException.class, resolve);
    }

    @Test
    void resolveSignatureAlgorithm_refusesAnRsaKeyWithoutSigningAttributes() {
        // when
        Executable resolve = () -> adapter
                .resolveSignatureAlgorithm(CryptographicKeyItemModelFixtures.activeSigningPrivateKey(KeyAlgorithm.RSA),
                        CryptographicKeyItemModelFixtures.publicKey(KeyAlgorithm.RSA), List.of());

        // then
        assertThrows(ValidationException.class, resolve);
    }

    @Test
    void resolveSignatureAlgorithm_readsThePostQuantumParameterSetFromThePublicKeyItem() {
        // when
        ResolvedSignatureAlgorithm resolved = adapter
                .resolveSignatureAlgorithm(
                        CryptographicKeyItemModelFixtures.activeSigningPrivateKey(KeyAlgorithm.MLDSA),
                        CryptographicKeyItemModelFixtures.publicKey(KeyAlgorithm.MLDSA, "ML-DSA-65"), List.of());

        // then
        assertEquals(SignatureAlgorithm.ML_DSA_65, resolved.platformAlgorithm());
    }

    @Test
    void resolveSignatureAlgorithm_namesAPostQuantumParameterSetOutsideThePlatformEnum() {
        // when
        ResolvedSignatureAlgorithm resolved = adapter
                .resolveSignatureAlgorithm(
                        CryptographicKeyItemModelFixtures.activeSigningPrivateKey(KeyAlgorithm.SLHDSA),
                        CryptographicKeyItemModelFixtures.publicKey(KeyAlgorithm.SLHDSA, "SLH-DSA-SHAKE-128S"),
                        List.of());

        // then
        assertEquals("SLH-DSA-SHAKE-128S", resolved.name());
        assertNull(resolved.platformAlgorithm());
        assertThrows(ValidationException.class, resolved::requirePlatformAlgorithm);
    }

    @Test
    void listEncryptAttributes_rejectsUnsupportedAlgorithm() {
        // given
        OperationKeyContext ecdsa = OperationKeyContext
                .legacy(keyItem(KeyAlgorithm.ECDSA, new RemoteKeyReference.UuidReference(UUID.randomUUID()),
                        UUID.randomUUID()));

        // when
        Executable list = () -> adapter.listEncryptAttributes(ecdsa);

        // then
        assertThrows(ValidationException.class, list);
    }

    private static CryptographicKeyItemOperationModel keyItem(KeyAlgorithm algorithm, RemoteKeyReference reference,
            UUID tokenInstanceUuid) {
        return new CryptographicKeyItemOperationModel(UUID.randomUUID(), true, algorithm, KeyState.ACTIVE,
                KeyType.PRIVATE_KEY, List.of(KeyUsage.SIGN, KeyUsage.ENCRYPT), null, reference, UUID.randomUUID(),
                tokenInstanceUuid, UUID.randomUUID(), null, null);
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
