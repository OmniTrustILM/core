package com.otilm.core.service.handler.key;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.otilm.api.exception.ConnectorEntityNotFoundException;
import com.otilm.api.exception.ConnectorException;
import com.otilm.api.exception.ConnectorProblemException;
import com.otilm.api.exception.ConnectorServerException;
import com.otilm.api.exception.ValidationException;
import com.otilm.api.interfaces.client.v2.CryptographicOperationsSyncApiClient;
import com.otilm.api.interfaces.client.v2.KeySyncApiClient;
import com.otilm.api.model.client.attribute.RequestAttribute;
import com.otilm.api.model.client.attribute.RequestAttributeV2;
import com.otilm.api.model.client.attribute.RequestAttributeV3;
import com.otilm.api.model.client.connector.v2.ConnectorInterface;
import com.otilm.api.model.client.connector.v2.ConnectorVersion;
import com.otilm.api.model.client.connector.v2.FeatureFlag;
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
import com.otilm.api.model.common.attribute.common.content.AttributeContentType;
import com.otilm.api.model.common.attribute.common.content.data.SecretAttributeContentData;
import com.otilm.api.model.common.attribute.common.properties.DataAttributeProperties;
import com.otilm.api.model.common.attribute.v2.DataAttributeV2;
import com.otilm.api.model.common.attribute.v2.MetadataAttributeV2;
import com.otilm.api.model.common.attribute.v2.content.BooleanAttributeContentV2;
import com.otilm.api.model.common.attribute.v2.content.SecretAttributeContentV2;
import com.otilm.api.model.common.attribute.v2.content.StringAttributeContentV2;
import com.otilm.api.model.common.attribute.v3.MetadataAttributeV3;
import com.otilm.api.model.common.attribute.v3.content.StringAttributeContentV3;
import com.otilm.api.model.common.enums.cryptography.KeyAlgorithm;
import com.otilm.api.model.common.enums.cryptography.KeyFormat;
import com.otilm.api.model.common.enums.cryptography.KeyType;
import com.otilm.api.model.common.enums.cryptography.SignatureAlgorithm;
import com.otilm.api.model.common.error.ErrorCode;
import com.otilm.api.model.common.error.ProblemDetailExtended;
import com.otilm.api.model.connector.common.v2.OperationExecutionMode;
import com.otilm.api.model.connector.cryptography.enums.TokenInstanceStatus;
import com.otilm.api.model.connector.cryptography.v2.OperationResponseValidator;
import com.otilm.api.model.connector.cryptography.v2.key.CreateKeyAttributesRequestV2Dto;
import com.otilm.api.model.connector.cryptography.v2.key.CreateKeyRequestV2Dto;
import com.otilm.api.model.connector.cryptography.v2.key.DestroyKeyRequestV2Dto;
import com.otilm.api.model.connector.cryptography.v2.key.ExportKeyRequestV2Dto;
import com.otilm.api.model.connector.cryptography.v2.key.ExportKeyResponseV2Dto;
import com.otilm.api.model.connector.cryptography.v2.key.KeyCreationResponseV2Dto;
import com.otilm.api.model.connector.cryptography.v2.key.KeyExportableAttribute;
import com.otilm.api.model.connector.cryptography.v2.key.KeyOperationResponseV2Dto;
import com.otilm.api.model.connector.cryptography.v2.key.KeyPairDataResponseV2Dto;
import com.otilm.api.model.connector.cryptography.v2.key.PrivateKeyDataResponseV2Dto;
import com.otilm.api.model.connector.cryptography.v2.key.PrivateKeyDataV2Dto;
import com.otilm.api.model.connector.cryptography.v2.key.PublicKeyDataResponseV2Dto;
import com.otilm.api.model.connector.cryptography.v2.key.PublicKeyDataV2Dto;
import com.otilm.api.model.connector.cryptography.v2.key.SecretKeyDataResponseV2Dto;
import com.otilm.api.model.connector.cryptography.v2.key.SecretKeyDataV2Dto;
import com.otilm.api.model.connector.cryptography.v2.material.EncryptedKeyMaterialV2Dto;
import com.otilm.api.model.connector.cryptography.v2.operations.DecryptDataResponseV2Dto;
import com.otilm.api.model.connector.cryptography.v2.operations.EncryptDataResponseV2Dto;
import com.otilm.api.model.connector.cryptography.v2.operations.SignDataRequestV2Dto;
import com.otilm.api.model.connector.cryptography.v2.operations.SignDataResponseV2Dto;
import com.otilm.api.model.connector.cryptography.v2.operations.SignatureAlgorithmAttribute;
import com.otilm.api.model.connector.cryptography.v2.operations.VerifyDataRequestV2Dto;
import com.otilm.api.model.connector.cryptography.v2.operations.VerifyDataResponseV2Dto;
import com.otilm.api.model.connector.cryptography.v2.operations.data.CipherDataV2Dto;
import com.otilm.api.model.connector.cryptography.v2.operations.data.SignatureDataV2Dto;
import com.otilm.api.model.connector.cryptography.v2.operations.data.VerificationResponseItemV2Dto;
import com.otilm.api.model.core.auth.Resource;
import com.otilm.api.model.core.connector.ConnectorStatus;
import com.otilm.api.model.core.cryptography.key.KeyState;
import com.otilm.api.model.core.cryptography.key.KeyUsage;
import com.otilm.api.model.core.secret.Passphrase;
import com.otilm.core.attribute.engine.AttributeEngine;
import com.otilm.core.attribute.engine.OutboundSecretContainment;
import com.otilm.core.attribute.engine.OutboundSecretLeakException;
import com.otilm.core.attribute.engine.records.ObjectAttributeContentInfo;
import com.otilm.core.client.CryptographyV2ApiClients;
import com.otilm.core.model.connector.ImmutableConnectorFullModel;
import com.otilm.core.model.connector.ImmutableConnectorInterface;
import com.otilm.core.model.crypto.CryptographicKeyItemModelFixtures;
import com.otilm.core.model.crypto.CryptographicKeyItemOperationModel;
import com.otilm.core.model.crypto.ImmutableCryptographicKeyFullModel;
import com.otilm.core.model.crypto.ImmutableTokenInstanceFullModel;
import com.otilm.core.model.crypto.ImmutableTokenProfileFullModel;
import com.otilm.core.model.crypto.ProviderKeyItem;
import com.otilm.core.model.crypto.RemoteKeyReference;
import com.otilm.core.model.crypto.TokenInstanceBasicModel;
import com.otilm.core.service.handler.ConnectorCapabilityService;
import com.otilm.core.service.handler.OperationAttributeResolver;
import com.otilm.core.util.ExportEnvelopeFixtures;
import jakarta.validation.Validation;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PublicKey;
import java.util.Base64;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.UUID;
import java.util.stream.Stream;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Named;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.function.Executable;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.EnumSource;
import org.junit.jupiter.params.provider.MethodSource;
import org.junit.jupiter.params.provider.NullAndEmptySource;
import org.junit.jupiter.params.provider.ValueSource;
import org.mockito.ArgumentCaptor;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Named.named;
import static org.junit.jupiter.params.provider.Arguments.arguments;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.ArgumentMatchers.isNull;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.verifyNoMoreInteractions;
import static org.mockito.Mockito.when;

class KeyProviderV2AdapterTest {

    private KeySyncApiClient client;
    private CryptographicOperationsSyncApiClient operationsClient;
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
                true, List.of(KeyUsage.SIGN), token, connectorUuid, Map.of(), 0);
        cryptographicKey = new ImmutableCryptographicKeyFullModel(UUID.randomUUID(), "key", null, profile.uuid(),
                profile.tokenInstanceReferenceUuid(), profile, profile.tokenInstance(), Set.of(), null, null, null,
                List.of(), List.of());
        CryptographyV2ApiClients apiClients = mock(CryptographyV2ApiClients.class);
        attributes = mock(AttributeEngine.class);
        resolver = mock(OperationAttributeResolver.class);
        client = mock(KeySyncApiClient.class);
        operationsClient = mock(CryptographicOperationsSyncApiClient.class);
        when(apiClients.getKeyManagementApiClient(connector)).thenReturn(client);
        when(apiClients.getCryptographicOperationsApiClient(connector)).thenReturn(operationsClient);
        when(attributes.getRequestObjectDataAttributesContent(any())).thenReturn(List.of());
        when(resolver.resolveForConnectorRequestAsSystem(connectorUuid, List.of())).thenReturn(List.of());
        adapter = new KeyProviderV2Adapter(apiClients, connector, attributes, resolver,
                new OutboundSecretContainment(new ObjectMapper()), new ConnectorCapabilityService(),
                new OperationResponseValidator(Validation.buildDefaultValidatorFactory().getValidator()));
    }

    private OperationKeyContext v2Context(List<MetadataAttribute> keyMeta) {
        CryptographicKeyItemOperationModel item = new CryptographicKeyItemOperationModel(UUID.randomUUID(), true,
                KeyAlgorithm.RSA, KeyState.ACTIVE, KeyType.PRIVATE_KEY, List.of(KeyUsage.SIGN, KeyUsage.ENCRYPT), null,
                new RemoteKeyReference.MetadataReference(keyMeta), profile.connectorUuid(), null, UUID.randomUUID(),
                ConnectorInterface.CRYPTOGRAPHY, "v2");
        return new OperationKeyContext(item, profile);
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

    @Test
    void resolveSignatureAlgorithm_readsTheSelection_withoutTouchingTheConnector() {
        // given
        List<RequestAttribute> signatureAttributes = List
                .of(stringAttribute("keyLabel", "tsa-key"),
                        SignatureAlgorithmAttribute.request(SignatureAlgorithm.SHA384_WITH_RSA_PSS));

        // when
        ResolvedSignatureAlgorithm resolved = adapter
                .resolveSignatureAlgorithm(CryptographicKeyItemModelFixtures.activeSigningPrivateKey(KeyAlgorithm.RSA),
                        CryptographicKeyItemModelFixtures.publicKey(KeyAlgorithm.RSA), signatureAttributes);

        // then
        assertEquals(SignatureAlgorithm.SHA384_WITH_RSA_PSS, resolved.platformAlgorithm());
        verifyNoInteractions(operationsClient);
    }

    @Test
    void resolveSignatureAlgorithm_acceptsThePostQuantumParameterSetOfTheKey() {
        // when
        ResolvedSignatureAlgorithm resolved = adapter
                .resolveSignatureAlgorithm(
                        CryptographicKeyItemModelFixtures.activeSigningPrivateKey(KeyAlgorithm.MLDSA),
                        CryptographicKeyItemModelFixtures.publicKey(KeyAlgorithm.MLDSA, "ML-DSA-65"),
                        List.of(SignatureAlgorithmAttribute.request(SignatureAlgorithm.ML_DSA_65)));

        // then
        assertEquals(SignatureAlgorithm.ML_DSA_65, resolved.platformAlgorithm());
    }

    @Test
    void resolveSignatureAlgorithm_refusesAMissingSelection() {
        // when
        Executable resolve = () -> adapter
                .resolveSignatureAlgorithm(CryptographicKeyItemModelFixtures.activeSigningPrivateKey(KeyAlgorithm.RSA),
                        CryptographicKeyItemModelFixtures.publicKey(KeyAlgorithm.RSA),
                        List.of(stringAttribute("signatureScheme", "PKCS1-v1_5")));

        // then
        assertThrows(ValidationException.class, resolve);
    }

    @ParameterizedTest(name = "{0}")
    @MethodSource("selectionsTheKeyCannotSignWith")
    void resolveSignatureAlgorithm_refusesAnAlgorithmTheKeyCannotSignWith(UnfitSelection selection) {
        // when
        Executable resolve = () -> adapter
                .resolveSignatureAlgorithm(selection.privateKey(), selection.publicKey(),
                        List.of(SignatureAlgorithmAttribute.request(selection.algorithm())));

        // then
        ValidationException failure = assertThrows(ValidationException.class, resolve);
        assertTrue(failure.getMessage().contains(selection.algorithm().getCode()));
    }

    private static Stream<Named<UnfitSelection>> selectionsTheKeyCannotSignWith() {
        return Stream
                .of(named("ECDSA on an RSA key",
                        new UnfitSelection(CryptographicKeyItemModelFixtures.activeSigningPrivateKey(KeyAlgorithm.RSA),
                                CryptographicKeyItemModelFixtures.publicKey(KeyAlgorithm.RSA),
                                SignatureAlgorithm.SHA256_WITH_ECDSA)),
                        named("ML-DSA on an RSA key",
                                new UnfitSelection(
                                        CryptographicKeyItemModelFixtures.activeSigningPrivateKey(KeyAlgorithm.RSA),
                                        CryptographicKeyItemModelFixtures.publicKey(KeyAlgorithm.RSA),
                                        SignatureAlgorithm.ML_DSA_65)),
                        named("another ML-DSA parameter set",
                                new UnfitSelection(
                                        CryptographicKeyItemModelFixtures.activeSigningPrivateKey(KeyAlgorithm.MLDSA),
                                        CryptographicKeyItemModelFixtures.publicKey(KeyAlgorithm.MLDSA, "ML-DSA-65"),
                                        SignatureAlgorithm.ML_DSA_44)),
                        named("Ed25519, which no platform key algorithm signs with",
                                new UnfitSelection(
                                        CryptographicKeyItemModelFixtures.activeSigningPrivateKey(KeyAlgorithm.ECDSA),
                                        CryptographicKeyItemModelFixtures.publicKey(KeyAlgorithm.ECDSA),
                                        SignatureAlgorithm.ED25519)));
    }

    record UnfitSelection(CryptographicKeyItemOperationModel privateKey, CryptographicKeyItemOperationModel publicKey,
            SignatureAlgorithm algorithm) {
    }

    @Test
    void signData_sendsKeyScope_validatesAttributes_andMapsSynchronousResult() throws Exception {
        // given
        List<MetadataAttribute> keyMeta = metadata("durable-key-handle");
        List<RequestAttribute> resolvedToken = List.of(requestAttribute("resolved-token"));
        List<RequestAttribute> resolvedProfile = List.of(requestAttribute("resolved-profile"));
        stubAttributes(Resource.TOKEN, profile.tokenInstanceReferenceUuid(), List.of(requestAttribute("stored-token")),
                resolvedToken);
        stubAttributes(Resource.TOKEN_PROFILE, profile.uuid(), List.of(requestAttribute("stored-profile")),
                resolvedProfile);
        when(operationsClient.listSignAttributes(any(), any()))
                .thenReturn(List.of(dataAttributeDefinition("digest", true)));
        SignDataResponseV2Dto body = new SignDataResponseV2Dto();
        body.setSignatures(List.of(new SignatureDataV2Dto(new byte[]{7}, "0")));
        when(operationsClient.signData(any(), any())).thenReturn(ResponseEntity.ok(body));
        SignDataRequestDto request = new SignDataRequestDto();
        request.setSignatureAttributes(List.of(stringAttribute("digest", "SHA256")));
        SignatureRequestData item = new SignatureRequestData();
        item.setData(Base64.getEncoder().encodeToString(new byte[]{1}));
        request.setData(List.of(item));

        // when
        SignDataResponseDto response = adapter.signData(v2Context(keyMeta), request);

        // then
        ArgumentCaptor<SignDataRequestV2Dto> sent = ArgumentCaptor.forClass(SignDataRequestV2Dto.class);
        verify(operationsClient).signData(any(), sent.capture());
        assertSame(keyMeta, sent.getValue().getKeyMeta());
        assertSame(resolvedToken, sent.getValue().getTokenAttributes());
        assertSame(resolvedProfile, sent.getValue().getTokenProfileAttributes());
        assertEquals(OperationExecutionMode.SYNCHRONOUS, sent.getValue().getExecutionMode());
        assertEquals("0", sent.getValue().getData().get(0).getIdentifier());
        assertNull(response.getSignatures().get(0).getIdentifier());
        assertEquals(Base64.getEncoder().encodeToString(new byte[]{7}), response.getSignatures().get(0).getData());
    }

    @ParameterizedTest
    @MethodSource("nonSynchronousSignResponses")
    void signData_rejectsResponseWithoutSynchronousResult(ResponseEntity<SignDataResponseV2Dto> response)
            throws Exception {
        // given
        when(operationsClient.listSignAttributes(any(), any())).thenReturn(List.of());
        when(operationsClient.signData(any(), any())).thenReturn(response);
        SignDataRequestDto request = new SignDataRequestDto();
        request.setSignatureAttributes(List.of());
        SignatureRequestData item = new SignatureRequestData();
        item.setData("AQ==");
        request.setData(List.of(item));

        // when
        Executable sign = () -> adapter.signData(v2Context(metadata("handle")), request);

        // then
        ConnectorException failure = assertThrows(ConnectorException.class, sign);
        assertEquals("Connector did not return a synchronous signing result.", failure.getMessage());
    }

    private static Stream<ResponseEntity<SignDataResponseV2Dto>> nonSynchronousSignResponses() {
        SignDataResponseV2Dto tracking = new SignDataResponseV2Dto();
        tracking.setOperationMeta(metadata("operation-handle"));
        SignDataResponseV2Dto empty = new SignDataResponseV2Dto();
        SignDataResponseV2Dto withSignaturesAndOperationMeta = new SignDataResponseV2Dto();
        withSignaturesAndOperationMeta.setSignatures(List.of(new SignatureDataV2Dto(new byte[]{7}, "0")));
        withSignaturesAndOperationMeta.setOperationMeta(metadata("operation-handle"));
        SignDataResponseV2Dto withEmptySignatureList = new SignDataResponseV2Dto();
        withEmptySignatureList.setSignatures(List.of());
        return Stream
                .of(ResponseEntity.accepted().body(tracking), ResponseEntity.ok(empty), ResponseEntity.ok(null),
                        ResponseEntity.ok(withSignaturesAndOperationMeta), ResponseEntity.ok(withEmptySignatureList));
    }

    @Test
    void signData_rejectsInvalidAttributes_beforeCallingConnector() throws Exception {
        // given
        when(operationsClient.listSignAttributes(any(), any()))
                .thenReturn(List.of(dataAttributeDefinition("digest", true)));
        SignDataRequestDto request = new SignDataRequestDto();
        request.setSignatureAttributes(List.of());
        SignatureRequestData item = new SignatureRequestData();
        item.setData("AQ==");
        request.setData(List.of(item));

        // when
        Executable sign = () -> adapter.signData(v2Context(metadata("handle")), request);

        // then
        assertThrows(ValidationException.class, sign);
        verify(operationsClient, never()).signData(any(), any());
    }

    @Test
    void signData_rejectsEmptyMetadataHandle_beforeCallingConnector() {
        // given
        SignDataRequestDto request = new SignDataRequestDto();
        request.setSignatureAttributes(List.of());
        request.setData(List.of());

        // when
        Executable sign = () -> adapter.signData(v2Context(List.of()), request);

        // then
        assertThrows(ValidationException.class, sign);
        verifyNoInteractions(operationsClient);
    }

    @Test
    void verifyData_pairsDataAndSignaturesByPosition_andRestoresIdentifiers() throws Exception {
        // given
        when(operationsClient.listVerifyAttributes(any(), any())).thenReturn(List.of());
        VerifyDataResponseV2Dto body = new VerifyDataResponseV2Dto();
        body.setVerifications(List.of(new VerificationResponseItemV2Dto(true, "0", null)));
        when(operationsClient.verifyData(any(), any())).thenReturn(body);
        VerifyDataRequestDto request = new VerifyDataRequestDto();
        request.setSignatureAttributes(List.of());
        SignatureRequestData data = new SignatureRequestData();
        data.setData("AQ==");
        SignatureRequestData signature = new SignatureRequestData();
        signature.setData("Ag==");
        request.setData(List.of(data));
        request.setSignatures(List.of(signature));

        // when
        VerifyDataResponseDto response = adapter.verifyData(v2Context(metadata("handle")), request);

        // then
        ArgumentCaptor<VerifyDataRequestV2Dto> sent = ArgumentCaptor.forClass(VerifyDataRequestV2Dto.class);
        verify(operationsClient).verifyData(any(), sent.capture());
        assertEquals("0", sent.getValue().getData().get(0).getIdentifier());
        assertEquals("0", sent.getValue().getSignatures().get(0).getIdentifier());
        assertTrue(response.getVerifications().get(0).isResult());
        assertNull(response.getVerifications().get(0).getIdentifier());
    }

    @Test
    void verifyData_rejectsMismatchedBatchSizes() throws Exception {
        // given
        when(operationsClient.listVerifyAttributes(any(), any())).thenReturn(List.of());
        VerifyDataRequestDto request = new VerifyDataRequestDto();
        request.setSignatureAttributes(List.of());
        SignatureRequestData one = new SignatureRequestData();
        one.setData("AQ==");
        request.setData(List.of(one));
        request.setSignatures(List.of());

        // when
        Executable verifyCall = () -> adapter.verifyData(v2Context(metadata("handle")), request);

        // then
        ValidationException failure = assertThrows(ValidationException.class, verifyCall);
        assertTrue(failure.getMessage().contains("one signature per data item"));
        verify(operationsClient, never()).verifyData(any(), any());
    }

    @Test
    void verifyData_sendsMatchingIdentifierSets_whenOnlyDataIsIdentified() throws Exception {
        // given
        when(operationsClient.listVerifyAttributes(any(), any())).thenReturn(List.of());
        VerifyDataResponseV2Dto body = new VerifyDataResponseV2Dto();
        body
                .setVerifications(List
                        .of(new VerificationResponseItemV2Dto(true, "0", null),
                                new VerificationResponseItemV2Dto(false, "1", null)));
        when(operationsClient.verifyData(any(), any())).thenReturn(body);
        VerifyDataRequestDto request = new VerifyDataRequestDto();
        request.setSignatureAttributes(List.of());
        request.setData(List.of(signatureItem("AQ==", "a"), signatureItem("Ag==", "b")));
        request.setSignatures(List.of(signatureItem("Aw==", null), signatureItem("BA==", null)));

        // when
        VerifyDataResponseDto response = adapter.verifyData(v2Context(metadata("handle")), request);

        // then
        ArgumentCaptor<VerifyDataRequestV2Dto> sent = ArgumentCaptor.forClass(VerifyDataRequestV2Dto.class);
        verify(operationsClient).verifyData(any(), sent.capture());
        assertEquals(List.of("0", "1"), sentIdentifiers(sent.getValue().getData()));
        assertEquals(List.of("0", "1"), sentIdentifiers(sent.getValue().getSignatures()));
        assertEquals("a", response.getVerifications().get(0).getIdentifier());
        assertEquals("b", response.getVerifications().get(1).getIdentifier());
    }

    @Test
    void signData_numbersEveryItemPositionally_andRestoresCallerIdentifiers() throws Exception {
        // given
        when(operationsClient.listSignAttributes(any(), any())).thenReturn(List.of());
        SignDataResponseV2Dto body = new SignDataResponseV2Dto();
        body
                .setSignatures(List
                        .of(new SignatureDataV2Dto(new byte[]{1}, "0"), new SignatureDataV2Dto(new byte[]{2}, "1"),
                                new SignatureDataV2Dto(new byte[]{3}, "2")));
        when(operationsClient.signData(any(), any())).thenReturn(ResponseEntity.ok(body));
        SignDataRequestDto request = new SignDataRequestDto();
        request.setSignatureAttributes(List.of());
        request
                .setData(List
                        .of(signatureItem("AQ==", "custom"), signatureItem("Ag==", null), signatureItem("Aw==", "1")));

        // when
        SignDataResponseDto response = adapter.signData(v2Context(metadata("handle")), request);

        // then
        ArgumentCaptor<SignDataRequestV2Dto> sent = ArgumentCaptor.forClass(SignDataRequestV2Dto.class);
        verify(operationsClient).signData(any(), sent.capture());
        assertEquals(List.of("0", "1", "2"), sentIdentifiers(sent.getValue().getData()));
        assertEquals("custom", response.getSignatures().get(0).getIdentifier());
        assertNull(response.getSignatures().get(1).getIdentifier());
        assertEquals("1", response.getSignatures().get(2).getIdentifier());
    }

    @Test
    void signData_restoresRequestOrder_whenConnectorReordersTheBatch() throws Exception {
        // given
        when(operationsClient.listSignAttributes(any(), any())).thenReturn(List.of());
        SignDataResponseV2Dto body = new SignDataResponseV2Dto();
        body
                .setSignatures(List
                        .of(new SignatureDataV2Dto(new byte[]{2}, "1"), new SignatureDataV2Dto(new byte[]{1}, "0")));
        when(operationsClient.signData(any(), any())).thenReturn(ResponseEntity.ok(body));
        SignDataRequestDto request = new SignDataRequestDto();
        request.setSignatureAttributes(List.of());
        request.setData(List.of(signatureItem("AQ==", "first"), signatureItem("Ag==", "second")));

        // when
        SignDataResponseDto response = adapter.signData(v2Context(metadata("handle")), request);

        // then
        assertEquals("first", response.getSignatures().get(0).getIdentifier());
        assertEquals(Base64.getEncoder().encodeToString(new byte[]{1}), response.getSignatures().get(0).getData());
        assertEquals("second", response.getSignatures().get(1).getIdentifier());
        assertEquals(Base64.getEncoder().encodeToString(new byte[]{2}), response.getSignatures().get(1).getData());
    }

    @Test
    void signData_rejectsRepeatedPosition() throws Exception {
        // given
        when(operationsClient.listSignAttributes(any(), any())).thenReturn(List.of());
        SignDataResponseV2Dto body = new SignDataResponseV2Dto();
        body
                .setSignatures(List
                        .of(new SignatureDataV2Dto(new byte[]{1}, "0"), new SignatureDataV2Dto(new byte[]{2}, "0")));
        when(operationsClient.signData(any(), any())).thenReturn(ResponseEntity.ok(body));
        SignDataRequestDto request = new SignDataRequestDto();
        request.setSignatureAttributes(List.of());
        request.setData(List.of(signatureItem("AQ==", null), signatureItem("Ag==", null)));

        // when
        Executable sign = () -> adapter.signData(v2Context(metadata("handle")), request);

        // then
        assertThrows(ConnectorException.class, sign);
    }

    @Test
    void signData_rejectsResultWithFewerItemsThanTheRequest() throws Exception {
        // given
        when(operationsClient.listSignAttributes(any(), any())).thenReturn(List.of());
        SignDataResponseV2Dto body = new SignDataResponseV2Dto();
        body.setSignatures(List.of(new SignatureDataV2Dto(new byte[]{1}, "0")));
        when(operationsClient.signData(any(), any())).thenReturn(ResponseEntity.ok(body));
        SignDataRequestDto request = new SignDataRequestDto();
        request.setSignatureAttributes(List.of());
        request.setData(List.of(signatureItem("AQ==", null), signatureItem("Ag==", null)));

        // when
        Executable sign = () -> adapter.signData(v2Context(metadata("handle")), request);

        // then
        assertThrows(ConnectorException.class, sign);
    }

    @Test
    void verifyData_rejectsCallerIdentifiersThatDoNotLineUp_beforeCallingConnector() throws Exception {
        // given
        VerifyDataRequestDto request = new VerifyDataRequestDto();
        request.setSignatureAttributes(List.of());
        request.setData(List.of(signatureItem("AQ==", "a"), signatureItem("Ag==", "b")));
        request.setSignatures(List.of(signatureItem("Aw==", "b"), signatureItem("BA==", "a")));

        // when
        Executable verify = () -> adapter.verifyData(v2Context(metadata("handle")), request);

        // then
        assertThrows(ValidationException.class, verify);
        verifyNoInteractions(operationsClient);
    }

    @Test
    void verifyData_rejectsResultEchoingAnExpandedSecret() throws Exception {
        // given
        String expandedSecret = "resolved-provider-password";
        stubExpandedSecret(Resource.TOKEN, expandedSecret);
        when(operationsClient.listVerifyAttributes(any(), any())).thenReturn(List.of());
        VerifyDataResponseV2Dto response = new VerifyDataResponseV2Dto();
        response.setVerifications(List.of(new VerificationResponseItemV2Dto(false, "0", expandedSecret)));
        when(operationsClient.verifyData(any(), any())).thenReturn(response);
        VerifyDataRequestDto request = new VerifyDataRequestDto();
        request.setSignatureAttributes(List.of());
        request.setData(List.of(signatureItem("AQ==", null)));
        request.setSignatures(List.of(signatureItem("Ag==", null)));

        // when
        Executable verify = () -> adapter.verifyData(v2Context(metadata("handle")), request);

        // then
        assertThrows(OutboundSecretLeakException.class, verify);
    }

    @Test
    void signData_resolvesScopeOnce_andNeverTouchesTheAttributeEngineForTheSchema() throws Exception {
        // given
        when(operationsClient.listSignAttributes(any(), any()))
                .thenReturn(List.of(dataAttributeDefinition("digest", false)));
        SignDataResponseV2Dto body = new SignDataResponseV2Dto();
        body.setSignatures(List.of(new SignatureDataV2Dto(new byte[]{7}, "0")));
        when(operationsClient.signData(any(), any())).thenReturn(ResponseEntity.ok(body));
        SignDataRequestDto request = new SignDataRequestDto();
        request.setSignatureAttributes(List.of());
        request.setData(List.of(signatureItem("AQ==", null)));

        // when
        adapter.signData(v2Context(metadata("handle")), request);

        // then
        verify(attributes)
                .getRequestObjectDataAttributesContent(
                        attributeScope(Resource.TOKEN, profile.tokenInstanceReferenceUuid()));
        verify(attributes)
                .getRequestObjectDataAttributesContent(attributeScope(Resource.TOKEN_PROFILE, profile.uuid()));
        verify(attributes, never()).updateDataAttributeDefinitions(any(), any(), any());
        verify(attributes, never()).validateUpdateDataAttributes(any(), any(), any(), any());
        verifyNoMoreInteractions(attributes);
    }

    @ParameterizedTest
    @ValueSource(strings = {"not-a-position", "1", "-1"})
    void signData_rejectsIdentifierThatWasNotPartOfTheRequest(String returnedIdentifier) throws Exception {
        // given
        when(operationsClient.listSignAttributes(any(), any())).thenReturn(List.of());
        SignDataResponseV2Dto body = new SignDataResponseV2Dto();
        body.setSignatures(List.of(new SignatureDataV2Dto(new byte[]{7}, returnedIdentifier)));
        when(operationsClient.signData(any(), any())).thenReturn(ResponseEntity.ok(body));
        SignDataRequestDto request = new SignDataRequestDto();
        request.setSignatureAttributes(List.of());
        request.setData(List.of(signatureItem("AQ==", "caller")));

        // when
        Executable sign = () -> adapter.signData(v2Context(metadata("handle")), request);

        // then
        ConnectorException failure = assertThrows(ConnectorException.class, sign);
        assertEquals("Connector returned an identifier that was not part of the request.", failure.getMessage());
    }

    @Test
    void encryptData_mapsBatch_andKeepsCallerIdentifiers() throws Exception {
        // given
        when(operationsClient.listEncryptAttributes(any(), any())).thenReturn(List.of());
        EncryptDataResponseV2Dto body = new EncryptDataResponseV2Dto();
        body.setEncryptedData(List.of(new CipherDataV2Dto(new byte[]{5}, "0")));
        when(operationsClient.encryptData(any(), any())).thenReturn(body);
        CipherDataRequestDto request = new CipherDataRequestDto();
        request.setCipherAttributes(List.of());
        CipherRequestData item = new CipherRequestData();
        item.setData("AQ==");
        item.setIdentifier("custom");
        request.setCipherData(List.of(item));

        // when
        EncryptDataResponseDto response = adapter.encryptData(v2Context(metadata("handle")), request);

        // then
        assertEquals("custom", response.getEncryptedData().get(0).getIdentifier());
        assertEquals(Base64.getEncoder().encodeToString(new byte[]{5}), response.getEncryptedData().get(0).getData());
    }

    @Test
    void decryptData_mapsBatch_andKeepsCallerIdentifiers() throws Exception {
        // given
        when(operationsClient.listDecryptAttributes(any(), any())).thenReturn(List.of());
        DecryptDataResponseV2Dto body = new DecryptDataResponseV2Dto();
        body.setDecryptedData(List.of(new CipherDataV2Dto(new byte[]{9}, "0")));
        when(operationsClient.decryptData(any(), any())).thenReturn(body);
        CipherDataRequestDto request = new CipherDataRequestDto();
        request.setCipherAttributes(List.of());
        CipherRequestData item = new CipherRequestData();
        item.setData("AQ==");
        item.setIdentifier("custom");
        request.setCipherData(List.of(item));

        // when
        DecryptDataResponseDto response = adapter.decryptData(v2Context(metadata("handle")), request);

        // then
        assertEquals("custom", response.getDecryptedData().get(0).getIdentifier());
        assertEquals(Base64.getEncoder().encodeToString(new byte[]{9}), response.getDecryptedData().get(0).getData());
    }

    @ParameterizedTest(name = "{0}")
    @MethodSource("operationAttributeListings")
    void listOperationAttributes_persistsDefinitionsFromItsOwnConnectorEndpoint(String operation,
            ClientListing clientListing, AdapterListing adapterListing) throws Exception {
        // given
        List<BaseAttribute> schema = List.of(new DataAttributeV2());
        when(clientListing.list(operationsClient)).thenReturn(schema);

        // when
        List<BaseAttribute> result = adapterListing.list(adapter, v2Context(metadata("handle")));

        // then
        assertSame(schema, result);
        verify(attributes).updateDataAttributeDefinitions(profile.connectorUuid(), null, schema);
    }

    @ParameterizedTest
    @EnumSource(value = Resource.class, names = {"TOKEN", "TOKEN_PROFILE"})
    void listSignAttributes_rejectsSchemaEchoingAnExpandedSecret(Resource secretScope) throws Exception {
        // given
        String expandedSecret = "resolved-provider-password";
        stubExpandedSecret(secretScope, expandedSecret);
        when(operationsClient.listSignAttributes(any(), any())).thenReturn(definitionsWithDefault(expandedSecret));

        // when
        Executable listDefinitions = () -> adapter.listSignAttributes(v2Context(metadata("handle")));

        // then
        assertThrows(OutboundSecretLeakException.class, listDefinitions);
    }

    @Test
    void signData_rejectsOperationSchemaEchoingAnExpandedSecret() throws Exception {
        // given
        String expandedSecret = "resolved-provider-password";
        stubExpandedSecret(Resource.TOKEN, expandedSecret);
        when(operationsClient.listSignAttributes(any(), any())).thenReturn(definitionsWithDefault(expandedSecret));
        SignDataRequestDto request = new SignDataRequestDto();
        request.setSignatureAttributes(List.of());
        request.setData(List.of(signatureItem("AQ==", null)));

        // when
        Executable sign = () -> adapter.signData(v2Context(metadata("handle")), request);

        // then
        assertThrows(OutboundSecretLeakException.class, sign);
        verify(operationsClient, never()).signData(any(), any());
    }

    @ParameterizedTest
    @NullAndEmptySource
    void signData_rejectsItemWithoutData_beforeCallingConnector(String data) throws Exception {
        // given
        when(operationsClient.listSignAttributes(any(), any())).thenReturn(List.of());
        SignDataRequestDto request = new SignDataRequestDto();
        request.setSignatureAttributes(List.of());
        request.setData(List.of(signatureItem(data, null)));

        // when
        Executable sign = () -> adapter.signData(v2Context(metadata("handle")), request);

        // then
        assertThrows(ValidationException.class, sign);
        verify(operationsClient, never()).signData(any(), any());
    }

    @Test
    void signData_rejectsSignatureWithoutData() throws Exception {
        // given
        when(operationsClient.listSignAttributes(any(), any())).thenReturn(List.of());
        SignDataResponseV2Dto body = new SignDataResponseV2Dto();
        body.setSignatures(List.of(new SignatureDataV2Dto(new byte[0], "0")));
        when(operationsClient.signData(any(), any())).thenReturn(ResponseEntity.ok(body));
        SignDataRequestDto request = new SignDataRequestDto();
        request.setSignatureAttributes(List.of());
        request.setData(List.of(signatureItem("AQ==", null)));

        // when
        Executable sign = () -> adapter.signData(v2Context(metadata("handle")), request);

        // then
        assertThrows(ConnectorException.class, sign);
    }

    @Test
    void listExportKeyAttributes_asksForTheKeysSchemaAndPublishesIt() throws Exception {
        // given
        List<BaseAttribute> schema = List.of(dataAttributeDefinition("exportLabel", false));
        when(client.listExportKeyAttributes(any(), any())).thenReturn(schema);

        // when
        List<BaseAttribute> listed = adapter.listExportKeyAttributes(v2Context(metadata("handle")));

        // then
        assertEquals(schema, listed);
        verify(attributes).updateDataAttributeDefinitions(any(), isNull(), eq(schema));
    }

    @Test
    void exportKey_sendsTheScopeHandleAndPassphraseAndReturnsTheEnvelope() throws Exception {
        // given
        KeyPair pair = rsaKeyPair();
        byte[] envelope = ExportEnvelopeFixtures.pinnedEnvelope(pair.getPrivate(), PASSPHRASE);
        when(client.listExportKeyAttributes(any(), any())).thenReturn(List.of());
        when(client.exportKey(any(), any())).thenReturn(exportResponse(envelope, pair.getPublic()));

        // when
        byte[] exported = adapter
                .exportKey(v2Context(metadata("handle")), heldKey(pair.getPublic()), passphrase(), List.of());

        // then
        assertArrayEquals(envelope, exported);
        ArgumentCaptor<ExportKeyRequestV2Dto> sent = ArgumentCaptor.forClass(ExportKeyRequestV2Dto.class);
        verify(client).exportKey(any(), sent.capture());
        assertEquals(KeyRequestType.KEY_PAIR, sent.getValue().getKeyRequestType());
        assertEquals(new String(PASSPHRASE), sent.getValue().getPassphrase());
        assertEquals(List.of(), sent.getValue().getExportKeyAttributes());
        assertEquals(metadata("handle").getFirst().getName(), sent.getValue().getKeyMeta().getFirst().getName());
        assertNull(sent.getValue().getKeyReference(),
                "a key with no reference of Core's own is exported by its handle");
    }

    @Test
    void exportKey_statesTheKeysReferenceWhenCoreHoldsOne() throws Exception {
        // given
        KeyPair pair = rsaKeyPair();
        UUID reference = UUID.randomUUID();
        ExportKeyResponseV2Dto response = exportResponse(
                ExportEnvelopeFixtures.pinnedEnvelope(pair.getPrivate(), PASSPHRASE), pair.getPublic());
        response.setKeyReference(reference.toString());
        when(client.listExportKeyAttributes(any(), any())).thenReturn(List.of());
        when(client.exportKey(any(), any())).thenReturn(response);
        HeldKey held = new HeldKey(KeyRequestType.KEY_PAIR, KeyAlgorithm.RSA, 2048, pair.getPublic().getEncoded(),
                reference);

        // when
        adapter.exportKey(v2Context(metadata("handle")), held, passphrase(), List.of());

        // then
        ArgumentCaptor<ExportKeyRequestV2Dto> sent = ArgumentCaptor.forClass(ExportKeyRequestV2Dto.class);
        verify(client).exportKey(any(), sent.capture());
        assertEquals(reference.toString(), sent.getValue().getKeyReference());
    }

    @Test
    void exportKey_refusesAnAnswerDescribingAnotherKey() throws Exception {
        // given
        KeyPair asked = rsaKeyPair();
        KeyPair other = rsaKeyPair();
        when(client.listExportKeyAttributes(any(), any())).thenReturn(List.of());
        when(client.exportKey(any(), any()))
                .thenReturn(exportResponse(ExportEnvelopeFixtures.pinnedEnvelope(other.getPrivate(), PASSPHRASE),
                        other.getPublic()));
        OperationKeyContext context = v2Context(metadata("handle"));
        HeldKey held = heldKey(asked.getPublic());
        Passphrase passphrase = passphrase();

        // when
        ConnectorServerException refused = assertThrows(ConnectorServerException.class,
                () -> adapter.exportKey(context, held, passphrase, NO_ATTRIBUTES));

        // then
        assertEquals(HttpStatus.BAD_GATEWAY, refused.getHttpStatus());
    }

    @Test
    void exportKey_refusesAResponseEchoingThePassphrase() throws Exception {
        // given
        KeyPair pair = rsaKeyPair();
        ExportKeyResponseV2Dto echoing = exportResponse(
                ExportEnvelopeFixtures.pinnedEnvelope(pair.getPrivate(), PASSPHRASE), pair.getPublic());
        echoing.getKeyData().setMetadata(List.of(metadataCarrying(new String(PASSPHRASE))));
        when(client.listExportKeyAttributes(any(), any())).thenReturn(List.of());
        when(client.exportKey(any(), any())).thenReturn(echoing);
        OperationKeyContext context = v2Context(metadata("handle"));
        HeldKey held = heldKey(pair.getPublic());
        Passphrase passphrase = passphrase();

        // when
        // then
        assertThrows(OutboundSecretLeakException.class,
                () -> adapter.exportKey(context, held, passphrase, NO_ATTRIBUTES));
    }

    @Test
    void exportKey_refusesAttributesTheSchemaDoesNotAccept() throws Exception {
        // given
        when(client.listExportKeyAttributes(any(), any()))
                .thenReturn(List.of(dataAttributeDefinition("exportLabel", true)));
        OperationKeyContext context = v2Context(metadata("handle"));
        HeldKey held = heldKey(rsaKeyPair().getPublic());
        Passphrase passphrase = passphrase();

        // when
        // then
        assertThrows(ValidationException.class, () -> adapter.exportKey(context, held, passphrase, NO_ATTRIBUTES));
        verify(client, never()).exportKey(any(), any());
    }

    /** Only key-pair algorithms exist, so the secret is described with one; type, algorithm and length are compared. */
    @Test
    void exportKey_returnsASecretKeyItsConnectorDescribesAsHeld() throws Exception {
        // given
        byte[] envelope = ExportEnvelopeFixtures.pinnedEnvelope(rsaKeyPair().getPrivate(), PASSPHRASE);
        when(client.listExportKeyAttributes(any(), any())).thenReturn(List.of());
        when(client.exportKey(any(), any())).thenReturn(secretExportResponse(envelope, 256));

        // when
        byte[] exported = adapter.exportKey(v2Context(metadata("handle")), heldSecret(256), passphrase(), List.of());

        // then
        assertArrayEquals(envelope, exported);
    }

    @Test
    void exportKey_refusesASecretKeyOfAnotherLength() throws Exception {
        // given
        when(client.listExportKeyAttributes(any(), any())).thenReturn(List.of());
        when(client.exportKey(any(), any()))
                .thenReturn(secretExportResponse(
                        ExportEnvelopeFixtures.pinnedEnvelope(rsaKeyPair().getPrivate(), PASSPHRASE), 128));
        OperationKeyContext context = v2Context(metadata("handle"));
        HeldKey held = heldSecret(256);
        Passphrase passphrase = passphrase();

        // when
        ConnectorServerException refused = assertThrows(ConnectorServerException.class,
                () -> adapter.exportKey(context, held, passphrase, NO_ATTRIBUTES));

        // then
        assertEquals(HttpStatus.BAD_GATEWAY, refused.getHttpStatus());
    }

    @Test
    void exportKey_namesARefusalByItsCodeAlone() throws Exception {
        // given
        String echoed = new String(PASSPHRASE);
        when(client.listExportKeyAttributes(any(), any())).thenReturn(List.of());
        when(client.exportKey(any(), any()))
                .thenThrow(new ConnectorProblemException(ProblemDetailExtended
                        .fromErrorCode(ErrorCode.KEY_NOT_EXPORTABLE, "refused for " + echoed, null, null)));
        OperationKeyContext context = v2Context(metadata("handle"));
        HeldKey held = heldKey(rsaKeyPair().getPublic());
        Passphrase passphrase = passphrase();

        // when
        ValidationException refused = assertThrows(ValidationException.class,
                () -> adapter.exportKey(context, held, passphrase, NO_ATTRIBUTES));

        // then
        assertTrue(refused.getMessage().contains(ErrorCode.KEY_NOT_EXPORTABLE.name()), refused.getMessage());
        assertFalse(refused.getMessage().contains(echoed), refused.getMessage());
    }

    /** The request carried the passphrase, so nothing the connector answered may travel on. */
    @ParameterizedTest
    @MethodSource("failedExports")
    void exportKey_dropsTheConnectorsWordsWhenTheExportFails(Exception failure) throws Exception {
        // given
        when(client.listExportKeyAttributes(any(), any())).thenReturn(List.of());
        when(client.exportKey(any(), any())).thenThrow(failure);
        OperationKeyContext context = v2Context(metadata("handle"));
        HeldKey held = heldKey(rsaKeyPair().getPublic());
        Passphrase passphrase = passphrase();

        // when
        ConnectorServerException failed = assertThrows(ConnectorServerException.class,
                () -> adapter.exportKey(context, held, passphrase, NO_ATTRIBUTES));

        // then
        assertEquals(HttpStatus.BAD_GATEWAY, failed.getHttpStatus());
        assertFalse(failed.getMessage().contains(new String(PASSPHRASE)), failed.getMessage());
        assertNull(failed.getCause());
    }

    private static Stream<Exception> failedExports() {
        String echoed = "failed for " + new String(PASSPHRASE);
        ProblemDetailExtended withoutCode = new ProblemDetailExtended();
        withoutCode.setStatus(HttpStatus.UNPROCESSABLE_ENTITY.value());
        withoutCode.setDetail(echoed);
        return Stream
                .of(new ConnectorProblemException(
                        ProblemDetailExtended.fromErrorCode(ErrorCode.INTERNAL_SERVER_ERROR, echoed, null, null)),
                        new ConnectorProblemException(
                                ProblemDetailExtended.fromErrorCode(ErrorCode.FORBIDDEN, echoed, null, null)),
                        new ConnectorProblemException(withoutCode),
                        new ConnectorServerException(echoed, HttpStatus.INTERNAL_SERVER_ERROR),
                        new ValidationException(echoed), new IllegalStateException(echoed));
    }

    private static Stream<Arguments> operationAttributeListings() {
        return Stream
                .of(Arguments
                        .of("encrypt", (ClientListing) client -> client.listEncryptAttributes(any(), any()),
                                (AdapterListing) KeyProviderV2Adapter::listEncryptAttributes),
                        Arguments
                                .of("decrypt", (ClientListing) client -> client.listDecryptAttributes(any(), any()),
                                        (AdapterListing) KeyProviderV2Adapter::listDecryptAttributes),
                        Arguments
                                .of("sign", (ClientListing) client -> client.listSignAttributes(any(), any()),
                                        (AdapterListing) KeyProviderV2Adapter::listSignAttributes),
                        Arguments
                                .of("verify", (ClientListing) client -> client.listVerifyAttributes(any(), any()),
                                        (AdapterListing) KeyProviderV2Adapter::listVerifyAttributes));
    }

    @FunctionalInterface
    interface ClientListing {
        List<BaseAttribute> list(CryptographicOperationsSyncApiClient client) throws ConnectorException;
    }

    @FunctionalInterface
    interface AdapterListing {
        List<BaseAttribute> list(KeyProviderV2Adapter adapter, OperationKeyContext context) throws ConnectorException;
    }

    private static DataAttributeV2 dataAttributeDefinition(String name, boolean required) {
        DataAttributeProperties properties = new DataAttributeProperties();
        properties.setLabel(name);
        properties.setRequired(required);
        DataAttributeV2 definition = new DataAttributeV2();
        definition.setUuid(UUID.randomUUID().toString());
        definition.setName(name);
        definition.setContentType(AttributeContentType.STRING);
        definition.setProperties(properties);
        return definition;
    }

    /** The profile on a token whose cryptography interface declares the given features. */
    private ImmutableTokenProfileFullModel profileDeclaring(FeatureFlag... features) {
        ImmutableConnectorInterface cryptography = new ImmutableConnectorInterface(UUID.randomUUID(),
                ConnectorInterface.CRYPTOGRAPHY, "v2", List.of(features));
        var token = new ImmutableTokenInstanceFullModel(UUID.randomUUID(), null, "token", TokenInstanceStatus.ACTIVATED,
                null, profile.connectorUuid(), "connector", cryptography.uuid(), cryptography, Set.of());
        return new ImmutableTokenProfileFullModel(UUID.randomUUID(), "profile", null, token.name(), token.uuid(), true,
                List.of(KeyUsage.SIGN), token, profile.connectorUuid(), Map.of(), 0);
    }

    private static RequestAttribute stringAttribute(String name, String value) {
        RequestAttributeV2 attribute = new RequestAttributeV2();
        attribute.setName(name);
        attribute.setContent(List.of(new StringAttributeContentV2(value)));
        return attribute;
    }

    private static RequestAttribute requestAttribute(String name) {
        RequestAttributeV2 attribute = new RequestAttributeV2();
        attribute.setName(name);
        return attribute;
    }

    private static SignatureRequestData signatureItem(String base64, String identifier) {
        SignatureRequestData item = new SignatureRequestData();
        item.setData(base64);
        item.setIdentifier(identifier);
        return item;
    }

    private static List<String> sentIdentifiers(List<SignatureDataV2Dto> items) {
        return items.stream().map(SignatureDataV2Dto::getIdentifier).toList();
    }

    private ObjectAttributeContentInfo attributeScope(Resource resource, UUID uuid) {
        return ObjectAttributeContentInfo.builder(resource, uuid).connector(profile.connectorUuid()).build();
    }

    private void stubAttributes(Resource resource, UUID uuid, List<RequestAttribute> stored,
            List<RequestAttribute> resolved) throws ConnectorException {
        ObjectAttributeContentInfo info = attributeScope(resource, uuid);
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
        List<ProviderKeyItem> items = adapter
                .createKey(profile, KeyRequestType.KEY_PAIR, List.of(), wrapperName, false);

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
                .createKey(profile, KeyRequestType.SECRET, creationAttributes, wrapperName, false);

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
        assertTrue(request.getValue().getCreateKeyAttributes().containsAll(creationAttributes));
        assertDoesNotThrow(() -> UUID.fromString(request.getValue().getKeyCreationId()));
    }

    @Test
    void createKey_statesTheExportableIntentAsTheReservedAttribute() throws Exception {
        // given
        when(client.createKey(any(), any())).thenReturn(ResponseEntity.ok(secretKeyResponse()));

        // when
        adapter
                .createKey(profileDeclaring(FeatureFlag.KEY_EXPORT), KeyRequestType.SECRET, List.of(), profile.name(),
                        true);

        // then
        ArgumentCaptor<CreateKeyRequestV2Dto> request = ArgumentCaptor.forClass(CreateKeyRequestV2Dto.class);
        verify(client).createKey(any(), request.capture());
        RequestAttribute intent = request.getValue().getCreateKeyAttributes().getFirst();
        assertInstanceOf(RequestAttributeV3.class, intent);
        assertEquals(KeyExportableAttribute.ATTRIBUTE_UUID, intent.getUuid());
        assertEquals(KeyExportableAttribute.NAME, intent.getName());
        assertEquals(AttributeContentType.BOOLEAN, intent.getContentType());
        assertTrue(KeyExportableAttribute.isRequested(request.getValue().getCreateKeyAttributes()));
    }

    @Test
    void createKey_statesANonExportableIntentToo() throws Exception {
        // given
        when(client.createKey(any(), any())).thenReturn(ResponseEntity.ok(secretKeyResponse()));

        // when
        adapter
                .createKey(profileDeclaring(FeatureFlag.KEY_EXPORT), KeyRequestType.SECRET, List.of(), profile.name(),
                        false);

        // then
        ArgumentCaptor<CreateKeyRequestV2Dto> request = ArgumentCaptor.forClass(CreateKeyRequestV2Dto.class);
        verify(client).createKey(any(), request.capture());
        assertFalse(KeyExportableAttribute.isRequested(request.getValue().getCreateKeyAttributes()));
        assertEquals(1, request.getValue().getCreateKeyAttributes().size());
    }

    @Test
    void createKey_statesTheExportableIntentWhenTheRequestCarriesNoAttributes() throws Exception {
        // given
        when(client.createKey(any(), any())).thenReturn(ResponseEntity.ok(secretKeyResponse()));

        // when
        adapter.createKey(profileDeclaring(FeatureFlag.KEY_EXPORT), KeyRequestType.SECRET, null, profile.name(), true);

        // then
        ArgumentCaptor<CreateKeyRequestV2Dto> request = ArgumentCaptor.forClass(CreateKeyRequestV2Dto.class);
        verify(client).createKey(any(), request.capture());
        assertTrue(KeyExportableAttribute.isRequested(request.getValue().getCreateKeyAttributes()));
        assertEquals(1, request.getValue().getCreateKeyAttributes().size());
    }

    @ParameterizedTest
    @ValueSource(booleans = {false, true})
    void createKey_statesNoExportableIntentToAConnectorWithoutKeyExport(boolean exportable) throws Exception {
        // given
        when(client.createKey(any(), any())).thenReturn(ResponseEntity.ok(secretKeyResponse()));
        RequestAttribute label = requestAttribute("keyLabel");

        // when
        adapter
                .createKey(profileDeclaring(FeatureFlag.STATELESS), KeyRequestType.SECRET,
                        List.of(label, requestAttribute(KeyExportableAttribute.NAME)), profile.name(), exportable);

        // then
        ArgumentCaptor<CreateKeyRequestV2Dto> request = ArgumentCaptor.forClass(CreateKeyRequestV2Dto.class);
        verify(client).createKey(any(), request.capture());
        assertEquals(List.of(label), request.getValue().getCreateKeyAttributes());
    }

    @Test
    void createKey_statesItsOwnIntentInPlaceOfOneTheCallerStated() throws Exception {
        // given
        when(client.createKey(any(), any())).thenReturn(ResponseEntity.ok(secretKeyResponse()));
        RequestAttributeV2 statedByTheCaller = new RequestAttributeV2();
        statedByTheCaller.setUuid(KeyExportableAttribute.ATTRIBUTE_UUID);
        statedByTheCaller.setName(KeyExportableAttribute.NAME);
        statedByTheCaller.setContentType(AttributeContentType.BOOLEAN);
        statedByTheCaller.setContent(List.of(new BooleanAttributeContentV2(true)));

        // when
        adapter
                .createKey(profileDeclaring(FeatureFlag.KEY_EXPORT), KeyRequestType.SECRET, List.of(statedByTheCaller),
                        profile.name(), false);

        // then
        ArgumentCaptor<CreateKeyRequestV2Dto> request = ArgumentCaptor.forClass(CreateKeyRequestV2Dto.class);
        verify(client).createKey(any(), request.capture());
        assertEquals(1, request.getValue().getCreateKeyAttributes().size());
        assertFalse(KeyExportableAttribute.isRequested(request.getValue().getCreateKeyAttributes()));
    }

    @Test
    void createKey_rejectsAsynchronousAcceptance() throws Exception {
        // given
        when(client.createKey(any(), any())).thenReturn(ResponseEntity.accepted().build());

        // when
        Executable createKey = () -> adapter
                .createKey(profile, KeyRequestType.SECRET, List.of(), profile.name(), false);

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
        adapter.createKey(profile, KeyRequestType.SECRET, List.of(), profile.name(), false);

        // then
        ArgumentCaptor<CreateKeyRequestV2Dto> request = ArgumentCaptor.forClass(CreateKeyRequestV2Dto.class);
        verify(client).createKey(any(), request.capture());
        assertEquals(resolvedToken, request.getValue().getTokenAttributes());
        assertEquals(resolvedProfile, request.getValue().getTokenProfileAttributes());
    }

    @ParameterizedTest(name = "{0}")
    @MethodSource("invalidCreationResults")
    void createKey_rejectsInvalidSynchronousResult(ResponseEntity<KeyCreationResponseV2Dto> response) throws Exception {
        // given
        when(client.createKey(any(), any())).thenReturn(response);

        // when
        Executable create = () -> adapter.createKey(profile, KeyRequestType.SECRET, List.of(), profile.name(), false);

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
        Executable create = () -> adapter.createKey(profile, KeyRequestType.SECRET, List.of(), profile.name(), false);

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
        assertEquals(expectedDefinitions, definitions);
        ArgumentCaptor<CreateKeyAttributesRequestV2Dto> request = ArgumentCaptor
                .forClass(CreateKeyAttributesRequestV2Dto.class);
        verify(client).listCreateKeyAttributes(any(), request.capture());
        assertEquals(type, request.getValue().getKeyRequestType());
        assertEquals(resolvedToken, request.getValue().getTokenAttributes());
        assertEquals(resolvedProfile, request.getValue().getTokenProfileAttributes());
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
    void listCreateKeyAttributes_leavesTheReservedExportableAttributeOut() throws Exception {
        // given
        DataAttributeV2 keySize = new DataAttributeV2();
        keySize.setName("key-size");
        when(client.listCreateKeyAttributes(any(), any()))
                .thenReturn(List.of(keySize, KeyExportableAttribute.definition()));

        // when
        List<BaseAttribute> definitions = adapter.listCreateKeyAttributes(profile, KeyRequestType.SECRET);

        // then
        assertEquals(List.of(keySize), definitions);
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
        assertEquals(expectedDefinitions, definitions);
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

    private static final char[] PASSPHRASE = "correct horse battery staple".toCharArray();
    private static final List<RequestAttribute> NO_ATTRIBUTES = List.of();

    private static Passphrase passphrase() {
        return new Passphrase(PASSPHRASE);
    }

    private static KeyPair rsaKeyPair() throws Exception {
        KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
        generator.initialize(2048);
        return generator.generateKeyPair();
    }

    private static HeldKey heldKey(PublicKey publicKey) {
        return new HeldKey(KeyRequestType.KEY_PAIR, KeyAlgorithm.RSA, 2048, publicKey.getEncoded(), null);
    }

    private static HeldKey heldSecret(int length) {
        return new HeldKey(KeyRequestType.SECRET, KeyAlgorithm.RSA, length, null, null);
    }

    private static ExportKeyResponseV2Dto secretExportResponse(byte[] envelope, int length) {
        EncryptedKeyMaterialV2Dto material = new EncryptedKeyMaterialV2Dto();
        material.setEncryptedPrivateKeyInfo(envelope);
        SecretKeyDataV2Dto descriptor = new SecretKeyDataV2Dto();
        descriptor.setAlgorithm(KeyAlgorithm.RSA);
        descriptor.setLength(length);
        ExportKeyResponseV2Dto response = new ExportKeyResponseV2Dto();
        response.setMaterial(material);
        response.setKeyData(descriptor);
        return response;
    }

    private static ExportKeyResponseV2Dto exportResponse(byte[] envelope, PublicKey publicKey) {
        EncryptedKeyMaterialV2Dto material = new EncryptedKeyMaterialV2Dto();
        material.setEncryptedPrivateKeyInfo(envelope);
        PublicKeyDataV2Dto descriptor = new PublicKeyDataV2Dto();
        descriptor.setAlgorithm(KeyAlgorithm.RSA);
        descriptor.setLength(2048);
        descriptor.setPublicKeySpki(publicKey.getEncoded());
        ExportKeyResponseV2Dto response = new ExportKeyResponseV2Dto();
        response.setMaterial(material);
        response.setKeyData(descriptor);
        return response;
    }

    private static MetadataAttribute metadataCarrying(String value) {
        MetadataAttributeV3 attribute = new MetadataAttributeV3();
        attribute.setName("note");
        attribute.setContent(List.of(new StringAttributeContentV3(value)));
        return attribute;
    }

    private static List<MetadataAttribute> metadata(String name) {
        MetadataAttributeV2 attribute = new MetadataAttributeV2();
        attribute.setName(name);
        return List.of(attribute);
    }
}
