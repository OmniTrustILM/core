package com.otilm.core.service.impl;

import com.otilm.api.exception.ConnectorException;
import com.otilm.api.exception.NotFoundException;
import com.otilm.api.exception.NotSupportedException;
import com.otilm.api.exception.ValidationException;
import com.otilm.api.model.client.connector.v2.ConnectorInterface;
import com.otilm.api.model.client.cryptography.operations.CipherDataRequestDto;
import com.otilm.api.model.client.cryptography.operations.RandomDataRequestDto;
import com.otilm.api.model.client.cryptography.operations.RandomDataResponseDto;
import com.otilm.api.model.client.cryptography.operations.SignDataRequestDto;
import com.otilm.api.model.client.cryptography.operations.SignDataResponseDto;
import com.otilm.api.model.client.cryptography.operations.VerifyDataRequestDto;
import com.otilm.api.model.common.attribute.common.BaseAttribute;
import com.otilm.api.model.common.attribute.v2.DataAttributeV2;
import com.otilm.api.model.common.attribute.v3.MetadataAttributeV3;
import com.otilm.api.model.common.enums.BitMaskEnum;
import com.otilm.api.model.common.enums.cryptography.KeyAlgorithm;
import com.otilm.api.model.common.enums.cryptography.KeyType;
import com.otilm.api.model.connector.cryptography.enums.TokenInstanceStatus;
import com.otilm.api.model.core.auth.Resource;
import com.otilm.api.model.core.cryptography.key.KeyEvent;
import com.otilm.api.model.core.cryptography.key.KeyEventStatus;
import com.otilm.api.model.core.cryptography.key.KeyState;
import com.otilm.api.model.core.cryptography.key.KeyUsage;
import com.otilm.core.attribute.RsaEncryptionAttributes;
import com.otilm.core.dao.repository.CryptographicKeyRepository;
import com.otilm.core.dao.repository.TokenInstanceReferenceRepository;
import com.otilm.core.dao.repository.TokenProfileRepository;
import com.otilm.core.model.auth.ResourceAction;
import com.otilm.core.model.crypto.CryptographicKeyItemOperationModel;
import com.otilm.core.model.crypto.ImmutableTokenInstanceBasicModel;
import com.otilm.core.model.crypto.ImmutableTokenProfileBasicModel;
import com.otilm.core.model.crypto.KeyOperationScope;
import com.otilm.core.model.crypto.RemoteKeyReference;
import com.otilm.core.model.crypto.TokenInstanceBasicModel;
import com.otilm.core.security.authz.AuthorizationEnforcer;
import com.otilm.core.security.authz.SecuredParentUUID;
import com.otilm.core.security.authz.SecuredUUID;
import com.otilm.core.service.CryptographicKeyEventHistoryService;
import com.otilm.core.service.CryptographicKeyInternalService;
import com.otilm.core.service.handler.key.KeyProviderAdapter;
import com.otilm.core.service.handler.key.KeyProviderAdapterFactory;
import com.otilm.core.service.handler.key.OperationKeyContext;
import com.otilm.core.service.handler.token.TokenProviderAdapter;
import com.otilm.core.service.handler.token.TokenProviderAdapterFactory;
import java.util.EnumSet;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.UUID;
import java.util.stream.Stream;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.api.function.Executable;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;
import org.mockito.ArgumentCaptor;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class CryptographicOperationServiceImplTest {

    @Mock
    private CryptographicKeyInternalService keyService;
    @Mock
    private CryptographicKeyRepository cryptographicKeyRepository;
    @Mock
    private KeyProviderAdapterFactory keyProviderAdapterFactory;
    @Mock
    private KeyProviderAdapter adapter;
    @Mock
    private AuthorizationEnforcer authorizationEnforcer;
    @Mock
    private CryptographicKeyEventHistoryService eventHistoryService;
    @Mock
    private TokenProviderAdapterFactory tokenProviderAdapterFactory;
    @Mock
    private TokenProviderAdapter tokenAdapter;
    @Mock
    private TokenInstanceReferenceRepository tokenInstanceReferenceRepository;
    @Mock
    private TokenProfileRepository tokenProfileRepository;
    @InjectMocks
    private CryptographicOperationServiceImpl service;

    @Test
    void randomData_routesThroughTokenAdapter_forV1Token() throws Exception {
        // given
        UUID tokenUuid = UUID.randomUUID();
        TokenInstanceBasicModel token = v1Token(tokenUuid);
        when(tokenInstanceReferenceRepository.findBasicModelByUuid(tokenUuid)).thenReturn(Optional.of(token));
        when(tokenProviderAdapterFactory.forToken(token)).thenReturn(tokenAdapter);
        RandomDataRequestDto request = new RandomDataRequestDto();
        request.setLength(8);
        RandomDataResponseDto expected = new RandomDataResponseDto();
        when(tokenAdapter.randomData(token, null, request)).thenReturn(expected);

        // when
        RandomDataResponseDto response = service.randomData(SecuredUUID.fromUUID(tokenUuid), request);

        // then
        assertSame(expected, response);
    }

    @Test
    void randomData_throwsNotFound_forUnknownToken() {
        // given
        UUID tokenUuid = UUID.randomUUID();
        when(tokenInstanceReferenceRepository.findBasicModelByUuid(tokenUuid)).thenReturn(Optional.empty());

        // when
        Executable generate = () -> service.randomData(SecuredUUID.fromUUID(tokenUuid), new RandomDataRequestDto());

        // then
        assertThrows(NotFoundException.class, generate);
        verifyNoInteractions(tokenProviderAdapterFactory);
    }

    @Test
    void randomData_rejectsV2Token_onTokenOnlyForm() {
        // given
        UUID tokenUuid = UUID.randomUUID();
        TokenInstanceBasicModel token = v2Token(tokenUuid);
        when(tokenInstanceReferenceRepository.findBasicModelByUuid(tokenUuid)).thenReturn(Optional.of(token));

        // when
        Executable generate = () -> service.randomData(SecuredUUID.fromUUID(tokenUuid), new RandomDataRequestDto());

        // then
        NotSupportedException failure = assertThrows(NotSupportedException.class, generate);
        assertEquals("Random-data generation on a cryptography provider v2 token requires a token profile; use the "
                + "token-profile form of this endpoint.", failure.getMessage());
        verifyNoInteractions(tokenProviderAdapterFactory);
    }

    @Test
    void listRandomAttributes_routesThroughTokenAdapter_forV1Token() throws Exception {
        // given
        UUID tokenUuid = UUID.randomUUID();
        TokenInstanceBasicModel token = v1Token(tokenUuid);
        when(tokenInstanceReferenceRepository.findBasicModelByUuid(tokenUuid)).thenReturn(Optional.of(token));
        when(tokenProviderAdapterFactory.forToken(token)).thenReturn(tokenAdapter);
        List<BaseAttribute> schema = List.of(new DataAttributeV2());
        when(tokenAdapter.listRandomAttributes(token, null)).thenReturn(schema);

        // when
        List<BaseAttribute> result = service.listRandomAttributes(SecuredUUID.fromUUID(tokenUuid));

        // then
        assertSame(schema, result);
    }

    @Test
    void listRandomAttributes_rejectsV2Token_onTokenOnlyForm() {
        // given
        UUID tokenUuid = UUID.randomUUID();
        TokenInstanceBasicModel token = v2Token(tokenUuid);
        when(tokenInstanceReferenceRepository.findBasicModelByUuid(tokenUuid)).thenReturn(Optional.of(token));

        // when
        Executable list = () -> service.listRandomAttributes(SecuredUUID.fromUUID(tokenUuid));

        // then
        NotSupportedException failure = assertThrows(NotSupportedException.class, list);
        assertEquals("Random-data generation on a cryptography provider v2 token requires a token profile; use the "
                + "token-profile form of this endpoint.", failure.getMessage());
        verifyNoInteractions(tokenProviderAdapterFactory);
    }

    @Test
    void listRandomAttributes_routesThroughTokenAdapter_forTokenProfile() throws Exception {
        // given
        UUID tokenUuid = UUID.randomUUID();
        TokenInstanceBasicModel token = v2Token(tokenUuid);
        ImmutableTokenProfileBasicModel profile = profileFor(token);
        when(tokenInstanceReferenceRepository.findBasicModelByUuid(tokenUuid)).thenReturn(Optional.of(token));
        when(tokenProfileRepository.findBasicModelByUuid(profile.uuid())).thenReturn(Optional.of(profile));
        when(tokenProviderAdapterFactory.forToken(token)).thenReturn(tokenAdapter);
        List<BaseAttribute> schema = List.of(new DataAttributeV2());
        when(tokenAdapter.listRandomAttributes(token, profile)).thenReturn(schema);

        // when
        List<BaseAttribute> result = service
                .listRandomAttributes(SecuredParentUUID.fromUUID(tokenUuid), SecuredUUID.fromUUID(profile.uuid()));

        // then
        assertSame(schema, result);
        verify(authorizationEnforcer)
                .enforce(eq(Resource.TOKEN_PROFILE), eq(ResourceAction.DETAIL), any(SecuredUUID.class));
    }

    @Test
    void listRandomAttributes_rejectsProfile_whenNotAssociatedWithToken() {
        // given
        UUID tokenUuid = UUID.randomUUID();
        TokenInstanceBasicModel token = v2Token(tokenUuid);
        ImmutableTokenProfileBasicModel profile = profileFor(v2Token(UUID.randomUUID()));
        when(tokenInstanceReferenceRepository.findBasicModelByUuid(tokenUuid)).thenReturn(Optional.of(token));
        when(tokenProfileRepository.findBasicModelByUuid(profile.uuid())).thenReturn(Optional.of(profile));

        // when
        Executable list = () -> service
                .listRandomAttributes(SecuredParentUUID.fromUUID(tokenUuid), SecuredUUID.fromUUID(profile.uuid()));

        // then
        ValidationException failure = assertThrows(ValidationException.class, list);
        assertEquals("Token profile is not associated with the token.", failure.getMessage());
        verifyNoInteractions(tokenProviderAdapterFactory);
    }

    @Test
    void randomData_routesThroughTokenAdapter_forTokenProfile() throws Exception {
        // given
        UUID tokenUuid = UUID.randomUUID();
        TokenInstanceBasicModel token = v2Token(tokenUuid);
        ImmutableTokenProfileBasicModel profile = profileFor(token);
        when(tokenInstanceReferenceRepository.findBasicModelByUuid(tokenUuid)).thenReturn(Optional.of(token));
        when(tokenProfileRepository.findBasicModelByUuid(profile.uuid())).thenReturn(Optional.of(profile));
        when(tokenProviderAdapterFactory.forToken(token)).thenReturn(tokenAdapter);
        RandomDataRequestDto request = new RandomDataRequestDto();
        request.setLength(8);
        RandomDataResponseDto expected = new RandomDataResponseDto();
        when(tokenAdapter.randomData(token, profile, request)).thenReturn(expected);

        // when
        RandomDataResponseDto response = service
                .randomData(SecuredParentUUID.fromUUID(tokenUuid), SecuredUUID.fromUUID(profile.uuid()), request);

        // then
        assertSame(expected, response);
        verify(authorizationEnforcer)
                .enforce(eq(Resource.TOKEN_PROFILE), eq(ResourceAction.DETAIL), any(SecuredUUID.class));
    }

    @Test
    void randomData_rejectsProfile_whenNotAssociatedWithToken() {
        // given
        UUID tokenUuid = UUID.randomUUID();
        TokenInstanceBasicModel token = v2Token(tokenUuid);
        ImmutableTokenProfileBasicModel profile = profileFor(v2Token(UUID.randomUUID()));
        when(tokenInstanceReferenceRepository.findBasicModelByUuid(tokenUuid)).thenReturn(Optional.of(token));
        when(tokenProfileRepository.findBasicModelByUuid(profile.uuid())).thenReturn(Optional.of(profile));

        // when
        Executable generate = () -> service
                .randomData(SecuredParentUUID.fromUUID(tokenUuid), SecuredUUID.fromUUID(profile.uuid()),
                        new RandomDataRequestDto());

        // then
        ValidationException failure = assertThrows(ValidationException.class, generate);
        assertEquals("Token profile is not associated with the token.", failure.getMessage());
        verifyNoInteractions(tokenProviderAdapterFactory);
    }

    private static TokenInstanceBasicModel v1Token(UUID tokenUuid) {
        return new ImmutableTokenInstanceBasicModel(tokenUuid, "remote", "token", TokenInstanceStatus.ACTIVATED, "SOFT",
                UUID.randomUUID(), "connector", null, null, null, 0);
    }

    private static TokenInstanceBasicModel v2Token(UUID tokenUuid) {
        return new ImmutableTokenInstanceBasicModel(tokenUuid, "remote", "token", TokenInstanceStatus.ACTIVATED, "SOFT",
                UUID.randomUUID(), "connector", UUID.randomUUID(), ConnectorInterface.CRYPTOGRAPHY, "v2", 0);
    }

    private static ImmutableTokenProfileBasicModel profileFor(TokenInstanceBasicModel token) {
        return new ImmutableTokenProfileBasicModel(UUID.randomUUID(), "profile", null, token.name(), token.uuid(), true,
                List.of(KeyUsage.SIGN));
    }

    @Test
    void signData_routesLegacyItemToAdapter_andRecordsSuccess() throws Exception {
        // given
        CryptographicKeyItemOperationModel key = legacyKey();
        when(keyService.getKeyItemModel(key.keyItemUuid())).thenReturn(key);
        when(keyProviderAdapterFactory.forKeyItem(key)).thenReturn(adapter);
        SignDataResponseDto expected = new SignDataResponseDto();
        when(adapter.signData(any(), any())).thenReturn(expected);

        // when
        SignDataResponseDto response = service
                .signData(SecuredParentUUID.fromUUID(key.tokenInstanceUuid()), SecuredUUID.fromUUID(UUID.randomUUID()),
                        UUID.randomUUID(), key.keyItemUuid(), signRequest());

        // then
        assertSame(expected, response);
        ArgumentCaptor<OperationKeyContext> context = ArgumentCaptor.forClass(OperationKeyContext.class);
        verify(adapter).signData(context.capture(), any());
        assertSame(key, context.getValue().keyItem());
        assertNull(context.getValue().tokenProfile());
        verify(eventHistoryService)
                .addEventHistory(KeyEvent.SIGN, KeyEventStatus.SUCCESS, "Signing data success ", null,
                        key.keyItemUuid());
        verifyNoInteractions(cryptographicKeyRepository);
    }

    @Test
    void signData_loadsProfileScope_forV2Item_andChecksPathAssociation() throws Exception {
        // given
        CryptographicKeyItemOperationModel key = v2Key();
        KeyOperationScope scope = scope();
        when(keyService.getKeyItemModel(key.keyItemUuid())).thenReturn(key);
        when(cryptographicKeyRepository.findOperationScopeByUuid(key.keyUuid())).thenReturn(Optional.of(scope));
        when(keyProviderAdapterFactory.forKeyItem(key)).thenReturn(adapter);
        when(adapter.signData(any(), any())).thenReturn(new SignDataResponseDto());

        // when
        service
                .signData(SecuredParentUUID.fromUUID(scope.tokenInstanceReferenceUuid()),
                        SecuredUUID.fromUUID(scope.tokenProfileUuid()), key.keyUuid(), key.keyItemUuid(),
                        signRequest());

        // then
        ArgumentCaptor<OperationKeyContext> context = ArgumentCaptor.forClass(OperationKeyContext.class);
        verify(adapter).signData(context.capture(), any());
        assertEquals(scope.tokenProfileUuid(), context.getValue().tokenProfile().uuid());
    }

    @Test
    void signData_rejectsV2Item_whenPathProfileDiffers() throws Exception {
        // given
        CryptographicKeyItemOperationModel key = v2Key();
        KeyOperationScope scope = scope();
        when(keyService.getKeyItemModel(key.keyItemUuid())).thenReturn(key);
        when(cryptographicKeyRepository.findOperationScopeByUuid(key.keyUuid())).thenReturn(Optional.of(scope));

        // when
        Executable sign = () -> service
                .signData(SecuredParentUUID.fromUUID(scope.tokenInstanceReferenceUuid()),
                        SecuredUUID.fromUUID(UUID.randomUUID()), key.keyUuid(), key.keyItemUuid(), signRequest());

        // then
        assertThrows(ValidationException.class, sign);
        verifyNoInteractions(keyProviderAdapterFactory, adapter);
    }

    @Test
    void signData_rejectsV2Item_whenPathKeyDiffers() throws Exception {
        // given
        CryptographicKeyItemOperationModel key = v2Key();
        KeyOperationScope scope = scope();
        when(keyService.getKeyItemModel(key.keyItemUuid())).thenReturn(key);
        when(cryptographicKeyRepository.findOperationScopeByUuid(key.keyUuid())).thenReturn(Optional.of(scope));

        // when
        Executable sign = () -> service
                .signData(SecuredParentUUID.fromUUID(scope.tokenInstanceReferenceUuid()),
                        SecuredUUID.fromUUID(scope.tokenProfileUuid()), UUID.randomUUID(), key.keyItemUuid(),
                        signRequest());

        // then
        assertThrows(ValidationException.class, sign);
        verifyNoInteractions(keyProviderAdapterFactory, adapter);
    }

    @Test
    void signData_rejectsV2Item_whenPathTokenDiffers() throws Exception {
        // given
        CryptographicKeyItemOperationModel key = v2Key();
        KeyOperationScope scope = scope();
        when(keyService.getKeyItemModel(key.keyItemUuid())).thenReturn(key);
        when(cryptographicKeyRepository.findOperationScopeByUuid(key.keyUuid())).thenReturn(Optional.of(scope));

        // when
        Executable sign = () -> service
                .signData(SecuredParentUUID.fromUUID(UUID.randomUUID()), SecuredUUID.fromUUID(scope.tokenProfileUuid()),
                        key.keyUuid(), key.keyItemUuid(), signRequest());

        // then
        assertThrows(ValidationException.class, sign);
        verifyNoInteractions(keyProviderAdapterFactory, adapter);
    }

    @Test
    void signData_recordsFailure_andRethrows_whenAdapterFails() throws Exception {
        // given
        CryptographicKeyItemOperationModel key = legacyKey();
        when(keyService.getKeyItemModel(key.keyItemUuid())).thenReturn(key);
        when(keyProviderAdapterFactory.forKeyItem(key)).thenReturn(adapter);
        ConnectorException failure = new ConnectorException("boom");
        when(adapter.signData(any(), any())).thenThrow(failure);

        // when
        Executable sign = () -> service
                .signData(SecuredParentUUID.fromUUID(key.tokenInstanceUuid()), SecuredUUID.fromUUID(UUID.randomUUID()),
                        UUID.randomUUID(), key.keyItemUuid(), signRequest());

        // then
        assertSame(failure, assertThrows(ConnectorException.class, sign));
        verify(eventHistoryService)
                .addEventHistory(KeyEvent.SIGN, KeyEventStatus.FAILED, "Signing of data failed ",
                        Map.of("exception", "boom"), key.keyItemUuid());
    }

    @Test
    void signData_doesNotRecordFailure_whenSuccessHistoryWriteFails() throws Exception {
        // given
        CryptographicKeyItemOperationModel key = legacyKey();
        when(keyService.getKeyItemModel(key.keyItemUuid())).thenReturn(key);
        when(keyProviderAdapterFactory.forKeyItem(key)).thenReturn(adapter);
        when(adapter.signData(any(), any())).thenReturn(new SignDataResponseDto());
        RuntimeException auditFailure = new RuntimeException("history unavailable");
        doThrow(auditFailure)
                .when(eventHistoryService)
                .addEventHistory(eq(KeyEvent.SIGN), eq(KeyEventStatus.SUCCESS), any(), any(),
                        eq((UUID) key.keyItemUuid()));

        // when
        Executable sign = () -> service
                .signData(SecuredParentUUID.fromUUID(key.tokenInstanceUuid()), SecuredUUID.fromUUID(UUID.randomUUID()),
                        UUID.randomUUID(), key.keyItemUuid(), signRequest());

        // then
        assertSame(auditFailure, assertThrows(RuntimeException.class, sign));
        verify(eventHistoryService, never())
                .addEventHistory(eq(KeyEvent.SIGN), eq(KeyEventStatus.FAILED), any(), any(), any(UUID.class));
    }

    @Test
    void signDataWithoutEventHistory_recordsNothing() throws Exception {
        // given
        CryptographicKeyItemOperationModel key = legacyKey();
        when(keyService.getKeyItemModel(key.keyItemUuid())).thenReturn(key);
        when(keyProviderAdapterFactory.forKeyItem(key)).thenReturn(adapter);
        when(adapter.signData(any(), any())).thenReturn(new SignDataResponseDto());

        // when
        service
                .signDataWithoutEventHistory(SecuredParentUUID.fromUUID(key.tokenInstanceUuid()),
                        SecuredUUID.fromUUID(UUID.randomUUID()), UUID.randomUUID(), key.keyItemUuid(), signRequest());

        // then
        verifyNoInteractions(eventHistoryService);
    }

    @Test
    void encryptData_rejectsKeyWithoutUsage_beforeRouting() throws Exception {
        // given
        CryptographicKeyItemOperationModel key = withUsage(legacyKey(), List.of(KeyUsage.DECRYPT));
        when(keyService.getKeyItemModel(key.keyItemUuid())).thenReturn(key);
        CipherDataRequestDto request = new CipherDataRequestDto();
        request.setCipherData(List.of());

        // when
        Executable encrypt = () -> service
                .encryptData(SecuredParentUUID.fromUUID(key.tokenInstanceUuid()),
                        SecuredUUID.fromUUID(UUID.randomUUID()), UUID.randomUUID(), key.keyItemUuid(), request);

        // then
        ValidationException failure = assertThrows(ValidationException.class, encrypt);
        assertTrue(failure.getMessage().contains("does not support encryption"));
        verifyNoInteractions(keyProviderAdapterFactory);
    }

    @Test
    void verifyData_rejectsInactiveKey() throws Exception {
        // given
        CryptographicKeyItemOperationModel active = legacyKey();
        CryptographicKeyItemOperationModel key = new CryptographicKeyItemOperationModel(active.keyItemUuid(), true,
                active.keyAlgorithm(), KeyState.DEACTIVATED, active.keyType(), active.keyUsage(), null,
                active.reference(), active.connectorUuid(), active.tokenInstanceUuid(), active.keyUuid(), null, null);
        when(keyService.getKeyItemModel(key.keyItemUuid())).thenReturn(key);
        VerifyDataRequestDto request = new VerifyDataRequestDto();
        request.setSignatures(List.of());

        // when
        Executable verifyCall = () -> service
                .verifyData(SecuredParentUUID.fromUUID(key.tokenInstanceUuid()),
                        SecuredUUID.fromUUID(UUID.randomUUID()), UUID.randomUUID(), key.keyItemUuid(), request);

        // then
        assertThrows(ValidationException.class, verifyCall);
        verifyNoInteractions(keyProviderAdapterFactory);
    }

    @ParameterizedTest(name = "{0}")
    @MethodSource("operationAttributeListings")
    void listOperationAttributes_delegatesToItsOwnAdapterCall(String operation, AdapterListing adapterListing,
            ServiceListing serviceListing) throws Exception {
        // given
        CryptographicKeyItemOperationModel key = legacyKey();
        when(keyService.getKeyItemModel(key.keyItemUuid())).thenReturn(key);
        when(keyProviderAdapterFactory.forKeyItem(key)).thenReturn(adapter);
        List<BaseAttribute> schema = List.of(new DataAttributeV2());
        when(adapterListing.list(adapter)).thenReturn(schema);

        // when
        List<BaseAttribute> result = serviceListing
                .list(service, SecuredParentUUID.fromUUID(key.tokenInstanceUuid()),
                        SecuredUUID.fromUUID(UUID.randomUUID()), UUID.randomUUID(), key.keyItemUuid());

        // then
        assertSame(schema, result);
        verifyNoInteractions(eventHistoryService);
    }

    private static Stream<Arguments> operationAttributeListings() {
        return Stream
                .of(Arguments
                        .of("encrypt", (AdapterListing) listing -> listing.listEncryptAttributes(any()),
                                (ServiceListing) CryptographicOperationServiceImpl::listEncryptAttributes),
                        Arguments
                                .of("decrypt", (AdapterListing) listing -> listing.listDecryptAttributes(any()),
                                        (ServiceListing) CryptographicOperationServiceImpl::listDecryptAttributes),
                        Arguments
                                .of("sign", (AdapterListing) listing -> listing.listSignAttributes(any()),
                                        (ServiceListing) CryptographicOperationServiceImpl::listSignAttributes),
                        Arguments
                                .of("verify", (AdapterListing) listing -> listing.listVerifyAttributes(any()),
                                        (ServiceListing) CryptographicOperationServiceImpl::listVerifyAttributes));
    }

    @FunctionalInterface
    interface AdapterListing {
        List<BaseAttribute> list(KeyProviderAdapter adapter) throws ConnectorException;
    }

    @FunctionalInterface
    interface ServiceListing {
        List<BaseAttribute> list(CryptographicOperationServiceImpl service, SecuredParentUUID tokenInstanceUuid,
                SecuredUUID tokenProfileUuid, UUID keyUuid, UUID keyItemUuid)
                throws ConnectorException, NotFoundException;
    }

    @Test
    void listSignatureAttributes_deprecated_rejectsV2Item() throws Exception {
        // given
        CryptographicKeyItemOperationModel key = v2Key();
        when(keyService.getKeyItemModel(key.keyItemUuid())).thenReturn(key);

        // when
        Executable list = () -> service
                .listSignatureAttributes(SecuredParentUUID.fromUUID(UUID.randomUUID()),
                        SecuredUUID.fromUUID(UUID.randomUUID()), key.keyUuid(), key.keyItemUuid(), KeyAlgorithm.RSA);

        // then
        NotSupportedException failure = assertThrows(NotSupportedException.class, list);
        assertTrue(failure.getMessage().contains("per-operation attribute endpoints"));
        verifyNoInteractions(keyProviderAdapterFactory);
    }

    @Test
    void listCipherAttributes_deprecated_stillServesCoreSchema_forLegacyItem() throws Exception {
        // given
        CryptographicKeyItemOperationModel key = legacyKey();
        when(keyService.getKeyItemModel(key.keyItemUuid())).thenReturn(key);

        // when
        List<BaseAttribute> result = service
                .listCipherAttributes(SecuredParentUUID.fromUUID(key.tokenInstanceUuid()),
                        SecuredUUID.fromUUID(UUID.randomUUID()), key.keyUuid(), key.keyItemUuid(), KeyAlgorithm.RSA);

        // then
        // DataAttributeV2.equals() delegates to DataAttributeProperties, which has no equals/hashCode override in
        // the interfaces library, so independently built schemas are never equal by value; toString() carries the
        // same field data and does compare by value.
        assertEquals(RsaEncryptionAttributes.getRsaEncryptionAttributes().toString(), result.toString());
        verifyNoInteractions(keyProviderAdapterFactory);
    }

    private static CryptographicKeyItemOperationModel legacyKey() {
        return new CryptographicKeyItemOperationModel(UUID.randomUUID(), true, KeyAlgorithm.RSA, KeyState.ACTIVE,
                KeyType.PRIVATE_KEY, List.of(KeyUsage.ENCRYPT, KeyUsage.DECRYPT, KeyUsage.SIGN, KeyUsage.VERIFY), null,
                new RemoteKeyReference.UuidReference(UUID.randomUUID()), UUID.randomUUID(), UUID.randomUUID(),
                UUID.randomUUID(), null, null);
    }

    private static CryptographicKeyItemOperationModel v2Key() {
        MetadataAttributeV3 handle = new MetadataAttributeV3();
        handle.setName("provider-key-handle");
        return new CryptographicKeyItemOperationModel(UUID.randomUUID(), true, KeyAlgorithm.RSA, KeyState.ACTIVE,
                KeyType.PRIVATE_KEY, List.of(KeyUsage.ENCRYPT, KeyUsage.DECRYPT, KeyUsage.SIGN, KeyUsage.VERIFY), null,
                new RemoteKeyReference.MetadataReference(List.of(handle)), UUID.randomUUID(), null, UUID.randomUUID(),
                ConnectorInterface.CRYPTOGRAPHY, "v2");
    }

    private static CryptographicKeyItemOperationModel withUsage(CryptographicKeyItemOperationModel key,
            List<KeyUsage> usage) {
        return new CryptographicKeyItemOperationModel(key.keyItemUuid(), key.enabled(), key.keyAlgorithm(),
                key.keyState(), key.keyType(), usage, key.pqcParameterSpecName(), key.reference(), key.connectorUuid(),
                key.tokenInstanceUuid(), key.keyUuid(), key.connectorInterfaceCode(), key.connectorInterfaceVersion());
    }

    private static KeyOperationScope scope() {
        return new KeyOperationScope(UUID.randomUUID(), "profile", null, "token", UUID.randomUUID(), true,
                BitMaskEnum.convertSetToBitMask(EnumSet.of(KeyUsage.SIGN)));
    }

    private static SignDataRequestDto signRequest() {
        SignDataRequestDto request = new SignDataRequestDto();
        request.setData(List.of());
        request.setSignatureAttributes(List.of());
        return request;
    }
}
