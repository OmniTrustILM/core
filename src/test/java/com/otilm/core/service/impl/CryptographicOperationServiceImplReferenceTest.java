package com.otilm.core.service.impl;

import com.otilm.api.clients.ApiClientConnectorInfo;
import com.otilm.api.exception.ConnectorException;
import com.otilm.api.interfaces.client.v1.CryptographicOperationsSyncApiClient;
import com.otilm.api.model.client.cryptography.operations.CipherDataRequestDto;
import com.otilm.api.model.client.cryptography.operations.SignDataRequestDto;
import com.otilm.api.model.client.cryptography.operations.VerifyDataRequestDto;
import com.otilm.api.model.common.attribute.v3.MetadataAttributeV3;
import com.otilm.api.model.common.attribute.v3.content.StringAttributeContentV3;
import com.otilm.api.model.common.enums.cryptography.KeyAlgorithm;
import com.otilm.api.model.common.enums.cryptography.KeyType;
import com.otilm.api.model.core.cryptography.key.KeyState;
import com.otilm.api.model.core.cryptography.key.KeyUsage;
import com.otilm.core.client.ConnectorApiFactory;
import com.otilm.core.model.crypto.CryptographicKeyItemOperationModel;
import com.otilm.core.model.crypto.RemoteKeyReference;
import com.otilm.core.security.authz.AuthorizationEnforcer;
import com.otilm.core.security.authz.SecuredParentUUID;
import com.otilm.core.security.authz.SecuredUUID;
import com.otilm.core.service.CryptographicKeyEventHistoryService;
import com.otilm.core.service.CryptographicKeyInternalService;
import com.otilm.core.service.v2.ConnectorInternalService;
import java.util.Arrays;
import java.util.List;
import java.util.UUID;
import java.util.stream.Stream;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.api.function.Executable;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Named.named;
import static org.junit.jupiter.params.provider.Arguments.arguments;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class CryptographicOperationServiceImplReferenceTest {

    @Mock
    private CryptographicKeyInternalService keyService;
    @Mock
    private ConnectorInternalService connectorService;
    @Mock
    private ConnectorApiFactory connectorApiFactory;
    @Mock
    private AuthorizationEnforcer authorizationEnforcer;
    @Mock
    private CryptographicKeyEventHistoryService eventHistoryService;
    @InjectMocks
    private CryptographicOperationServiceImpl service;

    @Test
    void signWithoutHistory_forwardsRemoteUuidWithoutRecordingHistory() throws Exception {
        // given
        UUID remoteUuid = UUID.randomUUID();
        var key = activeKey(new RemoteKeyReference.UuidReference(remoteUuid));
        var connector = mock(ApiClientConnectorInfo.class);
        var client = mock(CryptographicOperationsSyncApiClient.class);
        when(keyService.getKeyItemModel(key.keyItemUuid())).thenReturn(key);
        when(connectorService.getConnectorForApiClient(key.connectorUuid())).thenReturn(connector);
        when(connectorApiFactory.getCryptographicOperationsApiClient(connector)).thenReturn(client);
        when(client.signData(any(), any(), any(), any()))
                .thenReturn(new com.otilm.api.model.connector.cryptography.operations.SignDataResponseDto());

        // when
        var response = service
                .signDataWithoutEventHistory(SecuredParentUUID.fromUUID(key.tokenInstanceUuid()),
                        SecuredUUID.fromUUID(UUID.randomUUID()), UUID.randomUUID(), key.keyItemUuid(), signRequest());

        // then
        assertNotNull(response);
        verify(client)
                .signData(eq(connector), eq(key.tokenInstanceUuid().toString()), eq(remoteUuid.toString()), any());
        verifyNoInteractions(eventHistoryService);
    }

    @ParameterizedTest(name = "{0}: {1}")
    @MethodSource("unsupportedReferences")
    void operation_rejectsUnsupportedRemoteReference_beforeCallingConnector(Operation operation,
            RemoteKeyReference reference) throws Exception {
        // given
        var key = activeKey(reference);
        String expectedMessage = "This cryptographic operation requires a v1 remote key UUID; metadata references are not supported.";
        when(keyService.getKeyItemModel(key.keyItemUuid())).thenReturn(key);

        // when
        Executable execute = () -> execute(operation, key);

        // then
        ConnectorException failure = assertThrows(ConnectorException.class, execute);
        assertEquals(expectedMessage, failure.getMessage());
        verifyNoInteractions(connectorService, connectorApiFactory);
    }

    private static Stream<Arguments> unsupportedReferences() {
        var providerHandle = new MetadataAttributeV3();
        providerHandle.setName("provider-key-handle");
        providerHandle.setContent(List.of(new StringAttributeContentV3("hsm-key-17")));
        return Arrays
                .stream(Operation.values())
                .flatMap(operation -> Stream
                        .of(arguments(operation,
                                named("metadata handle",
                                        new RemoteKeyReference.MetadataReference(List.of(providerHandle)))),
                                arguments(operation,
                                        named("empty metadata handle",
                                                new RemoteKeyReference.MetadataReference(List.of()))),
                                arguments(operation, named("missing reference", null)), arguments(operation,
                                        named("missing UUID", new RemoteKeyReference.UuidReference(null)))));
    }

    private static CryptographicKeyItemOperationModel activeKey(RemoteKeyReference reference) {
        return new CryptographicKeyItemOperationModel(UUID.randomUUID(), true, KeyAlgorithm.MLDSA, KeyState.ACTIVE,
                KeyType.PRIVATE_KEY, List.of(KeyUsage.ENCRYPT, KeyUsage.DECRYPT, KeyUsage.SIGN, KeyUsage.VERIFY), null,
                reference, UUID.randomUUID(), UUID.randomUUID());
    }

    private void execute(Operation operation, CryptographicKeyItemOperationModel key) throws Exception {
        var tokenUuid = SecuredParentUUID.fromUUID(key.tokenInstanceUuid());
        var profileUuid = SecuredUUID.fromUUID(UUID.randomUUID());
        UUID keyUuid = UUID.randomUUID();
        switch (operation) {
            case ENCRYPT -> service.encryptData(tokenUuid, profileUuid, keyUuid, key.keyItemUuid(), cipherRequest());
            case DECRYPT -> service.decryptData(tokenUuid, profileUuid, keyUuid, key.keyItemUuid(), cipherRequest());
            case SIGN -> service.signData(tokenUuid, profileUuid, keyUuid, key.keyItemUuid(), signRequest());
            case SIGN_WITHOUT_HISTORY ->
                service.signDataWithoutEventHistory(tokenUuid, profileUuid, keyUuid, key.keyItemUuid(), signRequest());
            case VERIFY -> service.verifyData(tokenUuid, profileUuid, keyUuid, key.keyItemUuid(), verifyRequest());
        }
    }

    private static CipherDataRequestDto cipherRequest() {
        var request = new CipherDataRequestDto();
        request.setCipherData(List.of());
        return request;
    }

    private static SignDataRequestDto signRequest() {
        var request = new SignDataRequestDto();
        request.setData(List.of());
        request.setSignatureAttributes(List.of());
        return request;
    }

    private static VerifyDataRequestDto verifyRequest() {
        var request = new VerifyDataRequestDto();
        request.setSignatures(List.of());
        request.setSignatureAttributes(List.of());
        return request;
    }

    private enum Operation {
        ENCRYPT,
        DECRYPT,
        SIGN,
        SIGN_WITHOUT_HISTORY,
        VERIFY
    }
}
