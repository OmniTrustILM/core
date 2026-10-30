package com.otilm.core.service.impl;

import com.otilm.api.model.client.connector.v2.ConnectorInterface;
import com.otilm.api.model.connector.cryptography.enums.TokenInstanceStatus;
import com.otilm.api.model.core.cryptography.token.TokenInstanceStatusDetailDto;
import com.otilm.core.dao.repository.TokenInstanceReferenceRepository;
import com.otilm.core.model.connector.ImmutableConnectorInterface;
import com.otilm.core.model.crypto.ImmutableTokenInstanceFullModel;
import com.otilm.core.security.authz.SecuredUUID;
import com.otilm.core.service.handler.token.TokenProviderAdapter;
import com.otilm.core.service.handler.token.TokenProviderAdapterFactory;
import com.otilm.core.service.writer.KeyTransferCapabilityWriter;
import com.otilm.core.service.writer.TokenInstanceReferenceWriter;
import java.util.List;
import java.util.Optional;
import java.util.Set;
import java.util.UUID;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.function.Executable;
import org.mockito.InOrder;

import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.inOrder;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

class TokenInstanceServiceImplReloadTest {

    @Test
    void reloadStatus_forgetsTheExportAnswersBeforeRecordingTheStatus() throws Exception {
        // given
        ImmutableConnectorInterface connectorInterface = new ImmutableConnectorInterface(UUID.randomUUID(),
                ConnectorInterface.CRYPTOGRAPHY, "v2", List.of());
        ImmutableTokenInstanceFullModel token = new ImmutableTokenInstanceFullModel(UUID.randomUUID(),
                UUID.randomUUID().toString(), "token", TokenInstanceStatus.ACTIVATED, null, UUID.randomUUID(),
                "connector", connectorInterface.uuid(), connectorInterface, Set.of());
        TokenInstanceReferenceRepository tokens = mock(TokenInstanceReferenceRepository.class);
        when(tokens.findFullModelByUuid(token.uuid())).thenReturn(Optional.of(token));
        TokenProviderAdapter adapter = mock(TokenProviderAdapter.class);
        TokenInstanceStatusDetailDto status = new TokenInstanceStatusDetailDto();
        status.setStatus(TokenInstanceStatus.CONNECTED);
        when(adapter.getStatus(token)).thenReturn(status);
        TokenProviderAdapterFactory adapters = mock(TokenProviderAdapterFactory.class);
        when(adapters.forToken(token)).thenReturn(adapter);
        KeyTransferCapabilityWriter capabilities = mock(KeyTransferCapabilityWriter.class);
        TokenInstanceReferenceWriter tokenWriter = mock(TokenInstanceReferenceWriter.class);
        doThrow(new IllegalStateException("status not recorded")).when(tokenWriter).updateStatus(any(), any());
        TokenInstanceServiceImpl service = new TokenInstanceServiceImpl();
        service.setTokenInstanceReferenceRepository(tokens);
        service.setTokenProviderAdapterFactory(adapters);
        service.setKeyTransferCapabilityWriter(capabilities);
        service.setTokenInstanceReferenceWriter(tokenWriter);

        // when
        Executable reload = () -> service.reloadStatus(SecuredUUID.fromUUID(token.uuid()));

        // then
        assertThrows(IllegalStateException.class, reload);
        InOrder order = inOrder(capabilities, tokenWriter);
        order.verify(capabilities).forgetForToken(token.uuid());
        order.verify(tokenWriter).updateStatus(token.uuid(), TokenInstanceStatus.CONNECTED);
    }
}
