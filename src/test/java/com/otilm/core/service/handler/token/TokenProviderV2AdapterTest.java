package com.otilm.core.service.handler.token;

import com.otilm.api.exception.ConnectorException;
import com.otilm.api.interfaces.client.v2.TokenSyncApiClient;
import com.otilm.api.model.client.connector.v2.ConnectorVersion;
import com.otilm.api.model.connector.cryptography.enums.TokenInstanceStatus;
import com.otilm.api.model.core.connector.ConnectorStatus;
import com.otilm.core.attribute.engine.AttributeEngine;
import com.otilm.core.client.ConnectorApiFactory;
import com.otilm.core.model.connector.ImmutableConnectorFullModel;
import com.otilm.core.model.crypto.ImmutableTokenInstanceBasicModel;
import com.otilm.core.service.handler.OperationAttributeResolver;
import java.util.List;
import java.util.UUID;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.function.Executable;

import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

class TokenProviderV2AdapterTest {

    private TokenSyncApiClient tokenApiClient;
    private TokenProviderV2Adapter adapter;
    private ImmutableTokenInstanceBasicModel token;

    @BeforeEach
    void setUp() throws Exception {
        UUID connectorUuid = UUID.randomUUID();
        ImmutableConnectorFullModel connector = connector(connectorUuid);
        ConnectorApiFactory connectorApiFactory = mock(ConnectorApiFactory.class);
        AttributeEngine attributeEngine = mock(AttributeEngine.class);
        OperationAttributeResolver operationAttributeResolver = mock(OperationAttributeResolver.class);
        tokenApiClient = mock(TokenSyncApiClient.class);
        when(connectorApiFactory.getTokenInstanceApiClientV2(connector)).thenReturn(tokenApiClient);
        when(attributeEngine.getRequestObjectDataAttributesContent(any())).thenReturn(List.of());
        when(operationAttributeResolver.resolveForConnectorRequestAsSystem(connectorUuid, List.of()))
                .thenReturn(List.of());
        adapter = new TokenProviderV2Adapter(connectorApiFactory, attributeEngine, operationAttributeResolver,
                connector);
        token = token(connectorUuid);
    }

    @Test
    void listSupportedKeyUsages_throwsConnectorException_forNullResponse() throws Exception {
        // given
        when(tokenApiClient.listTokenProfileKeyUsages(any(), any())).thenReturn(null);

        // when
        Executable listUsages = () -> adapter.listSupportedKeyUsages(token);

        // then
        ConnectorException exception = assertThrows(ConnectorException.class, listUsages);
        assertTrue(exception.getMessage().contains("Connector returned no Key Usages"));
    }

    private static ImmutableConnectorFullModel connector(UUID connectorUuid) {
        return new ImmutableConnectorFullModel(connectorUuid, "connector", ConnectorVersion.V2, "http://connector.test",
                null, List.of(), ConnectorStatus.CONNECTED, null, List.of(), List.of());
    }

    private static ImmutableTokenInstanceBasicModel token(UUID connectorUuid) {
        return new ImmutableTokenInstanceBasicModel(UUID.randomUUID(), null, "token", TokenInstanceStatus.UNKNOWN,
                "SOFT", connectorUuid, "connector", UUID.randomUUID(), 0);
    }
}
