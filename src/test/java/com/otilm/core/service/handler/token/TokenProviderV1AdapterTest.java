package com.otilm.core.service.handler.token;

import com.otilm.api.clients.ApiClientConnectorInfo;
import com.otilm.api.interfaces.client.v1.AttributeSyncApiClient;
import com.otilm.api.interfaces.client.v1.TokenInstanceSyncApiClient;
import com.otilm.api.model.client.cryptography.key.KeyRequestType;
import com.otilm.api.model.core.cryptography.key.KeyUsage;
import com.otilm.core.client.ConnectorApiFactory;
import com.otilm.core.model.crypto.ImmutableTokenProfileBasicModel;
import com.otilm.core.model.crypto.TokenInstanceBasicModel;
import java.util.EnumSet;
import java.util.List;
import java.util.UUID;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;

class TokenProviderV1AdapterTest {

    @Test
    void listSupportedKeyRequestTypes_returnsAllRequestTypes_withoutConnectorCall() {
        // given
        ConnectorApiFactory connectorApiFactory = mock(ConnectorApiFactory.class);
        ApiClientConnectorInfo connectorInfo = mock(ApiClientConnectorInfo.class);
        TokenInstanceSyncApiClient tokenApiClient = mock(TokenInstanceSyncApiClient.class);
        when(connectorApiFactory.getTokenInstanceApiClient(connectorInfo)).thenReturn(tokenApiClient);
        TokenProviderV1Adapter adapter = new TokenProviderV1Adapter(connectorApiFactory, connectorInfo);
        var profile = new ImmutableTokenProfileBasicModel(UUID.randomUUID(), "profile", null, "token",
                UUID.randomUUID(), true, List.of());

        // when
        List<KeyRequestType> types = adapter.listSupportedKeyRequestTypes(profile);

        // then
        assertEquals(EnumSet.allOf(KeyRequestType.class), EnumSet.copyOf(types));
        verifyNoInteractions(tokenApiClient);
    }

    @Test
    void listSupportedKeyUsages_returnsAllKeyUsages_withoutConnectorCall() {
        // given
        ConnectorApiFactory connectorApiFactory = mock(ConnectorApiFactory.class);
        ApiClientConnectorInfo connectorInfo = mock(ApiClientConnectorInfo.class);
        TokenInstanceSyncApiClient tokenApiClient = mock(TokenInstanceSyncApiClient.class);
        AttributeSyncApiClient attributeApiClient = mock(AttributeSyncApiClient.class);
        TokenInstanceBasicModel token = mock(TokenInstanceBasicModel.class);
        when(connectorApiFactory.getTokenInstanceApiClient(connectorInfo)).thenReturn(tokenApiClient);
        when(connectorApiFactory.getAttributeApiClient(connectorInfo)).thenReturn(attributeApiClient);
        TokenProviderV1Adapter adapter = new TokenProviderV1Adapter(connectorApiFactory, connectorInfo);

        // when
        List<KeyUsage> usages = adapter.listSupportedKeyUsages(token);

        // then
        assertEquals(EnumSet.allOf(KeyUsage.class), EnumSet.copyOf(usages));
        verifyNoInteractions(tokenApiClient, attributeApiClient, token);
    }
}
