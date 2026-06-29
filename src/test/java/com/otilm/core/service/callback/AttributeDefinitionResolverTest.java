package com.otilm.core.service.callback;

import com.otilm.api.clients.ApiClientConnectorInfo;
import com.otilm.api.exception.AttributeException;
import com.otilm.api.exception.ValidationException;
import com.otilm.api.interfaces.client.v2.AttributesSyncApiClient;
import com.otilm.api.model.client.connector.v2.attribute.AttributeDefinitionsDto;
import com.otilm.api.model.common.attribute.common.AttributeType;
import com.otilm.api.model.common.attribute.common.content.AttributeContentType;
import com.otilm.api.model.common.attribute.v2.DataAttributeV2;
import com.otilm.core.attribute.engine.AttributeEngine;
import com.otilm.core.client.ConnectorApiFactory;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.Mockito;
import org.springframework.transaction.PlatformTransactionManager;
import org.springframework.transaction.TransactionStatus;

import java.util.List;
import java.util.UUID;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;

/**
 * #1622 — the definition-resolution ladder's miss-path (422) and its no-leak ingest translation. The success arm is
 * exercised through {@link NgCallbackDispatcherTest}; this pins the security-relevant fail arms that are otherwise
 * untested end-to-end: the 422 must name the unresolved UUID, and a raw engine/connector message must never reach it.
 */
class AttributeDefinitionResolverTest {

    private AttributeEngine attributeEngine;
    private ConnectorApiFactory connectorApiFactory;
    private AttributesSyncApiClient client;
    private PlatformTransactionManager txManager;
    private AttributeDefinitionResolver resolver;
    private ApiClientConnectorInfo connector;

    @BeforeEach
    void setUp() {
        attributeEngine = Mockito.mock(AttributeEngine.class);
        connectorApiFactory = Mockito.mock(ConnectorApiFactory.class);
        client = Mockito.mock(AttributesSyncApiClient.class);
        txManager = Mockito.mock(PlatformTransactionManager.class);

        resolver = new AttributeDefinitionResolver(attributeEngine, connectorApiFactory);
        resolver.setTransactionManager(txManager);

        connector = Mockito.mock(ApiClientConnectorInfo.class);
        Mockito.when(connector.getUuid()).thenReturn(UUID.randomUUID().toString());
        Mockito.when(connectorApiFactory.getAttributesApiClientV2(any())).thenReturn(client);
        Mockito.when(txManager.getTransaction(any())).thenReturn(Mockito.mock(TransactionStatus.class));
    }

    @Test
    void unresolvableAfterRefreshThrows422NamingTheUuid() throws Exception {
        UUID attributeUuid = UUID.randomUUID();
        // Stored read misses both before and after the registry fetch; the fetch returns nothing.
        Mockito.when(attributeEngine.getDataAttributeDefinitionStrict(any(), any(), any())).thenReturn(null);
        Mockito.when(client.listDefinitions(any(), any())).thenReturn(new AttributeDefinitionsDto());

        ValidationException ex = assertThrows(ValidationException.class,
                () -> resolver.resolve(connector, attributeUuid, "ngAttr", AttributeType.DATA));

        assertTrue(String.valueOf(ex.getMessage()).contains(attributeUuid.toString()),
                "the 422 must name the unresolved attribute UUID");
    }

    @Test
    void ingestFailureDoesNotLeakRawEngineMessageToTheWire() throws Exception {
        Mockito.when(attributeEngine.getDataAttributeDefinitionStrict(any(), any(), any())).thenReturn(null);

        DataAttributeV2 fetched = new DataAttributeV2();
        fetched.setUuid(UUID.randomUUID().toString());
        fetched.setName("ngAttr");
        fetched.setContentType(AttributeContentType.STRING);
        AttributeDefinitionsDto dto = new AttributeDefinitionsDto();
        dto.setDefinitions(List.of(fetched));
        Mockito.when(client.listDefinitions(any(), any())).thenReturn(dto);

        Mockito.doThrow(new AttributeException("raw engine detail: column attribute_definition.secret_col"))
                .when(attributeEngine).updateDataAttributeDefinitions(any(), any(), any());

        ValidationException ex = assertThrows(ValidationException.class,
                () -> resolver.resolve(connector, UUID.randomUUID(), "ngAttr", AttributeType.DATA));

        String message = String.valueOf(ex.getMessage());
        assertFalse(message.contains("secret_col"), "raw engine/SQL fragment must not reach the wire");
        assertFalse(message.contains("raw engine detail"), "raw engine message must not reach the wire");
    }
}
