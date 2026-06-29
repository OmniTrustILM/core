package com.otilm.core.service.callback;

import com.otilm.api.clients.ApiClientConnectorInfo;
import com.otilm.api.exception.ConnectorProblemException;
import com.otilm.api.exception.ValidationException;
import com.otilm.api.interfaces.client.v2.AttributesSyncApiClient;
import com.otilm.api.model.client.connector.v2.attribute.AttributeCallbackRequestDto;
import com.otilm.api.model.client.connector.v2.attribute.AttributeCallbackResponseDto;
import com.otilm.api.model.common.attribute.common.BaseAttribute;
import com.otilm.api.model.common.error.ErrorCode;
import com.otilm.api.model.common.error.ProblemDetailExtended;
import com.otilm.api.model.common.attribute.common.callback.RequestAttributeCallback;
import com.otilm.api.model.common.attribute.common.content.AttributeContentType;
import com.otilm.api.model.common.attribute.v2.DataAttributeV2;
import com.otilm.api.model.common.attribute.v3.content.StringAttributeContentV3;
import com.otilm.core.attribute.engine.AttributeEngine;
import com.otilm.core.attribute.engine.OutboundSecretContainment;
import com.otilm.core.attribute.engine.OutboundSecretLeakException;
import com.otilm.core.client.ConnectorApiFactory;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.Mockito;
import org.springframework.transaction.PlatformTransactionManager;
import org.springframework.transaction.TransactionStatus;

import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.UUID;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.ArgumentMatchers.any;

/**
 * #1621/#1622 fixes: the dispatcher must invoke the #1624 outbound leak gate with the secrets expanded on this
 * call (F2), and must never forward a raw runtime message from a failed child-definition ingest (F3).
 */
class NgCallbackDispatcherTest {

    private ConnectorApiFactory connectorApiFactory;
    private AttributesSyncApiClient client;
    private AttributeEngine attributeEngine;
    private AttributeDefinitionResolver definitionResolver;
    private PlatformTransactionManager txManager;
    private NgCallbackDispatcher dispatcher;
    private ApiClientConnectorInfo connector;

    @BeforeEach
    void setUp() {
        connectorApiFactory = Mockito.mock(ConnectorApiFactory.class);
        client = Mockito.mock(AttributesSyncApiClient.class);
        attributeEngine = Mockito.mock(AttributeEngine.class);
        definitionResolver = Mockito.mock(AttributeDefinitionResolver.class);
        txManager = Mockito.mock(PlatformTransactionManager.class);

        dispatcher = new NgCallbackDispatcher(connectorApiFactory, attributeEngine, definitionResolver,
                new OutboundSecretContainment(new com.fasterxml.jackson.databind.ObjectMapper()));
        dispatcher.setTransactionManager(txManager);

        connector = Mockito.mock(ApiClientConnectorInfo.class);
        Mockito.when(connector.getUuid()).thenReturn(UUID.randomUUID().toString());
        Mockito.when(connectorApiFactory.getAttributesApiClientV2(any())).thenReturn(client);
        Mockito.when(txManager.getTransaction(any())).thenReturn(Mockito.mock(TransactionStatus.class));
    }

    private NgCallbackDispatcher.NgDispatchContext context() {
        DataAttributeV2 def = new DataAttributeV2();
        def.setUuid(UUID.randomUUID().toString());
        def.setName("ngAttr");
        def.setContentType(AttributeContentType.STRING);
        return new NgCallbackDispatcher.NgDispatchContext(def, null, "v2", List.of(), List.of());
    }

    @Test
    void rejectsResponseEchoingAServerExpandedSecret() throws Exception {
        AttributeCallbackResponseDto response = new AttributeCallbackResponseDto();
        response.setContent(List.of(new StringAttributeContentV3("super-secret-token-123")));
        Mockito.when(client.callback(any(), any())).thenReturn(response);

        Set<String> expandedSecrets = new HashSet<>(Set.of("super-secret-token-123"));

        assertThrows(OutboundSecretLeakException.class, () ->
                dispatcher.dispatchNgCallback(connector, context(), new RequestAttributeCallback(), expandedSecrets));
    }

    @Test
    void allowsResponseThatDoesNotEchoAnyExpandedSecret() throws Exception {
        AttributeCallbackResponseDto response = new AttributeCallbackResponseDto();
        response.setContent(List.of(new StringAttributeContentV3("harmless-public-value")));
        Mockito.when(client.callback(any(), any())).thenReturn(response);

        Set<String> expandedSecrets = new HashSet<>(Set.of("super-secret-token-123"));

        assertDoesNotThrow(() ->
                dispatcher.dispatchNgCallback(connector, context(), new RequestAttributeCallback(), expandedSecrets));
    }

    @Test
    void definitionNotFoundRetry_rebuildsEnvelopeFromRefreshedDefinition() throws Exception {
        ProblemDetailExtended problem = ProblemDetailExtended.fromErrorCode(
                ErrorCode.ATTRIBUTE_DEFINITION_NOT_FOUND, "unknown to connector", null, null);
        AttributeCallbackResponseDto ok = new AttributeCallbackResponseDto();
        ok.setContent(List.of());
        Mockito.when(client.callback(any(), any()))
                .thenThrow(new ConnectorProblemException(problem))
                .thenReturn(ok);

        // The refresh corrects a stale local identity: the retry must send the refreshed uuid/name, not the original.
        DataAttributeV2 refreshed = new DataAttributeV2();
        refreshed.setUuid(UUID.randomUUID().toString());
        refreshed.setName("refreshedName");
        refreshed.setContentType(AttributeContentType.STRING);
        Mockito.when(definitionResolver.resolve(any(), any(), any(), any())).thenReturn((BaseAttribute) refreshed);

        dispatcher.dispatchNgCallback(connector, context(), new RequestAttributeCallback(), new HashSet<>());

        org.mockito.ArgumentCaptor<AttributeCallbackRequestDto> captor =
                org.mockito.ArgumentCaptor.forClass(AttributeCallbackRequestDto.class);
        Mockito.verify(client, Mockito.times(2)).callback(any(), captor.capture());
        AttributeCallbackRequestDto retried = captor.getAllValues().get(1);
        org.junit.jupiter.api.Assertions.assertEquals("refreshedName", retried.getAttributeName(),
                "the retry must dispatch the refreshed definition, not resend the original envelope");
    }

    @Test
    void containmentRunsBeforeChildDefinitionIngest() throws Exception {
        // A response that echoes a server-expanded secret AND carries child definitions must be rejected by the
        // containment gate BEFORE handleResponseArms persists anything — so the registry write never happens.
        AttributeCallbackResponseDto response = new AttributeCallbackResponseDto();
        response.setContent(List.of(new StringAttributeContentV3("leaked-secret-999")));
        DataAttributeV2 child = new DataAttributeV2();
        child.setUuid(UUID.randomUUID().toString());
        child.setName("child");
        child.setContentType(AttributeContentType.STRING);
        response.setAttributes(List.of(child));
        Mockito.when(client.callback(any(), any())).thenReturn(response);

        Set<String> expandedSecrets = new HashSet<>(Set.of("leaked-secret-999"));

        assertThrows(OutboundSecretLeakException.class, () ->
                dispatcher.dispatchNgCallback(connector, context(), new RequestAttributeCallback(), expandedSecrets));
        Mockito.verify(attributeEngine, Mockito.never())
                .updateDataAttributeDefinitions(any(), any(), any());
    }

    @Test
    void nullConnectorResponseIsRejectedAsValidationNotNpe() throws Exception {
        // The MQ/proxy transport can return a null body on an empty 2xx (unlike the REST client's requireBody guard).
        // A null response must surface as a clean ValidationException, not an NPE/500 at the caller's response.getContent().
        Mockito.when(client.callback(any(), any())).thenReturn(null);

        assertThrows(ValidationException.class, () ->
                dispatcher.dispatchNgCallback(connector, context(), new RequestAttributeCallback(), new HashSet<>()));
    }

    @Test
    void connectorInterfaceWithoutInterfaceVersionIsRejectedBeforeDispatch() {
        // A scope arm that stamps connectorInterface but no interfaceVersion would emit an envelope omitting the
        // @NotBlank interfaceVersion (NON_NULL drops it). Fail fast before the connector POST rather than ship it.
        DataAttributeV2 def = new DataAttributeV2();
        def.setUuid(UUID.randomUUID().toString());
        def.setName("ngAttr");
        def.setContentType(AttributeContentType.STRING);
        NgCallbackDispatcher.NgDispatchContext bad = new NgCallbackDispatcher.NgDispatchContext(
                def, com.otilm.api.model.client.connector.v2.ConnectorInterface.CRYPTOGRAPHY, null, List.of(), List.of());

        assertThrows(ValidationException.class, () ->
                dispatcher.dispatchNgCallback(connector, bad, new RequestAttributeCallback(), new HashSet<>()));
        Mockito.verifyNoInteractions(client);
    }

    @Test
    void childIngestFailureDoesNotLeakRawRuntimeMessageToTheWire() throws Exception {
        AttributeCallbackResponseDto response = new AttributeCallbackResponseDto();
        DataAttributeV2 child = new DataAttributeV2();
        child.setUuid(UUID.randomUUID().toString());
        child.setName("child");
        child.setContentType(AttributeContentType.STRING);
        response.setAttributes(List.of(child));
        Mockito.when(client.callback(any(), any())).thenReturn(response);
        Mockito.doThrow(new org.springframework.dao.DataIntegrityViolationException(
                        "ERROR: duplicate key value violates unique constraint \"attribute_definition_uq\""))
                .when(attributeEngine).updateDataAttributeDefinitions(any(), any(), any());

        ValidationException thrown = assertThrows(ValidationException.class, () ->
                dispatcher.dispatchNgCallback(connector, context(), new RequestAttributeCallback(), new HashSet<>()));

        String message = String.valueOf(thrown.getMessage());
        assertFalse(message.contains("duplicate key"), "raw SQL fragment must not reach the wire");
        assertFalse(message.contains("constraint"), "raw SQL fragment must not reach the wire");
    }
}
