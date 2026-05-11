package com.czertainly.core.messaging.proxy;

import com.czertainly.api.clients.mq.model.ConnectorAuth;
import com.czertainly.api.clients.mq.model.ConnectorResponse;
import com.czertainly.api.clients.mq.model.CoreMessage;
import com.czertainly.api.clients.mq.model.ProxyMessage;
import com.czertainly.api.exception.*;
import com.czertainly.api.model.core.connector.AuthType;
import com.czertainly.api.model.core.connector.ConnectorDto;
import com.czertainly.api.model.core.proxy.ProxyDto;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;

import java.io.IOException;
import java.time.Duration;
import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.CompletionException;
import java.util.concurrent.TimeUnit;

import static org.assertj.core.api.Assertions.*;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.*;

/**
 * Unit tests for {@link ProxyClientImpl}.
 * Tests request sending, response handling, and error mapping.
 */
@ExtendWith(MockitoExtension.class)
class ProxyClientImplTest {

    @Mock
    private CoreMessageProducer producer;

    @Mock
    private ProxyMessageCorrelator correlator;

    @Mock
    private ConnectorAuthConverter authConverter;

    private ObjectMapper objectMapper;
    private ProxyProperties proxyProperties;
    private ProxyClientImpl proxyClient;

    @BeforeEach
    void setUp() {
        objectMapper = new ObjectMapper();
        proxyProperties = new ProxyProperties(
                "test-exchange",
                "test-queue",
                "test-instance",
                Duration.ofSeconds(30),
                1000,
                null
        );

        // Default auth converter behavior
        lenient().when(authConverter.convert(any())).thenReturn(
                ConnectorAuth.builder().type("NONE").attributes(Map.of()).build()
        );

        proxyClient = new ProxyClientImpl(producer, correlator, authConverter, objectMapper, proxyProperties);
    }

    // ==================== Happy Path - Sync Tests ====================

    @Test
    @Timeout(value = 5, unit = TimeUnit.SECONDS)
    void sendRequest_withSuccessfulResponse_returnsDeserializedBody() throws Exception {
        ConnectorDto connector = createConnector("proxy-001");
        CompletableFuture<ProxyMessage> future = new CompletableFuture<>();
        when(correlator.registerRequest(anyString(), any(Duration.class))).thenReturn(future);

        // Complete the future with a successful response
        future.complete(ProxyMessage.builder()
                .correlationId("test-corr")
                .proxyId("proxy-001")
                .timestamp(Instant.now())
                .connectorResponse(ConnectorResponse.builder()
                        .statusCode(200)
                        .body(Map.of("result", "success"))
                        .build())
                .build());

        Map<String, Object> result = proxyClient.sendRequest(
                connector, "/v1/test", "GET", null, Map.class);

        assertThat(result).isNotNull();
        assertThat(result.get("result")).isEqualTo("success");
        verify(producer).send(any(), eq("proxy-001"));
    }

    @Test
    @Timeout(value = 5, unit = TimeUnit.SECONDS)
    void sendRequest_withVoidResponseType_returnsNull() throws Exception {
        ConnectorDto connector = createConnector("proxy-001");
        CompletableFuture<ProxyMessage> future = new CompletableFuture<>();
        when(correlator.registerRequest(anyString(), any(Duration.class))).thenReturn(future);

        future.complete(ProxyMessage.builder()
                .correlationId("test-corr")
                .proxyId("proxy-001")
                .timestamp(Instant.now())
                .connectorResponse(ConnectorResponse.builder()
                        .statusCode(204)
                        .build())
                .build());

        Void result = proxyClient.sendRequest(
                connector, "/v1/test", "DELETE", null, Void.class);

        assertThat(result).isNull();
    }

    @Test
    @Timeout(value = 5, unit = TimeUnit.SECONDS)
    void sendRequest_withNullBody_returnsNull() throws Exception {
        ConnectorDto connector = createConnector("proxy-001");
        CompletableFuture<ProxyMessage> future = new CompletableFuture<>();
        when(correlator.registerRequest(anyString(), any(Duration.class))).thenReturn(future);

        future.complete(ProxyMessage.builder()
                .correlationId("test-corr")
                .proxyId("proxy-001")
                .timestamp(Instant.now())
                .connectorResponse(ConnectorResponse.builder()
                        .statusCode(200)
                        .body(null)
                        .build())
                .build());

        String result = proxyClient.sendRequest(
                connector, "/v1/test", "GET", null, String.class);

        assertThat(result).isNull();
    }

    @Test
    @Timeout(value = 5, unit = TimeUnit.SECONDS)
    void sendRequest_withPathVariables_includesInRequest() throws Exception {
        ConnectorDto connector = createConnector("proxy-001");
        CompletableFuture<ProxyMessage> future = new CompletableFuture<>();
        when(correlator.registerRequest(anyString(), any(Duration.class))).thenReturn(future);

        future.complete(ProxyMessage.builder()
                .correlationId("test-corr")
                .proxyId("proxy-001")
                .timestamp(Instant.now())
                .connectorResponse(ConnectorResponse.builder()
                        .statusCode(200)
                        .body("ok")
                        .build())
                .build());

        Map<String, String> pathVars = Map.of("id", "123", "action", "activate");
        String result = proxyClient.sendRequest(
                connector, "/v1/items/{id}/{action}", "POST", pathVars, null, String.class);

        assertThat(result).isNotNull();

        ArgumentCaptor<CoreMessage> messageCaptor = ArgumentCaptor.forClass(CoreMessage.class);
        verify(producer).send(messageCaptor.capture(), eq("proxy-001"));

        CoreMessage message = messageCaptor.getValue();
        assertThat(message.getConnectorRequest().getPath()).isEqualTo("/v1/items/123/activate");
    }

    @Test
    void sendRequest_usesDefaultTimeout_whenNotSpecified() throws Exception {
        ConnectorDto connector = createConnector("proxy-001");
        CompletableFuture<ProxyMessage> future = new CompletableFuture<>();
        when(correlator.registerRequest(anyString(), eq(Duration.ofSeconds(30)))).thenReturn(future);

        future.complete(ProxyMessage.builder()
                .correlationId("test-corr")
                .proxyId("proxy-001")
                .timestamp(Instant.now())
                .connectorResponse(ConnectorResponse.builder()
                        .statusCode(200)
                        .body("ok")
                        .build())
                .build());

        proxyClient.sendRequest(connector, "/v1/test", "GET", null, String.class);

        verify(correlator).registerRequest(anyString(), eq(Duration.ofSeconds(30)));
    }

    // ==================== Happy Path - Async Tests ====================

    @Test
    void sendRequestAsync_registersCorrelationBeforeSend() {
        ConnectorDto connector = createConnector("proxy-001");
        CompletableFuture<ProxyMessage> future = new CompletableFuture<>();
        when(correlator.registerRequest(anyString(), any(Duration.class))).thenReturn(future);

        proxyClient.sendRequestAsync(connector, "/v1/test", "GET", null, String.class);

        // Verify registration happens BEFORE send
        var inOrder = inOrder(correlator, producer);
        inOrder.verify(correlator).registerRequest(anyString(), any(Duration.class));
        inOrder.verify(producer).send(any(), eq("proxy-001"));
    }

    @Test
    void sendRequestAsync_buildsCorrectCoreMessage() {
        ConnectorDto connector = createConnector("proxy-001");
        connector.setUrl("http://connector.example.com");
        CompletableFuture<ProxyMessage> future = new CompletableFuture<>();
        when(correlator.registerRequest(anyString(), any(Duration.class))).thenReturn(future);

        proxyClient.sendRequestAsync(connector, "/v1/certificates", "POST", Map.of("name", "test"), String.class);

        ArgumentCaptor<CoreMessage> messageCaptor = ArgumentCaptor.forClass(CoreMessage.class);
        verify(producer).send(messageCaptor.capture(), eq("proxy-001"));

        var message = messageCaptor.getValue();
        assertThat(message.getCorrelationId()).isNotNull();
        assertThat(message.getMessageType()).isEqualTo("POST.v1.certificates");
        assertThat(message.getConnectorRequest()).isNotNull();
        assertThat(message.getConnectorRequest().getConnectorUrl()).isEqualTo("http://connector.example.com");
        assertThat(message.getConnectorRequest().getMethod()).isEqualTo("POST");
        assertThat(message.getConnectorRequest().getPath()).isEqualTo("/v1/certificates");
    }

    // ==================== Error Handling - Proxy Errors ====================

    @Test
    @Timeout(value = 5, unit = TimeUnit.SECONDS)
    void sendRequest_withValidationError_throwsValidationException() {
        ConnectorDto connector = createConnector("proxy-001");
        CompletableFuture<ProxyMessage> future = new CompletableFuture<>();
        when(correlator.registerRequest(anyString(), any(Duration.class))).thenReturn(future);

        future.complete(ProxyMessage.builder()
                .correlationId("test-corr")
                .proxyId("proxy-001")
                .timestamp(Instant.now())
                .connectorResponse(ConnectorResponse.builder()
                        .statusCode(0)
                        .error("Invalid input data")
                        .errorCategory("validation")
                        .build())
                .build());

        assertThatThrownBy(() -> proxyClient.sendRequest(connector, "/v1/test", "POST", null, String.class))
                .isInstanceOf(ValidationException.class)
                .hasMessage("Invalid input data");
    }

    @Test
    @Timeout(value = 5, unit = TimeUnit.SECONDS)
    void sendRequest_withAuthenticationError_throwsConnectorClientException() {
        ConnectorDto connector = createConnector("proxy-001");
        CompletableFuture<ProxyMessage> future = new CompletableFuture<>();
        when(correlator.registerRequest(anyString(), any(Duration.class))).thenReturn(future);

        future.complete(ProxyMessage.builder()
                .correlationId("test-corr")
                .proxyId("proxy-001")
                .timestamp(Instant.now())
                .connectorResponse(ConnectorResponse.builder()
                        .statusCode(0)
                        .error("Invalid credentials")
                        .errorCategory("authentication")
                        .build())
                .build());

        assertThatThrownBy(() -> proxyClient.sendRequest(connector, "/v1/test", "GET", null, String.class))
                .isInstanceOf(ConnectorClientException.class);
    }

    @Test
    @Timeout(value = 5, unit = TimeUnit.SECONDS)
    void sendRequest_withAuthorizationError_throwsConnectorClientException() {
        ConnectorDto connector = createConnector("proxy-001");
        CompletableFuture<ProxyMessage> future = new CompletableFuture<>();
        when(correlator.registerRequest(anyString(), any(Duration.class))).thenReturn(future);

        future.complete(ProxyMessage.builder()
                .correlationId("test-corr")
                .proxyId("proxy-001")
                .timestamp(Instant.now())
                .connectorResponse(ConnectorResponse.builder()
                        .statusCode(0)
                        .error("Access denied")
                        .errorCategory("authorization")
                        .build())
                .build());

        assertThatThrownBy(() -> proxyClient.sendRequest(connector, "/v1/test", "GET", null, String.class))
                .isInstanceOf(ConnectorClientException.class);
    }

    @Test
    @Timeout(value = 5, unit = TimeUnit.SECONDS)
    void sendRequest_withNotFoundError_throwsConnectorEntityNotFoundException() {
        ConnectorDto connector = createConnector("proxy-001");
        CompletableFuture<ProxyMessage> future = new CompletableFuture<>();
        when(correlator.registerRequest(anyString(), any(Duration.class))).thenReturn(future);

        future.complete(ProxyMessage.builder()
                .correlationId("test-corr")
                .proxyId("proxy-001")
                .timestamp(Instant.now())
                .connectorResponse(ConnectorResponse.builder()
                        .statusCode(0)
                        .error("Resource not found")
                        .errorCategory("not_found")
                        .build())
                .build());

        assertThatThrownBy(() -> proxyClient.sendRequest(connector, "/v1/test", "GET", null, String.class))
                .isInstanceOf(ConnectorEntityNotFoundException.class);
    }

    @Test
    @Timeout(value = 5, unit = TimeUnit.SECONDS)
    void sendRequest_withTimeoutError_throwsConnectorCommunicationException() {
        ConnectorDto connector = createConnector("proxy-001");
        CompletableFuture<ProxyMessage> future = new CompletableFuture<>();
        when(correlator.registerRequest(anyString(), any(Duration.class))).thenReturn(future);

        future.complete(ProxyMessage.builder()
                .correlationId("test-corr")
                .proxyId("proxy-001")
                .timestamp(Instant.now())
                .connectorResponse(ConnectorResponse.builder()
                        .statusCode(0)
                        .error("Request timed out")
                        .errorCategory("timeout")
                        .build())
                .build());

        assertThatThrownBy(() -> proxyClient.sendRequest(connector, "/v1/test", "GET", null, String.class))
                .isInstanceOf(ConnectorCommunicationException.class);
    }

    @Test
    @Timeout(value = 5, unit = TimeUnit.SECONDS)
    void sendRequest_withConnectionError_throwsConnectorCommunicationException() {
        ConnectorDto connector = createConnector("proxy-001");
        CompletableFuture<ProxyMessage> future = new CompletableFuture<>();
        when(correlator.registerRequest(anyString(), any(Duration.class))).thenReturn(future);

        future.complete(ProxyMessage.builder()
                .correlationId("test-corr")
                .proxyId("proxy-001")
                .timestamp(Instant.now())
                .connectorResponse(ConnectorResponse.builder()
                        .statusCode(0)
                        .error("Connection refused")
                        .errorCategory("connection")
                        .build())
                .build());

        assertThatThrownBy(() -> proxyClient.sendRequest(connector, "/v1/test", "GET", null, String.class))
                .isInstanceOf(ConnectorCommunicationException.class);
    }

    @Test
    @Timeout(value = 5, unit = TimeUnit.SECONDS)
    void sendRequest_withServerError_throwsConnectorServerException() {
        ConnectorDto connector = createConnector("proxy-001");
        CompletableFuture<ProxyMessage> future = new CompletableFuture<>();
        when(correlator.registerRequest(anyString(), any(Duration.class))).thenReturn(future);

        future.complete(ProxyMessage.builder()
                .correlationId("test-corr")
                .proxyId("proxy-001")
                .timestamp(Instant.now())
                .connectorResponse(ConnectorResponse.builder()
                        .statusCode(500)
                        .error("Internal server error")
                        .errorCategory("server_error")
                        .build())
                .build());

        assertThatThrownBy(() -> proxyClient.sendRequest(connector, "/v1/test", "GET", null, String.class))
                .isInstanceOf(ConnectorServerException.class);
    }

    @Test
    @Timeout(value = 5, unit = TimeUnit.SECONDS)
    void sendRequest_withUnknownErrorCategory_throwsConnectorException() {
        ConnectorDto connector = createConnector("proxy-001");
        CompletableFuture<ProxyMessage> future = new CompletableFuture<>();
        when(correlator.registerRequest(anyString(), any(Duration.class))).thenReturn(future);

        future.complete(ProxyMessage.builder()
                .correlationId("test-corr")
                .proxyId("proxy-001")
                .timestamp(Instant.now())
                .connectorResponse(ConnectorResponse.builder()
                        .statusCode(0)
                        .error("Unknown error occurred")
                        .errorCategory("unknown_category")
                        .build())
                .build());

        assertThatThrownBy(() -> proxyClient.sendRequest(connector, "/v1/test", "GET", null, String.class))
                .isInstanceOf(ConnectorException.class);
    }

    @Test
    @Timeout(value = 5, unit = TimeUnit.SECONDS)
    void sendRequest_withNullErrorCategory_throwsConnectorException() {
        ConnectorDto connector = createConnector("proxy-001");
        CompletableFuture<ProxyMessage> future = new CompletableFuture<>();
        when(correlator.registerRequest(anyString(), any(Duration.class))).thenReturn(future);

        future.complete(ProxyMessage.builder()
                .correlationId("test-corr")
                .proxyId("proxy-001")
                .timestamp(Instant.now())
                .connectorResponse(ConnectorResponse.builder()
                        .statusCode(0)
                        .error("Some error")
                        .errorCategory(null)
                        .build())
                .build());

        assertThatThrownBy(() -> proxyClient.sendRequest(connector, "/v1/test", "GET", null, String.class))
                .isInstanceOf(ConnectorException.class);
    }

    // ==================== Error Handling - HTTP Errors ====================

    @Test
    @Timeout(value = 5, unit = TimeUnit.SECONDS)
    void sendRequest_withHttp404_throwsConnectorEntityNotFoundException() {
        ConnectorDto connector = createConnector("proxy-001");
        CompletableFuture<ProxyMessage> future = new CompletableFuture<>();
        when(correlator.registerRequest(anyString(), any(Duration.class))).thenReturn(future);

        future.complete(ProxyMessage.builder()
                .correlationId("test-corr")
                .proxyId("proxy-001")
                .timestamp(Instant.now())
                .connectorResponse(ConnectorResponse.builder()
                        .statusCode(404)
                        .build())
                .build());

        assertThatThrownBy(() -> proxyClient.sendRequest(connector, "/v1/test", "GET", null, String.class))
                .isInstanceOf(ConnectorEntityNotFoundException.class);
    }

    @Test
    @Timeout(value = 5, unit = TimeUnit.SECONDS)
    void sendRequest_withHttp422_throwsValidationException() {
        ConnectorDto connector = createConnector("proxy-001");
        CompletableFuture<ProxyMessage> future = new CompletableFuture<>();
        when(correlator.registerRequest(anyString(), any(Duration.class))).thenReturn(future);

        future.complete(ProxyMessage.builder()
                .correlationId("test-corr")
                .proxyId("proxy-001")
                .timestamp(Instant.now())
                .connectorResponse(ConnectorResponse.builder()
                        .statusCode(422)
                        .build())
                .build());

        assertThatThrownBy(() -> proxyClient.sendRequest(connector, "/v1/test", "POST", null, String.class))
                .isInstanceOf(ValidationException.class);
    }

    @Test
    @Timeout(value = 5, unit = TimeUnit.SECONDS)
    void sendRequest_withHttp4xx_throwsConnectorClientException() {
        ConnectorDto connector = createConnector("proxy-001");
        CompletableFuture<ProxyMessage> future = new CompletableFuture<>();
        when(correlator.registerRequest(anyString(), any(Duration.class))).thenReturn(future);

        future.complete(ProxyMessage.builder()
                .correlationId("test-corr")
                .proxyId("proxy-001")
                .timestamp(Instant.now())
                .connectorResponse(ConnectorResponse.builder()
                        .statusCode(400)
                        .build())
                .build());

        assertThatThrownBy(() -> proxyClient.sendRequest(connector, "/v1/test", "POST", null, String.class))
                .isInstanceOf(ConnectorClientException.class);
    }

    @Test
    @Timeout(value = 5, unit = TimeUnit.SECONDS)
    void sendRequest_withHttp5xx_throwsConnectorServerException() {
        ConnectorDto connector = createConnector("proxy-001");
        CompletableFuture<ProxyMessage> future = new CompletableFuture<>();
        when(correlator.registerRequest(anyString(), any(Duration.class))).thenReturn(future);

        future.complete(ProxyMessage.builder()
                .correlationId("test-corr")
                .proxyId("proxy-001")
                .timestamp(Instant.now())
                .connectorResponse(ConnectorResponse.builder()
                        .statusCode(503)
                        .build())
                .build());

        assertThatThrownBy(() -> proxyClient.sendRequest(connector, "/v1/test", "GET", null, String.class))
                .isInstanceOf(ConnectorServerException.class);
    }

    @Test
    @Timeout(value = 5, unit = TimeUnit.SECONDS)
    void sendRequest_withBlankErrorMessage_usesHttpStatusReasonPhrase() {
        ConnectorDto connector = createConnector("proxy-001");
        CompletableFuture<ProxyMessage> future = new CompletableFuture<>();
        when(correlator.registerRequest(anyString(), any(Duration.class))).thenReturn(future);

        future.complete(ProxyMessage.builder()
                .correlationId("test-corr")
                .proxyId("proxy-001")
                .timestamp(Instant.now())
                .connectorResponse(ConnectorResponse.builder()
                        .statusCode(500)
                        .error("")
                        .build())
                .build());

        assertThatThrownBy(() -> proxyClient.sendRequest(connector, "/v1/test", "GET", null, String.class))
                .isInstanceOf(ConnectorServerException.class)
                .hasMessageContaining("500");
    }

    // ==================== Exception Propagation ====================

    @Test
    void sendRequest_withNullProxy_throwsIllegalArgumentException() {
        ConnectorDto connector = new ConnectorDto();
        connector.setProxy(null);

        assertThatThrownBy(() -> proxyClient.sendRequest(connector, "/v1/test", "GET", null, String.class))
                .isInstanceOf(IllegalArgumentException.class);
    }

    @Test
    void sendRequest_withEmptyProxyCode_throwsIllegalArgumentException() {
        ConnectorDto connector = new ConnectorDto();
        ProxyDto proxy = new ProxyDto();
        proxy.setCode("");
        connector.setProxy(proxy);

        assertThatThrownBy(() -> proxyClient.sendRequest(connector, "/v1/test", "GET", null, String.class))
                .isInstanceOf(IllegalArgumentException.class);
    }

    @Test
    void sendRequest_withWhitespaceProxyCode_throwsIllegalArgumentException() {
        ConnectorDto connector = new ConnectorDto();
        ProxyDto proxy = new ProxyDto();
        proxy.setCode("   ");
        connector.setProxy(proxy);

        assertThatThrownBy(() -> proxyClient.sendRequest(connector, "/v1/test", "GET", null, String.class))
                .isInstanceOf(IllegalArgumentException.class);
    }

    @Test
    @Timeout(value = 5, unit = TimeUnit.SECONDS)
    void sendRequest_onInterruption_throwsConnectorCommunicationExceptionAndSetsInterruptFlag() {
        ConnectorDto connector = createConnector("proxy-001");
        CompletableFuture<ProxyMessage> future = new CompletableFuture<>();
        when(correlator.registerRequest(anyString(), any(Duration.class))).thenReturn(future);

        // Interrupt the current thread before making the call
        Thread.currentThread().interrupt();

        assertThatThrownBy(() -> proxyClient.sendRequest(connector, "/v1/test", "GET", null, String.class))
                .isInstanceOf(ConnectorCommunicationException.class);

        // Verify interrupt flag is restored
        assertThat(Thread.currentThread().isInterrupted()).isTrue();

        // Clear interrupt flag for other tests
        Thread.interrupted();
    }

    // ==================== Custom Timeout ====================

    @Test
    void sendRequest_withCustomTimeout_usesProvidedTimeout() throws Exception {
        ConnectorDto connector = createConnector("proxy-001");
        Duration customTimeout = Duration.ofMinutes(2);
        CompletableFuture<ProxyMessage> future = new CompletableFuture<>();
        when(correlator.registerRequest(anyString(), eq(customTimeout))).thenReturn(future);

        future.complete(ProxyMessage.builder()
                .correlationId("test-corr")
                .proxyId("proxy-001")
                .timestamp(Instant.now())
                .connectorResponse(ConnectorResponse.builder()
                        .statusCode(200)
                        .body("ok")
                        .build())
                .build());

        proxyClient.sendRequest(connector, "/v1/test", "GET", null, String.class, customTimeout);

        verify(correlator).registerRequest(anyString(), eq(customTimeout));
    }

    // ==================== Fire-and-Forget Tests ====================

    @Test
    void sendFireAndForget_sendsMessageWithoutCorrelation() {
        ConnectorDto connector = createConnector("proxy-001");
        connector.setUrl("http://connector.example.com");

        proxyClient.sendFireAndForget(connector, "/v1/notifications", "POST", Map.of("event", "test"));

        // Verify message was sent
        ArgumentCaptor<CoreMessage> messageCaptor = ArgumentCaptor.forClass(CoreMessage.class);
        verify(producer).send(messageCaptor.capture(), eq("proxy-001"));

        var message = messageCaptor.getValue();
        // Fire-and-forget should not have correlationId
        assertThat(message.getCorrelationId()).isNull();
        assertThat(message.getMessageType()).isEqualTo("POST.v1.notifications");
        assertThat(message.getConnectorRequest()).isNotNull();
        assertThat(message.getConnectorRequest().getMethod()).isEqualTo("POST");
        assertThat(message.getConnectorRequest().getPath()).isEqualTo("/v1/notifications");

        // Verify correlator was NOT called
        verifyNoInteractions(correlator);
    }

    @Test
    void sendFireAndForget_withCustomMessageType_usesProvidedType() {
        ConnectorDto connector = createConnector("proxy-001");

        proxyClient.sendFireAndForget(connector, "/v1/trigger", "POST", null, "discovery.trigger");

        ArgumentCaptor<CoreMessage> messageCaptor = ArgumentCaptor.forClass(CoreMessage.class);
        verify(producer).send(messageCaptor.capture(), eq("proxy-001"));

        var message = messageCaptor.getValue();
        assertThat(message.getMessageType()).isEqualTo("discovery.trigger");
        assertThat(message.getCorrelationId()).isNull();
    }

    @Test
    void sendFireAndForget_withNullMessageType_derivesFromMethodAndPath() {
        ConnectorDto connector = createConnector("proxy-001");

        proxyClient.sendFireAndForget(connector, "/v1/events/audit", "GET", null, null);

        ArgumentCaptor<CoreMessage> messageCaptor = ArgumentCaptor.forClass(CoreMessage.class);
        verify(producer).send(messageCaptor.capture(), eq("proxy-001"));

        var message = messageCaptor.getValue();
        assertThat(message.getMessageType()).isEqualTo("GET.v1.events.audit");
    }

    @Test
    void sendFireAndForget_withBlankMessageType_derivesFromMethodAndPath() {
        ConnectorDto connector = createConnector("proxy-001");

        proxyClient.sendFireAndForget(connector, "/v1/events", "POST", null, "   ");

        ArgumentCaptor<CoreMessage> messageCaptor = ArgumentCaptor.forClass(CoreMessage.class);
        verify(producer).send(messageCaptor.capture(), eq("proxy-001"));

        var message = messageCaptor.getValue();
        assertThat(message.getMessageType()).isEqualTo("POST.v1.events");
    }

    @Test
    void sendFireAndForget_withNullProxy_throwsIllegalArgumentException() {
        ConnectorDto connector = new ConnectorDto();
        connector.setProxy(null);

        assertThatThrownBy(() -> proxyClient.sendFireAndForget(connector, "/v1/test", "POST", null))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("proxy");
    }

    @Test
    void sendFireAndForget_withEmptyProxyCode_throwsIllegalArgumentException() {
        ConnectorDto connector = new ConnectorDto();
        ProxyDto proxy = new ProxyDto();
        proxy.setCode("");
        connector.setProxy(proxy);

        assertThatThrownBy(() -> proxyClient.sendFireAndForget(connector, "/v1/test", "POST", null))
                .isInstanceOf(IllegalArgumentException.class);
    }

    @Test
    void sendFireAndForget_withNullBody_sendsMessageSuccessfully() {
        ConnectorDto connector = createConnector("proxy-001");

        proxyClient.sendFireAndForget(connector, "/v1/ping", "GET", null);

        ArgumentCaptor<CoreMessage> messageCaptor = ArgumentCaptor.forClass(CoreMessage.class);
        verify(producer).send(messageCaptor.capture(), eq("proxy-001"));

        var message = messageCaptor.getValue();
        assertThat(message.getConnectorRequest().getBody()).isNull();
    }

    @Test
    void sendFireAndForget_includesConnectorAuth() {
        ConnectorDto connector = createConnector("proxy-001");
        connector.setAuthType(AuthType.BASIC);

        ConnectorAuth expectedAuth = ConnectorAuth.builder()
                .type("BASIC")
                .attributes(Map.of("username", "admin"))
                .build();
        when(authConverter.convert(connector)).thenReturn(expectedAuth);

        proxyClient.sendFireAndForget(connector, "/v1/test", "POST", null);

        ArgumentCaptor<CoreMessage> messageCaptor = ArgumentCaptor.forClass(CoreMessage.class);
        verify(producer).send(messageCaptor.capture(), eq("proxy-001"));

        var message = messageCaptor.getValue();
        assertThat(message.getConnectorRequest().getConnectorAuth()).isEqualTo(expectedAuth);
    }

    @Test
    void sendFireAndForget_setsTimestamp() {
        ConnectorDto connector = createConnector("proxy-001");

        Instant before = Instant.now();
        proxyClient.sendFireAndForget(connector, "/v1/test", "POST", null);
        Instant after = Instant.now();

        ArgumentCaptor<CoreMessage> messageCaptor = ArgumentCaptor.forClass(CoreMessage.class);
        verify(producer).send(messageCaptor.capture(), eq("proxy-001"));

        var message = messageCaptor.getValue();
        assertThat(message.getTimestamp()).isAfterOrEqualTo(before);
        assertThat(message.getTimestamp()).isBeforeOrEqualTo(after);
    }

    // ==================== Message Type Derivation Edge Cases ====================

    @Test
    void sendFireAndForget_withNullPath_messageTypeIsBareHttpMethod() {
        ConnectorDto connector = createConnector("proxy-001");

        proxyClient.sendFireAndForget(connector, null, "GET", null);

        ArgumentCaptor<CoreMessage> captor = ArgumentCaptor.forClass(CoreMessage.class);
        verify(producer).send(captor.capture(), eq("proxy-001"));
        assertThat(captor.getValue().getMessageType()).isEqualTo("GET");
    }

    @Test
    void sendFireAndForget_withEmptyPath_messageTypeIsBareHttpMethod() {
        ConnectorDto connector = createConnector("proxy-001");

        proxyClient.sendFireAndForget(connector, "", "POST", null);

        ArgumentCaptor<CoreMessage> captor = ArgumentCaptor.forClass(CoreMessage.class);
        verify(producer).send(captor.capture(), eq("proxy-001"));
        assertThat(captor.getValue().getMessageType()).isEqualTo("POST");
    }

    @Test
    void sendFireAndForget_withSlashOnlyPath_messageTypeIsBareHttpMethod() {
        // Edge case the toMessageType Javadoc doesn't spell out: "/" stripped of its leading
        // slash leaves an empty string, so the second null/empty guard returns the bare method.
        ConnectorDto connector = createConnector("proxy-001");

        proxyClient.sendFireAndForget(connector, "/", "DELETE", null);

        ArgumentCaptor<CoreMessage> captor = ArgumentCaptor.forClass(CoreMessage.class);
        verify(producer).send(captor.capture(), eq("proxy-001"));
        assertThat(captor.getValue().getMessageType()).isEqualTo("DELETE");
    }

    // ==================== Missing Connector Response ====================

    @Test
    @Timeout(value = 5, unit = TimeUnit.SECONDS)
    void sendRequest_withHealthCheckMessageAndNullResponse_returnsNull() throws Exception {
        ConnectorDto connector = createConnector("proxy-001");
        CompletableFuture<ProxyMessage> future = new CompletableFuture<>();
        when(correlator.registerRequest(anyString(), any(Duration.class))).thenReturn(future);

        // Health-check messages legitimately arrive with no connectorResponse.
        future.complete(ProxyMessage.builder()
                .correlationId("test-corr")
                .proxyId("proxy-001")
                .messageType("health.check")
                .timestamp(Instant.now())
                .connectorResponse(null)
                .build());

        String result = proxyClient.sendRequest(connector, "/v1/health", "GET", null, String.class);

        assertThat(result).isNull();
    }

    @Test
    @Timeout(value = 5, unit = TimeUnit.SECONDS)
    void sendRequest_withNullResponseAndNotHealthCheck_throwsConnectorCommunicationException() {
        ConnectorDto connector = createConnector("proxy-001");
        CompletableFuture<ProxyMessage> future = new CompletableFuture<>();
        when(correlator.registerRequest(anyString(), any(Duration.class))).thenReturn(future);

        // Non-health-check message with no connectorResponse is a protocol violation.
        future.complete(ProxyMessage.builder()
                .correlationId("test-corr")
                .proxyId("proxy-001")
                .messageType("GET.v1.test")
                .timestamp(Instant.now())
                .connectorResponse(null)
                .build());

        assertThatThrownBy(() -> proxyClient.sendRequest(connector, "/v1/test", "GET", null, String.class))
                .isInstanceOf(ConnectorCommunicationException.class)
                .hasMessageContaining("without connector response");
    }

    @Test
    @Timeout(value = 5, unit = TimeUnit.SECONDS)
    void sendRequest_whenBodyCannotBeDeserializedToResponseType_throwsConnectorCommunicationException() {
        ConnectorDto connector = createConnector("proxy-001");
        CompletableFuture<ProxyMessage> future = new CompletableFuture<>();
        when(correlator.registerRequest(anyString(), any(Duration.class))).thenReturn(future);

        // Body is a Map; caller asks for Integer → ObjectMapper.convertValue throws,
        // which the impl re-wraps as ConnectorCommunicationException via sneakyThrow.
        future.complete(ProxyMessage.builder()
                .correlationId("test-corr")
                .proxyId("proxy-001")
                .timestamp(Instant.now())
                .connectorResponse(ConnectorResponse.builder()
                        .statusCode(200)
                        .body(Map.of("nested", "object"))
                        .build())
                .build());

        assertThatThrownBy(() -> proxyClient.sendRequest(connector, "/v1/test", "GET", null, Integer.class))
                .isInstanceOf(ConnectorCommunicationException.class)
                .hasMessageContaining("Failed to deserialize");
    }

    // ==================== sendRequestForEntity (status-preserving) ====================

    @Test
    @Timeout(value = 5, unit = TimeUnit.SECONDS)
    void sendRequestForEntity_with200_returnsOkWithBody() throws Exception {
        ConnectorDto connector = createConnector("proxy-001");
        CompletableFuture<ProxyMessage> future = new CompletableFuture<>();
        when(correlator.registerRequest(anyString(), any(Duration.class))).thenReturn(future);

        future.complete(ProxyMessage.builder()
                .correlationId("test-corr")
                .proxyId("proxy-001")
                .timestamp(Instant.now())
                .connectorResponse(ConnectorResponse.builder()
                        .statusCode(200)
                        .body(Map.of("certificateData", "BASE64="))
                        .build())
                .build());

        ResponseEntity<Map> result = proxyClient.sendRequestForEntity(
                connector, "/v1/test", "POST", null, Map.class);

        assertThat(result.getStatusCode()).isEqualTo(HttpStatus.OK);
        assertThat(result.getBody()).containsEntry("certificateData", "BASE64=");
    }

    @Test
    @Timeout(value = 5, unit = TimeUnit.SECONDS)
    void sendRequestForEntity_with202_preservesAcceptedStatus() throws Exception {
        // The whole reason for sendRequestForEntity: a 202 from the upstream connector
        // must NOT be collapsed to 200. Core uses the status to decide PENDING_ISSUE/PENDING_REVOKE.
        ConnectorDto connector = createConnector("proxy-001");
        CompletableFuture<ProxyMessage> future = new CompletableFuture<>();
        when(correlator.registerRequest(anyString(), any(Duration.class))).thenReturn(future);

        future.complete(ProxyMessage.builder()
                .correlationId("test-corr")
                .proxyId("proxy-001")
                .timestamp(Instant.now())
                .connectorResponse(ConnectorResponse.builder()
                        .statusCode(202)
                        .body(Map.of("meta", List.of()))
                        .build())
                .build());

        ResponseEntity<Map> result = proxyClient.sendRequestForEntity(
                connector, "/v1/test", "POST", null, Map.class);

        assertThat(result.getStatusCode()).isEqualTo(HttpStatus.ACCEPTED);
        assertThat(result.getBody()).isNotNull();
    }

    @Test
    @Timeout(value = 5, unit = TimeUnit.SECONDS)
    void sendRequestForEntity_with204_returnsNoContentWithNullBody() throws Exception {
        ConnectorDto connector = createConnector("proxy-001");
        CompletableFuture<ProxyMessage> future = new CompletableFuture<>();
        when(correlator.registerRequest(anyString(), any(Duration.class))).thenReturn(future);

        future.complete(ProxyMessage.builder()
                .correlationId("test-corr")
                .proxyId("proxy-001")
                .timestamp(Instant.now())
                .connectorResponse(ConnectorResponse.builder()
                        .statusCode(204)
                        .body(null)
                        .build())
                .build());

        ResponseEntity<Map> result = proxyClient.sendRequestForEntity(
                connector, "/v1/test", "POST", null, Map.class);

        assertThat(result.getStatusCode()).isEqualTo(HttpStatus.NO_CONTENT);
        assertThat(result.getBody()).isNull();
    }

    @Test
    @Timeout(value = 5, unit = TimeUnit.SECONDS)
    void sendRequestForEntity_with422_throwsValidationException() {
        // 4xx upstream errors must still throw (consistent with sendRequest); never returned as ResponseEntity.
        ConnectorDto connector = createConnector("proxy-001");
        CompletableFuture<ProxyMessage> future = new CompletableFuture<>();
        when(correlator.registerRequest(anyString(), any(Duration.class))).thenReturn(future);

        future.complete(ProxyMessage.builder()
                .correlationId("test-corr")
                .proxyId("proxy-001")
                .timestamp(Instant.now())
                .connectorResponse(ConnectorResponse.builder()
                        .statusCode(0)
                        .error("Validation failed")
                        .errorCategory("validation")
                        .build())
                .build());

        assertThatThrownBy(() -> proxyClient.sendRequestForEntity(connector, "/v1/test", "POST", null, Map.class))
                .isInstanceOf(ValidationException.class);
    }

    @Test
    @Timeout(value = 5, unit = TimeUnit.SECONDS)
    void sendRequestForEntity_withConnectionError_throwsConnectorCommunicationException() {
        ConnectorDto connector = createConnector("proxy-001");
        CompletableFuture<ProxyMessage> future = new CompletableFuture<>();
        when(correlator.registerRequest(anyString(), any(Duration.class))).thenReturn(future);

        future.complete(ProxyMessage.builder()
                .correlationId("test-corr")
                .proxyId("proxy-001")
                .timestamp(Instant.now())
                .connectorResponse(ConnectorResponse.builder()
                        .statusCode(0)
                        .error("Connection refused")
                        .errorCategory("connection")
                        .build())
                .build());

        assertThatThrownBy(() -> proxyClient.sendRequestForEntity(connector, "/v1/test", "POST", null, Map.class))
                .isInstanceOf(ConnectorCommunicationException.class);
    }

    @Test
    @Timeout(value = 5, unit = TimeUnit.SECONDS)
    void sendRequestForEntity_withServerError_throwsConnectorServerException() {
        ConnectorDto connector = createConnector("proxy-001");
        CompletableFuture<ProxyMessage> future = new CompletableFuture<>();
        when(correlator.registerRequest(anyString(), any(Duration.class))).thenReturn(future);

        future.complete(ProxyMessage.builder()
                .correlationId("test-corr")
                .proxyId("proxy-001")
                .timestamp(Instant.now())
                .connectorResponse(ConnectorResponse.builder()
                        .statusCode(503)
                        .error("Service unavailable")
                        .errorCategory("server_error")
                        .build())
                .build());

        assertThatThrownBy(() -> proxyClient.sendRequestForEntity(connector, "/v1/test", "POST", null, Map.class))
                .isInstanceOf(ConnectorServerException.class);
    }

    @Test
    @Timeout(value = 5, unit = TimeUnit.SECONDS)
    void sendRequestForEntity_withMissingConnectorResponse_throwsConnectorCommunicationException() {
        // Defensive: ProxyMessage with no connector response and not a health check —
        // surfaced as a comms exception with a clear message.
        ConnectorDto connector = createConnector("proxy-001");
        CompletableFuture<ProxyMessage> future = new CompletableFuture<>();
        when(correlator.registerRequest(anyString(), any(Duration.class))).thenReturn(future);

        future.complete(ProxyMessage.builder()
                .correlationId("test-corr")
                .proxyId("proxy-001")
                .timestamp(Instant.now())
                .connectorResponse(null)
                .build());

        assertThatThrownBy(() -> proxyClient.sendRequestForEntity(connector, "/v1/test", "POST", null, Map.class))
                .isInstanceOf(ConnectorCommunicationException.class)
                .hasMessageContaining("without connector response");
    }

    @Test
    @Timeout(value = 5, unit = TimeUnit.SECONDS)
    void sendRequestForEntity_with401_throwsConnectorClientException() {
        ConnectorDto connector = createConnector("proxy-001");
        CompletableFuture<ProxyMessage> future = new CompletableFuture<>();
        when(correlator.registerRequest(anyString(), any(Duration.class))).thenReturn(future);

        future.complete(ProxyMessage.builder()
                .correlationId("test-corr")
                .proxyId("proxy-001")
                .timestamp(Instant.now())
                .connectorResponse(ConnectorResponse.builder()
                        .statusCode(0)
                        .error("Bad credentials")
                        .errorCategory("authentication")
                        .build())
                .build());

        assertThatThrownBy(() -> proxyClient.sendRequestForEntity(connector, "/v1/test", "POST", null, Map.class))
                .isInstanceOf(ConnectorClientException.class);
    }

    @Test
    @Timeout(value = 5, unit = TimeUnit.SECONDS)
    void sendRequestForEntity_with404_throwsConnectorEntityNotFoundException() {
        ConnectorDto connector = createConnector("proxy-001");
        CompletableFuture<ProxyMessage> future = new CompletableFuture<>();
        when(correlator.registerRequest(anyString(), any(Duration.class))).thenReturn(future);

        future.complete(ProxyMessage.builder()
                .correlationId("test-corr")
                .proxyId("proxy-001")
                .timestamp(Instant.now())
                .connectorResponse(ConnectorResponse.builder()
                        .statusCode(0)
                        .error("Not tracked")
                        .errorCategory("not_found")
                        .build())
                .build());

        assertThatThrownBy(() -> proxyClient.sendRequestForEntity(connector, "/v1/test", "POST", null, Map.class))
                .isInstanceOf(ConnectorEntityNotFoundException.class);
    }

    @Test
    @Timeout(value = 5, unit = TimeUnit.SECONDS)
    void sendRequestForEntity_withMissingProxyCode_throwsIllegalArgumentException() {
        // Defensive: a connector without a proxy code cannot be routed; surface the
        // misconfiguration as a clean IllegalArgumentException at the call site instead
        // of a downstream NPE.
        ConnectorDto connector = createConnector(null);

        assertThatThrownBy(() -> proxyClient.sendRequestForEntity(connector, "/v1/test", "POST", null, Map.class))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("Connector proxy code must be set");
    }

    @Test
    @Timeout(value = 5, unit = TimeUnit.SECONDS)
    void sendRequestForEntity_withBlankProxyCode_throwsIllegalArgumentException() {
        ConnectorDto connector = createConnector("   ");

        assertThatThrownBy(() -> proxyClient.sendRequestForEntity(connector, "/v1/test", "POST", null, Map.class))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("Connector proxy code must be set");
    }

    @Test
    @Timeout(value = 5, unit = TimeUnit.SECONDS)
    void sendRequestForEntity_withDeserializationFailure_throwsConnectorCommunicationException() {
        // A 200 OK with a body the ObjectMapper cannot map to the requested type must
        // not silently produce a null-bodied response; surface as ConnectorCommunicationException
        // so the caller sees the upstream contract was violated.
        ConnectorDto connector = createConnector("proxy-001");
        CompletableFuture<ProxyMessage> future = new CompletableFuture<>();
        when(correlator.registerRequest(anyString(), any(Duration.class))).thenReturn(future);

        // Body is a map, but we ask for a String — Jackson will attempt convertValue(map, String.class)
        // and fail. NotASimpleType causes IllegalArgumentException from convertValue.
        future.complete(ProxyMessage.builder()
                .correlationId("test-corr")
                .proxyId("proxy-001")
                .timestamp(Instant.now())
                .connectorResponse(ConnectorResponse.builder()
                        .statusCode(200)
                        .body(Map.of("nested", Map.of("deeper", List.of("a", "b"))))
                        .build())
                .build());

        assertThatThrownBy(() -> proxyClient.sendRequestForEntity(
                connector, "/v1/test", "POST", null, java.net.URL.class))
                .isInstanceOf(ConnectorCommunicationException.class)
                .hasMessageContaining("deserialize");
    }

    @Test
    @Timeout(value = 5, unit = TimeUnit.SECONDS)
    void sendRequestForEntity_withCheckedExceptionCause_wrapsInConnectorCommunicationException() {
        // ExecutionException whose cause is a checked exception (not a ConnectorException
        // and not a RuntimeException) must be wrapped — otherwise the caller sees an
        // opaque ExecutionException with no proxy/connector context.
        ConnectorDto connector = createConnector("proxy-001");
        CompletableFuture<ProxyMessage> future = new CompletableFuture<>();
        when(correlator.registerRequest(anyString(), any(Duration.class))).thenReturn(future);
        future.completeExceptionally(new IOException("forced io failure"));

        assertThatThrownBy(() -> proxyClient.sendRequestForEntity(connector, "/v1/test", "POST", null, Map.class))
                .isInstanceOf(ConnectorCommunicationException.class)
                .hasMessageContaining("Proxy request failed");
    }

    @Test
    @Timeout(value = 5, unit = TimeUnit.SECONDS)
    void sendRequestForEntity_withCompletionExceptionWrappedRuntime_unwrapsAndRethrows() {
        // The unwrapping branch: a CompletionException wrapping a RuntimeException must be
        // unwrapped and the inner RuntimeException re-thrown, not the outer CompletionException.
        ConnectorDto connector = createConnector("proxy-001");
        CompletableFuture<ProxyMessage> future = new CompletableFuture<>();
        when(correlator.registerRequest(anyString(), any(Duration.class))).thenReturn(future);
        IllegalStateException inner = new IllegalStateException("forced runtime failure");
        future.completeExceptionally(new CompletionException("wrapper", inner));

        assertThatThrownBy(() -> proxyClient.sendRequestForEntity(connector, "/v1/test", "POST", null, Map.class))
                .isInstanceOf(IllegalStateException.class)
                .hasMessage("forced runtime failure");
    }

    @Test
    @Timeout(value = 5, unit = TimeUnit.SECONDS)
    void sendRequestForEntity_withDirectRuntime_rethrowsWithoutWrapping() {
        ConnectorDto connector = createConnector("proxy-001");
        CompletableFuture<ProxyMessage> future = new CompletableFuture<>();
        when(correlator.registerRequest(anyString(), any(Duration.class))).thenReturn(future);
        future.completeExceptionally(new IllegalStateException("forced direct runtime"));

        assertThatThrownBy(() -> proxyClient.sendRequestForEntity(connector, "/v1/test", "POST", null, Map.class))
                .isInstanceOf(IllegalStateException.class)
                .hasMessage("forced direct runtime");
    }

    @Test
    @Timeout(value = 5, unit = TimeUnit.SECONDS)
    void sendRequestForEntity_withNon4xxNon5xxNonOk_normalizesToOk() throws Exception {
        // Defensive: an unrecognised status outside 4xx/5xx (e.g. 299) is normalised to OK
        // so downstream callers can rely on a stable contract.
        ConnectorDto connector = createConnector("proxy-001");
        CompletableFuture<ProxyMessage> future = new CompletableFuture<>();
        when(correlator.registerRequest(anyString(), any(Duration.class))).thenReturn(future);

        future.complete(ProxyMessage.builder()
                .correlationId("test-corr")
                .proxyId("proxy-001")
                .timestamp(Instant.now())
                .connectorResponse(ConnectorResponse.builder()
                        .statusCode(299) // unrecognised 2xx
                        .body(Map.of("ok", true))
                        .build())
                .build());

        ResponseEntity<Map> result = proxyClient.sendRequestForEntity(
                connector, "/v1/test", "POST", null, Map.class);

        // HttpStatus.resolve(299) is null → normalised to OK.
        assertThat(result.getStatusCode().value()).isEqualTo(200);
    }

    // ==================== Helper Methods ====================

    private ConnectorDto createConnector(String proxyCode) {
        ConnectorDto connector = new ConnectorDto();
        if (proxyCode != null) {
            ProxyDto proxy = new ProxyDto();
            proxy.setCode(proxyCode);
            connector.setProxy(proxy);
        }
        connector.setUrl("http://connector.example.com");
        connector.setAuthType(AuthType.NONE);
        return connector;
    }
}
