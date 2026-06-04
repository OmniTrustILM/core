package com.czertainly.core.messaging.proxy;

import com.czertainly.api.clients.mq.model.ConnectorResponse;
import com.czertainly.api.clients.mq.model.CoreMessage;
import com.czertainly.api.clients.mq.model.ProxyMessage;
import com.czertainly.api.model.core.connector.AuthType;
import com.czertainly.api.model.core.connector.ConnectorDto;
import com.czertainly.api.model.core.proxy.ProxyDto;
import com.czertainly.core.util.BaseSpringBootTest;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;
import org.mockito.ArgumentCaptor;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.jms.core.JmsTemplate;
import org.springframework.test.context.bean.override.mockito.MockitoBean;

import java.time.Duration;
import java.time.Instant;
import java.util.Map;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.TimeUnit;

import static org.assertj.core.api.Assertions.*;
import static org.awaitility.Awaitility.await;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.*;

/**
 * Integration tests for {@link ProxyClientImpl}.
 * Tests end-to-end proxy request/response flow with mocked JMS.
 */
class ProxyClientIntegrationTest extends BaseSpringBootTest {

    @MockitoBean
    private JmsTemplate jmsTemplate;

    @Autowired
    private ProxyClientImpl proxyClient;

    @Autowired
    private ProxyMessageCorrelator correlator;

    @BeforeEach
    void setUpProxyTest() {
        // Reset mock interaction counts between tests
        reset(jmsTemplate);
        // Clear any pending requests from previous tests
        correlator.clearPendingRequests();
    }

    // ==================== End-to-End Flow Tests ====================

    @Test
    @Timeout(value = 5, unit = TimeUnit.SECONDS)
    void sendRequest_registersAndSendsViaJms() {
        ConnectorDto connector = createConnector("proxy-int-001");

        // Start async request
        CompletableFuture<String> future = proxyClient.sendRequestAsync(
                connector, "/v1/test", "GET", null, String.class);

        // Verify request was registered and message was sent via JMS
        await().atMost(Duration.ofSeconds(2)).untilAsserted(() -> {
            assertThat(correlator.getPendingCount()).isGreaterThanOrEqualTo(1);
            verify(jmsTemplate).convertAndSend(any(String.class), any(CoreMessage.class), any());
        });

        // Cleanup to avoid leaking pending request
        future.cancel(true);
    }

    @Test
    @Timeout(value = 5, unit = TimeUnit.SECONDS)
    @DisplayName("When response arrives, future completes with deserialized body")
    void sendRequest_whenResponseArrives_completesSuccessfully() throws Exception {
        ConnectorDto connector = createConnector("proxy-int-002");

        // Capture the correlation ID when request is sent
        ArgumentCaptor<CoreMessage> requestCaptor = ArgumentCaptor.forClass(CoreMessage.class);

        // Send async request
        CompletableFuture<Map> future = proxyClient.sendRequestAsync(
                connector, "/v1/test", "GET", null, Map.class);

        // Wait for JMS send to be called using Awaitility
        await().atMost(Duration.ofSeconds(2))
               .untilAsserted(() -> verify(jmsTemplate).convertAndSend(any(String.class), requestCaptor.capture(), any()));

        String correlationId = requestCaptor.getValue().getCorrelationId();

        // Simulate response arriving
        ProxyMessage message = ProxyMessage.builder()
                .correlationId(correlationId)
                .proxyId("proxy-int-002")
                .timestamp(Instant.now())
                .connectorResponse(ConnectorResponse.builder()
                        .statusCode(200)
                        .body(Map.of("status", "ok"))
                        .build())
                .build();

        correlator.completeRequest(message);

        // Verify future completes
        Map result = future.get(2, TimeUnit.SECONDS);
        assertThat(result).isNotNull();
        assertThat(result.get("status")).isEqualTo("ok");
    }

    @Test
    @Timeout(value = 10, unit = TimeUnit.SECONDS)
    @DisplayName("Multiple concurrent requests correlate correctly even when completed out of order")
    void multipleRequests_correlateCorrectly() throws Exception {
        ConnectorDto connector = createConnector("proxy-int-003");

        // Send multiple async requests
        CompletableFuture<String> future1 = proxyClient.sendRequestAsync(
                connector, "/v1/resource/1", "GET", null, String.class);
        CompletableFuture<String> future2 = proxyClient.sendRequestAsync(
                connector, "/v1/resource/2", "GET", null, String.class);
        CompletableFuture<String> future3 = proxyClient.sendRequestAsync(
                connector, "/v1/resource/3", "GET", null, String.class);

        // Wait for all JMS sends using Awaitility
        ArgumentCaptor<CoreMessage> requestCaptor = ArgumentCaptor.forClass(CoreMessage.class);
        await().atMost(Duration.ofSeconds(2))
               .untilAsserted(() -> verify(jmsTemplate, times(3)).convertAndSend(any(String.class), requestCaptor.capture(), any()));

        var capturedRequests = requestCaptor.getAllValues();
        String corrId1 = capturedRequests.get(0).getCorrelationId();
        String corrId2 = capturedRequests.get(1).getCorrelationId();
        String corrId3 = capturedRequests.get(2).getCorrelationId();

        // All correlation IDs should be unique
        assertThat(corrId1).isNotEqualTo(corrId2);
        assertThat(corrId2).isNotEqualTo(corrId3);
        assertThat(corrId1).isNotEqualTo(corrId3);

        // Complete in different order
        correlator.completeRequest(createMessage(corrId2, "response-2"));
        correlator.completeRequest(createMessage(corrId3, "response-3"));
        correlator.completeRequest(createMessage(corrId1, "response-1"));

        // Each future should get correct response
        assertThat(future1.get(2, TimeUnit.SECONDS)).isEqualTo("response-1");
        assertThat(future2.get(2, TimeUnit.SECONDS)).isEqualTo("response-2");
        assertThat(future3.get(2, TimeUnit.SECONDS)).isEqualTo("response-3");
    }

    @Test
    @DisplayName("Response with wrong correlation ID does not complete unrelated pending request")
    void responseForDifferentCorrelationId_doesNotAffectOther() {
        ConnectorDto connector = createConnector("proxy-int-004");

        CompletableFuture<String> future = proxyClient.sendRequestAsync(
                connector, "/v1/test", "GET", null, String.class);

        // Wait for registration using Awaitility
        await().atMost(Duration.ofSeconds(2))
               .until(() -> correlator.getPendingCount() >= 1);

        // Complete with wrong correlation ID
        correlator.completeRequest(createMessage("wrong-corr-id", "wrong response"));

        // Original future should still be pending
        assertThat(future.isDone()).isFalse();
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

    private ProxyMessage createMessage(String correlationId, Object body) {
        return ProxyMessage.builder()
                .correlationId(correlationId)
                .proxyId("test-proxy")
                .timestamp(Instant.now())
                .connectorResponse(ConnectorResponse.builder()
                        .statusCode(200)
                        .body(body)
                        .build())
                .build();
    }
}
