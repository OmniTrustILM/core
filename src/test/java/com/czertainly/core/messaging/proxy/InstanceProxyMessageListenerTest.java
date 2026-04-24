package com.czertainly.core.messaging.proxy;

import com.czertainly.api.clients.mq.model.ConnectorResponse;
import com.czertainly.api.clients.mq.model.ProxyMessage;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.time.Instant;

import static org.assertj.core.api.Assertions.assertThatCode;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
class InstanceProxyMessageListenerTest {

    @Mock
    private ProxyMessageCorrelator correlator;

    private InstanceProxyMessageListener listener;

    @BeforeEach
    void setUp() {
        listener = new InstanceProxyMessageListener(correlator);
    }

    @Test
    void processMessage_withCorrelationId_callsCorrelator() throws Exception {
        ProxyMessage message = createMessage("corr-1", "GET:/v1/test");
        when(correlator.tryCompleteRequest(message)).thenReturn(true);

        listener.processMessage(message);

        verify(correlator).tryCompleteRequest(message);
    }

    @Test
    void processMessage_correlatorReturnsFalse_doesNotThrow() throws Exception {
        ProxyMessage message = createMessage("corr-unknown", "GET:/v1/test");
        when(correlator.tryCompleteRequest(message)).thenReturn(false);

        assertThatCode(() -> listener.processMessage(message)).doesNotThrowAnyException();
        verify(correlator).tryCompleteRequest(message);
    }

    @Test
    void processMessage_withNullCorrelationId_doesNotCallCorrelator() throws Exception {
        ProxyMessage message = createMessage(null, "GET:/v1/test");

        listener.processMessage(message);

        verify(correlator, never()).tryCompleteRequest(any());
    }

    @Test
    void processMessage_withBlankCorrelationId_doesNotCallCorrelator() throws Exception {
        ProxyMessage message = createMessage("   ", "GET:/v1/test");

        listener.processMessage(message);

        verify(correlator, never()).tryCompleteRequest(any());
    }

    @Test
    void processMessage_withNullMessage_doesNotThrow() throws Exception {
        assertThatCode(() -> listener.processMessage(null)).doesNotThrowAnyException();
        verify(correlator, never()).tryCompleteRequest(any());
    }

    private ProxyMessage createMessage(String correlationId, String messageType) {
        return ProxyMessage.builder()
                .correlationId(correlationId)
                .proxyId("test-proxy")
                .messageType(messageType)
                .timestamp(Instant.now())
                .connectorResponse(ConnectorResponse.builder()
                        .statusCode(200)
                        .build())
                .build();
    }
}
